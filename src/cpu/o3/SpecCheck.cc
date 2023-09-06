#include "cpu/o3/SpecCheck.hh"

#include "debug/SpecCheck.hh"

#define KNOWN(X) (false)

gem5::o3::DynInstPtr prev;

// Global definition of SpecCheck FSM
SpecCheck SC = SpecCheck();

SpecCheck::SpecCheck() {

    currentFsmState = Q_INIT;

    numFlushed = 0;
    numUniqFlushed = 0;
    numVulnerable = 0;
    numUniqVulnerable = 0;

    // Remove out file
    std::ofstream sc_out;
    sc_out.open(SC_OUT, std::ofstream::out);
    sc_out.close();
}

int SpecCheck::in_flushed(unsigned long long pc) {
    return (std::find(flushed_pcs.begin(), flushed_pcs.end(), pc)
             != flushed_pcs.end());
}

int SpecCheck::in_vulnerable(unsigned long long pc) {
    return (std::find(vuln_pcs.begin(), vuln_pcs.end(), pc)
             != vuln_pcs.end());
}

int SpecCheck::in_taint_table(gem5::PhysRegIdPtr reg1,
                              gem5::PhysRegIdPtr reg2,
                              size_t num) {
    if (num == 1) {
        return (std::find(taint_table.begin(), taint_table.end(), reg1)
                 != taint_table.end());
    }
    else if (num == 2) {
        return ((std::find(taint_table.begin(), taint_table.end(), reg1)
                    != taint_table.end()) ||
               (std::find(taint_table.begin(), taint_table.end(), reg2)
                    != taint_table.end()));
    }
    else {
        return false;
    }
}

void SpecCheck::set_taint(gem5::PhysRegIdPtr reg) {
    taint_table.push_back(reg);
}

void SpecCheck::remove_taint(gem5::PhysRegIdPtr reg) {
    taint_table.erase(std::remove(taint_table.begin(),
        taint_table.end(), reg), taint_table.end());
}

void SpecCheck::clear_taint_table() {
    taint_table.clear();
    gadget_components.clear();
}

int SpecCheck::is_load(gem5::StaticInstPtr staticInst, std::string inst) {
    return staticInst->isLoad() && inst.find("DS:[") != std::string::npos;
}

int SpecCheck::is_micro_visible(gem5::StaticInstPtr staticInst,
                                std::string inst) {
    return ((staticInst->isLoad() && inst.find("MOV") != std::string::npos) ||
            staticInst->isFloating() ||
            staticInst->isControl() ||
            staticInst->isCall() ||
            staticInst->isReturn());
}

void SpecCheck::log_components() {
    std::string transitions[] = {
        "Misspeculation start: ",
        "First CLoad: ",
        "Transmitter: "
    };
    std::ofstream sc_out;
    sc_out.open(SC_OUT, std::ofstream::out | std::ofstream::app);
    for (int i=0; i<3; ++i) {
        sc_out << transitions[i] << gadget_components[i] << std::endl;
    }
    sc_out << std::endl;
    sc_out.close();
}

// TODO, include this in SpecCheck:: namespace
void print_instruction(gem5::o3::DynInstPtr dynInst,
                       unsigned long long PC,
                       std::string inst,
                       gem5::PhysRegIdPtr dest,
                       gem5::PhysRegIdPtr src1,
                       gem5::PhysRegIdPtr src2,
                       size_t numSrcs, size_t numDsts) {
    std::cout << "PC: " << std::hex << PC
              << std::dec << inst
              << " dest: " << dest << " src1: " << src1 << " src2: " << src2
              << " num dst: " << numDsts << " num src: " << numSrcs
              << std::endl
              << "      Fetch: " << dynInst->fetchTick
              << " Decode: " << dynInst->decodeTick
              << " Rename: " << dynInst->renameTick
              << " Dispatch: " << dynInst->dispatchTick
              << " Issue: " << dynInst->issueTick
              << " Complete: " << dynInst->completeTick
              << " Commit: " << dynInst->commitTick
              << std::endl;

}

int SpecCheck::consume_instruction(gem5::o3::DynInstPtr dynInst) {

    bool issue = (dynInst->issueTick == -1) ? 0 : 1;
    bool complete = (dynInst->completeTick == -1) ? 0 : 1;
    bool commit = (dynInst->commitTick == -1) ? 0 : 1;
    unsigned long long PC = dynInst->pcState().instAddr();
    std::string inst = dynInst->staticInst->disassemble(
        dynInst->pcState().instAddr());
    gem5::StaticInstPtr staticInst = dynInst->staticInst;

    size_t numSrcs = staticInst->numSrcRegs();
    size_t numDsts = staticInst->numDestRegs();

    gem5::PhysRegIdPtr dest = 0;
    gem5::PhysRegIdPtr src1 = 0;
    gem5::PhysRegIdPtr src2 = 0;

    if (numDsts > 0) {
        // dest = staticInst->destRegIdx(0);
        dest = dynInst->renamedDestIdx(0);
        numDsts = 1;
    }
    if (numSrcs > 0) {
        // src1 = staticInst->srcRegIdx(0);
        src1 = dynInst->renamedSrcIdx(0);
        if (numSrcs > 1) {
            // src2 = staticInst->srcRegIdx(1);
            src2 = dynInst->renamedSrcIdx(1);
            numSrcs = 2;
        }
    }

    if (currentFsmState == Q_INIT) {
        savedPC = -1;

        // beginning of misspeculation window
        if (commit == 0) {

            savedPC = PC;
            numFlushed++;

            // check if flushed window is unique
            if (!in_flushed(savedPC)) {
                flushed_pcs.push_back(savedPC);
                numUniqFlushed = flushed_pcs.size();
            }

            // Completed memroy load
            if (is_load(staticInst, inst) && complete != 0 && numDsts > 0) {
                    set_taint(dest);
                    currentFsmState = Q_2;

                    // Inst is both misspeculation start and CLoad
                    gadget_components.push_back(inst);
                    gadget_components.push_back(inst);


                    if (KNOWN(savedPC)) {
                        std::cout << "Q0->Q2 (taint): ";
                    }
            }
            // Non completed memory load or non memory operation
            else {
                    currentFsmState = Q_1;

                    // Log misspeculation start
                    gadget_components.push_back(inst);
                    if (KNOWN(savedPC)) {
                        std::cout << "Q0->Q1: ";
                    }
            }
        }

    }

    else if (currentFsmState == Q_1) {

        // Retired instruction
        // goto Q_INIT
        if (commit != 0) {
            clear_taint_table();
            currentFsmState = Q_INIT;
        }
        // flushed instruction
        else {
            // If completed memory inst:
            // add destination register to register array
            // goto Q_2
            if (is_load(staticInst, inst) && complete != 0 && numDsts > 0) {
                set_taint(dest);
                currentFsmState = Q_2;

                // Log Cload
                gadget_components.push_back(inst);
                if (KNOWN(savedPC)) {
                    std::cout << "Q1->Q2 (taint): ";
                }
            }
            // Any other flushed instruction does not change state
        }
    }

    else if (currentFsmState == Q_2) {

        // Retired instruction
        if (commit != 0) {
            clear_taint_table();
            currentFsmState = Q_INIT;
        }
        // Flushed instruction
        else {
            // If instruction is micro visible and either of
            // its sources are in the taint table, goto accept
            if (issue!= 0 && is_micro_visible(staticInst, inst) &&
                in_taint_table(src1, src2, numSrcs) ){
                currentFsmState = Q_ACC;

                // Log transmitter
                gadget_components.push_back(inst);
                if (KNOWN(savedPC)) {
                    std::cout << "Q2->QACC: ";
                }
            }
            // If instruction is a CLoad, add dest to taint table
            if (complete != 0 && numDsts > 0 &&
                        (is_load(staticInst, inst)
                        || in_taint_table(src1, src2, numSrcs)
                        )
                    ){
                set_taint(dest);
                if (KNOWN(savedPC)) {
                    std::cout << "(taint) ";
                }
            }

            // If destination in taint and gets overwritten by
            // non tainted sources, untaint
            else if (complete != 0 && numDsts > 0 &&
                    (
                    ( (staticInst->isLoad() || staticInst->getName() == "rdip")
                    && !(in_taint_table(src1, src2, numSrcs)) )
                    || staticInst->getName() == "limm"
                    )
                    && in_taint_table(dest, 0 , 1)
                   ){
                // Remove dest from taint table
                remove_taint(dest);
                if (KNOWN(savedPC)) {
                    std::cout << "(untaint) ";
                }
            }
        }
    }

    if (currentFsmState == Q_ACC) {
        numVulnerable++;
        // Check if misspeculated window is not already in list
        if (!in_vulnerable(savedPC)) {
            vuln_pcs.push_back(savedPC);
            numUniqVulnerable = vuln_pcs.size();

            std::ofstream sc_out;
            sc_out.open(SC_OUT, std::ofstream::out | std::ofstream::app);
            sc_out << std::hex << savedPC << std::endl;
            sc_out.close();

            log_components();

            // printf("Potential vulnerable window found at: 0x%08llx\n",
            //        savedPC);
        }

        // End of misspeculation window
        if (commit != 0) {
            clear_taint_table();
            currentFsmState = Q_INIT;
        }
    }

    if (KNOWN(savedPC)) {
        print_instruction(dynInst, PC, inst,
            dest, src1, src2, numSrcs, numDsts);
    }

    prev = dynInst;

    return 0;
}
