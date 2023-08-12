#include "cpu/o3/SpecCheck.hh"

#include "debug/SpecCheck.hh"

// Global definition of SpecCheck FSM
SpecCheck SC;

int SpecCheck::in_flushed(unsigned long long pc) {
    return (std::find(flushed_pcs.begin(), flushed_pcs.end(), pc)
             != flushed_pcs.end());
}

int SpecCheck::in_vulnerable(unsigned long long pc) {
    return (std::find(vuln_pcs.begin(), vuln_pcs.end(), pc)
             != vuln_pcs.end());
}

int SpecCheck::in_taint_table(gem5::PhysRegIdPtr reg) {
    return (std::find(taint_table.begin(), taint_table.end(), reg)
             != taint_table.end());
}

void SpecCheck::set_taint(gem5::PhysRegIdPtr reg) {
    taint_table.push_back(reg);
}

void SpecCheck::clear_taint_table() {
    taint_table.clear();
}

int SpecCheck::is_load(gem5::StaticInstPtr staticInst) {
    return staticInst->isLoad();
}

int SpecCheck::is_micro_visible(gem5::StaticInstPtr staticInst) {
    return (staticInst->isLoad() ||
            staticInst->isStore() ||
            staticInst->isFloating() ||
            staticInst->isControl() ||
            staticInst->isCall() ||
            staticInst->isReturn());
}

void SpecCheck::init(unsigned long long addr, size_t size) {

    numFlushed = 0;
    numUniqFlushed = 0;
    numVulnerable = 0;
    numUniqVulnerable = 0;

    mainStart = addr;
    mainEnd = mainStart + size;
    printf("Main found! Start: 0x%08llx, End: 0x%08llx\n", mainStart, mainEnd);

    // Remove out file
    std::ofstream sc_out;
    sc_out.open(SC_OUT, std::ofstream::out);
    sc_out.close();
}

int SpecCheck::consume_instruction(gem5::o3::DynInstPtr dynInst) {

    bool issue = (dynInst->issueTick == -1) ? 0 : 1;
    bool complete = (dynInst->completeTick == -1) ? 0 : 1;
    bool commit = (dynInst->commitTick == -1) ? 0 : 1;
    unsigned long long PC = dynInst->pcState().instAddr();
    std::string inst = dynInst->staticInst->disassemble(
        dynInst->pcState().instAddr());
    gem5::StaticInstPtr staticInst = dynInst->staticInst;

    // Only run if we have started the main fn
    if (PC == mainStart) {
        inMain = true;
    }
    if (inMain && (PC == mainEnd || PC == mainEnd - 1)) {
        inMain = false;
    }
    if (!inMain || staticInst->isNop()) {
        return 0;
    }

    size_t numSrcs = dynInst->numSrcs();
    size_t numDsts = dynInst->numDests();

    gem5::PhysRegIdPtr dest = 0;
    gem5::PhysRegIdPtr src1 = 0;
    gem5::PhysRegIdPtr src2 = 0;

    if (numDsts > 0)
        dest = dynInst->renamedDestIdx(0);
    if (numSrcs > 0) {
        src1 = dynInst->renamedSrcIdx(0);
        if (numSrcs > 1) {
            src2 = dynInst->renamedSrcIdx(1);
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
            if (is_load(staticInst) && complete != 0 && dest != 0) {
                    set_taint(dest);
                    currentFsmState = Q_2;
            }
            // Non completed memory load or non memory operation
            else {
                    currentFsmState = Q_1;
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
            if (is_load(staticInst) && complete != 0 && dest != 0) {
                set_taint(dest);
                currentFsmState = Q_2;
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
            if (issue!= 0 && is_micro_visible(staticInst) &&
               ((src1 != 0 && in_taint_table(src1)) ||
               (src2 != 0 && in_taint_table(src2)))) {
                currentFsmState = Q_ACC;
            }
            // If instruction is a CLoad, add dest to taint table
            else if (complete != 0 && dest != 0 && is_load(staticInst)) {
                set_taint(dest);
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

            // printf("Potential vulnerable window found at: 0x%08llx\n",
            //        savedPC);
        }
        clear_taint_table();
        currentFsmState = Q_INIT;
    }

    return 0;
}
