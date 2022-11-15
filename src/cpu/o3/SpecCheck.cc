#include "cpu/o3/SpecCheck.hh"
#include "debug/SpecCheck.hh"

namespace gem5 {

namespace o3 {

int numFlushedWindows = 0;
int numVulnWindows = 0;
int numUniqWindows = 0;
int currentFsmState = Q_INIT;
unsigned long long savedPC = -1;
std::vector<unsigned long long>PCs;
std::vector<PhysRegIdPtr>registers;

int in_destination_array(PhysRegIdPtr reg) {
    return (std::find(registers.begin(), registers.end(), reg)
             != registers.end());
}

void set_destination(PhysRegIdPtr reg) {
    registers.push_back(reg);
}

int register_array_empty() {
    return registers.empty();
}

void clear_register_array() {
    registers.clear();
}

int is_memory_op(StaticInstPtr staticInst) {
    return staticInst->isLoad();
}

int consume_instruction(std::string inst,
            unsigned long long PC,
            bool commit,
            bool issue,
            bool complete,
            StaticInstPtr staticInst,
            DynInstPtr dynInst) {

    size_t numSrcs = dynInst->numSrcs();
    size_t numDsts = dynInst->numDests();

    PhysRegIdPtr dest = 0;
    PhysRegIdPtr src1 = 0;
    PhysRegIdPtr src2 = 0;

    if (numDsts > 0)
        dest = dynInst->renamedDestIdx(0);
    if (numSrcs > 0) {
        src1 = dynInst->renamedSrcIdx(0);
        if (numSrcs > 1) {
            src2 = dynInst->renamedSrcIdx(1);
        }
    }

    if (currentFsmState == Q_INIT) {
        clear_register_array();
        savedPC = -1;

            // beginning of misspeculation window
            if (commit == 0) {

                savedPC = PC;
                numFlushedWindows++;

                // Completed memroy load
                if (is_memory_op(staticInst) && complete != 0 && dest != 0) {
                        set_destination(dest);
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
            currentFsmState = Q_INIT;
        }
        // flushed instruction
        else {
            // If completed memory inst:
            // add destination register to register array
            // goto Q_2
            if (is_memory_op(staticInst) && complete != 0 && dest != 0) {
                set_destination(dest);
                currentFsmState = Q_2;
            }
            // Any other flushed instruction does not change state
        }
    }

    else if (currentFsmState == Q_2) {

        // Retired instruction
        if (commit != 0) {
            currentFsmState = Q_INIT;
        }
        // Flushed instruction
        else {
            // Check if inst executes and uses a tainted source
            if (issue != 0 && src1 != 0 && in_destination_array(src1)) {
                // Propogate taint to destiation register if inst completes
                if (complete != 0)
                    set_destination(src1);
                currentFsmState = Q_3;
            }
            // Check both source registers, adding both to list
            if (issue != 0 && src2 != 0 && in_destination_array(src2)) {
                // Propogate taint to destiation register if inst completes
                if (complete != 0)
                    set_destination(src2);
                currentFsmState = Q_3;
            }
            // If memory operation completes
            // Add destination to dest register
            // Remain in state, regardless of tainted sources
            if (is_memory_op(staticInst) && complete != 0 && dest != 0) {
                set_destination(dest);
                currentFsmState = Q_2;
            }
            // Otherwise do nothing and remain in state Q_2
        }
    }

    else if (currentFsmState == Q_3) {
        // Retired instruction
        if (commit != 0) {
            if (PC == savedPC) {
                currentFsmState = Q_INIT;
            }
            // PC != SavedPC
            else {
                currentFsmState = Q_ACC;
            }
        }
        // Flushed instruction
        else {
            if (issue != 0 && src1 != 0 && in_destination_array(src1)) {
                if (complete != 0)
                    set_destination(src1);
            }
            if (issue != 0 && src2 != 0 && in_destination_array(src2)) {
                if (complete != 0)
                    set_destination(src2);
            }
            if (is_memory_op(staticInst) && complete != 0 && dest != 0) {
                set_destination(dest);
            }
        }

    }


    if (currentFsmState == Q_ACC) {
        numVulnWindows++;
        // Check if misspeculated window is not already in list
        if (std::find(PCs.begin(), PCs.end(), savedPC) == PCs.end()) {
            PCs.push_back(savedPC);
            numUniqWindows = PCs.size();
            // printf("Vulnerable speculative code found!\n");
            // printf("Misspeculation window beginning at \
            //             0x%08llx is vulnerable!\n",savedPC);
            // printf("Total number of malicious windows: %d/%d (total)\n",
            //         numVulnWindows, numFlushedWindows);
            // printf("Unique PCs: %ld\n", PCs.size());
        }
        currentFsmState = Q_INIT;
    }

    return 0;
}

} // namespace o3
} // namespace gem5
