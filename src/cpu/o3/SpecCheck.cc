#include "cpu/o3/SpecCheck.hh"

namespace gem5 {

namespace o3 {

int numFlushedWindows = 0;
int numVulnWindows = 0;
int currentFsmState = Q_INIT;
unsigned long long savedPC = -1;
std::vector<unsigned long long>PCs;

// INCLUDE SUPPORT FOR EBP AND OTHER 32 BIT REGISTERS
// If register is not in map, ignore?

// Register mapping
// Any registers set to 1 are "in" the register array
// Removing a regsiter sets it to 0
// An "empty" register array is all 0s
// https://www.tortall.net/projects/yasm/manual/html/arch-x86/x86-registers.png

// FIX THESE TO

std::map<std::string, int>registers = {
    {"rax", 0}, {"eax",  0}, {"ax",   0}, {"ah",   0}, {"al", 0},
    {"rbx", 0}, {"ebx",  0}, {"bx",   0}, {"bh",   0}, {"bl", 0},
    {"rcx", 0}, {"ecx",  0}, {"cx",   0}, {"ch",   0}, {"cl", 0},
    {"rdx", 0}, {"edx",  0}, {"dx",   0}, {"dh",   0}, {"dl", 0},
    {"rsi", 0}, {"esi",  0}, {"si",   0}, {"sil",  0},
    {"rdi", 0}, {"edi",  0}, {"di",   0}, {"dil",  0},
    {"rsp", 0}, {"esp",  0}, {"sp",   0}, {"spl",  0},
    {"rbp", 0}, {"ebp",  0}, {"bp",   0}, {"bpl",  0},
    {"r8",  0}, {"r8d",  0}, {"r8w",  0}, {"r8b",  0},
    {"r9",  0}, {"r9d",  0}, {"r9w",  0}, {"r9b",  0},
    {"r10", 0}, {"r10d", 0}, {"r10w", 0}, {"r10b", 0},
    {"r11", 0}, {"r11d", 0}, {"r11w", 0}, {"r11b", 0},
    {"r12", 0}, {"r12d", 0}, {"r12w", 0}, {"r12b", 0},
    {"r13", 0}, {"r13d", 0}, {"r13w", 0}, {"r13b", 0},
    {"r14", 0}, {"r14d", 0}, {"r14w", 0}, {"r14b", 0},
    {"r15", 0}, {"r15d", 0}, {"r15w", 0}, {"r15b", 0},
    {"t0",  0}, {"t0d",  0}, {"t0w",  0}, {"t0b",  0},
    {"t1",  0}, {"t1d",  0}, {"t1w",  0}, {"t1b",  0},
    {"t2",  0}, {"t2d",  0}, {"t2w",  0}, {"t2b",  0},
    {"t3",  0}, {"t3d",  0}, {"t3w",  0}, {"t3b",  0},
    {"t4",  0}, {"t4d",  0}, {"t4w",  0}, {"t4b",  0},
    {"t5",  0}, {"t5d",  0}, {"t5w",  0}, {"t5b",  0},
    {"t6",  0}, {"t6d",  0}, {"t6w",  0}, {"t6b",  0},
    {"t7",  0}, {"t7d",  0}, {"t7w",  0}, {"t7b",  0}
};

int register_array_empty() {
    std::map<std::string, int>::iterator it;
    for (it = registers.begin(); it != registers.end(); it++) {
        // check if value is 1
        if (it->second == 1) {
            return 0;
        }
    }
    // No 1s found
    return 1;
}

void clear_register_array() {
    std::map<std::string, int>::iterator it;
    for (it = registers.begin(); it != registers.end(); it++) {
        // set values to 0
        it->second = 0;
    }

}

// CHANGE TO IS IT A LOAD
// idea, staticInst->isLoad() or staticInst->isStore()
// instead of checking memory operations?
// int is_memory_op(std::string inst) {
//
// 	// get the macroop
// 	// remove leading spaces
// 	inst.erase(0,2);
// 	std::string macroop;
// 	std::string delim = " ";
// 	size_t pos = inst.find(delim);
// 	macroop = inst.substr(0,pos);
//
// 	// Add more later!
// 	if (macroop == "MOV_R_M" ||
// 	  macroop == "MOV_M_R" ){
// 		return 1;
// 	}
//
// 	return 0;
// }

int is_memory_op(StaticInstPtr staticInst) {
    return staticInst->isLoad();
}

std::string get_dest_register(std::string inst) {
    std::string token;
    std::string delim = "   ";
    size_t pos = inst.find(delim);
    inst.erase(0, pos + delim.length());
    token = inst.substr(0, pos);
    delim = ", ";
    pos = token.find(delim);
    return token.substr(0, pos);
}

std::string get_src1_register(std::string inst) {
    std::string delim = "   ";
    size_t pos = inst.find(delim);
    inst.erase(0, pos + delim.length());
    delim = ", ";
    pos = inst.find(delim);
    inst.erase(0, pos + delim.length());
    pos = inst.find(delim);
    return inst.substr(0,pos);
}

std::string get_src2_register(std::string inst) {
    std::string delim = "   ";
    size_t pos = inst.find(delim);
    inst.erase(0, pos + delim.length());
    delim = ", ";
    pos = inst.find(delim);
    inst.erase(0, pos + delim.length());
    pos = inst.find(delim);

    if (pos != std::string::npos) {
        inst.erase(0, pos + delim.length());
        return inst;
    }
    else {
        return "";
    }
}

// TODO: UPDATE FSM TO INCLUDE COMPLETES!!!
// TODO: modify logic to NOT consume additional
// instruction once the ACC state has been reached
// TODO: when checking src, doesnt matter
// Maybe change input parameters to whole instruction?
// FSM transition function
// Consumes the instruction and changes state
int consume_instruction(std::string inst,
            unsigned long long PC,
            Tick commit,
            Tick issue,
            Tick complete,
            StaticInstPtr staticInst) {

    std::string dest = get_dest_register(inst);
    std::string src1 = get_src1_register(inst);
    std::string src2 = get_src2_register(inst);

    if (currentFsmState == Q_INIT) {
        clear_register_array();
        savedPC = -1;
        // instruction retires
        // do not change state
        if (commit != -1) {
            // return 0;
        }

        // instruction is flushed
        else {
            // If instruction is mem op that doesnt execute or non mem op
            // Save PC, change state
            if ((is_memory_op(staticInst) && issue == -1)
                || !is_memory_op(staticInst)) {
                currentFsmState = Q_1;
                savedPC = PC;
            }
            // If instruction is memory op that executes
            // Save PC, change state
            else if (is_memory_op(staticInst) && issue != -1){
                currentFsmState = Q_2;
                savedPC = PC;
                // add destination register to register array
                // first check that destination register is in array
                if (registers.find(dest) != registers.end())
                    registers[dest] = 1;
                else
                    return -1;
            }
            // Should never reach here...
            else {
                return -1;
            }
        }
    }

    else if (currentFsmState == Q_1) {

        // If flushed non memory inst or flushed mem inst that doesnt execute
        // do nothing
        if ((is_memory_op(staticInst) && issue == -1)
            || !is_memory_op(staticInst)) {
            // return 0;
        }
        // If flushed mem inst that completes
        // Change state, add dst to register array
        else if (is_memory_op(staticInst) && issue != -1) {
            currentFsmState = Q_2;
            if (registers.find(dest) != registers.end())
                registers[dest] = 1;
            else
                return -1;
        }
        // Retired instruction
        // goto Q_INIT
        else if (commit != -1) {
            currentFsmState = Q_INIT;
        }
        // Should never reach here...
        else {
            return -1;
        }
    }

    else if (currentFsmState == Q_2) {

        if (commit != -1 && PC == savedPC) {
            currentFsmState = Q_INIT;
        }
        else if (registers.find(src1) != registers.end()
                && registers[src1] == 1) {
            currentFsmState = Q_3;
        }
        else if (registers.find(src2) != registers.end()
                && registers[src2] == 1) {
            currentFsmState = Q_3;
        }
        else if (is_memory_op(staticInst) && issue != -1) {
                if (registers.find(dest) != registers.end())
                    registers[dest] = 1;
                else
                    return -1;
        }
        else if (commit != -1 && PC != savedPC) {
            // If mem inst and executes
            if (is_memory_op(staticInst) && issue != -1) {
                    currentFsmState = Q_4;
                    if (registers.find(dest) != registers.end())
                        registers[dest] = 0;
                    else
                        return -1;
            }
            // Non memory instruction or mem inst that doesnt execute
            // change state
            else {
                currentFsmState = Q_4;
            }
        }
        else {
        //	std::cout << "Help! Inst: " << inst << std::endl;
        }
    }

    else if (currentFsmState == Q_3) {
        // Retired instruction and PC == savedPC
        // goto initial state
        if (commit != -1 && PC == savedPC) {
            currentFsmState = Q_INIT;
        }
        // Retired inst and PC != savedPC
        // goto accept state
        else if (commit != -1 && PC != savedPC) {
            currentFsmState = Q_ACC;
        }
        // Any flushed instruction
        // do nothing
        else if (commit == -1) {
        }
        // should never reach here...
        else {
            // return -1;
        }
    }

    else if (currentFsmState == Q_4) {
        // if no more registers in reg array, goto initial state
        if (register_array_empty()) {
            currentFsmState = Q_INIT;
        }
        // If retired inst
        else if (commit != -1) {
            if (registers.find(src1) != registers.end()
                && registers[src1] == 1) {
                currentFsmState = Q_3;
            }
            else if (registers.find(src2) != registers.end()
                && registers[src2] == 1) {
                currentFsmState = Q_3;
            }
            // if memory op that executes
            else if (is_memory_op(staticInst) && issue != -1) {
                    if (registers.find(dest) != registers.end())
                        registers[dest] = 0;
                    else
                        return -1;
            }
            // otherwise any retired instruction
            // do not change state
            else {
                // return 0;
            }
        }
        // flushed instruction
        else {
            // if memory inst that executes, goto Q_2
            if (is_memory_op(staticInst) && issue != -1) {
                clear_register_array();
                savedPC = PC;
                if (registers.find(dest) != registers.end())
                    registers[dest] = 1;
                currentFsmState = Q_2;
            }
            // otherwise goto Q_1
            else if ((is_memory_op(staticInst) && issue == -1)
                || !is_memory_op(staticInst)){
                clear_register_array();
                savedPC = PC;
                currentFsmState = Q_1;
            }
            // should never reach here...
            else {
                // return -1;
            }
        }
    }

    if (currentFsmState == Q_ACC) {

        // Check if misspeculated window is not already in list
        if (std::find(PCs.begin(), PCs.end(), savedPC) == PCs.end()) {
            PCs.push_back(savedPC);
            numVulnWindows++;
            currentFsmState = Q_INIT;
            printf("Vulnerable speculative code found!\n");
            printf("Misspeculation window beginning at \
                        0x%08llx is vulnerable!\n",savedPC);
            printf("Total number of malicious windows: %d\n", numVulnWindows);
        }
        return 0;
    }

    return 0;
}

} // namespace o3
} // namespace gem5
