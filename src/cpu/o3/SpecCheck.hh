#ifndef __CPU_O3_SPECCHECK_HH__
#define __CPU_O3_SPECCHECK_HH__

#include <iostream>
#include <map>
#include <string>

#include "cpu/o3/dyn_inst.hh"

// TODO: minimize this file to expose ONLY
// functions/vars that will be used externally

namespace gem5 {

namespace o3 {

extern int numFlushedWindows;
extern int numVulnWindows;
extern int currentFsmState;
extern unsigned long long savedPC;
extern std::map<std::string, int>registers;
extern std::vector<unsigned long long>PCs;

enum fsmStates
{
        Q_INIT,
        Q_1,
        Q_2,
        Q_3,
        Q_4,
        Q_ACC
};

int register_array_empty();

void clear_register_array();

// function to determine whether or not a given instruction
// is a (vulnerable) memory operation
// i.e. loads
// int is_memory_op(std::string inst);

int consume_instruction(std::string inst,
                        unsigned long long PC,
                        Tick commit, Tick issue,
                        Tick complete,
                        StaticInstPtr staticInst);

} // namespace 03
} // namespace gem5

#endif // __CPU_O3_SPECCHECK_HH__
