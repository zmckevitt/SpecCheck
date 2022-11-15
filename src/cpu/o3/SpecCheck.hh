#ifndef __CPU_O3_SPECCHECK_HH__
#define __CPU_O3_SPECCHECK_HH__

#include <iostream>
#include <map>
#include <string>

#include "cpu/o3/dyn_inst.hh"

namespace gem5 {

namespace o3 {

extern int numFlushedWindows;
extern int numVulnWindows;
extern int numUniqWindows;
extern int currentFsmState;

// I believe we can delete these...
// Although we could add savedPCs as a Stats::vector in commit
// Make PCs private!
extern unsigned long long savedPC;
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

int consume_instruction(std::string inst,
                        unsigned long long PC,
                        bool commit,
                        bool issue,
                        bool complete,
                        StaticInstPtr staticInst,
                        DynInstPtr dynInst);


} // namespace 03
} // namespace gem5

#endif // __CPU_O3_SPECCHECK_HH__
