#ifndef __CPU_O3_SPECCHECK_HH__
#define __CPU_O3_SPECCHECK_HH__

#include <iostream>
#include <map>
#include <string>

#include "cpu/o3/dyn_inst.hh"

#define SC_OUT "./m5out/SpecCheck.out"

class SpecCheck
{

public:
    int numFlushed;
    int numUniqFlushed;
    int numVulnerable;
    int numUniqVulnerable;
    int currentFsmState;

    enum fsmStates
    {
            Q_INIT,
            Q_1,
            Q_2,
            Q_ACC
    };

    // Initialize SpecCheck when we encounter main
    // Specify main starting address and section length
    void init(unsigned long long addr,
                          size_t size);

    int consume_instruction(gem5::o3::DynInstPtr dynInst);

private:
    unsigned long long savedPC;
    unsigned long long mainStart;
    unsigned long long mainEnd;
    bool inMain;

    std::vector<unsigned long long>flushed_pcs;
    std::vector<unsigned long long>vuln_pcs;
    std::vector<gem5::PhysRegIdPtr>taint_table;

    int in_flushed(unsigned long long pc);
    int in_vulnerable(unsigned long long pc);
    int in_taint_table(gem5::PhysRegIdPtr);
    void set_taint(gem5::PhysRegIdPtr);
    void clear_taint_table();
    int is_load(gem5::StaticInstPtr);
    int is_micro_visible(gem5::StaticInstPtr);

};

extern SpecCheck SC;

#endif // __CPU_O3_SPECCHECK_HH__
