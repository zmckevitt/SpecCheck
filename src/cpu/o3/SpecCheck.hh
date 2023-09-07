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

    // Initialize SpecCheck and stats
    SpecCheck();

    int consume_instruction(gem5::o3::DynInstPtr dynInst);

private:
    unsigned long long savedPC;
    int currentFsmState;

    enum fsmStates
    {
            Q_INIT,
            Q_1,
            Q_2,
            Q_ACC
    };

    std::vector<std::string>gadget_components;
    std::vector<unsigned long long>flushed_pcs;
    std::vector<unsigned long long>vuln_pcs;
    std::vector<gem5::PhysRegIdPtr>taint_table;

    int in_flushed(unsigned long long pc);
    int in_vulnerable(unsigned long long pc);
    int in_taint_table(gem5::PhysRegIdPtr, gem5::PhysRegIdPtr, size_t);
    void set_taint(gem5::PhysRegIdPtr);
    void remove_taint(gem5::PhysRegIdPtr);
    void clear_taint_table();
    int is_load(gem5::StaticInstPtr, std::string inst);
    int is_micro_visible(gem5::StaticInstPtr, std::string);
    void log_components();
};

extern SpecCheck SC;

#endif // __CPU_O3_SPECCHECK_HH__
