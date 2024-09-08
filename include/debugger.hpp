#ifndef MINIDBG_DEBUGGER_HPP
#define MINIDBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>
#include <memory>
#include <unordered_map>

#include "breakpoint.hpp"

namespace minigdb {
    class debugger {
    public:
        debugger (std::string progName, pid_t pid)
            : debugeeProgramName{std::move(progName)}, debugeePid{pid} {}

        void run();

    private:
        std::unordered_map<uintptr_t, std::shared_ptr<breakpoint>> mapAddressToBreakpoint;
        bool handleCommand(const std::string& line);
        void continueExecution();
        void waitForDebugeeToStop();      
        void addBreakpoint(uintptr_t bpAddr);  
        void handleIfCurrentlyAtBreakpoint();
        unsigned long long getRegisterValue(std::string reg);
        void writeRegisterValue(std::string reg, unsigned long long val);
        void dumpRegisterValues();
        long readDataAtAddress(uintptr_t addr);
        void writeDataAtAddress(uintptr_t addr, long data);
        void fillRegisterStruct();
        siginfo_t get_signal_info();
        void handleSigTrap(siginfo_t sigInfo);
        void vmmap();

        
        std::string debugeeProgramName;
        pid_t debugeePid;
    };
}

#endif
