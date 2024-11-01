#ifndef MINIDBG_DEBUGGER_HPP
#define MINIDBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>
#include <memory>
#include <unordered_map>
#include <fcntl.h>  
#include <unistd.h>  

#include "breakpoint.hpp"

#include "elf/elf++.hh"
#include "dwarf/dwarf++.hh"

namespace minigdb {
    class debugger {
    public:
        debugger (std::string progName, pid_t pid)
            : debugeeProgramName{std::move(progName)}, debugeePid{pid}
            {
               auto fd = open(debugeeProgramName.c_str(), O_RDONLY);
               ef = elf::elf{elf::create_mmap_loader(fd)}; 
               dw = dwarf::dwarf{dwarf::elf::create_loader(ef)};
            }

        void run();

    private:
        bool handleCommand(const std::string& line);
        void continueExecution();
        void waitForDebugeeToStop();      
        void addBreakpoint(uintptr_t bpAddr);  
        void removeBreakpoint(uintptr_t bpAddr);
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
        void getDebugeeExecutableLoadAddress();
        void displaySourceCode(uintptr_t ripValue);
        auto getIteratorToCurrentLineTableEntry(uintptr_t ripValue);
        void stepOut();
        void stepOver();
        void singleStepWithBreakpointCheck();
        void stepToNextLine();
        void listBreakpoints();
        void setBreakpointAtSourceLine(std::string file, unsigned long long lineNum);
        void setBreakpointAtFunction(std::string function);
        auto getFunctionDieFromPC(uintptr_t pc);
        void printBacktrace();
        
        
        unsigned long long exeLoadAddress{};
        std::string debugeeProgramName;
        pid_t debugeePid;
        elf::elf ef{};
        dwarf::dwarf dw{};
        std::unordered_map<uintptr_t, std::shared_ptr<breakpoint>> mapAddressToBreakpoint;
        std::vector<std::string> linesInDebugeeSourceFile{};
    };
}

#endif
