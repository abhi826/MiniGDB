#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <cstdint>
#include <sys/user.h>
#include <cstring>
#include <inttypes.h>
#include <fstream>
#include <filesystem> 
#include <algorithm>
#include <deque>
#include <utility> 

#include "linenoise.h"

#include "debugger.hpp"
#include "breakpoint.hpp"
#include "registersMapping.hpp"

using namespace minigdb;

void exitDebugger(pid_t pid);
void displaySourceWindowFromFile(const std::string& filePath, int currentLine, int context, bool isNotEndOfLine);

/*

long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);

*/
void writeData(pid_t pid, uintptr_t addr, long data){
    /*ptrace(PTRACE_POKETEXT/POKEDATA/POKEUSER, pid, addr, long_val);*/
    ptrace(PTRACE_POKEDATA, pid, addr, data);
}
long readData(pid_t pid, uintptr_t addr){
    //ptrace(PTRACE_PEEKTEXT/PEEKDATA/PEEKUSER, pid, addr, 0); //returns 8 bytes
    long data  = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    return data;
}

void getRegisters(pid_t pid, struct user_regs_struct& data){
    ptrace(PTRACE_GETREGS, pid, 0, &data);
}

void setRegisters(pid_t pid, struct user_regs_struct& data){
    ptrace(PTRACE_SETREGS, pid, 0, &data);
}

void singleStep(pid_t pid){
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
}

long debugger::readDataAtAddress(uintptr_t addr){
    return readData(debugeePid, addr);
}

void debugger::writeDataAtAddress(uintptr_t addr, long data){
    return writeData(debugeePid, addr, data);
}

void debugger::singleStepWithBreakpointCheck(){
        uintptr_t ripValue = getRegisterValue("rip");
        if(mapAddressToBreakpoint.find(ripValue) != mapAddressToBreakpoint.end()){
            handleIfCurrentlyAtBreakpoint();
        }
        else{
            singleStep(debugeePid);
            waitForDebugeeToStop();
        } 
}

void breakpoint::setBreakpoint(){
   originalDataAtBPAddr = readData(debugeePid, bpAddr);
   long newDataWithBPInstruction = ((originalDataAtBPAddr & ~0xFF) | 0xCC);
   writeData(debugeePid, bpAddr, newDataWithBPInstruction);
}

void breakpoint::unsetBreakpoint(){
    writeData(debugeePid, bpAddr, originalDataAtBPAddr);
}


std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> out{};
    std::stringstream ss {s};
    std::string item;

    while (std::getline(ss,item,delimiter)) {
        out.push_back(item);
    }

    return out;
}

bool isPrefix(const std::string& s, const std::string& of) {
    if (s.size() > of.size()) return false;
    return std::equal(s.begin(), s.end(), of.begin());
}

bool debugger::handleCommand(const std::string& line) {
    auto args = split(line,' ');
    auto command = args[0];

    if (isPrefix(command, "cont")) {
        continueExecution();
    }
    else if(isPrefix(command, "breakpoint") && (args.size()>1)){
        // 0x<hexadecimal> -> address breakpoint
        // <filename>:<line> -> line number breakpoint
        // <anything else> -> function name breakpoint
        if(args[1][0] == '0' && args[1][1] =='x'){
            std::string addressStr(args[1]);
            std::uintptr_t address = std::stoull(addressStr, nullptr, 16);
            addBreakpoint(address);
        }
        else if(args[1].find(':') != std::string::npos){
            auto fileAndLine = split(args[1], ':');
            setBreakpointAtSourceLine(fileAndLine[0], stoull(fileAndLine[1]));
        }
        else{
            setBreakpointAtFunction(args[1]);
        }
    }
    else if(isPrefix(command, "step")){
        // step forward into the very next line in the source file.
        // steps into function calls.
        stepToNextLine();
    }
    else if (isPrefix(command, "stepi")){
        // steps forward 1 instruction in the disassembly.
        singleStepWithBreakpointCheck();
        uintptr_t ripValue = getRegisterValue("rip");
        displaySourceCode(ripValue);
    }
    else if (isPrefix(command, "next"))
    {
        // Do not step into function calls. 
        // Step forward to the next line in the source file that should be executed.
        stepOver();

    }
    else if(isPrefix(command, "finish")) {
        // Finish execution of the current function.
        stepOut();
    }
    else if(isPrefix(command, "list")){
        // List the Addresses of the current breakpoints that are set.
        listBreakpoints();
    }
    else if(isPrefix(command, "memory")) {
        std::string addr {args[2], 2}; //assume 0xADDRESS
        if (isPrefix(args[1], "read")) {
            std::cout << std::hex << readDataAtAddress(std::stoull(addr, 0, 16)) << std::endl;
        }
        if (isPrefix(args[1], "write")) {
            std::string val {args[3], 2}; //assume 0xVAL
            writeDataAtAddress(std::stoull(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else if (isPrefix(command, "register")) {
        if (isPrefix(args[1], "dump")) {
            dumpRegisterValues();
        }
        else if (isPrefix(args[1], "read")) {
            std::cout  << std::hex<< "0x" << getRegisterValue(args[2]) << std::endl;
        }
        else if (isPrefix(args[1], "write")) {
            std::string val {args[3], 2}; //assume 0xVAL
            writeRegisterValue(args[2], std::stoull(val, 0, 16));
        }
    }
    else if(isPrefix(command, "vmmap")){
        vmmap();
    }
    else if(isPrefix(command, "quit")){
        return false;
    }
    else {
        std::cerr << "Unknown command\n";
    }
    return true;
}


void debugger::addBreakpoint(uintptr_t bpAddr){
    // Change first byte at the breakpoint instruction into CC.
    // Save the byte to change it back later.
    // Continue the program until it hits the breakpoint.
    // To continue the program after the breakpoint:
    //      If current address is a breakpoint address
    //      Change 'CC' byte back to what it was originally
    //      Decrement the instruction pointer by 1 bye.
    //      Step forward by 1 instruction
    //      Restore the breakpoint again
    //      continue the program   
    auto bp = std::make_shared<breakpoint>(debugeePid, bpAddr);
    mapAddressToBreakpoint[bpAddr] = bp;
    bp->setBreakpoint();
}

void debugger::removeBreakpoint(uintptr_t bpAddr){
    if(mapAddressToBreakpoint.count(bpAddr)){
        auto bp = mapAddressToBreakpoint[bpAddr];
        bp->unsetBreakpoint();
        mapAddressToBreakpoint.erase(bpAddr);
    }
}

auto debugger::getIteratorToCurrentLineTableEntry(uintptr_t ripValue){
    unsigned long long pc = ripValue - exeLoadAddress;
    int lineNumber = -1;
    for (auto &cu : dw.compilation_units()) {
            if (die_pc_range(cu.root()).contains(pc)) {
                    // Map PC to a line
                    auto &lt = cu.get_line_table();
                    auto it = lt.find_address(pc);
                    if(it == lt.end()){
                        return std::make_pair(it,false);
                    }
                    return std::make_pair(it,true);
            }
    }
    return std::make_pair(dw.compilation_units()[0].get_line_table().end(),false);
}

void debugger::stepOut(){
    // step out of function
    uintptr_t rbpValue = getRegisterValue("rbp");
    uintptr_t addressOfFuncRetValInStack = rbpValue + 8;
    uintptr_t returnAddress = readDataAtAddress(addressOfFuncRetValInStack);
    bool shouldRemoveBreakpoint = false;
    if(!mapAddressToBreakpoint.count(returnAddress)){
        addBreakpoint(returnAddress);
        shouldRemoveBreakpoint = true;
    }
    continueExecution();
    if(shouldRemoveBreakpoint){
        removeBreakpoint(returnAddress);
    }
}

void debugger::stepOver(){
    // Go to next line in the source file that should be executed.
    // If currently at a function call, dont step into the function. 

    // The simple solution to implement step over would be to put a breakpoint
    // at the very next source line and continue. However, if we are in a loop or some conditional
    // construct, the line that should be executed next may not necessarily be the very 
    // next line in the source code.
    // For example, look at the disassembly of 'function.cpp' in the examples folder.
    // Suppose we are at the line 'if(n==5)', and attempt a step over. If the condition is false,
    // it should go to the line "bar()" in the else statement and not the very next line
    // in the source file.
    // It seems like "real" debuggers implement an 
    // instruction emulator to examine which instruction is currently being executed
    // and work out all the possible branch targets, and place breakpoints on those targets. 
    // That seems a bit too intensive to implement for this project currently (can be a future work item),
    // so to emulate that behavior I will implement a simpler solution:
    // Place a temporary breakpoint at every line in the current function.

    // Figure out the current function we are in and get its DW_AT_low_pc and DW_AT_high_pc.
    // DW_AT_high_pc is just an offset so its address would be DW_AT_low_pc + DW_AT_high_pc.
    // You can get the iterator for the line table entry corresponding to DW_AT_low_pc.
    // Keep iterating through the line table entries until the address of the entry is greater
    // than DW_AT_high_pc. You can get the address of each line table entry as a field in the iterator
    // line_table::entry->address.
    uintptr_t ripValue = getRegisterValue("rip");
    // pc is just the offset value.
    uintptr_t pc = ripValue - exeLoadAddress;
    // These addresses are just offsets. The load address of the debugee executable isn't added to them yet.
    uintptr_t addrOfCurrFuncLow = 0;
    uintptr_t addrOfCurrFuncHigh = 0;

    for(auto& cu: dw.compilation_units()){
        // root die = DW_TAG_compile_unit
        const auto& rootDie = cu.root();
        if (die_pc_range(rootDie).contains(pc))
        {
            // We found the right compilation unit that we are currently in.
            //std::cout<<"Found the CU!"<<std::endl;
            for(const auto& child : rootDie){
                // FYI:
                // When using a range-based for loop the compiler will translate it to:
                // for (auto it = rootDie.begin(); it != rootDie.end(); ++it) {
                //      const auto& child = *it;  
                
                // Each compilation unit can have multiple subprograms(functions), so get the one which contains
                // the current instruction pointer value.
                if ((child.has(dwarf::DW_AT::low_pc)) && (child.has(dwarf::DW_AT::high_pc)) &&
                    // Need to check that the DIE has the attributes low_pc and high_pc first because
                    // die_pc_range() calls at_low_pc(die) which calls die[low_pc] without checking if
                    // low_pc is even an atribute of the die first. It seems that there are subprogram DIEs
                    // that don't have those attributes. For those DIEs it can throw an exception and cause
                    // a core dump.
                    //                              Core Dump Backtrace
                    /*
                        gef➤  bt
                        #0  __pthread_kill_implementation (no_tid=0x0, signo=0x6, threadid=<optimized out>) at ./nptl/pthread_kill.c:44
                        ...
                        #7  0x000076f5a42a5a55 in std::terminate() () from /lib/x86_64-linux-gnu/libstdc++.so.6
                        #8  0x000076f5a42bb391 in __cxa_throw () from /lib/x86_64-linux-gnu/libstdc++.so.6
                        #9  0x000076f5a462c17a in dwarf::die::operator[] (this=this@entry=0x7ffc2ec45530, attr=attr@entry=dwarf::DW_AT::low_pc) at /usr/include/c++/13/bits/allocator.h:184
                        #10 0x000076f5a464381c in dwarf::at_low_pc (d=...) at attrs.cc:105
                        #11 0x000076f5a4644cc8 in dwarf::die_pc_range (d=...) at attrs.cc:262
                        #12 0x00005ba6e8ec427c in minigdb::debugger::stepOver (this=0x7ffc2ec458c0) at /home/hades/MiniGDB/src/minigbd.cpp:281
                        #13 0x00005ba6e8ec2da3 in minigdb::debugger::handleCommand (this=0x7ffc2ec458c0, line="next") at /home/hades/MiniGDB/src/minigbd.cpp:131
                        #14 0x00005ba6e8ec5d03 in minigdb::debugger::run (this=0x7ffc2ec458c0) at /home/hades/MiniGDB/src/minigbd.cpp:499
                        #15 0x00005ba6e8ec71e3 in main (argc=0x2, argv=0x7ffc2ec45aa8) at /home/hades/MiniGDB/src/minigbd.cpp:675
                        gef➤  frame 12
                        #12 0x00005ba6e8ec427c in minigdb::debugger::stepOver (this=0x7ffc2ec458c0) at /home/hades/MiniGDB/src/minigbd.cpp:281
                        281	                if ((child.has(dwarf::DW_AT::low_pc)) && (child.has(dwarf::DW_AT::high_pc)) &&
                        gef➤  frame 11
                        #11 0x000076f5a4644cc8 in dwarf::die_pc_range (d=...) at attrs.cc:262
                        262	        taddr low = at_low_pc(d);
                        gef➤  frame 10
                        #10 0x000076f5a464381c in dwarf::at_low_pc (d=...) at attrs.cc:105
                        105	AT_ADDRESS(low_pc);
                        gef➤  frame 9
                        #9  0x000076f5a462c17a in dwarf::die::operator[] (this=this@entry=0x7ffc2ec45530, attr=attr@entry=dwarf::DW_AT::low_pc) at /usr/include/c++/13/bits/allocator.h:184
                        184	      ~allocator() _GLIBCXX_NOTHROW { }
                    */

                    (child.tag == dwarf::DW_TAG::subprogram) && (die_pc_range(child).contains(pc))){
                    // We found the right function we are currently in.

                    //std::cout<<"Found the right function"<<std::endl;
                    //std::cout<<"low_pc form: "<<to_string(child[dwarf::DW_AT::low_pc].get_form())<<std::endl;
                    //std::cout<<"low pc address: "<<(child[dwarf::DW_AT::low_pc].as_address())<<std::endl;
                    //std::cout<<"high_pc form: "<<to_string(child[dwarf::DW_AT::high_pc].get_form())<<std::endl;
                    //std::cout<<"high_pc value: "<<(child[dwarf::DW_AT::high_pc].as_uconstant())<<std::endl;

                    // Looking at the .debug_abrev section, it seems like DW_AT_low_pc is of type DW_FORM_addr
                    // while DW_AT_high_pc is of type DW_FORM_data8.
                    addrOfCurrFuncLow = child[dwarf::DW_AT::low_pc].as_address();
                    addrOfCurrFuncHigh = child[dwarf::DW_AT::high_pc].as_uconstant();
                    addrOfCurrFuncHigh += addrOfCurrFuncLow;
                    //std::cout<<"addrOfCurrFuncLow: " <<addrOfCurrFuncLow << " addrOfCurrFuncHigh: " <<addrOfCurrFuncHigh << std::endl;
                    break;
                }
            }
            auto currLineItr = getIteratorToCurrentLineTableEntry(ripValue);
            const auto& lineTable = cu.get_line_table();
            auto itr = lineTable.find_address(addrOfCurrFuncLow);
            // itr->address only gives an offset.
            // tempBreakpoints should hold breakpoint address (itr->address + exeLoadAddress)
            std::vector<uintptr_t> tempBreakpoints;
            while((itr != lineTable.end()) && (itr->address <= addrOfCurrFuncHigh)){
                // Don't add a breakpoint at the current line we are in.
                //
                // Sometimes one line can be associated with more than 1 address.
                // For example:
                /*
                    for (int i = 1; i <= 5; ++i) {
                    11e2:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [rbp-0x4],0x1
                    11e9:	eb 0e                	jmp    11f9 <main+0x23>
                                                                   line            address
                /home/hades/MiniGDB/examples/loopFunction.cpp       9              0x11e2
                /home/hades/MiniGDB/examples/loopFunction.cpp       9              0x11e9
                */
                // To accomodate for this, don't add breakpoints at addresses which correspond
                // to the same line as the current line we are in. Otherwise, when we stepOver we 
                // will still be in the same line. 
                if(itr==currLineItr.first || itr->line == currLineItr.first->line){
                    //std::cout<<"Skipping adding breakpoint at current line # " << currLineItr.first->line << " at address " <<currLineItr.first->address+exeLoadAddress <<std::endl;
                    itr++;
                    continue;
                }
                if(!mapAddressToBreakpoint.count(itr->address+exeLoadAddress)){
                    tempBreakpoints.push_back(itr->address + exeLoadAddress);
                    //std::cout<<"Adding breakpoint at " << (itr->address+exeLoadAddress) << " for line # " << itr->line << std::endl;
                    addBreakpoint(itr->address + exeLoadAddress);
                }
                itr++;
            }
            // Set a breakpoint at the return address of the function as well in case execution returns back to the caller.
            uintptr_t rbpValue = getRegisterValue("rbp");
            uintptr_t addressOfFuncRetValInStack = rbpValue + 8;
            uintptr_t returnAddress = readDataAtAddress(addressOfFuncRetValInStack);
            if(!mapAddressToBreakpoint.count(returnAddress)){
                //std::cout << "Adding breakpoint at return address " << returnAddress << std::endl;
                tempBreakpoints.push_back(returnAddress);
                addBreakpoint(returnAddress);
            }
            continueExecution();
            for(const auto addr:tempBreakpoints){
                //std::cout << "Removing breakpoint at address "<<addr<<std::endl;
                removeBreakpoint(addr);
            }
            break;
        }
    }
}

void debugger::setBreakpointAtFunction(std::string function)
{
    for(auto& cu: dw.compilation_units()){
        for(const auto& child:cu.root()){
            if((child.tag == dwarf::DW_TAG::subprogram) && (child.has(dwarf::DW_AT::name)) && 
               (child[dwarf::DW_AT::name].as_string()==function) && (child.has(dwarf::DW_AT::low_pc)))
            {
                // Found the right DIE
                uintptr_t addrOfFunction = child[dwarf::DW_AT::low_pc].as_address();
                // If we set a breakpoint at addrOfFunction, it would be at the function prologue,
                // but we want it on the first line of source code in the function. Get an iterator
                // to the entry in the lineTable for addrOfFunction and increment it by 1 to get 
                // the first actual line of code in the function. If for some reason the function
                // is empty, don't use the incremented iterator's address.
                const auto& lineTable = cu.get_line_table();
                auto itr = lineTable.find_address(addrOfFunction);
                itr++;
                if(itr != lineTable.end()){
                    addrOfFunction = itr->address;
                }
                addBreakpoint(addrOfFunction+exeLoadAddress);
                return;
            }
        }
    }
}

void debugger::setBreakpointAtSourceLine(std::string file, unsigned long long lineNum)
{
    for(auto& cu: dw.compilation_units()){
        auto& root = cu.root();
        if (root.has(dwarf::DW_AT::name) && root[dwarf::DW_AT::name].as_string().find(file) != std::string::npos){
            // Found the right compilation unit 
            const auto& lineTable  = cu.get_line_table();
            for (auto itr = lineTable.begin(); itr!=lineTable.end(); itr++){
                if(itr->line == lineNum){
                    // Found the right line number. Add the breakpoint at its address.
                    addBreakpoint(itr->address+exeLoadAddress);
                    break;
                }
            }
            break;
        }
    }
}

void debugger::stepToNextLine(){
    // get current line in file and keep doing a single step instruction until the
    // line changes.
    uintptr_t ripValue = getRegisterValue("rip");
    auto currLineItrAndValidLinePair = getIteratorToCurrentLineTableEntry(ripValue);
    auto lineItr = currLineItrAndValidLinePair.first;
    while(true){
        singleStepWithBreakpointCheck();
        uintptr_t ripValue = getRegisterValue("rip");
        currLineItrAndValidLinePair = getIteratorToCurrentLineTableEntry(ripValue);
        if(!currLineItrAndValidLinePair.second || currLineItrAndValidLinePair.first->line != lineItr->line){
            break;
        }
    }
    displaySourceWindowFromFile(currLineItrAndValidLinePair.first->file->path, currLineItrAndValidLinePair.first->line,5,currLineItrAndValidLinePair.second);
}

// Function to display the window around the current line using a streaming approach
void displaySourceWindowFromFile(const std::string& filePath, int currentLine, int context = 5, bool isNotEndOfLine=true) {
    if(!isNotEndOfLine){
        std::cout << "Mapping to source file line not available" << std::endl;
        return;
    }
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return;
    }

    std::string line;
    int lineNumber = 0;

    std::deque<std::string> lineWindow;

    while (std::getline(file, line)) {
        lineNumber++;

        if (lineNumber >= currentLine - context && lineNumber <= currentLine + context) {
            lineWindow.push_back(line);
        }

        if (lineNumber > currentLine + context) {
            break;
        }
    }

    // Display the window
    int startLine = std::max(1, currentLine - context);
    int endLine = std::min(lineNumber, currentLine + context); // Ensure end is within bounds

    for (int i = startLine; i <= endLine; ++i) {
        if (i == currentLine) {
            std::cout << "-> " << i << ": " << lineWindow[i - startLine] << std::endl;  // Highlight current line
        } else {
            std::cout << "   " << i << ": " << lineWindow[i - startLine] << std::endl;
        }
    }
}

void debugger::displaySourceCode(uintptr_t ripValue){
    auto currLineItrAndValidLinePair = getIteratorToCurrentLineTableEntry(ripValue);
    displaySourceWindowFromFile(currLineItrAndValidLinePair.first->file->path, currLineItrAndValidLinePair.first->line, 5, currLineItrAndValidLinePair.second);
}

siginfo_t debugger::get_signal_info(){
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    ptrace(PTRACE_GETSIGINFO, debugeePid, nullptr, &info);
    return info;
}

void debugger::waitForDebugeeToStop(){
    int waitStatus;
    int options = 0;
    waitpid(debugeePid, &waitStatus, options);

    // Check if the child process exited normally
    if (WIFEXITED(waitStatus)) {
        std::cout << "Child exited normally with status " << WEXITSTATUS(waitStatus) << std::endl;
        return;
    }

    // Check if the child process was terminated by a signal
    if (WIFSIGNALED(waitStatus)) {
        int sig = WTERMSIG(waitStatus);
        std::cout << "Child terminated by signal " << strsignal(sig) << " (signal number " << sig << ")" << std::endl;
        return;
    }
    // Check if the child process is stopped (e.g., for a SIGTRAP or SIGSTOP)
    if (WIFSTOPPED(waitStatus))
    {
        auto siginfo = get_signal_info();
        // using si_signo to work out which signal was sent, 
        // and si_code to get more information about the signal.
        // https://elixir.bootlin.com/linux/v6.8/source/arch/x86/include/uapi/asm/signal.h#L26 (to see what the value of si_signo represents)
        // https://elixir.bootlin.com/linux/v6.8/source/include/uapi/asm-generic/siginfo.h#L175 (to see what the value of si_code represents)
        // std::cout << "Got signal " << siginfo.si_signo << " " << strsignal(siginfo.si_signo) << std::endl;
        // std::cout << "SIGTRAP code " << siginfo.si_code << std::endl;
        switch (siginfo.si_signo)
        {
            case SIGTRAP:
                handleSigTrap(siginfo);
                break;
            case SIGSEGV:
                std::cout << "The process being traced segfaulted - Reason Code: " << siginfo.si_code << std::endl;
                break;
            default:
                std::cout << "Received signal: " << strsignal(siginfo.si_signo) << std::endl;
        }
    }
}

void debugger::handleSigTrap(siginfo_t sigInfo){
    // SI_KERNEL or TRAP_BRKPT will be sent when a breakpoint is hit,
    // and TRAP_TRACE will be sent on single step completion.
    switch(sigInfo.si_code)
    {
        case SI_KERNEL:
        case TRAP_BRKPT:
        {
            // SI_KERNEL or TRAP_BRKPT will be sent when a breakpoint is hit.
            // When it hits a breakpoint, the instruction pointer points
            // 1 byte ahead, so set it back 1 byte.
            uintptr_t ripValue = getRegisterValue("rip");
            ripValue-=1;
            writeRegisterValue("rip", ripValue);
            std::cout << "Hit breakpoint at address 0x" << std::hex << getRegisterValue("rip") << std::endl;
            displaySourceCode(ripValue);
            break;
        }
        case TRAP_TRACE:
            // TRAP_TRACE will be sent on single step completion.
            break;
        case SI_USER:
            // Seems like the first call to execve by the debugee leads to this signal number.
            break;
        default:
            std::cout << "Unknown SIGTRAP code: " << sigInfo.si_code << std::endl;
    }
}

void debugger::run() {
    /*
    Cases when debugger gets control:
    1) Debugee calls execv.
    2) Debugee hits a breakpoint. When it hits a beakpoint
    it will cause a SIGTRAP signal to be sent to the debugee and 
    any signal (except SIGKILL) delivered to the debugee will cause 
    it to stop. Execution will then go to the debugger and it can determine
    what caused the state change of the debugee process through the wait status.
    */
        waitForDebugeeToStop();
        getDebugeeExecutableLoadAddress();
        char* line = nullptr;
        bool shouldContinue = true;
        while(shouldContinue && (line = linenoise("minigbd> ")) ) {
            std::string lineStr(line);
            if (lineStr.empty() || lineStr.find_first_not_of(' ') == std::string::npos) {
                linenoiseFree(line);
                continue;
            }
            shouldContinue = handleCommand(line);
            linenoiseHistoryAdd(line);
            linenoiseFree(line);
        }
}


unsigned long long user_regs_struct::* getRegisterIdxInStruct(std::string reg){
    auto it = mapRegisterToIdx.find(reg);
    if(it == mapRegisterToIdx.end()){
        return nullptr;
    }
    return it->second;
}

unsigned long long debugger::getRegisterValue(std::string reg){
    struct user_regs_struct regValues;
    memset(&regValues, 0, sizeof(regValues));
    getRegisters(debugeePid, regValues);
    unsigned long long user_regs_struct::* ptrToRegInStruct = getRegisterIdxInStruct(reg);
    if(ptrToRegInStruct){
            unsigned long long regValue = regValues.*ptrToRegInStruct;
            return regValue;
    }
    else{
            std::cerr << reg << " register not found in mapRegisterToIdx!" << std::endl;

    }

    return -1;
}

void debugger::writeRegisterValue(std::string reg, ull value){
    struct user_regs_struct regValues;
    memset(&regValues, 0, sizeof(regValues));
    getRegisters(debugeePid, regValues);
    unsigned long long user_regs_struct::* ptrToRegInStruct = getRegisterIdxInStruct(reg);
    if(ptrToRegInStruct){
        regValues.*ptrToRegInStruct = value;
        setRegisters(debugeePid, regValues);
    }
}

void debugger::dumpRegisterValues(){
    struct user_regs_struct regValues;
    memset(&regValues,0,sizeof(regValues));
    getRegisters(debugeePid, regValues);
    for(auto& [reg, ptrToMem] : mapRegisterToIdx){
        unsigned long long regValue = regValues.*ptrToMem;
        std::cout<< reg << ": 0x"<< std::hex << regValue << std::endl;
    }
}

void debugger::vmmap(){
    std::string pidStr = std::to_string(debugeePid); 
    std::string printMemoryMappingCmd = "cat /proc/"+pidStr+"/maps";
    system(printMemoryMappingCmd.c_str());

}

void debugger::listBreakpoints(){
    int count  = 1;
    for(const auto& [addr,_] : mapAddressToBreakpoint){
        std::cout<<count<<") 0x"<<addr<<std::endl;
        count++;
    }
}

void debugger::handleIfCurrentlyAtBreakpoint(){
    uintptr_t ripValue = getRegisterValue("rip");
    if(mapAddressToBreakpoint.find(ripValue) != mapAddressToBreakpoint.end()){
        auto bp = mapAddressToBreakpoint[ripValue];
        bp->unsetBreakpoint();
        singleStep(debugeePid);
        waitForDebugeeToStop();
        bp->setBreakpoint();
    }
}

void debugger::continueExecution() {
    handleIfCurrentlyAtBreakpoint();
    ptrace(PTRACE_CONT, debugeePid, nullptr, nullptr);
    waitForDebugeeToStop();
}

void debugger::getDebugeeExecutableLoadAddress() {
    std::string mapsPath = "/proc/" + std::to_string(debugeePid) + "/maps";
    std::ifstream mapsFile(mapsPath);
    if (!mapsFile.is_open()) {
        std::cerr << "Failed to open " << mapsPath << '\n';
        return;
    }

    std::string line;
    unsigned long long loadAddress = 0;

    std::filesystem::path debugeePath(debugeeProgramName);
    std::string debugeeFilename = debugeePath.filename().string();

    while (std::getline(mapsFile, line)) {
        std::istringstream iss(line);
        std::string addressRange, permissions, offset, dev, inode, pathname;

        // Read fields from the line
        iss >> addressRange >> permissions >> offset >> dev >> inode;
        std::getline(iss, pathname); 

        if (!pathname.empty()) {
            std::filesystem::path p(pathname);
            std::string filename = p.filename().string();
            if (filename == debugeeFilename) {
                size_t dashPos = addressRange.find('-');
                if (dashPos != std::string::npos) {
                    std::string startAddressStr = addressRange.substr(0, dashPos);
                    std::stringstream ss;
                    ss << std::hex << startAddressStr;
                    ss >> loadAddress;
                    break;
                }
            }
        }
    }

    mapsFile.close();

    if (loadAddress != 0) {
        exeLoadAddress = loadAddress;
    } else {
        std::cerr << "Failed to find the load address for the executable " << debugeeProgramName << '\n';
    }
}


void executeDebugee (const std::string& prog_name) {
    /* Allow tracing of this process */
    if (ptrace(/*enum __ptrace_request op*/PTRACE_TRACEME,/*pid_t pid*/ 0,/*void *addr*/ 0,/*void *data*/ 0) < 0) {
        std::cerr << "Error in ptrace\n";
        return;
    }
    /*
    Replace this process's image with the given program 

    All successful calls to execve(2) by the traced process will cause it to be sent
    a SIGTRAP signal, giving the parent a chance to gain control
    before the new program begins execution
    */
    execl(prog_name.c_str(), prog_name.c_str(), nullptr);
}

void exitDebugger(pid_t pid){
    ptrace(PTRACE_DETACH, pid, 0, 0);
    exit(0);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Program name not specified";
        return -1;
    }

    auto prog = argv[1];

    auto pid = fork();
    if (pid == 0) {
        //child
        /* Disable ASLR(Address Space Layour Randomization) to make testing setting
        breakpoints at addresses easier. The stack, heap, shared libraries, and 
        other segments will have fixed addresses, making the memory layout predictable.*/
        personality(ADDR_NO_RANDOMIZE);
        executeDebugee(prog);

    }
    else if (pid >= 1)  {
        //parent
        std::cout << "Started debugging process " << pid << '\n';
        debugger dbg{prog, pid};
        dbg.run();
    }
}

