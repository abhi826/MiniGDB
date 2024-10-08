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

#include "linenoise.h"

#include "debugger.hpp"
#include "breakpoint.hpp"
#include "registersMapping.hpp"

using namespace minigdb;

void exitDebugger(pid_t pid);

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

void breakpoint::setBreakpoint(){
   originalDataAtBPAddr = readData(debugeePid, bpAddr);
   long newDataWithBPInstruction = ((originalDataAtBPAddr & ~0xFF) | 0xCC);
   writeData(debugeePid, bpAddr, newDataWithBPInstruction);
}

void breakpoint::unsetBreakpoint(){
    writeData(debugeePid, bpAddr, originalDataAtBPAddr);
}

void breakpoint::restoreBreakpoint(){


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

        std::string addressStr(args[1]);
        std::uintptr_t address = std::stoull(addressStr, nullptr, 16);
        addBreakpoint(address);

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

// Function to display the window around the current line using a streaming approach
void displaySourceWindowFromFile(const std::string& filePath, int currentLine, int context = 5) {
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

auto debugger::getIteratorToCurrentLineTableEntry(uintptr_t ripValue){
    unsigned long long pc = ripValue - exeLoadAddress;
    int lineNumber = -1;
    for (auto &cu : dw.compilation_units()) {
            if (die_pc_range(cu.root()).contains(pc)) {
                    // Map PC to a line
                    auto &lt = cu.get_line_table();
                    auto it = lt.find_address(pc);
                    return it;
            }
    }
    return dw.compilation_units()[0].get_line_table().begin();
}

void debugger::displaySourceCode(uintptr_t ripValue){
    auto currLineItr = getIteratorToCurrentLineTableEntry(ripValue);
    displaySourceWindowFromFile(currLineItr->file->path, currLineItr->line, 5);
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

