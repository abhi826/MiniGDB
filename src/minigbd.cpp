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

#include "linenoise.h"

#include "debugger.hpp"
#include "breakpoint.hpp"
#include "registersMapping.hpp"

using namespace minigdb;

std::unordered_map<uintptr_t, breakpoint*> mapAddressToBreakpoint;

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

long debugger::readDataAtAddress(uintptr_t addr){
    return readData(debugeePid, addr);
}

void debugger::writeDataAtAddress(uintptr_t addr, long data){
    return writeData(debugeePid, addr, data);
}

void breakpoint::setBreakpoint(){
   long originalData = readData(debugeePid, bpAddr);
   originalDataAtBPAddr = originalData;
   long newData = originalData | 0xCC;
   writeData(debugeePid, bpAddr, newData);
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

void debugger::handleCommand(const std::string& line) {
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
    else if(isPrefix(command, "quit")){
        exitDebugger(debugeePid);
    }
    else {
        std::cerr << "Unknown command\n";
    }
}


void debugger::addBreakpoint(uintptr_t bpAddr){
     breakpoint* bp = new breakpoint(debugeePid, bpAddr);
     mapAddressToBreakpoint[bpAddr]=bp;
     bp->setBreakpoint();
}

void debugger::waitForDebugeeToStop(){
    int waitStatus;
    int options = 0;
    waitpid(debugeePid, &waitStatus, options);
    if(WIFSTOPPED(waitStatus)){
        std::cout<<"\nThe debugee has stopped execution."<<std::endl;
        return;
    }
    else if(WIFEXITED(waitStatus)){
        std::cout<<"\nThe debugee has finished execution."<<std::endl;
        exit(0);
    }
    else
    {
        std::cout<<"\nUnknown status of debugee."<<std::endl;
        exit(0);
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
        char* line = nullptr;
        while(line = linenoise("minigbd> ")) {
            std::string lineStr(line);
            if (lineStr.empty() || lineStr.find_first_not_of(' ') == std::string::npos) {
                linenoiseFree(line);
                continue;
            }
            handleCommand(line);
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

bool debugger::currentlyAtBreakpoint(){
    uintptr_t ripValue = getRegisterValue("rip");
}

void debugger::continueExecution() {
    ptrace(PTRACE_CONT, debugeePid, nullptr, nullptr);
    waitForDebugeeToStop();
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
        exitDebugger(pid);
    }
}

