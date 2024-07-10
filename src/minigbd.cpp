#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <unistd.h>
#include <sstream>
#include <iostream>

#include "linenoise.h"

#include "debugger.hpp"

using namespace minigdb;

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
    else {
        std::cerr << "Unknown command\n";
    }
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
        while((line = linenoise("minidbg> ")) != nullptr) {
            handleCommand(line);
            linenoiseHistoryAdd(line);
            linenoiseFree(line);
        }
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
        ptrace(PTRACE_DETACH, pid, 0, 0);
    }
}

