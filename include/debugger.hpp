#ifndef MINIDBG_DEBUGGER_HPP
#define MINIDBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>

namespace minigdb {
    class debugger {
    public:
        debugger (std::string progName, pid_t pid)
            : debugeeProgramName{std::move(progName)}, debugeePid{pid} {}

        void run();

    private:
        void handleCommand(const std::string& line);
        void continueExecution();
        void waitForDebugeeToStop();        
        
        std::string debugeeProgramName;
        pid_t debugeePid;
    };
}

#endif
