#ifndef MINIDBG_BREAKPOINT_HPP
#define MINIDBG_BREAKPOINT_HPP
#define ull unsigned long long 

#include <utility>
#include <string>
#include <linux/types.h>
#include <cstdint>

namespace minigdb{
    class breakpoint{
        public:
            breakpoint(pid_t debugeePid, uintptr_t bpAddr): debugeePid(debugeePid), bpAddr(bpAddr){}
            void setBreakpoint();
            void restoreBreakpoint();
        private:
            pid_t debugeePid;
            uintptr_t bpAddr;
            long originalDataAtBPAddr;
    };
}


#endif //MINIDBG_BREAKPOINT_HPP