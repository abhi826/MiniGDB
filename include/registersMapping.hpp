// Map Registers to position within user_regs_struct
#ifndef registermappings
#define registermappings
#include <unordered_map>
#include <string>

/*
From /usr/include/x86_64-linux-gnu/sys/user.h
struct user_regs_struct
{
  __extension__ unsigned long long int r15;
  __extension__ unsigned long long int r14;
  __extension__ unsigned long long int r13;
  __extension__ unsigned long long int r12;
  __extension__ unsigned long long int rbp;
  __extension__ unsigned long long int rbx;
  __extension__ unsigned long long int r11;
  __extension__ unsigned long long int r10;
  __extension__ unsigned long long int r9;
  __extension__ unsigned long long int r8;
  __extension__ unsigned long long int rax;
  __extension__ unsigned long long int rcx;
  __extension__ unsigned long long int rdx;
  __extension__ unsigned long long int rsi;
  __extension__ unsigned long long int rdi;
  __extension__ unsigned long long int orig_rax;
  __extension__ unsigned long long int rip;
  __extension__ unsigned long long int cs;
  __extension__ unsigned long long int eflags;
  __extension__ unsigned long long int rsp;
  __extension__ unsigned long long int ss;
  __extension__ unsigned long long int fs_base;
  __extension__ unsigned long long int gs_base;
  __extension__ unsigned long long int ds;
  __extension__ unsigned long long int es;
  __extension__ unsigned long long int fs;
  __extension__ unsigned long long int gs;
};
*/
namespace minigdb{

   const std::unordered_map<std::string, unsigned long long user_regs_struct::*> mapRegisterToIdx {
    {"r15", &user_regs_struct::r15},
    {"r14", &user_regs_struct::r14},
    {"r13", &user_regs_struct::r13},
    {"r12", &user_regs_struct::r12},
    {"rbp", &user_regs_struct::rbp},
    {"rbx", &user_regs_struct::rbx},
    {"r11", &user_regs_struct::r11},
    {"r10", &user_regs_struct::r10},
    {"r9", &user_regs_struct::r9},
    {"r8", &user_regs_struct::r8},
    {"rax", &user_regs_struct::rax},
    {"rcx", &user_regs_struct::rcx},
    {"rdx", &user_regs_struct::rdx},
    {"rsi", &user_regs_struct::rsi},
    {"rdi", &user_regs_struct::rdi},
    {"orig_rax", &user_regs_struct::orig_rax},
    {"rip", &user_regs_struct::rip},
    {"cs", &user_regs_struct::cs},
    {"eflags", &user_regs_struct::eflags},
    {"rsp", &user_regs_struct::rsp},
    {"ss", &user_regs_struct::ss},
    {"fs_base", &user_regs_struct::fs_base},
    {"gs_base", &user_regs_struct::gs_base},
    {"ds", &user_regs_struct::ds},
    {"es", &user_regs_struct::es},
    {"fs", &user_regs_struct::fs},
    {"gs", &user_regs_struct::gs}
};

}

#endif //registermappings