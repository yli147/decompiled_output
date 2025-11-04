// lkv_ptrace.h
#ifndef LKV_PTRACE_H
#define LKV_PTRACE_H

#include <sys/ptrace.h>

typedef struct {
    int signal;
    int errno_val;
    int code;
    union {
        long addr;
        struct {
            uint32_t pid;
            uint32_t uid;
            uint32_t status;
            void* utime;
            void* stime;
        } child;
        struct {
            void* addr;
            uint32_t flags;
            uint32_t data;
        } fault;
    } data;
} siginfo_compat_t;

void ptrace_handler(void);
int convert_signal_to_native(int signal, int* native_signal);
void convert_siginfo_to_native(uint32_t* siginfo, siginfo_compat_t* native);

#endif
