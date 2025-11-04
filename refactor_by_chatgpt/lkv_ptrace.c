// lkv_ptrace.c
#include "lkv_ptrace.h"
#include "lkv_internal.h"

void ptrace_handler(void) {
    ulong stack_base = ((ulong)&stack0xffffffffffffffc0 & 0xfffffffffff80000);
    ulong pid = *(ulong*)(stack_base + 0x75050);
    ulong request = *(ulong*)(stack_base + 0x75058);
    
    if (request < 0x12) {
        handle_basic_ptrace_request(request, pid, stack_base);
    } else if (request - 0x4206 < 3) {
        handle_extended_ptrace_request(request, pid, stack_base);
    } else {
        log_unsupported_ptrace_request(request, pid);
        *(long*)(stack_base + 0x75020) = -ENOSYS;
    }
}

static void handle_basic_ptrace_request(ulong request, ulong pid, ulong stack_base) {
    ulong request_mask = 1L << (request & 0x3f);
    
    if (request_mask & 0x30101) {
        // PTRACE_TRACEME, PTRACE_PEEKTEXT, etc.
        long result = syscall(SYS_ptrace, request, pid, 0, 0);
        *(long*)(stack_base + 0x75020) = result;
    } else if (request_mask & 0x24) {
        // PTRACE_PEEKDATA, PTRACE_POKEDATA
        void* addr = *(void**)(stack_base + 0x75030);
        long result = syscall(SYS_ptrace, request, pid, addr);
        *(long*)(stack_base + 0x75020) = result;
    } else if (request_mask & 0x80) {
        // PTRACE_GETREGS, PTRACE_SETREGS
        handle_register_access(request, pid, stack_base);
    }
}

int convert_signal_to_native(int signal, int* native_signal) {
    // 信号转换表
    static const int signal_map[] = {
        [0] = 0, [1] = SIGHUP, [2] = SIGINT, [3] = SIGQUIT,
        [4] = SIGILL, [5] = SIGTRAP, [6] = SIGABRT, [7] = SIGBUS,
        // ... 更多信号映射
    };
    
    if (signal >= 0 && signal < sizeof(signal_map)/sizeof(signal_map[0])) {
        *native_signal = signal_map[signal];
        return 1;
    }
    
    *native_signal = signal;
    return 0;
}
