// signal_utils.c
#include "signal_utils.h"

static const char* signal_names[] = {
    [1] = "SIGHUP", [2] = "SIGINT", [3] = "SIGQUIT", [4] = "SIGILL",
    [5] = "SIGTRAP", [6] = "SIGABRT", [7] = "SIGBUS", [8] = "SIGFPE",
    [9] = "SIGKILL", [10] = "SIGUSR1", [11] = "SIGSEGV", [12] = "SIGUSR2",
    [13] = "SIGPIPE", [14] = "SIGALRM", [15] = "SIGTERM", [16] = "SIGSTKFLT",
    [17] = "SIGCHLD", [18] = "SIGCONT", [19] = "SIGSTOP", [20] = "SIGTSTP",
    // ... 更多信号定义
};

void format_signal_name(trace_buffer_t *buf, int signum) {
    if (signum > 0 && signum < ARRAY_SIZE(signal_names) && signal_names[signum]) {
        append_to_buffer(buf, signal_names[signum]);
    } else {
        append_to_buffer(buf, "[invalid]");
    }
}

void format_signal_set(trace_buffer_t *buf, uint64_t addr) {
    if (addr == 0) {
        append_to_buffer(buf, "NULL");
        return;
    }
    
    uint64_t mask;
    if (copy_from_user(addr, &mask, sizeof(mask)) != 0) {
        append_to_buffer(buf, "{...}");
        return;
    }
    
    append_to_buffer(buf, "[");
    
    bool first = true;
    for (int sig = 1; sig <= 64; sig++) {
        if (mask & (1ULL << (sig - 1))) {
            if (!first) {
                append_to_buffer(buf, " ");
            }
            format_signal_name(buf, sig);
            first = false;
        }
    }
    
    append_to_buffer(buf, "]");
}

void format_sigaction(trace_buffer_t *buf, uint64_t addr, bool is_old_format) {
    if (addr == 0) {
        append_to_buffer(buf, "NULL");
        return;
    }
    
    sigaction_t sa;
    size_t struct_size = is_old_format ? 32 : 32; // 根据格式调整
    
    if (copy_from_user(addr, &sa, struct_size) != 0) {
        append_to_buffer(buf, "{...}");
        return;
    }
    
    append_to_buffer(buf, "{sa_handler=");
    if (sa.sa_handler == NULL) {
        append_to_buffer(buf, "NULL");
    } else {
        snprintf(temp_buf, sizeof(temp_buf), "0x%llx", (uint64_t)sa.sa_handler);
        append_to_buffer(buf, temp_buf);
    }
    
    append_to_buffer(buf, ", sa_flags=");
    format_sa_flags(buf, sa.sa_flags);
    
    append_to_buffer(buf, ", sa_restorer=");
    if (sa.sa_restorer == NULL) {
        append_to_buffer(buf, "NULL");
    } else {
        snprintf(temp_buf, sizeof(temp_buf), "0x%llx", (uint64_t)sa.sa_restorer);
        append_to_buffer(buf, temp_buf);
    }
    
    append_to_buffer(buf, ", sa_mask=");
    format_signal_set(buf, addr + offsetof(sigaction_t, sa_mask));
    
    append_to_buffer(buf, "}");
}
