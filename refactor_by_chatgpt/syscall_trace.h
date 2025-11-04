// syscall_trace.h
#ifndef SYSCALL_TRACE_H
#define SYSCALL_TRACE_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char *buffer;
    size_t size;
    size_t pos;
    bool truncated;
} trace_buffer_t;

typedef struct {
    const char *name;
    int arg_count;
    uint32_t arg_flags;
} syscall_desc_t;

// 系统调用跟踪
void syscall_trace_entry(long *context, uint32_t syscall_num, uint32_t flags);
void syscall_trace_exit(long *context);

// 格式化函数
void format_string_arg(trace_buffer_t *buf, uint64_t addr, size_t max_len);
void format_signal_set(trace_buffer_t *buf, uint64_t addr);
void format_sigaction(trace_buffer_t *buf, uint64_t addr, bool is_old_format);
void format_epoll_event(trace_buffer_t *buf, uint64_t addr);

#endif
