// syscall_trace.c
#include "syscall_trace.h"
#include <string.h>
#include <stdio.h>

static const syscall_desc_t syscall_table[] = {
    {"read", 3, 0x07},
    {"write", 3, 0x06},
    {"open", 3, 0x05},
    {"close", 1, 0x01},
    // ... 更多系统调用定义
};

void syscall_trace_entry(long *context, uint32_t syscall_num, uint32_t flags) {
    if (syscall_num > MAX_SYSCALL_NUM) {
        printf("Invalid syscall number: %d\n", syscall_num);
        return;
    }
    
    trace_buffer_t buf = {
        .buffer = (char*)(context + 1),
        .size = 0x200,
        .pos = 0,
        .truncated = false
    };
    
    // 添加进程ID前缀
    if (should_show_pid()) {
        snprintf(buf.buffer + buf.pos, buf.size - buf.pos, 
                "[Pid %d] ", get_current_pid());
        buf.pos = strlen(buf.buffer);
    }
    
    const syscall_desc_t *desc = &syscall_table[syscall_num];
    context[0x202] = (long)desc->name;
    *(int*)(context + 0x210) = desc->arg_count;
    
    // 设置参数格式化标志
    setup_arg_formatting(context, desc);
    
    // 格式化系统调用名称和参数
    format_syscall_args(&buf, context, desc);
}

static void setup_arg_formatting(long *context, const syscall_desc_t *desc) {
    uint32_t flags = *(uint32_t*)(context + 0x201) & 0xfffffffe;
    
    for (int i = 0; i < desc->arg_count; i++) {
        if (context[0x204 + i] == 0 || context[0x204 + i] == 5) {
            flags &= ~(1 << i);
        }
    }
    
    *(uint32_t*)(context + 0x201) = flags;
}

void format_string_arg(trace_buffer_t *buf, uint64_t addr, size_t max_len) {
    if (addr == 0) {
        append_to_buffer(buf, "NULL");
        return;
    }
    
    char temp_buf[64];
    size_t copy_len = (max_len > 63) ? 63 : max_len;
    
    if (copy_from_user(addr, temp_buf, copy_len) != 0) {
        append_to_buffer(buf, "[invalid]");
        return;
    }
    
    append_to_buffer(buf, "\"");
    
    for (size_t i = 0; i < copy_len && temp_buf[i]; i++) {
        char c = temp_buf[i];
        if (c >= 0x20 && c < 0x7f) {
            if (c == '\\') {
                append_to_buffer(buf, "\\\\");
            } else {
                append_char_to_buffer(buf, c);
            }
        } else {
            // 转义特殊字符
            switch (c) {
                case '\n': append_to_buffer(buf, "\\n"); break;
                case '\t': append_to_buffer(buf, "\\t"); break;
                case '\r': append_to_buffer(buf, "\\r"); break;
                case '\b': append_to_buffer(buf, "\\b"); break;
                case '\f': append_to_buffer(buf, "\\f"); break;
                case '\a': append_to_buffer(buf, "\\a"); break;
                case '\v': append_to_buffer(buf, "\\v"); break;
                default:
                    snprintf(temp_buf, sizeof(temp_buf), "\\%02X", (unsigned char)c);
                    append_to_buffer(buf, temp_buf);
                    break;
            }
        }
    }
    
    append_to_buffer(buf, "\"");
    
    if (max_len > 64) {
        append_to_buffer(buf, "...");
    }
}
