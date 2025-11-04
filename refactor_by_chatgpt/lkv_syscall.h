// lkv_syscall.h
#ifndef LKV_SYSCALL_H
#define LKV_SYSCALL_H

#include <stdint.h>
#include <sys/types.h>

// 系统调用处理函数
void syscall_handler_85100(void);
void syscall_process_request_89a24(void* param);
void syscall_simple_handler_89cb0(void* param);
void syscall_simple_handler_89cf4(void* param);

// 内存映射相关
ulong memory_remap_with_fallback(ulong addr, ulong size, long prot, 
                                uint flags, ulong new_addr);

#endif
