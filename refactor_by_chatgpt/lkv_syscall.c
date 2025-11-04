// lkv_syscall.c
#include "lkv_syscall.h"
#include "lkv_internal.h"

void syscall_handler_85100(void) {
    ulong stack_base = ((ulong)&stack0x00000000 & 0xfffffffffff80000);
    void* arg1 = *(void**)(stack_base + 0x75058);
    void* arg2 = *(void**)(stack_base + 0x75050);
    
    FUN_8010001d5300(arg1, arg2);
}

void syscall_process_request_89a24(void* param) {
    syscall_params_t* params = (syscall_params_t*)param;
    
    // 复制基本参数
    syscall_data_t local_data = {0};
    local_data.param3 = params->param3;
    local_data.param4 = params->param4;
    local_data.param6 = params->param6;
    local_data.param7 = params->param7;
    local_data.param10 = params->param10;
    local_data.param5 = *(uint32_t*)(params + 5);
    local_data.param8 = params->param8;
    local_data.param9 = params->param9;
    local_data.count = *(uint32_t*)(params + 0xc);
    
    // 处理特殊系统调用类型 (9-10)
    if (*(int*)((long)params + 0x1c) - 9U < 2) {
        long source_ptr = params->source_data;
        if (local_data.count != 0) {
            process_syscall_data_array(&local_data, source_ptr, params);
        }
    } else {
        // 处理其他类型的系统调用
        handle_other_syscall_types(&local_data, params);
    }
    
    // 执行系统调用
    local_data.context = *(void**)((long)params + 100);
    int result = FUN_8010001e6f54(*params, &local_data, 0x58);
    params->result = (long)result;
}

static void process_syscall_data_array(syscall_data_t* data, long source_ptr, 
                                     syscall_params_t* params) {
    uint32_t count = data->count;
    
    for (uint32_t i = 0; i < count; i++) {
        long src_offset = i * 0x40;
        long dst_offset = data->target_ptr + src_offset;
        long src_addr = source_ptr + src_offset;
        
        // 复制基本数据
        copy_syscall_entry_data(dst_offset, src_addr, params);
        
        // 处理扩展数据
        process_extended_syscall_data(dst_offset, src_addr, params);
    }
}

// 系统调用处理函数 - 获取当前工作目录
void syscall_getcwd(void) {
    ulong stack_base = (ulong)&stack0xffffffffffffdfe0 & 0xfffffffffff80000;

    void* buffer = *(void**)(stack_base + 0x75058);
    size_t size = *(size_t*)(stack_base + 0x75050);

    int result = copy_from_user(buffer, temp_buffer, 4096);
    long syscall_result = (long)result;

    if (syscall_result + 0xfffU <= 0xffe) {
        *(long*)(stack_base + 0x75020) = syscall_result;
        return;
    }

    syscall_result = path_to_string(temp_buffer, output_buffer, 4096, 1);
    if (syscall_result + 0xfffU <= 0xffe) {
        *(long*)(stack_base + 0x75020) = syscall_result;
        return;
    }

    // 执行实际的系统调用
    void* syscall_result_ptr = make_syscall(0xe1, output_buffer, 0, 0, 0, 0, 0,
                                           stack_base + 0x7a000);
    *(void**)(stack_base + 0x75020) = syscall_result_ptr;
}

// 系统调用处理函数 - 改变目录
void syscall_chdir(void) {
    ulong stack_base = (ulong)&stack0xffffffffffffdfd0 & 0xfffffffffff80000;

    ulong path_addr = *(ulong*)(stack_base + 0x75050);
    int fd = *(int*)(stack_base + 0x75058);

    int result = copy_from_user(path_addr, temp_buffer, 4096);
    long syscall_result = (long)result;

    if (syscall_result + 0xfffU <= 0xffe) {
        *(long*)(stack_base + 0x75020) = syscall_result;
        return;
    }

    syscall_result = path_to_string(temp_buffer, output_buffer, 4096, 0);
    if (syscall_result + 0xfffU <= 0xffe) {
        *(long*)(stack_base + 0x75020) = syscall_result;
        return;
    }

    // 检查地址范围
    if ((path_addr < MEMORY_START || path_addr >= MEMORY_END) && path_addr != 0) {
        *(long*)(stack_base + 0x75020) = -EFAULT;
        return;
    }

    void* result_ptr = make_syscall(0xf, output_buffer, path_addr, 0, 0, 0, 0,
                                   stack_base + 0x7a000);
    *(void**)(stack_base + 0x75020) = result_ptr;
}

// 内存映射系统调用
void syscall_mmap(void) {
    ulong stack_base = (ulong)&stack0xffffffffffffffb0 & 0xfffffffffff80000;

    void* addr = *(void**)(stack_base + 0x75050);
    size_t length = *(size_t*)(stack_base + 0x75058);
    int prot = *(int*)(stack_base + 0x75030);
    int flags = *(int*)(stack_base + 0x75060);
    int fd = *(int*)(stack_base + 0x75070);
    off_t offset = *(off_t*)(stack_base + 0x75068);

    void* result = make_syscall(0x9, addr, length, prot, flags, fd, offset,
                               stack_base + 0x7a000);
    *(void**)(stack_base + 0x75020) = result;
}

// 内存保护系统调用
void syscall_mprotect(void) {
    ulong stack_base = (ulong)&stack0xffffffffffffffe0 & 0xfffffffffff80000;

    void* addr = *(void**)(stack_base + 0x75058);
    size_t length = *(size_t*)(stack_base + 0x75050);
    int prot = *(int*)(stack_base + 0x75030);

    // 检查地址对齐
    if ((ulong)addr & 0xfff) {
        *(long*)(stack_base + 0x75020) = -EINVAL;
        return;
    }

    // 检查地址范围
    if (length != 0 &&
        (((ulong)addr < MEMORY_START || (ulong)addr >= MEMORY_END) ||
         (MEMORY_END - (ulong)addr < length))) {
        *(long*)(stack_base + 0x75020) = -EINVAL;
        return;
    }

    void* result = make_syscall(0xe3, addr, length, prot, 0, 0, 0,
                               stack_base + 0x7a000);
    *(void**)(stack_base + 0x75020) = result;
}

// 打开文件系统调用
void syscall_open(void) {
    ulong stack_base = (ulong)&stack0xffffffffffffdfc0 & 0xfffffffffff80000;

    ulong pathname_addr = *(ulong*)(stack_base + 0x75050);
    int flags = *(int*)(stack_base + 0x75030);
    mode_t mode = *(mode_t*)(stack_base + 0x75070);
    int fd = *(int*)(stack_base + 0x75058);

    int result = copy_from_user(pathname_addr, temp_buffer, 4096);
    long syscall_result = (long)result;

    if (syscall_result + 0xfffU <= 0xffe) {
        *(long*)(stack_base + 0x75020) = syscall_result;
        return;
    }

    syscall_result = path_to_string(temp_buffer, output_buffer, 4096, 1);
    if (syscall_result + 0xfffU <= 0xffe) {
        *(long*)(stack_base + 0x75020) = syscall_result;
        return;
    }

    // 检查地址范围
    if ((MEMORY_START <= pathname_addr && pathname_addr < MEMORY_END) &&
        ((mode == 0) ||
         ((MEMORY_START <= flags && flags <= MEMORY_END) &&
          (mode <= MEMORY_END - flags)))) {

        void* result_ptr = make_syscall(0x8, output_buffer, pathname_addr,
                                       flags, mode, 0, 0, stack_base + 0x7a000);
        *(void**)(stack_base + 0x75020) = result_ptr;
        return;
    }

    *(long*)(stack_base + 0x75020) = -EFAULT;
}

// 读取文件系统调用
void syscall_read(void) {
    ulong stack_base = (ulong)&stack0xffffffffffffffe0 & 0xfffffffffff80000;

    int fd = *(int*)(stack_base + 0x75058);
    void* buffer = *(void**)(stack_base + 0x75030);
    size_t count = *(size_t*)(stack_base + 0x75050);

    // 检查缓冲区地址范围
    if ((MEMORY_START <= (ulong)buffer && (ulong)buffer <= MEMORY_END) &&
        (count <= MEMORY_END - (ulong)buffer)) {

        void* result = make_syscall(0x7b, fd, count, buffer, 0, 0, 0,
                                   stack_base + 0x7a000);
        *(void**)(stack_base + 0x75020) = result;
        return;
    }

    *(long*)(stack_base + 0x75020) = -EFAULT;
}

// 写入文件系统调用
void syscall_write(void) {
    ulong stack_base = (ulong)&stack0xffffffffffffffe0 & 0xfffffffffff80000;

    int fd = *(int*)(stack_base + 0x75058);
    const void* buffer = *(const void**)(stack_base + 0x75030);
    size_t count = *(size_t*)(stack_base + 0x75050);

    // 检查缓冲区地址范围
    if ((MEMORY_START <= (ulong)buffer && (ulong)buffer <= MEMORY_END) &&
        (count <= MEMORY_END - (ulong)buffer)) {

        void* result = make_syscall(0x7a, fd, count, buffer, 0, 0, 0,
                                   stack_base + 0x7a000);
        *(void**)(stack_base + 0x75020) = result;
        return;
    }

    *(long*)(stack_base + 0x75020) = -EFAULT;
}

// 进程控制系统调用 (prctl)
void syscall_prctl(void) {
    ulong stack_base = (ulong)&stack0xffffffffffffffb0 & 0xfffffffffff80000;
    
    int option = *(int*)(stack_base + 0x75058);
    unsigned long arg2 = *(unsigned long*)(stack_base + 0x75050);
    unsigned long arg3 = *(unsigned long*)(stack_base + 0x75030);
    unsigned long arg4 = *(unsigned long*)(stack_base + 0x75060);
    unsigned long arg5 = *(unsigned long*)(stack_base + 0x75070);
    
    long result;
    
    switch (option) {
        case PR_SET_NAME:
            result = handle_prctl_set_name(arg2);
            break;
            
        case PR_GET_NAME:
            result = handle_prctl_get_name(arg2);
            break;
            
        case PR_SET_MM:
            result = handle_prctl_set_mm(arg2, arg3, arg4, arg5);
            break;
            
        case PR_SET_SECCOMP:
            log_unhandled_prctl("PR_SET_SECCOMP", option, arg2);
            result = 0; // 假装成功
            break;
            
        default:
            if (option == ULIBC_PR_SET_VMA) {
                if (arg2 == 0) {
                    result = make_syscall(0xa7, ULIBC_PR_SET_VMA, 0, arg3, 
                                        arg4, arg5, 0, stack_base + 0x7a000);
                } else {
                    log_unhandled_prctl("ULIBC_PR_SET_VMA", option, arg2);
                    result = -EINVAL;
                }
            } else {
                log_unhandled_prctl("unknown", option, arg2);
                result = make_syscall(0xa7, option, arg2, arg3, arg4, arg5, 0, 
                                    stack_base + 0x7a000);
            }
            break;
    }
    
    *(long*)(stack_base + 0x75020) = result;
}

// 处理 PR_SET_MM 子选项
long handle_prctl_set_mm(unsigned long subopt, unsigned long addr, 
                        unsigned long arg4, unsigned long arg5) {
    process_mm_struct* mm = get_process_mm();
    
    switch (subopt) {
        case PR_SET_MM_START_CODE:
            if (validate_address(addr)) {
                mm->start_code = addr;
                update_mm_ranges(mm);
                return 0;
            }
            break;
            
        case PR_SET_MM_END_CODE:
            if (validate_vdso_or_user_address(addr)) {
                mm->end_code = addr;
                update_mm_ranges(mm);
                return 0;
            }
            break;
            
        case PR_SET_MM_START_STACK:
            if (validate_vdso_or_user_address(addr)) {
                mm->start_stack = addr;
                update_mm_ranges(mm);
                return 0;
            }
            break;
            
        default:
            log_unhandled_prctl("PR_SET_MM", subopt, addr);
            return -EINVAL;
    }
    
    return -EINVAL;
}
