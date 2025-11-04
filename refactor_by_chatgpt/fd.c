#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

// 重构第一个函数：跟踪获取函数
void acquire_trace(uint64_t param1, long param2) {
    // 栈变量声明
    bool trace_enabled = false;
    uint32_t trace_flags = 0;
    uint8_t buffer[136000];
    uint8_t trace_buffer[8];
    uint8_t *buffer_ptr = buffer;
    
    // 获取栈基址并检查跟踪状态
    uintptr_t stack_base = ((uintptr_t)&stack_base) & 0xfffffffffff80000;
    bool has_trace = *(long *)(stack_base + 0x75188) != 0;
    
    if (global_trace_flag != 0) {
        has_trace = (global_trace_flag == 1);
    }
    
    trace_enabled = has_trace;
    trace_flags = *(uint32_t *)(stack_base + 0x75170);
    
    // 获取跟踪锁
    acquire_lock(&global_lock, "rgnacq_trace.cc", 0xdc);
    
    // 尝试获取跟踪
    char result = acquire_trace_internal(param2, param1, &trace_enabled, 0);
    
    release_lock(&global_lock);
    
    if (result == 0) {
        log_error("Can't acquire trace.\n");
        return;
    }
    
    // 设置跟踪缓冲区
    uint64_t *trace_ptr = &global_trace_buffer;
    if (global_flag != 0) {
        trace_ptr = (uint64_t *)(stack_base + 0x7d000);
    }
    
    // 初始化跟踪参数
    initialize_trace_buffers(buffer, trace_buffer);
    
    // 设置硬件配置
    *(uint32_t *)(param2 + 0x87c0) = 
        ((uint32_t)global_hw_config << 1) | 0x100 | 
        create_hw_flags(global_hw_flags);
    
    // 处理跟踪数据
    process_trace_data(trace_buffer, param2);
    setup_trace_channels(trace_buffer);
    configure_trace_output(trace_buffer);
    
    // 处理特殊情况
    if (*(int *)(param2 + 0x24e4) != 0) {
        handle_special_trace_case(param2, trace_buffer);
    }
    
    // 最终配置
    finalize_trace_setup(trace_buffer, param2);
}

// 重构第二个函数：地址范围检查
bool is_address_in_range(uintptr_t addr, uintptr_t size) {
    if (global_base_addr <= addr) {
        return (addr <= global_end_addr) && 
               (size <= global_end_addr - addr);
    }
    return false;
}

// 重构第三个函数：VFS对象创建
void create_vfs_objects(uint64_t **obj1, uint64_t **obj2) {
    acquire_lock(&vfs_lock, "lkv_vfs_objects.cc", 0x1a);
    
    if (vfs_pool_count == 0) {
        // 创建新对象
        *obj1 = allocate_vfs_object(&vfs_pool1);
        initialize_vfs_object1(*obj1);
        
        *obj2 = allocate_vfs_object(&vfs_pool2);
        initialize_vfs_object2(*obj2);
    } else {
        // 从池中获取对象
        *obj1 = vfs_pool[vfs_pool_count - 1];
        *obj2 = vfs_pool[vfs_pool_count + 1];
        vfs_pool_count--;
    }
    
    release_lock(&vfs_lock);
}

// 重构第四个函数：获取当前工作目录
int get_current_working_directory(char *buffer, size_t size) {
    if (size < 2) {
        set_errno(EINVAL);
        return -1;
    }
    
    // 使用readlink获取当前工作目录
    int result = syscall_readlink(AT_FDCWD, "/proc/self/cwd", buffer, size);
    
    if (result < 0) {
        return -1;
    }
    
    if (result >= 0) {
        if (size == result) {
            set_errno(ERANGE);
            return -1;
        }
        
        buffer[result] = '\0';
        
        // 处理删除标记
        if (check_and_remove_deleted_suffix(buffer, result)) {
            return 0;
        }
    }
    
    return 0;
}

// 重构第五个函数：路径处理
int process_path(char *path) {
    if (*path == '\0') {
        return 0;
    }
    
    int path_len = strlen(path);
    
    // 遍历路径列表
    for (path_entry_t *entry = global_path_list; entry != NULL; entry = entry->next) {
        const char *host_path = get_host_path(entry);
        const char *guest_path = get_guest_path(entry);
        
        int host_len = strlen(host_path);
        int guest_len = strlen(guest_path);
        int total_len = host_len + guest_len;
        
        if (total_len <= path_len) {
            if (path_matches(path, host_path, host_len) &&
                path_matches(path + host_len, guest_path, guest_len)) {
                return process_matched_path(path, host_len, guest_len);
            }
        }
    }
    
    return finalize_path_processing(path, path_len);
}

// 重构内存映射函数
uintptr_t memory_map(uintptr_t addr, size_t length, int prot, int flags, 
                     int fd, off_t offset) {
    if ((flags & MAP_ANONYMOUS) != 0) {
        fd = -1;
    }
    
    // 初始化文件描述符信息
    fd_info_t fd_info;
    initialize_fd_info(&fd_info, fd, 0);
    
    size_t page_size = 0x1000;
    size_t aligned_length = (length + page_size - 1) & ~(page_size - 1);
    
    if ((flags & MAP_FIXED) == 0) {
        // 非固定映射
        return handle_non_fixed_mapping(addr, aligned_length, prot, flags, 
                                       &fd_info, offset);
    } else {
        // 固定映射
        return handle_fixed_mapping(addr, aligned_length, prot, flags, 
                                   &fd_info, offset);
    }
}

// 辅助函数实现
static void initialize_trace_buffers(uint8_t *buffer1, uint8_t *buffer2) {
    memset(buffer1, 0, 0xed8);
    memset(buffer2, 0, 0x1450);
}

static uint32_t create_hw_flags(uint32_t flags) {
    return ((flags >> 4 & 1) << 2) |
           ((flags & 1) << 3) |
           ((flags >> 2 & 1) << 4) |
           ((flags >> 1 & 1) << 5) |
           ((flags >> 3 & 1) << 6) |
           ((flags >> 5 & 1) << 7);
}

static bool path_matches(const char *path, const char *pattern, int len) {
    if (len == 0) return true;
    return memcmp(path, pattern, len) == 0;
}

static void initialize_vfs_object1(uint64_t *obj) {
    *obj = 0;
    *(uint64_t *)(obj + 1) = 0xffffffff00000000;
    *(uint64_t *)(obj + 0x200) = 0;
    *(uint64_t *)(obj + 0x205) = 0;
}

static void initialize_vfs_object2(uint64_t *obj) {
    *(uint64_t *)(obj + 0x400) = 0;
    *(uint64_t *)(obj + 0x401) = 0;
    *(uint64_t *)(obj + 0x469) = 0;
    *(uint64_t *)(obj + 0x46a) = 0;
    *obj = 0;
    *(uint32_t *)(obj + 0x402) = 0;
}

static uintptr_t handle_non_fixed_mapping(uintptr_t addr, size_t length, 
                                         int prot, int flags, 
                                         fd_info_t *fd_info, off_t offset) {
    // 获取合适的地址
    uintptr_t target_addr = find_suitable_address(addr, length, flags);
    
    if (target_addr == MAP_FAILED) {
        return MAP_FAILED;
    }
    
    // 执行实际的内存映射
    uintptr_t result = perform_mmap(target_addr, length, prot, flags, 
                                   fd_info, offset);
    
    if (result != MAP_FAILED) {
        // 记录映射信息
        record_mapping(result, length, prot, flags);
    }
    
    return result;
}

static uintptr_t handle_fixed_mapping(uintptr_t addr, size_t length, 
                                     int prot, int flags, 
                                     fd_info_t *fd_info, off_t offset) {
    // 检查地址范围
    if (!is_valid_address_range(addr, length)) {
        return -EINVAL;
    }
    
    // 清理现有映射
    cleanup_existing_mappings(addr, length);
    
    // 执行映射
    uintptr_t result = perform_mmap(addr, length, prot, flags, fd_info, offset);
    
    if (result != MAP_FAILED) {
        record_mapping(addr, length, prot, flags);
    }
    
    return result;
}
