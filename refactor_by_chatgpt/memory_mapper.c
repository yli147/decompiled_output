// memory_mapper.c
#include <sys/mman.h>

typedef struct {
    void *start_addr;
    void *end_addr;
    char allocation_map[2048]; // 位图，每位表示32MB块
} memory_region_t;

/**
 * 释放内存区域
 * @param region 内存区域信息
 * @param addr 要释放的地址
 */
void release_memory_region(memory_region_t *region, uintptr_t addr) {
    pthread_mutex_lock(&memory_mutex);
    
    // 验证地址范围和对齐
    if (!validate_memory_address(region, addr)) {
        log_error("Memory area is out of range or unaligned!");
        abort();
    }
    
    // 使用mmap重新映射内存区域
    void *result = mmap((void *)addr, 0x2000000, 
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 
                       -1, 0);
    
    if (result == MAP_FAILED) {
        set_errno_from_result((uintptr_t)result);
    }
    
    // 更新分配位图
    size_t block_index = (addr - (uintptr_t)region->start_addr) >> 25;
    region->allocation_map[block_index] = 0;
    
    pthread_mutex_unlock(&memory_mutex);
}

/**
 * 分配内存区域
 * @param region 内存区域信息
 * @return 成功返回分配的地址，失败返回0
 */
uintptr_t allocate_memory_region(memory_region_t *region) {
    pthread_mutex_lock(&memory_mutex);
    
    // 查找空闲块
    for (int i = 2047; i >= 0; i--) {
        if (region->allocation_map[i] == 0) {
            uintptr_t addr = (uintptr_t)region->start_addr + i * 0x2000000;
            
            // 尝试映射内存
            void *result = mmap((void *)addr, 0x2000000,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                               -1, 0);
            
            if (result != MAP_FAILED) {
                region->allocation_map[i] = 1;
                pthread_mutex_unlock(&memory_mutex);
                return addr;
            }
        }
    }
    
    // 没有找到空闲块，调用系统分配器
    uintptr_t addr = system_allocate_memory();
    pthread_mutex_unlock(&memory_mutex);
    return addr;
}

/**
 * 验证内存地址
 */
static int validate_memory_address(const memory_region_t *region, uintptr_t addr) {
    return (addr >= (uintptr_t)region->start_addr) &&
           (addr + 0x2000000 < (uintptr_t)region->end_addr) &&
           ((addr & 0x1ffffff) == 0);
}

// 内存分配器相关的重构

// 内存区域查找和分配
typedef struct MemoryRegion {
    struct MemoryRegion* left;
    struct MemoryRegion* right;
    struct MemoryRegion* parent;
    ulong start_addr;
    ulong end_addr;
    uint flags;
    // 其他字段...
} MemoryRegion;

// 全局内存管理器状态
typedef struct MemoryManager {
    MemoryRegion* region_tree;
    ulong heap_start;
    ulong heap_end;
    ulong stack_start;
    ulong stack_end;
    bool hugepage_enabled;
    long hugepage_size;
} MemoryManager;

static MemoryManager g_memory_manager = {0};

// 重构后的内存分配函数
ulong allocate_memory_region(ulong size, ulong base_addr, ulong limit_addr,
                            ulong alignment_addr, long alignment) {
    // 参数验证
    if ((limit_addr - base_addr < size) ||
        (alignment_addr - g_memory_manager.stack_start < size)) {
        return INVALID_ADDRESS;
    }

    if (g_memory_manager.region_tree == NULL) {
        return base_addr;
    }

    // 对齐计算
    long align_mask = -alignment;
    ulong aligned_size = (size + alignment - 1) & align_mask;
    ulong aligned_base = (base_addr + alignment - 1) & align_mask;
    ulong aligned_limit = limit_addr & align_mask;

    return find_free_region(aligned_size, aligned_base, aligned_limit, alignment);
}

// 查找空闲内存区域
static ulong find_free_region(ulong size, ulong start, ulong end, long alignment) {
    MemoryRegion* current = g_memory_manager.region_tree;

    // 遍历内存区域树，查找合适的空闲区域
    while (current != NULL) {
        if (size <= current->end_addr - current->start_addr) {
            // 检查是否有足够空间
            if (can_allocate_in_region(current, size, start, end)) {
                return allocate_in_region(current, size, alignment);
            }
        }
        current = get_next_region(current);
    }

    return INVALID_ADDRESS;
}

// 内存映射函数重构
long map_memory_region(long addr, long size, uint prot_flags) {
    if ((prot_flags & CONFLICTING_FLAGS) == CONFLICTING_FLAGS) {
        return -EINVAL;
    }

    acquire_memory_lock();

    long result = -EINVAL;

    // 地址对齐检查
    if ((addr & PAGE_MASK) != 0) {
        goto cleanup;
    }

    if (size == 0) {
        result = 0;
        goto cleanup;
    }

    // 检查地址范围有效性
    if (!is_valid_address_range(addr, size)) {
        result = -ENOMEM;
        goto cleanup;
    }

    // 执行内存映射
    result = perform_memory_mapping(addr, size, prot_flags);

cleanup:
    release_memory_lock();
    return result;
}

// 内存保护函数重构
static long perform_memory_mapping(long addr, long size, uint flags) {
    ulong aligned_size = (size + PAGE_SIZE - 1) & PAGE_MASK;
    uint mmap_flags = prepare_mmap_flags(flags);

    // 执行系统调用
    long result = syscall_mmap(addr, aligned_size, mmap_flags);
    if (result < 0) {
        return result;
    }

    // 更新内存区域信息
    update_memory_regions(addr, aligned_size, flags);

    // 处理大页面
    if (g_memory_manager.hugepage_enabled) {
        handle_hugepage_allocation(addr, aligned_size);
    }

    return 0;
}

// 文件描述符清理函数重构
int cleanup_file_descriptors(int exclude_fd) {
    char proc_path[128];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd", getpid());

    int dir_fd = open_directory(proc_path);
    if (dir_fd < 0) {
        log_error("Failed to open /proc/self/fd");
        return -1;
    }

    DIR* dir = fdopendir(dir_fd);
    if (!dir) {
        log_error("fdopendir failed for /proc/self/fd");
        close(dir_fd);
        return -1;
    }

    int closed_count = 0;
    int fd_list[MAX_FDS];

    // 收集需要关闭的文件描述符
    closed_count = collect_fds_to_close(dir, exclude_fd, dir_fd, fd_list, MAX_FDS);

    closedir(dir);

    // 关闭收集到的文件描述符
    close_collected_fds(fd_list, closed_count);

    return closed_count;
}

// 收集需要关闭的文件描述符
static int collect_fds_to_close(DIR* dir, int exclude_fd, int dir_fd,
                               int* fd_list, int max_fds) {
    struct dirent* entry;
    int count = 0;

    while ((entry = readdir(dir)) != NULL && count < max_fds) {
        // 跳过 "." 和 ".." 目录项
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        int fd = parse_fd_number(entry->d_name);
        if (should_close_fd(fd, exclude_fd, dir_fd)) {
            fd_list[count++] = fd;
        }
    }

    return count;
}

// 判断是否应该关闭文件描述符
static bool should_close_fd(int fd, int exclude_fd, int dir_fd) {
    return (fd >= 0) &&
           (fd != exclude_fd) &&
           (fd != dir_fd) &&
           (fd > STDERR_FILENO);  // 保留标准输入输出错误
}

// 关闭收集到的文件描述符
static void close_collected_fds(int* fd_list, int count) {
    for (int i = 0; i < count; i++) {
        if (close(fd_list[i]) < 0) {
            // 记录关闭失败，但继续处理其他fd
            log_warning("Failed to close fd %d", fd_list[i]);
        }
    }
}

// 解析文件描述符编号
static int parse_fd_number(const char* name) {
    char* endptr;
    long fd = strtol(name, &endptr, 10);

    if (*endptr != '\0' || fd < 0 || fd > INT_MAX) {
        return -1;  // 无效的文件描述符
    }

    return (int)fd;
}

// 获取大页面大小
long get_hugepage_size(void) {
    static long cached_size = -1;

    if (cached_size == -1) {
        cached_size = read_hugepage_size_from_proc();
        if (cached_size <= 0) {
            cached_size = DEFAULT_PAGE_SIZE;
        }
    }

    return cached_size;
}

// 从 /proc/meminfo 读取大页面大小
static long read_hugepage_size_from_proc(void) {
    FILE* meminfo = fopen("/proc/meminfo", "r");
    if (!meminfo) {
        return -1;
    }

    char line[512];
    long hugepage_size = -1;

    while (fgets(line, sizeof(line), meminfo)) {
        if (strncmp(line, "Hugepagesize:", 13) == 0) {
            sscanf(line + 13, "%ld", &hugepage_size);
            break;
        }
    }

    fclose(meminfo);
    return hugepage_size > 0 ? hugepage_size * 1024 : -1;  // 转换为字节
}

// 内存区域验证
bool validate_memory_region(ulong addr, ulong size, uint required_flags) {
    acquire_memory_lock();

    bool valid = false;
    MemoryRegion* region = find_memory_region(addr);

    while (region && (region->flags & required_flags) == required_flags) {
        if (addr + size <= region->end_addr) {
            valid = true;
            break;
        }

        // 检查下一个连续区域
        region = get_next_contiguous_region(region);
        if (!region || region->start_addr != addr + size) {
            break;
        }
    }

    release_memory_lock();
    return valid;
}

// 常量定义
#define INVALID_ADDRESS     0xFFFFFFFFFFFFFFFF
#define PAGE_SIZE           0x1000
#define PAGE_MASK           0xFFF
#define DEFAULT_PAGE_SIZE   0x1000
#define MAX_FDS             1024
#define CONFLICTING_FLAGS   0x3000000
#define EINVAL              22
#define ENOMEM              12

// 错误处理宏
#define log_error(fmt, ...) \
    fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)

#define log_warning(fmt, ...) \
    fprintf(stderr, "WARNING: " fmt "\n", ##__VA_ARGS__)
