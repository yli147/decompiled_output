#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

// 常量定义
#define MAX_PATH_LENGTH 4096
#define MAX_FD_COUNT 6
#define STACK_BASE_MASK 0xfffffffffff80000
#define RESULT_OFFSET 0x75020
#define ERROR_INVALID_FD -9
#define ERROR_ACCESS_DENIED -13
#define ERROR_NOT_FOUND -2
#define ERROR_INVALID_PARAM -22

// 结构体定义
typedef struct {
    long start_addr;
    long end_addr;
    uint32_t flags;
    uint32_t prot;
    char path[MAX_PATH_LENGTH];
} memory_mapping_t;

typedef struct vma_node {
    struct vma_node *left;
    struct vma_node *right;
    struct vma_node *parent;
    bool is_red;
    uint64_t start_addr;
    uint64_t end_addr;
    uint32_t flags;
    uint32_t protection;
    // 其他VMA相关字段
} vma_node_t;

// 全局变量
extern uint32_t g_reserved_fd_base;
extern bool g_proc_access_enabled;
extern char g_guest_root_path[MAX_PATH_LENGTH];

// 辅助函数声明
static int validate_fd(int fd);
static int copy_path_from_user(const char *user_path, char *kernel_path, size_t max_len);
static int resolve_path(const char *path, char *resolved_path);
static bool is_proc_path(const char *path);
static int handle_proc_access(const char *path);

// 系统调用实现

/**
 * 重命名文件或目录
 */
void sys_renameat2(int old_dirfd, const char *old_path, 
                   int new_dirfd, const char *new_path, 
                   unsigned int flags) {
    uint64_t stack_base = get_stack_base();
    char old_resolved[MAX_PATH_LENGTH];
    char new_resolved[MAX_PATH_LENGTH];
    int result;

    // 验证文件描述符
    if (validate_fd(old_dirfd) != 0 || validate_fd(new_dirfd) != 0) {
        set_syscall_result(stack_base, ERROR_INVALID_FD);
        return;
    }

    // 复制并解析路径
    result = copy_path_from_user(old_path, old_resolved, sizeof(old_resolved));
    if (result < 0) {
        set_syscall_result(stack_base, result);
        return;
    }

    result = copy_path_from_user(new_path, new_resolved, sizeof(new_resolved));
    if (result < 0) {
        set_syscall_result(stack_base, result);
        return;
    }

    // 检查是否为受保护的路径
    if (is_protected_path(old_resolved) || is_protected_path(new_resolved)) {
        set_syscall_result(stack_base, ERROR_ACCESS_DENIED);
        return;
    }

    // 执行重命名操作
    result = perform_rename_operation(old_dirfd, old_resolved, 
                                    new_dirfd, new_resolved, flags);
    set_syscall_result(stack_base, result);
}

/**
 * 创建硬链接
 */
void sys_linkat(int old_dirfd, const char *old_path,
                int new_dirfd, const char *new_path,
                int flags) {
    uint64_t stack_base = get_stack_base();
    char old_resolved[MAX_PATH_LENGTH];
    char new_resolved[MAX_PATH_LENGTH];
    int result;

    // 验证参数
    if (validate_fd(old_dirfd) != 0 || validate_fd(new_dirfd) != 0) {
        set_syscall_result(stack_base, ERROR_INVALID_FD);
        return;
    }

    // 处理路径解析
    result = resolve_and_validate_paths(old_path, new_path, 
                                      old_resolved, new_resolved);
    if (result < 0) {
        set_syscall_result(stack_base, result);
        return;
    }

    // 执行链接操作
    result = create_hard_link(old_dirfd, old_resolved, 
                            new_dirfd, new_resolved, flags);
    set_syscall_result(stack_base, result);
}

/**
 * 获取文件状态
 */
void sys_fstatat(int dirfd, const char *pathname, 
                 struct stat *statbuf, int flags) {
    uint64_t stack_base = get_stack_base();
    char resolved_path[MAX_PATH_LENGTH];
    int result;

    // 验证文件描述符
    if (validate_fd(dirfd) != 0) {
        set_syscall_result(stack_base, ERROR_INVALID_FD);
        return;
    }

    // 解析路径
    result = copy_path_from_user(pathname, resolved_path, sizeof(resolved_path));
    if (result < 0) {
        set_syscall_result(stack_base, result);
        return;
    }

    // 处理特殊路径（如/proc）
    if (is_proc_path(resolved_path)) {
        result = handle_proc_stat(resolved_path, statbuf, flags);
    } else {
        result = get_file_stat(dirfd, resolved_path, statbuf, flags);
    }

    set_syscall_result(stack_base, result);
}

/**
 * 读取符号链接
 */
void sys_readlinkat(int dirfd, const char *pathname, 
                    char *buf, size_t bufsiz) {
    uint64_t stack_base = get_stack_base();
    char resolved_path[MAX_PATH_LENGTH];
    int result;

    // 验证参数
    if (validate_fd(dirfd) != 0) {
        set_syscall_result(stack_base, ERROR_INVALID_FD);
        return;
    }

    if (buf == NULL || bufsiz == 0) {
        set_syscall_result(stack_base, ERROR_INVALID_PARAM);
        return;
    }

    // 解析路径
    result = copy_path_from_user(pathname, resolved_path, sizeof(resolved_path));
    if (result < 0) {
        set_syscall_result(stack_base, result);
        return;
    }

    // 读取符号链接
    result = read_symbolic_link(dirfd, resolved_path, buf, bufsiz);
    set_syscall_result(stack_base, result);
}

/**
 * 获取当前工作目录
 */
void sys_getcwd(char *buf, size_t size) {
    uint64_t stack_base = get_stack_base();
    char temp_path[MAX_PATH_LENGTH];
    int result;

    if (size < 2) {
        set_syscall_result(stack_base, ERROR_INVALID_PARAM);
        return;
    }

    // 获取当前工作目录
    result = get_current_working_directory(temp_path, sizeof(temp_path));
    if (result < 0) {
        set_syscall_result(stack_base, result);
        return;
    }

    // 处理路径转换
    result = convert_guest_to_host_path(temp_path, buf, size);
    set_syscall_result(stack_base, result);
}

/**
 * 打开文件
 */
void sys_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    uint64_t stack_base = get_stack_base();
    char resolved_path[MAX_PATH_LENGTH];
    int result;

    // 验证文件描述符
    if (validate_fd(dirfd) != 0) {
        set_syscall_result(stack_base, ERROR_INVALID_FD);
        return;
    }

    // 解析路径
    result = copy_path_from_user(pathname, resolved_path, sizeof(resolved_path));
    if (result < 0) {
        set_syscall_result(stack_base, result);
        return;
    }

    // 处理特殊文件（如/proc下的文件）
    if (is_proc_path(resolved_path)) {
        result = handle_proc_open(resolved_path, flags, mode);
    } else {
        result = open_regular_file(dirfd, resolved_path, flags, mode);
    }

    set_syscall_result(stack_base, result);
}

// VMA（虚拟内存区域）管理函数

/**
 * 查找包含指定地址的VMA
 */
vma_node_t* find_vma_by_address(vma_node_t *root, uint64_t address) {
    vma_node_t *current = root;
    vma_node_t *result = NULL;

    while (current != NULL) {
        if (address >= current->start_addr && address < current->end_addr) {
            return current;
        }
        
        if (address < current->start_addr) {
            current = current->left;
        } else {
            current = current->right;
        }
    }

    return result;
}

/**
 * 插入新的VMA节点
 */
vma_node_t* insert_vma_node(vma_node_t **root, uint64_t start, uint64_t end,
                            uint32_t flags, uint32_t prot) {
    vma_node_t *new_node = allocate_vma_node();
    if (new_node == NULL) {
        return NULL;
    }

    // 初始化节点
    new_node->start_addr = start;
    new_node->end_addr = end;
    new_node->flags = flags;
    new_node->protection = prot;
    new_node->is_red = true;
    new_node->left = new_node->right = new_node->parent = NULL;

    // 插入到红黑树中
    insert_into_rbtree(root, new_node);
    
    return new_node;
}

/**
 * 删除VMA节点
 */
void remove_vma_node(vma_node_t **root, vma_node_t *node) {
    if (node == NULL) {
        return;
    }

    // 从红黑树中删除
    remove_from_rbtree(root, node);
    
    // 释放节点内存
    deallocate_vma_node(node);
}

// 辅助函数实现

static int validate_fd(int fd) {
    if (fd >= 0 && fd >= g_reserved_fd_base && fd < g_reserved_fd_base + MAX_FD_COUNT) {
        return ERROR_INVALID_FD;
    }
    return 0;
}

static int copy_path_from_user(const char *user_path, char *kernel_path, size_t max_len) {
    if (user_path == NULL || kernel_path == NULL) {
        return ERROR_INVALID_PARAM;
    }

    size_t len = strnlen(user_path, max_len);
    if (len >= max_len) {
        return ERROR_INVALID_PARAM;
    }

    memcpy(kernel_path, user_path, len + 1);
    return len;
}

static bool is_proc_path(const char *path) {
    return (strncmp(path, "/proc/", 6) == 0);
}

static uint64_t get_stack_base(void) {
    uint64_t stack_ptr;
    __asm__ volatile ("mov %0, sp" : "=r" (stack_ptr));
    return stack_ptr & STACK_BASE_MASK;
}

static void set_syscall_result(uint64_t stack_base, int result) {
    *(int64_t*)(stack_base + RESULT_OFFSET) = result;
}

// 位操作函数

/**
 * 位扫描 - 查找最低位的1
 */
uint64_t bit_scan_forward(uint64_t value, uint64_t unused, int size) {
    uint64_t stack_base = get_stack_base();
    
    if (size == 2) {
        value &= 0xFFFF;
    } else if (size == 4) {
        value &= 0xFFFFFFFF;
    }
    
    if (value == 0) {
        set_flags_zero_parity(stack_base);
        return unused;
    }
    
    // 查找最低位的1
    uint64_t result = __builtin_ctzll(value);
    set_flags_with_parity(stack_base, result);
    
    return result;
}

/**
 * 位扫描 - 查找最高位的1
 */
uint64_t bit_scan_reverse(uint64_t value, uint64_t unused, int size) {
    uint64_t stack_base = get_stack_base();
    
    if (size == 2) {
        value &= 0xFFFF;
    } else if (size == 4) {
        value &= 0xFFFFFFFF;
    }
    
    if (value == 0) {
        set_flags_zero_parity(stack_base);
        return unused;
    }
    
    // 查找最高位的1
    uint64_t result = (size * 8 - 1) - __builtin_clzll(value);
    set_flags_with_parity(stack_base, result);
    
    return result;
}

/**
 * 位测试
 */
uint64_t bit_test(uint64_t value, uint64_t bit_pos, int size) {
    uint64_t stack_base = get_stack_base();
    uint64_t bit_offset = bit_pos & 0xFF;
    uint64_t bit_count = (bit_pos >> 8) & 0xFF;
    
    if (bit_offset >= size * 8 || bit_count == 0) {
        set_flags_zero(stack_base);
        return 0;
    }
    
    uint64_t mask_width = (bit_count < (size * 8 - bit_offset)) ? 
                         bit_count : (size * 8 - bit_offset);
    
    uint64_t mask = (0xFFFFFFFFFFFFFFFFULL >> (64 - mask_width));
    uint64_t result = (value >> bit_offset) & mask;
    
    set_flags_test_result(stack_base, result == 0);
    
    return result;
}

// 标志位设置函数
static void set_flags_zero_parity(uint64_t stack_base) {
    *(bool*)(stack_base + 0x75502) = true;  // ZF = 1
    *(bool*)(stack_base + 0x75505) = true;  // PF = 1
    *(bool*)(stack_base + 0x75500) = false; // CF = 0
    *(bool*)(stack_base + 0x75503) = false; // SF = 0
    *(bool*)(stack_base + 0x75504) = false; // OF = 0
    *(bool*)(stack_base + 0x75506) = false; // AF = 0
}

static void set_flags_with_parity(uint64_t stack_base, uint64_t value) {
    bool parity = (__builtin_popcount(value & 0xFF) & 1) == 0;
    
    *(bool*)(stack_base + 0x75502) = false; // ZF = 0
    *(bool*)(stack_base + 0x75505) = parity; // PF
    *(bool*)(stack_base + 0x75500) = false; // CF = 0
    *(bool*)(stack_base + 0x75503) = false; // SF = 0
    *(bool*)(stack_base + 0x75504) = false; // OF = 0
    *(bool*)(stack_base + 0x75506) = false; // AF = 0
}

static void set_flags_test_result(uint64_t stack_base, bool is_zero) {
    *(bool*)(stack_base + 0x75500) = false; // CF = 0
    *(bool*)(stack_base + 0x75502) = is_zero; // ZF
    *(bool*)(stack_base + 0x75503) = false; // SF = 0
    *(bool*)(stack_base + 0x75504) = false; // OF = 0
    *(bool*)(stack_base + 0x75505) = false; // PF = 0
    *(bool*)(stack_base + 0x75506) = false; // AF = 0
}
