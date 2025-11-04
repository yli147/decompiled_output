#include <stdint.h>
#include <stdbool.h>

// 常量定义
#define GUARD_PAGE_SIZE 0x1000
#define FCB_CCB_SIZE 0x2000
#define STACK_BASE_OFFSET 0x75000
#define STACK_DATA_OFFSET 0x7d000
#define THREAD_SIGNAL_SIZE 0x820
#define MAX_FD_COUNT 6

// 错误码
#define ERROR_INVALID_FD -7
#define ERROR_INVALID_PARAM -22
#define ERROR_ACCESS_DENIED -2

// 结构体前向声明
typedef struct HostStack HostStack_t;
typedef struct ThreadInfo ThreadInfo_t;
typedef struct SignalHandler SignalHandler_t;
typedef struct FileSystemRoot FileSystemRoot_t;
typedef struct ResourceLimit ResourceLimit_t;

// 辅助函数声明
static int create_guard_pages(long base_addr);
static int create_fcb_ccb(long base_addr);
static void initialize_stack_data(long param1);
static void setup_trace_system(long param1);
static ThreadInfo_t* create_thread_info(long param2, uint32_t flags);
static SignalHandler_t* create_signal_handler(ThreadInfo_t* parent, uint32_t flags);
static ResourceLimit_t* create_resource_limits(long param2, uint32_t flags);
static FileSystemRoot_t* create_fs_root(long param2, uint32_t flags);
static void copy_stack_data(long dest, long src);
static void link_to_global_list(long param1);

/**
 * 初始化主机栈
 * @param param1 栈基地址
 * @param param2 父栈地址（用于fork）
 * @param param3 标志位
 */
void initialize_host_stack(long param1, long param2, uint32_t param3) {
    // 创建保护页
    if (create_guard_pages(param1) != 0) {
        FUN_80100003db60("mman_hoststack.cc", 0x1d8,
                        "HostStack_t::initializeStack: failed to create guard pages\n");
        return;
    }

    // 创建FCB/CCB
    if (create_fcb_ccb(param1) != 0) {
        FUN_80100003db60("mman_hoststack.cc", 0x1e9,
                        "HostStack_t::initializeStack: failed to create FCB/CCB\n");
        return;
    }

    // 初始化栈数据结构
    initialize_stack_data(param1);

    if (param2 == 0) {
        // 新进程：创建新的资源
        setup_new_process(param1);
    } else {
        // Fork：从父进程复制资源
        setup_forked_process(param1, param2, param3);
    }

    // 链接到全局栈列表
    link_to_global_list(param1);
}

/**
 * 创建保护页
 */
static int create_guard_pages(long base_addr) {
    // 创建底部保护页
    int result = FUN_801000035f50(base_addr, GUARD_PAGE_SIZE, 0);
    if (result != 0) return result;

    // 创建顶部保护页
    return FUN_801000035f50(base_addr + 0x7a000, GUARD_PAGE_SIZE, 1);
}

/**
 * 创建FCB/CCB区域
 */
static int create_fcb_ccb(long base_addr) {
    ulong result = FUN_8010001ffc34(0xde, base_addr + 0x7e000, FCB_CCB_SIZE, 
                                   7, 0x32, 0xffffffffffffffff, 0);
    
    if (result > 0xfffffffffffff000) {
        int* error_ptr = (int*)FUN_8010000444c0();
        *error_ptr = -(int)result;
        return -1;
    }
    return 0;
}

/**
 * 初始化栈数据结构
 */
static void initialize_stack_data(long param1) {
    // 清零关键字段
    *(uint64_t*)(param1 + 0x75968) = 0;
    *(uint64_t*)(param1 + 0x75960) = 0;
    *(uint32_t*)(param1 + 0x75970) = 0;
    *(uint64_t*)(param1 + 0x75000) = 0;

    // 设置虚函数表指针
    *(void***)(param1 + 0x75920) = &PTR_LAB_8010002aeff0;

    // 初始化栈数据区域
    ulong* stack_data = (ulong*)(param1 + STACK_DATA_OFFSET);
    memset(stack_data, 0, sizeof(ulong) * 16);
    
    // 设置特殊值
    *(uint32_t*)(param1 + 0x7d010) = 0xffffffff;
    
    // 初始化段描述符
    initialize_segment_descriptors(param1);
    
    // 初始化文件描述符表
    initialize_fd_table(param1);
    
    // 设置栈指针
    *(ulong**)(param1 + 0x75008) = stack_data;
    *(long*)(param1 + 0x75018) = param1 + 0x7b000;
    *(long*)(param1 + 0x75010) = param1 + STACK_DATA_OFFSET - 0x10;
}

/**
 * 初始化段描述符
 */
static void initialize_segment_descriptors(long param1) {
    uint32_t gdt_base = DAT_801000400b80;
    uint32_t idt_base = DAT_801000400b88;
    uint32_t ldt_base = DAT_80105c6de220;
    uint32_t tss_base = DAT_80105c6de228;

    // 设置GDT
    *(uint32_t*)(param1 + 0x7d050) = gdt_base >> 3;
    *(uint64_t*)(param1 + 0x7d054) = 0xffffffff00000000;
    *(uint8_t*)(param1 + 0x7d05c) = 0xd4;

    // 设置IDT
    *(uint32_t*)(param1 + 0x7d060) = idt_base >> 3;
    *(uint64_t*)(param1 + 0x7d064) = 0xffffffff00000000;
    *(uint8_t*)(param1 + 0x7d06c) = 0x51;

    // 设置LDT
    *(uint32_t*)(param1 + 0x7d070) = ldt_base >> 3;
    *(uint64_t*)(param1 + 0x7d074) = 0xffffffff00000000;
    *(uint8_t*)(param1 + 0x7d07c) = 0x51;

    // 设置TSS
    *(uint32_t*)(param1 + 0x7d080) = tss_base >> 3;
    *(uint32_t*)(param1 + 0x7d084) = 0;
    *(uint32_t*)(param1 + 0x7d088) = 0xffffffff;
    *(uint8_t*)(param1 + 0x7d08c) = 0x51;
}

/**
 * 初始化文件描述符表
 */
static void initialize_fd_table(long param1) {
    // 初始化FD表项
    for (long offset = param1 + 0x7d0d8; offset < param1 + 0x7d468; offset += 0x18) {
        *(char**)(offset + 8) = "";
        *(uint32_t*)(offset + 0x10) = 0xffffffff;
    }

    // 设置默认值
    *(uint32_t*)(param1 + 0x7d468) = 0;
    *(uint8_t*)(param1 + 0x7d478) = 0;
    *(uint64_t*)(param1 + 0x7d480) = 0;
    *(uint32_t*)(param1 + 0x7d488) = 0;
    *(uint8_t*)(param1 + 0x7d48c) |= 1;  // 设置标志位

    // 初始化信号掩码
    for (int i = 0; i < 8; i++) {
        *(uint64_t*)(param1 + 0x7d498 + i * 8) = 0xffffffffffffffff;
    }
    
    *(uint32_t*)(param1 + 0x7d490) = 8;
    *(uint32_t*)(param1 + 0x7d4d8) = 0;
}

/**
 * 设置新进程
 */
static void setup_new_process(long param1) {
    // 创建信号处理器
    SignalHandler_t* signal_handler = create_new_signal_handler();
    
    // 创建文件系统根
    FileSystemRoot_t* fs_root = create_new_fs_root();
    
    // 创建资源限制
    ResourceLimit_t* rlimit = create_new_resource_limits();
    
    // 创建线程信息
    ThreadInfo_t* thread_info = create_new_thread_info();
    
    // 关联所有组件
    associate_components(param1, thread_info, signal_handler, rlimit, fs_root);
}

/**
 * 设置Fork进程
 */
static void setup_forked_process(long param1, long param2, uint32_t flags) {
    // 复制栈数据
    copy_stack_data(param1, param2);
    
    // 根据标志位决定是否共享资源
    SignalHandler_t* signal_handler = create_signal_handler(param2, flags);
    ResourceLimit_t* rlimit = create_resource_limits(param2, flags);
    FileSystemRoot_t* fs_root = create_fs_root(param2, flags);
    
    // 创建线程信息
    ThreadInfo_t* thread_info = create_thread_info_from_parent(param2);
    
    // 关联组件
    associate_components(param1, thread_info, signal_handler, rlimit, fs_root);
    
    // 设置特殊标志
    *(uint8_t*)(param1 + 0x7d5c8) = (flags >> 14) & 1;
}

/**
 * 复制栈数据（优化的内存复制）
 */
static void copy_stack_data(long dest, long src) {
    // 使用优化的内存复制函数
    efficient_memcpy((void*)(dest + 0x75020), (void*)(src + 0x75020), 0x1f0);
    efficient_memcpy((void*)(dest + 0x75220), (void*)(src + 0x75220), 0x200);
    efficient_memcpy((void*)(dest + 0x75420), (void*)(src + 0x75420), 0xc0);
    efficient_memcpy((void*)(dest + 0x75500), (void*)(src + 0x75500), 0x20);
    efficient_memcpy((void*)(dest + 0x75960), (void*)(src + 0x75960), 0x18);
    efficient_memcpy((void*)(dest + 0x75980), (void*)(src + 0x75980), 0x80);
    efficient_memcpy((void*)(dest + 0x75a00), (void*)(src + 0x75a00), 0x40);
    efficient_memcpy((void*)(dest + 0x76000), (void*)(src + 0x76000), 0x2000);
    efficient_memcpy((void*)(dest + 0x78000), (void*)(src + 0x78000), 0x2000);
}

/**
 * 优化的内存复制函数
 */
static void efficient_memcpy(void* dest, const void* src, size_t size) {
    if (((uintptr_t)dest | (uintptr_t)src) & 7) {
        // 未对齐，使用字节复制
        memcpy(dest, src, size);
    } else {
        // 8字节对齐，使用64位复制
        uint64_t* d = (uint64_t*)dest;
        const uint64_t* s = (const uint64_t*)src;
        size_t count = size / 8;
        
        for (size_t i = 0; i < count; i++) {
            d[i] = s[i];
        }
        
        // 处理剩余字节
        size_t remaining = size % 8;
        if (remaining > 0) {
            memcpy((char*)dest + count * 8, (char*)src + count * 8, remaining);
        }
    }
}

/**
 * 链接到全局栈列表
 */
static void link_to_global_list(long param1) {
    ulong* stack_ptr = (ulong*)(param1 + STACK_DATA_OFFSET);
    ulong* global_head = (ulong*)DAT_801054282950;
    ulong* global_tail = DAT_801054282958;

    if (global_head == NULL) {
        // 第一个栈
        DAT_801054282958 = stack_ptr;
        DAT_801054282950 = stack_ptr;
        return;
    }

    // 按地址顺序插入
    ulong* current = global_head;
    ulong* prev = NULL;

    while (current != NULL && current < stack_ptr) {
        prev = current;
        current = (ulong*)*current;
    }

    if (prev == NULL) {
        // 插入到头部
        *stack_ptr = (ulong)global_head;
        *(ulong**)(param1 + 0x7d008) = NULL;
        DAT_801054282958 = stack_ptr;
    } else {
        // 插入到中间或尾部
        *stack_ptr = *prev;
        *prev = (ulong)stack_ptr;
        *(ulong**)(param1 + 0x7d008) = prev;
        
        if (*stack_ptr == 0) {
            DAT_801054282950 = stack_ptr;
        }
    }
}

// 其他系统调用处理函数的重构版本...

/**
 * 系统调用：获取当前线程ID
 */
void syscall_gettid(void) {
    ulong stack_base = get_current_stack_base();
    ulong tid = *(ulong*)(stack_base + 0x75058);
    
    if (is_valid_tid(tid)) {
        ulong result = FUN_8010001ffe20(0x61, (long)(int)tid, 0, 0, 0, 0, 0, 
                                       stack_base + 0x7a000);
        set_syscall_result(stack_base, result);
    } else {
        set_syscall_result(stack_base, ERROR_INVALID_FD);
    }
}

/**
 * 获取当前栈基地址
 */
static inline ulong get_current_stack_base(void) {
    return (ulong)&stack0x00000000 & 0xfffffffffff80000;
}

/**
 * 检查线程ID是否有效
 */
static inline bool is_valid_tid(ulong tid) {
    int itid = (int)tid;
    return (itid >= 0) && (itid >= DAT_8010002b0338) && (itid < DAT_8010002b0338 + MAX_FD_COUNT);
}

/**
 * 设置系统调用返回值
 */
static inline void set_syscall_result(ulong stack_base, ulong result) {
    *(ulong*)(stack_base + 0x75020) = result;
}
