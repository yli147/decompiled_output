// SMC页面缓存结构
typedef struct {
    ulong pages[8];     // 最近访问的页面缓存 (0x93-0x9a)
    uint next_index;    // 下一个插入位置 (0x9b)
} smc_page_cache_t;

// 翻译节点结构
typedef struct translation_node {
    struct translation_node *left;
    struct translation_node *right;
    struct translation_node *parent;
    ulong guest_address;    // 偏移 0x19
    uint translation_id;    // 偏移 0x22
    // 其他字段...
} translation_node_t;

// 全局变量声明
extern uint smc_marked_pages_count;     // DAT_8010542828b8
extern ulong smc_marked_pages[];       // DAT_80105c6d7560
extern translation_node_t *translation_tree_root; // DAT_801054200000

/**
 * 处理SMC标记和翻译失效
 * @param start_addr 起始地址
 * @param size 大小
 * @param add_smc_marks 是否添加SMC标记
 * @param invalidate_all 是否失效所有翻译
 */
void handle_smc_and_translation_invalidation(ulong start_addr, long size, 
                                           bool add_smc_marks, bool invalidate_all) {
    // 计算页面对齐的地址范围
    ulong start_page = start_addr & 0xfffffffffffff000;
    ulong end_page = (start_addr + size + 0xfff) & 0xfffffffffffff000;
    
    // 第一部分：处理SMC标记
    if (add_smc_marks && start_page < end_page) {
        handle_smc_page_marking(start_page, end_page);
    }
    
    // 第二部分：处理翻译失效
    if (translation_tree_root != NULL) {
        invalidate_translations_in_range(start_addr, start_addr + size, invalidate_all);
    }
}

/**
 * 处理SMC页面标记
 */
static void handle_smc_page_marking(ulong start_page, ulong end_page) {
    smc_page_cache_t *cache = get_smc_page_cache();
    
    for (ulong current_page = start_page; current_page < end_page; current_page += 0x1000) {
        // 检查页面是否已在缓存中
        int cache_hits = count_page_in_cache(cache, current_page);
        
        if (cache_hits <= 1) {
            // 添加到缓存
            add_page_to_cache(cache, current_page);
        } else {
            // 页面已多次出现，需要添加到全局SMC标记列表
            add_page_to_smc_list(current_page);
        }
    }
}

/**
 * 统计页面在缓存中出现的次数
 */
static int count_page_in_cache(smc_page_cache_t *cache, ulong page_addr) {
    int count = 0;
    for (int i = 0; i < 8; i++) {
        if (cache->pages[i] == page_addr) {
            count++;
        }
    }
    return count;
}

/**
 * 添加页面到缓存
 */
static void add_page_to_cache(smc_page_cache_t *cache, ulong page_addr) {
    cache->pages[cache->next_index] = page_addr;
    cache->next_index = (cache->next_index + 1) & 7;  // 循环索引
}

/**
 * 添加页面到SMC标记列表
 */
static void add_page_to_smc_list(ulong page_addr) {
    // 检查页面是否已在列表中
    if (find_page_in_smc_list(page_addr) >= 0) {
        return;  // 已存在，跳过
    }
    
    log_debug("Added SMC mark to page 0x%016llx\n", page_addr);
    
    // 检查列表是否已满
    if (smc_marked_pages_count >= 0x800) {
        return;  // 列表已满
    }
    
    // 插入到有序列表中
    insert_page_into_sorted_list(page_addr);
}

/**
 * 在SMC列表中查找页面
 */
static int find_page_in_smc_list(ulong page_addr) {
    if (smc_marked_pages_count == 0) {
        return -1;
    }
    
    // 二分查找
    int left = 0, right = smc_marked_pages_count;
    
    while (left < right) {
        int mid = left + (right - left) / 2;
        if (smc_marked_pages[mid] < page_addr) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    
    if (left < smc_marked_pages_count && smc_marked_pages[left] == page_addr) {
        return left;
    }
    
    return -1;
}

/**
 * 插入页面到有序列表
 */
static void insert_page_into_sorted_list(ulong page_addr) {
    int insert_pos = find_insertion_position(page_addr);
    
    if (insert_pos >= smc_marked_pages_count) {
        // 插入到末尾
        smc_marked_pages[smc_marked_pages_count] = page_addr;
    } else {
        // 检查是否是标记为删除的页面
        if (smc_marked_pages[insert_pos] == (page_addr | 1)) {
            // 清除删除标记
            smc_marked_pages[insert_pos] &= 0xfffffffffffffffe;
            return;
        }
        
        // 移动元素为新页面腾出空间
        int elements_to_move = smc_marked_pages_count - insert_pos;
        memmove(&smc_marked_pages[insert_pos + 1], 
                &smc_marked_pages[insert_pos], 
                elements_to_move * sizeof(ulong));
        
        smc_marked_pages[insert_pos] = page_addr;
    }
    
    smc_marked_pages_count++;
}

/**
 * 查找插入位置
 */
static int find_insertion_position(ulong page_addr) {
    int left = 0, right = smc_marked_pages_count;
    
    while (left < right) {
        int mid = left + (right - left) / 2;
        if (smc_marked_pages[mid] < page_addr) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    
    return left;
}

/**
 * 失效指定范围内的翻译
 */
static void invalidate_translations_in_range(ulong start_addr, ulong end_addr, bool invalidate_all) {
    translation_node_t *current = find_first_translation_in_range(start_addr);
    
    while (current != NULL && current->guest_address < end_addr) {
        translation_node_t *next = get_next_translation_node(current);
        
        if (should_invalidate_translation(current, start_addr, end_addr, invalidate_all)) {
            invalidate_single_translation(current);
        }
        
        current = next;
    }
}

/**
 * 查找范围内第一个翻译节点
 */
static translation_node_t *find_first_translation_in_range(ulong start_addr) {
    translation_node_t *current = translation_tree_root;
    translation_node_t *result = NULL;
    
    // 在BST中查找第一个 >= start_addr 的节点
    while (current != NULL) {
        if (current->guest_address >= start_addr) {
            result = current;
            current = current->left;
        } else {
            current = current->right;
        }
    }
    
    return result;
}

/**
 * 获取下一个翻译节点（中序遍历）
 */
static translation_node_t *get_next_translation_node(translation_node_t *node) {
    if (node->right != NULL) {
        // 找右子树的最左节点
        node = node->right;
        while (node->left != NULL) {
            node = node->left;
        }
        return node;
    }
    
    // 向上找第一个作为左子树的祖先
    translation_node_t *parent = node->parent;
    while (parent != NULL && node == parent->right) {
        node = parent;
        parent = parent->parent;
    }
    
    return parent;
}

/**
 * 判断是否应该失效翻译
 */
static bool should_invalidate_translation(translation_node_t *node, ulong start_addr, 
                                        ulong end_addr, bool invalidate_all) {
    if (invalidate_all) {
        return true;
    }
    
    // 检查翻译的地址范围是否与目标范围重叠
    return check_translation_overlap(node, start_addr, end_addr);
}

/**
 * 检查翻译地址范围重叠
 */
static bool check_translation_overlap(translation_node_t *node, ulong start_addr, ulong end_addr) {
    // 获取翻译对应的代码块
    uint *translation = get_translation_block(node->translation_id);
    if (translation == NULL) {
        return false;
    }
    
    // 检查代码块中的地址范围
    return check_code_block_overlap(translation, start_addr, end_addr);
}

/**
 * 失效单个翻译
 */
static void invalidate_single_translation(translation_node_t *node) {
    uint *translation = get_translation_block(node->translation_id);
    if (translation == NULL) {
        return;
    }
    
    // 执行翻译失效的具体操作
    perform_translation_invalidation(translation);
    
    // 清理相关的缓存和数据结构
    cleanup_translation_caches(translation);
    
    // 从翻译树中移除节点
    remove_translation_from_tree(node);
}

/**
 * 获取SMC页面缓存
 */
static smc_page_cache_t *get_smc_page_cache() {
    static smc_page_cache_t *cache = NULL;
    
    if (cache == NULL) {
        if (is_thread_local_storage_enabled()) {
            cache = get_thread_local_cache();
        } else {
            cache = get_global_cache();
        }
    }
    
    return cache;
}

/**
 * 获取翻译块
 */
static uint *get_translation_block(uint translation_id) {
    if (translation_id == 0x48000000) {
        return NULL;
    }
    
    return (uint *)(&translation_pool_base + translation_id);
}

/**
 * 日志记录函数
 */
static void log_debug(const char *format, ...) {
    if (debug_logging_enabled) {
        va_list args;
        va_start(args, format);
        // 调用实际的日志函数
        debug_log_function("addPage2SmcMarkedPagesList", get_current_thread_id(), format, args);
        va_end(args);
    }
}

void translation_protection_handler(ulong start_addr, ulong size,
                                  bool add_smc_marks, bool invalidate_all) {
    // 获取当前状态
    int current_counter = atomic_load(&protection_counter);

    // 原子操作更新计数器
    atomic_compare_exchange(&protection_counter, current_counter, -1);
    increment_nested_counter();

    // 检查是否需要清理
    if (get_nested_count() + get_protection_count() != 0) {
        perform_cleanup();
    }

    // 如果启用了性能监控
    if (performance_monitoring_enabled) {
        update_performance_counters();
    }

    // 获取翻译缓存锁
    acquire_lock(&translation_cache_lock, "tp_real.cc", 0x166);

    // 处理SMC标记和翻译失效
    handle_smc_and_invalidation(start_addr, size, add_smc_marks, invalidate_all);

    // 处理内存管理
    acquire_lock(&memory_manager_lock, "mman_hoststack.cc", 0x168);

    // 清理内存栈
    cleanup_memory_stacks();

    release_lock(&memory_manager_lock);
    release_lock(&translation_cache_lock);

    // 恢复计数器状态
    restore_counter_state(current_counter);

    // 唤醒等待的线程
    wake_waiting_threads();
}

void handle_smc_invalidation(bool remove_smc_mark, ulong address) {
    // 获取当前线程上下文
    void *thread_context = get_thread_context();

    // 原子递减计数器
    atomic_decrement(&global_counter);

    // 获取锁
    acquire_lock(&translation_lock, "tp_real.cc", 0x26e);

    // 查找地址对应的翻译
    long translation = find_translation(address);
    if (translation != 0 && (*(char *)(translation + 0x2c) & 0xc0) != 0x80) {

        if (remove_smc_mark) {
            // 移除SMC标记
            remove_smc_marks_from_pages(translation);
        }

        // 使翻译无效
        invalidate_translation(translation, 1, 2);
    }

    // 释放锁
    release_lock(&translation_lock);

    // 清理相关资源
    cleanup_translation_resources();

    log_debug("Thread %d: Invalidated translation at address 0x%016llx. remove_smc_mark = %d\n",
              get_thread_id(), address, remove_smc_mark);
}

/**
 * 翻译保护和内存管理的主函数
 * @param start_addr 起始地址
 * @param size 大小
 * @param add_smc_marks 是否添加SMC标记
 * @param invalidate_all 是否失效所有翻译
 */
void translation_protection_manager(ulong start_addr, ulong size,
                                   bool add_smc_marks, bool invalidate_all) {
    // 第一阶段：获取同步锁并设置状态
    int old_counter = acquire_sync_lock();
    increment_nested_counter(old_counter);

    // 检查是否需要执行清理操作
    if (needs_cleanup()) {
        perform_system_cleanup();
    }

    // 如果启用了性能监控，执行相关操作
    if (g_performance_monitoring) {
        handle_performance_monitoring();
    }

    // 第二阶段：处理翻译保护
    acquire_translation_lock();
    handle_smc_and_translation_invalidation(start_addr, size, add_smc_marks, invalidate_all);

    // 第三阶段：处理SMC页面清理
    handle_smc_page_cleanup();

    // 第四阶段：处理内存栈清理
    acquire_memory_manager_lock();
    cleanup_memory_stacks();
    release_memory_manager_lock();

    // 第五阶段：恢复同步状态并唤醒等待线程
    release_translation_lock();
    restore_sync_state_and_wake_waiters(old_counter);
}

// 事件标志位定义
typedef struct {
    bool memory_protection_event;    // 0xe50
    bool guest_protection_alarm;     // 0xe30
    bool translation_invalidation;   // 0x20e8
    bool cache_flush_request;        // 0x20e9
    bool performance_dump;           // 0x20f8
    bool internal_event_1;           // 0x20f9
    bool internal_event_2;           // 0x20fa
    bool internal_event_3;           // 0x20fb
    bool internal_event_4;           // 0x20fc
} event_flags_t;

// 线程上下文结构
typedef struct {
    ulong stack_base;
    void *thread_data;
    event_flags_t *events;
    uint thread_id;
    // 其他字段...
} thread_context_t;

// 全局变量
extern bool g_thread_local_storage_enabled;    // DAT_801000400000
extern uint g_pending_invalidations_count;     // DAT_801000400a58
extern void *g_pending_invalidations[];        // DAT_801000400a60
extern bool g_performance_monitoring;          // DAT_8010002b0098
extern bool g_debug_perfmap_enabled;          // DAT_801000400ae0

/**
 * 主事件处理函数
 */
void handle_internal_events(void) {
    // 初始化上下文
    thread_context_t ctx;
    initialize_thread_context(&ctx);

    // 处理各种事件
    bool event_handled = false;

    // 1. 处理内存保护事件
    event_handled |= handle_memory_protection_event(&ctx);

    // 2. 处理客户代码保护告警
    event_handled |= handle_guest_protection_alarm(&ctx);

    // 3. 处理翻译失效事件
    event_handled |= handle_translation_invalidation(&ctx);

    // 4. 处理缓存刷新请求
    event_handled |= handle_cache_flush_request(&ctx);

    // 5. 处理性能转储请求
    event_handled |= handle_performance_dump_request(&ctx);

    // 6. 处理其他内部事件
    event_handled |= handle_other_internal_events(&ctx);

    // 确保至少有一个事件被处理
    if (!event_handled) {
        fatal_error("ubt_al.cc", 0x122,
                   "UBT: assertion \"internal_event_handled\" failed.\n"
                   "Unprocessed internal event happened.\n");
    }
}

/**
 * 初始化线程上下文
 */
static void initialize_thread_context(thread_context_t *ctx) {
    // 获取CPU状态信息
    ulong cpu_state = get_cpu_state();
    ctx->stack_base = get_stack_base();

    // 更新CPU状态寄存器
    update_cpu_state_registers(cpu_state, ctx->stack_base);

    // 获取线程数据指针
    if (g_thread_local_storage_enabled) {
        ctx->thread_data = get_thread_local_data(ctx->stack_base);
    } else {
        ctx->thread_data = get_global_thread_data();
    }

    ctx->events = get_event_flags(ctx->thread_data);
    ctx->thread_id = get_thread_id(ctx->thread_data);

    // 清理锁状态
    cleanup_lock_state(ctx);

    // 执行系统清理
    perform_system_cleanup();
}

/**
 * 更新CPU状态寄存器
 */
static void update_cpu_state_registers(ulong cpu_state, ulong stack_base) {
    uint state_bits = (uint)(cpu_state >> 0xd);
    uint enable_bit = (uint)(cpu_state >> 0xf) & 1;

    // 检查是否有覆盖配置
    if (get_cpu_override_config() != 0) {
        enable_bit = get_cpu_override_config();
    }

    // 更新状态寄存器
    *(ulong *)(stack_base + 0x751f8) = cpu_state & 0xffffffff;

    // 更新控制寄存器
    uint *control_reg = (uint *)(stack_base + 0x75208);
    *control_reg = (*control_reg & 0xfe000000) |
                   (*control_reg & 0x3fffff) |
                   (((state_bits & 1) << 1 | (state_bits & 3) >> 1) << 0x16) |
                   ((enable_bit & 1) << 0x18);
}

/**
 * 清理锁状态
 */
static void cleanup_lock_state(thread_context_t *ctx) {
    void *thread_data = get_thread_data_pointer(ctx);

    if (*(long *)((char *)thread_data + 0x470) != 0) {
        *(long *)((char *)thread_data + 0x470) = 0;
        release_lock();
    }
}

/**
 * 处理内存保护事件
 */
static bool handle_memory_protection_event(thread_context_t *ctx) {
    event_flags_t *events = ctx->events;

    if (!events->memory_protection_event) {
        return false;
    }

    // 获取保护区域信息
    long protected_region = get_protected_region_info(ctx->thread_data);
    ulong current_pc = get_current_pc(ctx->stack_base);

    // 检查是否在保护范围内
    if (is_address_in_protected_region(protected_region, current_pc)) {
        // 处理保护违规
        handle_protection_violation(ctx, protected_region);
    } else {
        // 执行默认处理
        perform_default_protection_handling(ctx);
    }

    // 清除事件标志
    events->memory_protection_event = false;
    return true;
}

/**
 * 处理客户代码保护告警
 */
static bool handle_guest_protection_alarm(thread_context_t *ctx) {
    event_flags_t *events = ctx->events;

    if (!events->guest_protection_alarm) {
        return false;
    }

    // 获取告警信息
    ulong alarm_start = get_alarm_start_address(ctx->thread_data);
    uint alarm_size = get_alarm_size(ctx->thread_data);
    bool invalidate_flag = get_invalidate_flag(ctx->thread_data);

    log_debug("Guest code protection alarm in thread %d. Range [%016llx; %016llx]\n",
              ctx->thread_id, alarm_start, alarm_start + alarm_size - 1);

    // 如果启用了性能监控
    if (g_performance_monitoring) {
        update_performance_counters();
    }

    // 处理保护告警
    process_protection_alarm(alarm_start, alarm_size, invalidate_flag);

    // 处理待处理的失效操作
    handle_pending_invalidations();

    // 清除事件标志
    events->guest_protection_alarm = false;
    return true;
}

/**
 * 处理翻译失效事件
 */
static bool handle_translation_invalidation(thread_context_t *ctx) {
    event_flags_t *events = ctx->events;

    if (!events->translation_invalidation) {
        return false;
    }

    // 清除事件标志
    events->translation_invalidation = false;
    return true;
}

/**
 * 处理缓存刷新请求
 */
static bool handle_cache_flush_request(thread_context_t *ctx) {
    event_flags_t *events = ctx->events;

    if (!events->cache_flush_request) {
        return false;
    }

    // 获取要失效的翻译地址
    ulong translation_addr = get_translation_address(ctx->thread_data);

    // 获取翻译锁并执行失效
    acquire_translation_lock();

    long translation = find_translation(translation_addr);
    if (translation != 0) {
        invalidate_translation(translation, 1, 2);
    }

    release_translation_lock();

    // 清除事件标志
    events->cache_flush_request = false;
    return true;
}

/**
 * 处理性能转储请求
 */
static bool handle_performance_dump_request(thread_context_t *ctx) {
    event_flags_t *events = ctx->events;

    if (!events->performance_dump) {
        return false;
    }

    // 如果启用了性能映射调试
    if (g_debug_perfmap_enabled) {
        acquire_perfmap_lock();
        write_perfmap_data();
        release_perfmap_lock();
    }

    // 执行性能转储
    perform_performance_dump();

    // 清除事件标志
    events->performance_dump = false;
    return true;
}

/**
 * 处理其他内部事件
 */
static bool handle_other_internal_events(thread_context_t *ctx) {
    event_flags_t *events = ctx->events;
    bool handled = false;

    // 处理内部事件1
    if (events->internal_event_1) {
        events->internal_event_1 = false;
        handled = true;
    }

    // 处理内部事件2
    if (events->internal_event_2) {
        events->internal_event_2 = false;
        set_internal_flag(ctx);
        handled = true;
    }

    // 处理内部事件3
    if (events->internal_event_3) {
        events->internal_event_3 = false;
        handled = true;
    }

    // 处理内部事件4
    if (events->internal_event_4) {
        handle_thread_synchronization(ctx);
        events->internal_event_4 = false;
        handled = true;
    }

    // 如果有调试事件，触发调试处理
    if (has_debug_event(events)) {
        handle_debug_event(ctx);
        handled = true;
    }

    return handled;
}

/**
 * 处理保护告警的具体实现
 */
static void process_protection_alarm(ulong start_addr, uint size, bool invalidate_flag) {
    acquire_multiple_locks();

    // 查找内存区域
    ulong page_addr = start_addr & 0xfffffffffffff000;
    long memory_region = find_memory_region(&page_addr);

    if (memory_region == 0 ||
        (start_addr + size + 0xfff & 0xfffffffffffff000) <=
        *(ulong *)(memory_region + 0x19)) {
        // 区域在范围内，只需释放锁
        release_multiple_locks();
    } else {
        // 需要执行翻译保护处理
        release_multiple_locks();
        translation_protection_manager(start_addr, size, true, invalidate_flag ^ 1);
    }
}

/**
 * 处理待处理的失效操作
 */
static void handle_pending_invalidations(void) {
    if (g_pending_invalidations_count == 0) {
        return;
    }

    acquire_invalidation_locks();

    while (g_pending_invalidations_count > 0) {
        g_pending_invalidations_count--;

        void *invalidation_target = g_pending_invalidations[g_pending_invalidations_count];
        if (invalidation_target == NULL) {
            break;
        }

        perform_invalidation(invalidation_target, 1, 1);
    }

    release_invalidation_locks();
}

/**
 * 处理调试事件
 */
static void handle_debug_event(thread_context_t *ctx) {
    log_error("Dump current context:\n");
    dump_current_context();
    fatal_error("ubt_al.cc", 0x11f, "al debug event\n");
}

/**
 * 获取线程数据指针
 */
static void *get_thread_data_pointer(thread_context_t *ctx) {
    if (g_thread_local_storage_enabled) {
        return *(void **)(ctx->stack_base + 0x7d018);
    } else {
        return get_global_thread_data();
    }
}

/**
 * 辅助函数
 */
static ulong get_cpu_state(void) {
    return get_system_cpu_state();  // FUN_80100009fa20
}

static ulong get_stack_base(void) {
    return (ulong)&stack0xffffffffffffff80 & 0xfffffffffff80000;
}

static void perform_system_cleanup(void) {
    system_cleanup_function();  // FUN_801000035c60
}

static void acquire_multiple_locks(void) {
    acquire_lock(&protection_lock, "ubt_al.cc", 200);
    acquire_lock(&translation_lock, "ubt_al.cc", 0xc9);
}

static void release_multiple_locks(void) {
    release_lock(&translation_lock);
    release_lock(&protection_lock);
}
