// cache_manager.c

typedef struct cache_entry {
    uint32_t prev_index;
    uint32_t next_index;
    void *address;
    uint32_t size;
    // 其他缓存条目字段...
} cache_entry_t;

extern cache_entry_t cache_entries[];
extern uint32_t cache_counter;

/**
 * 移除缓存条目
 * @param entry 要移除的缓存条目
 */
void remove_cache_entry(cache_entry_t *entry) {
    uint32_t region_type = 1;
    void *base_addr = entry->address;
    
    // 更新统计计数器
    cache_counter++;
    
    // 计算地址范围
    uint32_t start_index = ((uintptr_t)base_addr + 0xFC600000U) >> 8 & 0x7FFFF;
    uint32_t end_index = ((uintptr_t)base_addr + 
                         ((entry->size & 0xF) << 16 | entry->size) + 0xFC600000U) >> 8 & 0x7FFFF;
    
    // 确定区域类型
    extern void *region_boundary1, *region_boundary2;
    if (base_addr >= region_boundary1) {
        region_type = (base_addr >= region_boundary2) ? 1 : 0;
    }
    
    // 调用清理函数
    cleanup_cache_entry(entry, 0, 2);
    finalize_cache_entry(entry);
    
    // 更新哈希表
    update_hash_table(start_index, end_index, entry);
    
    // 更新链表
    update_cache_links(entry, region_type);
    
    // 处理调试信息
    if (debug_enabled()) {
        process_debug_info(entry);
    }
}

/**
 * 更新哈希表条目
 */
static void update_hash_table(uint32_t start_index, uint32_t end_index, 
                             cache_entry_t *entry) {
    extern void **hash_table;
    extern cache_entry_t *cache_base;
    
    // 清理起始位置的哈希表条目
    if (hash_table[start_index] == entry) {
        uint32_t entry_index = entry->prev_index;
        if (entry_index != 0x48000000) {
            if (entry->address <= cache_base[entry_index].address &&
                start_index == calculate_hash_index(cache_base[entry_index].address)) {
                hash_table[start_index] = &cache_base[entry_index];
            } else {
                hash_table[start_index] = NULL;
            }
        } else {
            hash_table[start_index] = NULL;
        }
    }
    
    // 清理结束位置的哈希表条目
    if (hash_table[end_index] == entry) {
        // 类似的逻辑...
        hash_table[end_index] = NULL;
    }
    
    // 清理中间的哈希表条目
    for (uint32_t i = end_index - 1; i > start_index && end_index - start_index > 1; i--) {
        hash_table[i] = NULL;
    }
}

/**
 * 更新缓存链表
 */
static void update_cache_links(cache_entry_t *entry, uint32_t region_type) {
    extern void **region_heads, **region_tails;
    
    cache_entry_t *head = (cache_entry_t *)region_heads[region_type];
    cache_entry_t *tail = (cache_entry_t *)region_tails[region_type];
    
    // 如果头尾相等，重置区域
    if (head == tail) {
        extern void **region_defaults;
        region_tails[region_type] = region_defaults[region_type];
    }
    
    // 更新前后链接
    if (entry->prev_index != 0x48000000) {
        cache_base[entry->prev_index].next_index = entry->next_index;
    }
    
    if (entry->next_index != 0x48000000) {
        cache_base[entry->next_index].prev_index = entry->prev_index;
    }
    
    // 更新头尾指针
    if (entry == head) {
        void *new_head = (entry->prev_index == 0x48000000) ? 
                        NULL : &cache_base[entry->prev_index];
        region_heads[region_type] = new_head;
    }
    
    if (entry == tail) {
        void *new_tail = (entry->next_index == 0x48000000) ? 
                        NULL : &cache_base[entry->next_index];
        region_tails[region_type] = new_tail;
    }
}
