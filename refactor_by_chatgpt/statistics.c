// statistics.c

typedef struct {
    uint64_t count;
    uint64_t total_size;
    uint64_t min_size;
    uint64_t max_size;
} stat_entry_t;

extern stat_entry_t statistics[];

/**
 * 更新统计信息
 * @param stat_id 统计ID
 * @param size 大小值
 */
void update_statistics(uint32_t stat_id, uint64_t size) {
    if (stat_id >= MAX_STAT_ENTRIES) return;
    
    // 计算统计条目的偏移
    uint64_t offset = -(stat_id >> 31 & 1) & 0xFFFFFFE000000000UL | 
                     (stat_id & 0xFFFFFFFF) << 5;
    
    stat_entry_t *entry = (stat_entry_t *)((char *)statistics + offset);
    uint64_t config = get_stat_config(stat_id);
    uint32_t flags = config & 3;
    
    // 原子更新计数
    if (is_atomic_mode()) {
        atomic_increment(&entry->count);
        if (flags != 0) {
            atomic_add(&entry->total_size, size);
        }
    } else {
        // 使用独占监视器进行原子操作
        do {
            if (!exclusive_monitor_pass(&entry->count, 16)) continue;
            entry->count++;
        } while (!exclusive_monitor_success());
        
        if (flags != 0) {
            do {
                if (!exclusive_monitor_pass(&entry->total_size, 16)) continue;
                entry->total_size += size;
            } while (!exclusive_monitor_success());
        }
    }
    
    // 更新最小值
    if ((config >> 2) & 1) {
        update_minimum(&entry->min_size, size);
    }
    
    // 更新最大值
    if ((config >> 3) & 1) {
        update_maximum(&entry->max_size, size);
    }
}

/**
 * 原子更新最小值
 */
static void update_minimum(uint64_t *min_ptr, uint64_t new_value) {
    do {
        if (*min_ptr <= new_value) break;
        if (!exclusive_monitor_pass(min_ptr, 16)) continue;
        *min_ptr = new_value;
    } while (!exclusive_monitor_success());
}

/**
 * 原子更新最大值
 */
static void update_maximum(uint64_t *max_ptr, uint64_t new_value) {
    do {
        if (new_value <= *max_ptr) return;
        if (!exclusive_monitor_pass(max_ptr, 16)) continue;
        *max_ptr = new_value;
    } while (!exclusive_monitor_success());
}
