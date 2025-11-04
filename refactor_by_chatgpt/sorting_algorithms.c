// sorting_algorithms.c

#define ELEMENT_SIZE_18 18
#define ELEMENT_SIZE_24 24
#define ELEMENT_SIZE_32 32

/**
 * 通用快速排序实现
 * @param array 要排序的数组
 * @param count 元素数量
 * @param element_size 元素大小
 * @param compare 比较函数
 */
void generic_quicksort(void *array, size_t count, size_t element_size,
                      int (*compare)(const void *, const void *)) {
    if (count <= 6) {
        insertion_sort(array, count, element_size, compare);
        return;
    }
    
    // 选择枢轴
    void *pivot = select_pivot(array, count, element_size, compare);
    
    // 分区
    size_t left_size, right_size;
    partition_array(array, count, element_size, pivot, compare, 
                   &left_size, &right_size);
    
    // 递归排序
    if (left_size > 1) {
        generic_quicksort(array, left_size, element_size, compare);
    }
    
    if (right_size > 1) {
        char *right_start = (char *)array + (count - right_size) * element_size;
        generic_quicksort(right_start, right_size, element_size, compare);
    }
}

/**
 * 18字节元素排序
 */
void sort_18byte_elements(void *array, size_t count) {
    generic_quicksort(array, count, ELEMENT_SIZE_18, compare_18byte);
}

/**
 * 16字节元素排序（双字）
 */
void sort_16byte_elements(void *array, size_t count) {
    generic_quicksort(array, count, 16, compare_16byte);
}

/**
 * 32字节元素排序（四字）
 */
void sort_32byte_elements(void *array, size_t count) {
    generic_quicksort(array, count, ELEMENT_SIZE_32, compare_32byte);
}

/**
 * 插入排序（用于小数组）
 */
static void insertion_sort(void *array, size_t count, size_t element_size,
                          int (*compare)(const void *, const void *)) {
    char *arr = (char *)array;
    char temp[element_size];
    
    for (size_t i = 1; i < count; i++) {
        memcpy(temp, arr + i * element_size, element_size);
        
        size_t j = i;
        while (j > 0 && compare(arr + (j-1) * element_size, temp) > 0) {
            memcpy(arr + j * element_size, arr + (j-1) * element_size, element_size);
            j--;
        }
        
        memcpy(arr + j * element_size, temp, element_size);
    }
}

// 查找虚拟地址对应的翻译缓存条目
void* lookup_translation_cache(char enable_fallback) {
    // 检查系统状态
    bool is_user_mode = (DAT_801000400000 == 0);
    void* base_ptr;

    if (is_user_mode) {
        base_ptr = &DAT_801054281000;
        if (DAT_80105428158c != 0) {
            return nullptr;  // 系统忙碌
        }
    } else {
        // 内核模式，使用栈基址计算
        uintptr_t stack_base = (uintptr_t)&stack0xffffffffffffffb0 & 0xfffffffffff80000;
        base_ptr = (void*)(stack_base + 0x7d000);
        if (*(char*)(stack_base + 0x7d58c) != 0) {
            return nullptr;  // 系统忙碌
        }
    }

    // 检查系统标志
    if (*(char*)((long)base_ptr + 0x58d) != 0 || DAT_8010002b7729 != 0) {
        return nullptr;
    }

    // 获取目标地址
    uintptr_t stack_base = (uintptr_t)&stack0xffffffffffffffb0 & 0xfffffffffff80000;
    ulong target_addr = *(ulong*)(stack_base + 0x750a8);

    // 检查地址范围
    if (!is_valid_address_range(target_addr)) {
        return nullptr;
    }

    // 检查模块列表
    if (!check_module_boundaries(target_addr)) {
        return nullptr;
    }

    // 尝试快速查找
    if (enable_fallback) {
        void* result = fast_lookup(target_addr);
        if (result != nullptr) {
            return result;
        }
    }

    // 计算哈希索引
    long hash_index = calculate_hash_index(target_addr);

    // 构造查找键
    ulong lookup_key = build_lookup_key(target_addr, base_ptr);

    // 在哈希表中查找
    void* cached_entry = search_hash_table(hash_index, lookup_key);
    if (cached_entry != nullptr) {
        return cached_entry;
    }

    // 如果启用回退，尝试动态查找
    if (enable_fallback) {
        return dynamic_lookup(target_addr, hash_index, lookup_key);
    }

    return nullptr;
}
