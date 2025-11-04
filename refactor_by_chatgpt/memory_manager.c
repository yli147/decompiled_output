// memory_manager.c
#include <sys/mman.h>

/**
 * 释放内存区域
 * @param mem_info 内存区域信息
 * @param addr 要释放的地址
 */
void release_memory_area(ulong *mem_info, ulong addr) {
    pthread_mutex_lock(&memory_mutex);
    
    // 检查地址范围和对齐
    if (addr < mem_info[0] || 
        addr + 0x2000000 >= mem_info[1] || 
        (addr & 0x1ffffff) != 0) {
        fprintf(stderr, "Memory area is out of range or unaligned!\n");
        abort();
    }
    
    // 使用mmap释放内存
    int result = mmap((void *)addr, 0x2000000, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (result == MAP_FAILED) {
        perror("Failed to remap memory area");
    }
    
    // 更新内存状态
    size_t index = (addr - mem_info[0]) >> 25; // 除以32MB
    *((char *)mem_info + 0x10 + index) = 0;
    
    pthread_mutex_unlock(&memory_mutex);
}
