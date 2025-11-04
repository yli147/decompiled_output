// lkv_hifd.h
#ifndef LKV_HIFD_H
#define LKV_HIFD_H

#include <pthread.h>

#define HIFD_COUNT 7
#define HIFD_BASE_OFFSET 6

typedef struct {
    pthread_mutex_t mutex;
    uint32_t allocated_mask;  // 位掩码表示已分配的高位fd
    uint32_t count;          // 已分配的数量
} hifd_manager_t;

uint32_t hifd_allocate(uint32_t fd, char close_on_exec);
void hifd_deallocate(uint32_t hifd);
uint32_t hifd_move_to_high_area(int fd);

#endif
