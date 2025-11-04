// exagear_common.h
#ifndef EXAGEAR_COMMON_H
#define EXAGEAR_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// 函数声明
int cleanup_file_descriptors(int keep_fd);
int create_optimizer_process(void);
int send_to_optimizer(const void *data);
void shutdown_optimizer_comm(void);
void show_help(const char *program_name);
void release_memory_area(ulong *mem_info, ulong addr);

// 常量定义
#define MAX_FDS 1024
#define OPTIMIZER_LOG_PATH "/var/log/exagear/optimizer.log"

#endif // EXAGEAR_COMMON_H
