// lkv_rlimit.h
#ifndef LKV_RLIMIT_H
#define LKV_RLIMIT_H

#include <sys/resource.h>

typedef struct {
    pthread_mutex_t mutex;
    ulong soft_limit;
    ulong hard_limit;
} resource_limit_t;

typedef struct {
    resource_limit_t cpu_limit;      // RLIMIT_CPU
    resource_limit_t fsize_limit;    // RLIMIT_FSIZE  
    resource_limit_t data_limit;     // RLIMIT_DATA
    resource_limit_t stack_limit;    // RLIMIT_STACK
    resource_limit_t as_limit;       // RLIMIT_AS
} process_limits_t;

long setrlimit_handler(int resource, ulong* new_limit, long* old_limit);
void getrlimit_handler(void);
void setrlimit_handler_wrapper(void);

#endif
