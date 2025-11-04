// lkv_rlimit.c
#include "lkv_rlimit.h"
#include "lkv_internal.h"

static int set_cpu_limit(process_limits_t* limits, ulong* new_limit) {
    pthread_mutex_lock(&limits->cpu_limit.mutex);
    
    if (new_limit[1] < new_limit[0]) {
        pthread_mutex_unlock(&limits->cpu_limit.mutex);
        return -EINVAL;
    }
    
    // 检查权限
    if (limits->cpu_limit.hard_limit < new_limit[1]) {
        if (!check_capability(CAP_SYS_RESOURCE)) {
            pthread_mutex_unlock(&limits->cpu_limit.mutex);
            return -EPERM;
        }
    }
    
    limits->cpu_limit.soft_limit = new_limit[0];
    limits->cpu_limit.hard_limit = new_limit[1];
    
    pthread_mutex_unlock(&limits->cpu_limit.mutex);
    return 0;
}

long setrlimit_handler(int resource, ulong* new_limit, long* old_limit) {
    process_limits_t* limits = get_current_process_limits();
    long result = 0;
    
    switch (resource) {
        case RLIMIT_CPU:
            if (old_limit) {
                get_cpu_limits(limits, old_limit);
            }
            if (new_limit) {
                result = set_cpu_limit(limits, new_limit);
            }
            break;
            
        case RLIMIT_FSIZE:
            if (old_limit) {
                get_fsize_limits(limits, old_limit);
            }
            if (new_limit) {
                result = set_fsize_limit(limits, new_limit);
            }
            break;
            
        case RLIMIT_AS:
            return handle_as_limit_special(limits, new_limit, old_limit);
            
        default:
            // 使用系统调用处理其他资源类型
            return syscall(SYS_prlimit64, 0, resource, new_limit, old_limit);
    }
    
    return result;
}
