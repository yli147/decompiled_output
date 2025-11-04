// lkv_hifd.c
#include "lkv_hifd.h"
#include "lkv_internal.h"

static hifd_manager_t g_hifd_manager = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .allocated_mask = 0,
    .count = 0
};

uint32_t hifd_allocate(uint32_t fd, char close_on_exec) {
    pthread_mutex_lock(&g_hifd_manager.mutex);
    
    // 找到第一个可用的高位fd槽
    uint32_t slot = 0;
    uint32_t target_fd = DAT_8010002b0338;  // 高位fd基址
    
    for (int i = 0; i < HIFD_COUNT; i++) {
        if ((g_hifd_manager.allocated_mask & (1 << i)) == 0) {
            slot = i;
            target_fd = DAT_8010002b0338 + i;
            break;
        }
    }
    
    if (fd == target_fd) {
        // fd已经在目标位置
        if (close_on_exec) {
            int result = set_fd_cloexec(target_fd);
            if (result != 0) {
                pthread_mutex_unlock(&g_hifd_manager.mutex);
                abort_with_error("Failed to set FD_CLOEXEC");
            }
        }
    } else {
        // 需要移动fd到高位区域
        uint32_t flags = close_on_exec ? O_CLOEXEC : 0;
        uint32_t new_fd = syscall(SYS_dup3, fd, target_fd, flags);
        
        if (new_fd != target_fd) {
            pthread_mutex_unlock(&g_hifd_manager.mutex);
            abort_with_error("Failed to move fd to high area");
        }
        
        close(fd);
    }
    
    // 标记为已分配
    g_hifd_manager.allocated_mask |= (1 << slot);
    g_hifd_manager.count++;
    
    pthread_mutex_unlock(&g_hifd_manager.mutex);
    return target_fd;
}

void hifd_deallocate(uint32_t hifd) {
    pthread_mutex_lock(&g_hifd_manager.mutex);
    
    // 打开占位符文件描述符
    uint32_t placeholder_fd = syscall(SYS_openat, AT_FDCWD, "/dev/null", 
                                     O_RDONLY | O_CLOEXEC, 0);
    if (placeholder_fd < 0) {
        abort_with_error("Failed to open placeholder fd");
    }
    
    // 将占位符移动到要释放的hifd位置
    uint32_t result = syscall(SYS_dup2, placeholder_fd, hifd);
    if (result != hifd) {
        abort_with_error("Failed to replace hifd with placeholder");
    }
    
    close(placeholder_fd);
    
    // 更新分配状态
    uint32_t slot = hifd - DAT_8010002b0338;
    g_hifd_manager.allocated_mask &= ~(1 << slot);
    g_hifd_manager.count--;
    
    pthread_mutex_unlock(&g_hifd_manager.mutex);
}
