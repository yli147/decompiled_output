// lkv_logging.c
#include "lkv_logging.h"
#include "lkv_internal.h"

void log_ioctl_call(long request) {
    char buffer[1024];
    char log_buffer[8192];
    
    // 获取进程信息
    pid_t pid = getpid();
    pid_t tid = gettid();
    
    // 格式化日志消息
    snprintf(log_buffer, sizeof(log_buffer), 
             "%s %d [%d] %s 0x%08lx\n",
             "IOCTL", pid, tid, "request", request);
    
    // 写入日志文件
    int log_fd = open("/var/log/exagear/ioctl.log", 
                      O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd >= 0) {
        write(log_fd, log_buffer, strlen(log_buffer));
        close(log_fd);
    } else {
        fprintf(stderr, "Failed to open log file \"%s\" (errno == %d)\n",
                "/var/log/exagear/ioctl.log", errno);
    }
}

void log_prctl_call(int option, long arg) {
    char log_buffer[8192];
    
    pid_t pid = getpid();
    pid_t tid = gettid();
    
    snprintf(log_buffer, sizeof(log_buffer),
             "%s %d [%d] %s %d 0x%08lx\n", 
             "PRCTL", pid, tid, "option", option, arg);
    
    int log_fd = open("/var/log/exagear/prctl.log",
                      O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd >= 0) {
        write(log_fd, log_buffer, strlen(log_buffer));
        close(log_fd);
    } else {
        fprintf(stderr, "Failed to open log file \"%s\" (errno == %d)\n",
                "/var/log/exagear/prctl.log", errno);
    }
}
