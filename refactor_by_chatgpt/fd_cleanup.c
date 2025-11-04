// fd_cleanup.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/syscall.h>

#define MAX_FDS 1024

/**
 * 清理进程的文件描述符，关闭除指定fd外的所有打开的文件描述符
 * @param keep_fd 需要保留的文件描述符
 * @return 关闭的文件描述符数量，失败返回-1
 */
int cleanup_file_descriptors(int keep_fd) {
    char proc_path[128];
    DIR *dir;
    struct dirent *entry;
    int fd_list[MAX_FDS];
    int fd_count = 0;
    int dir_fd, fd_num;
    
    // 获取当前进程PID并构造/proc/PID/fd路径
    pid_t pid = getpid();
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd", pid);
    
    // 打开/proc/self/fd目录
    dir_fd = open(proc_path, O_RDONLY);
    if (dir_fd < 0) {
        fprintf(stderr, "Failed to open %s\n", proc_path);
        return -1;
    }
    
    dir = fdopendir(dir_fd);
    if (!dir) {
        fprintf(stderr, "Failed to fdopendir %s\n", proc_path);
        close(dir_fd);
        return -1;
    }
    
    // 遍历目录，收集需要关闭的文件描述符
    while ((entry = readdir(dir)) != NULL && fd_count < MAX_FDS) {
        // 跳过"."和".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        fd_num = atoi(entry->d_name);
        
        // 跳过目录fd、标准输入输出错误和需要保留的fd
        if (fd_num != dir_fd && fd_num > 2 && fd_num != keep_fd) {
            fd_list[fd_count++] = fd_num;
        }
    }
    
    closedir(dir);
    
    // 关闭收集到的文件描述符
    for (int i = 0; i < fd_count; i++) {
        close(fd_list[i]);
    }
    
    return fd_count;
}
