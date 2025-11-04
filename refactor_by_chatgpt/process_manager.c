// process_manager.c
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>

/**
 * 创建优化器进程
 * @return 成功返回socket fd，失败返回-1
 */
int create_optimizer_process(void) {
    int socket_pair[2];
    pid_t pid;
    int log_fd;
    
    // 创建socket对用于进程间通信
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair) < 0) {
        perror("Failed to create socket pair");
        return -1;
    }
    
    // fork子进程
    pid = fork();
    if (pid < 0) {
        perror("Failed to fork optimizer process");
        close(socket_pair[0]);
        close(socket_pair[1]);
        return -1;
    }
    
    if (pid > 0) {
        // 父进程
        close(socket_pair[1]);
        
        // 等待子进程准备就绪
        int status;
        waitpid(pid, &status, WNOHANG | WUNTRACED);
        
        return socket_pair[0];
    }
    
    // 子进程 - 优化器进程
    close(socket_pair[0]);
    
    // 清理文件描述符
    cleanup_file_descriptors(socket_pair[1]);
    
    // 重定向socket fd到标准位置
    if (socket_pair[1] < 3) {
        int new_fd = dup2(socket_pair[1], 3);
        if (new_fd < 0) {
            perror("Failed to move socket fd");
            exit(1);
        }
        close(socket_pair[1]);
        socket_pair[1] = new_fd;
    }
    
    // 重定向标准输入输出到/dev/null或日志文件
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    log_fd = open("/var/log/exagear/optimizer.log", 
                  O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (log_fd >= 0) {
        dup2(log_fd, STDOUT_FILENO);
        dup2(log_fd, STDERR_FILENO);
        close(log_fd);
    }
    
    // 创建新会话
    if (setsid() < 0) {
        perror("Failed to create new session");
        exit(1);
    }
    
    // 再次fork以完全脱离终端
    pid = fork();
    if (pid < 0) {
        perror("Failed to fork daemon");
        exit(1);
    }
    if (pid > 0) {
        exit(0); // 父进程退出
    }
    
    // 切换到根目录
    chdir("/");
    
    // 执行优化器程序
    char fd_str[16];
    snprintf(fd_str, sizeof(fd_str), "%d", socket_pair[1]);
    
    char *argv[] = {
        "optimizer",
        "--opt_fd",
        fd_str,
        NULL
    };
    
    execv("/path/to/optimizer", argv);
    
    // 如果execv失败
    perror("Failed to exec optimizer");
    exit(1);
}
