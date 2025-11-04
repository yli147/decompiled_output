// communication.c
#include <pthread.h>

typedef struct {
    pthread_mutex_t mutex;
    int socket_fd;
    int state; // 0: 未初始化, 1: 初始化中, 2: 就绪, 3: 已发送
    volatile int shutdown_flag;
} optimizer_comm_t;

static optimizer_comm_t g_comm = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .socket_fd = -1,
    .state = 0,
    .shutdown_flag = 0
};

/**
 * 向优化器发送数据
 * @param data 要发送的数据
 * @return 1成功，0失败
 */
int send_to_optimizer(const void *data) {
    pthread_mutex_lock(&g_comm.mutex);
    
    // 检查是否需要初始化
    if (g_comm.state == 0) {
        g_comm.socket_fd = create_optimizer_process();
        if (g_comm.socket_fd < 0) {
            g_comm.state = 0;
            pthread_mutex_unlock(&g_comm.mutex);
            return 0;
        }
        g_comm.state = 2; // 就绪状态
    }
    
    if (g_comm.state != 2) {
        pthread_mutex_unlock(&g_comm.mutex);
        return 0;
    }
    
    // 检查关闭标志
    if (g_comm.shutdown_flag) {
        g_comm.shutdown_flag = 0;
        pthread_mutex_unlock(&g_comm.mutex);
        return 0;
    }
    
    // 发送数据
    const char *buffer = (const char *)data;
    size_t total_size = *((uint32_t *)((char *)data + 8)); // 假设大小在偏移8处
    size_t sent = 0;
    
    while (sent < total_size) {
        ssize_t result = write(g_comm.socket_fd, buffer + sent, total_size - sent);
        if (result < 0) {
            if (errno == EINTR) continue;
            perror("Failed to write to optimizer socket");
            pthread_mutex_unlock(&g_comm.mutex);
            return 0;
        }
        sent += result;
    }
    
    if (sent == total_size) {
        g_comm.state = 3; // 已发送状态
        pthread_mutex_unlock(&g_comm.mutex);
        return 1;
    }
    
    pthread_mutex_unlock(&g_comm.mutex);
    return 0;
}

/**
 * 关闭与优化器的通信
 */
void shutdown_optimizer_comm(void) {
    pthread_mutex_lock(&g_comm.mutex);
    g_comm.shutdown_flag = 1;
    if (g_comm.socket_fd >= 0) {
        close(g_comm.socket_fd);
        g_comm.socket_fd = -1;
    }
    g_comm.state = 0;
    pthread_mutex_unlock(&g_comm.mutex);
}
