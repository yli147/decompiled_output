// region_receiver.c
#include <pthread.h>
#include <errno.h>

typedef struct {
    pthread_mutex_t mutex;
    int socket_fd;
    int state;
    volatile int shutdown_flag;
    uint32_t region_size;
    uint32_t data_size;
    uint32_t entry_count;
} region_receiver_t;

static region_receiver_t g_receiver = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .socket_fd = -1,
    .state = 2, // 就绪状态
    .shutdown_flag = 0
};

/**
 * 从socket读取指定大小的数据
 * @param fd socket文件描述符
 * @param buffer 缓冲区
 * @param size 要读取的字节数
 * @return 成功返回1，失败返回0
 */
static int read_full_data(int fd, void *buffer, size_t size) {
    size_t total_read = 0;
    char *buf = (char *)buffer;
    
    while (total_read < size) {
        ssize_t bytes_read;
        do {
            bytes_read = read(fd, buf + total_read, size - total_read);
        } while (bytes_read == -1 && errno == EINTR);
        
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                errno = 0; // EOF
            }
            return 0;
        }
        
        total_read += bytes_read;
    }
    
    return (total_read == size) ? 1 : 0;
}

/**
 * 接收优化区域数据
 * @return 成功返回1，失败返回0
 */
char receive_region_data(void) {
    pthread_mutex_lock(&g_receiver.mutex);
    
    int fd = g_receiver.socket_fd;
    
    // 读取区域大小
    if (!read_full_data(fd, &g_receiver.region_size, sizeof(uint32_t))) {
        goto error_exit;
    }
    
    // 读取区域数据
    extern char region_data_buffer[];
    if (!read_full_data(fd, region_data_buffer, g_receiver.region_size)) {
        goto error_exit;
    }
    
    // 读取数据大小
    if (!read_full_data(fd, &g_receiver.data_size, sizeof(uint32_t))) {
        goto error_exit;
    }
    
    // 计算条目数量
    extern uint32_t region_entry_count;
    region_entry_count = g_receiver.data_size / 0x28; // 每个条目40字节
    
    // 读取条目数据
    extern char region_entries[];
    if (!read_full_data(fd, region_entries, g_receiver.data_size)) {
        goto error_exit;
    }
    
    // 读取附加数据大小
    uint32_t additional_size;
    if (!read_full_data(fd, &additional_size, sizeof(uint32_t))) {
        goto error_exit;
    }
    
    // 读取附加数据
    extern char additional_data[];
    if (!read_full_data(fd, additional_data, additional_size)) {
        goto error_exit;
    }
    
    // 更新状态
    g_receiver.state = 5; // 数据接收完成
    
    if (!g_receiver.shutdown_flag) {
        pthread_mutex_unlock(&g_receiver.mutex);
        
        printf("Region Received (%d bytes)!\n", g_receiver.region_size);
        
        // 处理接收到的区域数据
        char result = process_region_data(region_entries, region_entry_count, 
                                        additional_data, additional_size);
        
        const char *status = result ? "" : "Not ";
        extern uint32_t current_region_id;
        printf("Region %d %sAdded to TCache.\n", current_region_id, status);
        
        pthread_mutex_lock(&g_receiver.mutex);
        g_receiver.state = 2; // 重置为就绪状态
        pthread_mutex_unlock(&g_receiver.mutex);
        
        return result;
    }
    
error_exit:
    g_receiver.state = 2;
    g_receiver.shutdown_flag = 0;
    pthread_mutex_unlock(&g_receiver.mutex);
    return 0;
}
