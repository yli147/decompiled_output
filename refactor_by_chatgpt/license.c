#include <stdint.h>
#include <stdbool.h>

// 常量定义
#define BUFFER_SIZE 16
#define MAX_ITERATIONS 16
#define HASH_CONSTANTS_COUNT 4
#define CRYPTO_BLOCK_SIZE 64

// 数据结构定义
typedef struct {
    uint8_t data[BUFFER_SIZE];
    bool flags[BUFFER_SIZE];
} ProcessorState;

typedef struct {
    uint32_t constants[HASH_CONSTANTS_COUNT];
    uint32_t (*operation)(uint32_t, uint32_t, uint32_t);
} HashContext;

// 全局状态获取函数
static uintptr_t get_base_address() {
    return ((uintptr_t)&get_base_address & 0xfffffffffff80000);
}

// 重构函数1：条件数据复制
void copy_conditional_data(uint8_t *output) {
    uintptr_t base = get_base_address();
    
    for (int i = 0; i < BUFFER_SIZE; i++) {
        if (*(char *)(base + 0x75420 + i) < 0) {
            output[i] = *(uint8_t *)(base + 0x75440 + i);
        }
    }
}

// 重构函数2：浮点数处理
void process_floating_point(int mode, uint32_t rounding_mode) {
    uintptr_t base = get_base_address();
    uint32_t control_reg = *(uint32_t *)(base + 0x75208);
    
    // 保存并修改控制寄存器
    uint32_t saved_fpcr = control_reg & 0xfeffffff;
    // 设置浮点控制寄存器
    // fpcr = saved_fpcr;
    
    double value = *(double *)(base + 0x75420);
    
    // 处理非正规化数
    if ((*(uintptr_t *)(base + 0x751f8) & 0x40) != 0 && 
        ((*(uint64_t *)&value & 0x7ff0000000000000) == 0) &&
        ((*(uint64_t *)&value & 0xfffff00000000) != 0 || 
         (*(uint64_t *)&value & 0xffffffff) != 0)) {
        value = (double)((*(uint64_t *)&value & 0x80000000) << 32);
    }
    
    // 根据舍入模式处理
    long result;
    switch (rounding_mode) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
            result = (long)value;
            break;
        default:
            result = 0;
            break;
    }
    
    *(long *)(base + 0x75420) = result;
    
    // 如果不是单精度模式，处理第二个值
    if (mode == 0) {
        double value2 = *(double *)(base + 0x75428);
        
        // 处理非正规化数
        if ((*(uintptr_t *)(base + 0x751f8) & 0x40) != 0 && 
            ((*(uint64_t *)&value2 & 0x7ff0000000000000) == 0) &&
            ((*(uint64_t *)&value2 & 0xfffff00000000) != 0 || 
             (*(uint64_t *)&value2 & 0xffffffff) != 0)) {
            value2 = (double)((*(uint64_t *)&value2 & 0x80000000) << 32);
        }
        
        switch (rounding_mode) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
                result = (long)value2;
                break;
            default:
                result = 0;
                break;
        }
        
        *(long *)(base + 0x75428) = result;
    }
    
    // 恢复控制寄存器
    uint32_t final_fpcr = (control_reg & 0xfe000000) | 
                          (control_reg & 0xffffff) | 
                          ((control_reg >> 24 & 1) << 24);
    // fpcr = final_fpcr;
}

// 重构函数3：位操作函数
uint32_t bitwise_select(uint32_t selector, uint32_t a, uint32_t b) {
    return (a ^ b) & selector ^ b;
}

uint32_t bitwise_xor(uint32_t a, uint32_t b, uint32_t c) {
    return a ^ b ^ c;
}

uint32_t bitwise_majority(uint32_t a, uint32_t b, uint32_t c) {
    return (a | b) & c | a & b;
}

// 重构函数4：哈希处理主函数
void process_hash_round(uint32_t round_type) {
    uintptr_t base = get_base_address();
    
    // 选择操作函数和常量
    int constant;
    uint32_t (*operation)(uint32_t, uint32_t, uint32_t);
    
    uint32_t type_index = (round_type & 3) - 1;
    if (type_index < 3) {
        constant = *(int *)(0x8010002241a0 + type_index * 4);
        operation = ((uint32_t (*)(uint32_t, uint32_t, uint32_t)*)0x8010002241b0)[type_index];
    } else {
        constant = 0x5a827999;
        operation = bitwise_select;
    }
    
    // 加载状态
    uint32_t a = *(uint32_t *)(base + 0x75420);
    uint32_t b = *(uint32_t *)(base + 0x75424);
    uint32_t c = *(uint32_t *)(base + 0x75428);
    uint32_t d = *(uint32_t *)(base + 0x7542c);
    
    // 加载数据块
    int data[BUFFER_SIZE];
    for (int i = 0; i < BUFFER_SIZE; i++) {
        data[i] = *(int *)(base + 0x75440 + i * 4);
    }
    
    // 执行哈希轮次
    for (int i = 0; i < BUFFER_SIZE; i++) {
        uint32_t f = operation(c, b, a);
        uint32_t temp = ((d << 5) | (d >> 27)) + data[i] + f + constant;
        
        // 更新状态
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;
    }
    
    // 保存结果
    *(uint32_t *)(base + 0x75420) = a;
    *(uint32_t *)(base + 0x75424) = b;
    *(uint32_t *)(base + 0x75428) = c;
    *(uint32_t *)(base + 0x7542c) = d;
}

// 重构函数5：数据扩展
void expand_data() {
    uintptr_t base = get_base_address();
    
    uint32_t w13 = *(uint32_t *)(base + 0x75448);
    uint32_t w8 = *(uint32_t *)(base + 0x7542c);
    uint32_t w2 = *(uint32_t *)(base + 0x75420);
    uint32_t w0 = *(uint32_t *)(base + 0x75440);
    
    uint32_t temp = w13 ^ w8 ^ w2 ^ w0;
    uint32_t expanded = (temp << 1) | (temp >> 31);
    
    *(uint32_t *)(base + 0x7542c) = expanded;
    
    // 继续处理其他数据
    uint32_t w14 = *(uint32_t *)(base + 0x75444);
    uint32_t w9 = *(uint32_t *)(base + 0x75428);
    uint32_t w3 = *(uint32_t *)(base + 0x75424);
    uint32_t w1 = *(uint32_t *)(base + 0x75440);
    
    temp = w14 ^ w9 ^ w3 ^ w1;
    *(uint32_t *)(base + 0x75420) = (temp << 1) | (temp >> 31);
    
    temp = w14 ^ w9;
    *(uint32_t *)(base + 0x75428) = (temp << 1) | (temp >> 31);
    
    temp = w1 ^ w3;
    *(uint32_t *)(base + 0x75424) = (temp << 1) | (temp >> 31);
}

// 重构函数6：SHA-256风格的处理
void process_sha256_style() {
    uintptr_t base = get_base_address();
    
    uint32_t a = *(uint32_t *)(base + 0x75420);
    uint32_t b = *(uint32_t *)(base + 0x75424);
    uint32_t c = *(uint32_t *)(base + 0x75428);
    uint32_t d = *(uint32_t *)(base + 0x7542c);
    uint32_t e = *(uint32_t *)(base + 0x75444);
    uint32_t f = *(uint32_t *)(base + 0x75448);
    uint32_t g = *(uint32_t *)(base + 0x7544c);
    uint32_t h = *(uint32_t *)(base + 0x75460);
    
    // SHA-256 风格的 Sigma 函数
    uint32_t s1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t temp1 = h + s1 + ch + *(uint32_t *)(base + 0x75460) + a;
    
    uint32_t s0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
    uint32_t maj = (a & b) | ((a | b) & c);
    uint32_t temp2 = s0 + maj;
    
    // 更新状态
    *(uint32_t *)(base + 0x75420) = temp1 + c;
    *(uint32_t *)(base + 0x75424) = temp1 + temp2;
    *(uint32_t *)(base + 0x75428) = temp2;
    *(uint32_t *)(base + 0x7542c) = temp1 + temp2;
}

// 重构函数7：内存操作
void secure_memory_operation(void *ptr, size_t size, uint64_t param) {
    uintptr_t base = get_base_address();
    
    if ((size >> 2 & 0x3fffffff) == 0) {
        return;
    }
    
    uintptr_t end_addr = (uintptr_t)ptr + 8 + (size >> 2 & 0x3fffffff) - 1;
    uintptr_t current = (uintptr_t)ptr + 4;
    uintptr_t boundary = (uintptr_t)ptr + 3;
    
    while (current <= end_addr) {
        uint32_t data = *(uint32_t *)(current - (uintptr_t)ptr + base + 0x7541c);
        
        // 根据段选择器处理内存访问
        uint32_t segment = param & 0xff;  // 假设段选择器在低8位
        uintptr_t segment_base;
        uint64_t segment_limit;
        
        switch (segment) {
            case 0:
                segment_base = *(uintptr_t *)(base + 0x75158);
                segment_limit = *(uint64_t *)(base + 0x75160);
                break;
            case 1:
                segment_base = *(uintptr_t *)(base + 0x75170);
                segment_limit = *(uint64_t *)(base + 0x75178);
                break;
            case 2:
                segment_base = *(uintptr_t *)(base + 0x75190);
                segment_limit = *(uint64_t *)(base + 0x75198);
                break;
            case 3:
                segment_base = *(uintptr_t *)(base + 0x751a8);
                segment_limit = *(uint64_t *)(base + 0x751b0);
                break;
            case 4:
                segment_base = *(uintptr_t *)(base + 0x751c0);
                segment_limit = *(uint64_t *)(base + 0x751c8);
                break;
            case 5:
                segment_base = *(uintptr_t *)(base + 0x751d8);
                segment_limit = *(uint64_t *)(base + 0x751e0);
                break;
            default:
                // 错误处理
                return;
        }
        
        // 检查段限制
        if (boundary > segment_limit) {
            // 触发段违例
            // trigger_segment_fault(0xd, 0);
            return;
        }
        
        // 执行内存写入
        *(uint32_t *)(current - 4 + segment_base) = data;
        
        current += 4;
        boundary += 4;
    }
}

// 重构函数8：许可证验证系统
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t expiration;
    uint32_t key_count;
    uint16_t *keys;
} LicenseHeader;

bool validate_license() {
    char exe_path[4097];
    char license_path[4097];
    
    // 获取可执行文件路径
    ssize_t path_len = readlink("/proc/self/exe", exe_path + 1, 4096);
    if (path_len <= 0 || path_len >= 4096) {
        return false;
    }
    
    exe_path[path_len + 1] = '\0';
    
    // 找到最后一个'/'并截断路径
    char *last_slash = strrchr(exe_path + 1, '/');
    if (!last_slash) {
        return false;
    }
    *last_slash = '\0';
    
    // 尝试不同的许可证文件
    for (int key_id = 0; key_id < 3; key_id++) {
        snprintf(license_path, sizeof(license_path), 
                "%s/../lic/secondary%08x.key", exe_path + 1, key_id);
        
        FILE *license_file = fopen(license_path, "r");
        if (!license_file) {
            continue;
        }
        
        LicenseHeader header;
        if (fread(&header, 1, sizeof(header), license_file) != sizeof(header)) {
            fclose(license_file);
            continue;
        }
        
        // 验证魔数
        if (header.magic != 0x6c544255) {  // "UBTl"
            fclose(license_file);
            continue;
        }
        
        // 检查版本和过期时间
        if (header.version != 0 || header.key_count >= 14) {
            fclose(license_file);
            continue;
        }
        
        // 检查当前时间
        time_t current_time;
        time(&current_time);
        if ((uint64_t)current_time > header.expiration) {
            fclose(license_file);
            continue;
        }
        
        // 读取密钥数据
        if (header.key_count > 0) {
            header.keys = malloc(header.key_count * sizeof(uint16_t) * 2);
            if (!header.keys) {
                fclose(license_file);
                continue;
            }
            
            size_t keys_size = header.key_count * sizeof(uint16_t) * 2;
            if (fread(header.keys, 1, keys_size, license_file) != keys_size) {
                free(header.keys);
                fclose(license_file);
                continue;
            }
            
            // 验证密钥格式
            bool valid_format = false;
            for (int i = 0; i < header.key_count; i++) {
                if (header.keys[i] == 0x202) {  // 找到格式标记
                    valid_format = true;
                    break;
                }
            }
            
            if (valid_format) {
                // 进一步验证许可证内容
                // 这里应该包含具体的许可证验证逻辑
                free(header.keys);
                fclose(license_file);
                return true;
            }
            
            free(header.keys);
        }
        
        fclose(license_file);
    }
    
    return false;
}

// 主要的许可证检查函数
bool check_license_and_hardware() {
    // 首先验证许可证文件
    if (!validate_license()) {
        printf("License validation failed.\n");
        return false;
    }
    
    // 检查系统时间
    time_t current_time;
    time(&current_time);
    
    if (current_time < 0x51d0c680) {  // 某个基准时间
        printf("Your system time is not valid.\nExiting.\n");
        return false;
    }
    
    if (current_time > 0x5e5afb01) {  // 过期时间
        printf("Sorry, demo license is no longer valid.\nExiting.\n");
        return false;
    }
    
    printf("License check passed.\n");
    return true;
}

// 程序入口点
int main() {
    if (!check_license_and_hardware()) {
        return 3;
    }
    
    printf("Application started successfully.\n");
    return 0;
}
