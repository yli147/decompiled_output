// 重构后的代码

#include <stdint.h>
#include <stdbool.h>

// ========== 函数1: 地址查找和验证 ==========
typedef struct {
    void *start_addr;
    void *end_addr;
    size_t size;
    void *data_ptr;
} MemoryRegion;

typedef struct {
    uint32_t magic;
    uint32_t version;
    // 其他字段...
} RegionHeader;

/**
 * 在内存区域中查找指定地址的信息
 * @param target_addr 目标地址
 * @param region_info 输出区域信息
 * @param region_data 输出区域数据
 * @return 0表示成功，其他值表示错误
 */
uint64_t find_address_in_regions(uint32_t *target_addr, long *region_info, uint64_t *region_data) {
    // 检查地址范围
    if (target_addr > (uint32_t*)0x8010039fffff && target_addr < (uint32_t*)0x80100ba00000) {
        *region_info = 0;
        return call_function_036060();
    }

    uint8_t *region_base = (uint8_t*)0x80100397d640;
    
    // 检查区域数量
    if (global_region_count == 0) {
        *region_data = 0;
        trigger_software_breakpoint(1000, 0x8010001ed9cc);
        return 0;
    }

    // 遍历所有区域
    for (uint64_t i = 0; i < global_region_count; i++) {
        MemoryRegion *current_region = (MemoryRegion*)(region_base + i * 0x68);
        
        // 检查地址是否在当前区域范围内
        if (target_addr >= current_region->start_addr && 
            target_addr < current_region->end_addr) {
            
            *region_data = (uint64_t)(region_base + 0x18 + i * 0x68);
            
            // 执行详细的地址查找逻辑
            return perform_detailed_address_lookup(target_addr, current_region, region_info);
        }
        
        region_base += 0x68;
    }
    
    *region_info = 0;
    return 0;
}

// ========== 函数2: 地址验证 ==========
/**
 * 检查地址是否有效
 * @param addr 要检查的地址
 * @return true表示地址有效
 */
bool is_valid_address(uint64_t addr) {
    // 检查特殊地址范围
    if ((addr & 0xfffffffffffff000) == 0xffffffffff600000) {
        return true;
    }
    
    // 检查全局地址范围
    return (global_addr_start <= addr && addr < global_addr_end);
}

// ========== 函数3: 系统调用包装 ==========
/**
 * 执行系统调用的包装函数
 * @param param1 参数1
 * @param param2 参数2
 * @return 系统调用结果
 */
uint64_t system_call_wrapper(int param1, int param2) {
    uint64_t result = perform_syscall(0x3e, (long)param1, 0, (long)param2);
    
    if (result > 0xfffffffffffff000) {
        int *errno_ptr = get_errno_location();
        *errno_ptr = -(int)result;
        return 0xffffffffffffffff;
    }
    
    return result;
}

// ========== 函数4: 缓冲区刷新 ==========
typedef struct {
    void *next;
    int count;
    void *buffer_list;
} BufferManager;

/**
 * 刷新所有缓冲区
 * @return 0表示成功，-1表示失败
 */
uint64_t flush_all_buffers(void) {
    BufferManager **manager_ptr = (BufferManager**)&global_buffer_manager;
    uint64_t result = 0;
    
    do {
        BufferManager *current = *manager_ptr;
        if (current == NULL) {
            return result;
        }
        
        if (current->count > 0) {
            void **buffer_ptr = (void**)current->buffer_list;
            void **end_ptr = buffer_ptr + current->count;
            
            // 处理每个缓冲区
            do {
                if (should_flush_buffer(buffer_ptr)) {
                    if (flush_single_buffer(buffer_ptr) < 0) {
                        result = 0xffffffff;
                        mark_buffer_error(buffer_ptr);
                        break;
                    }
                }
                buffer_ptr = (void**)((char*)buffer_ptr + 0x93 * sizeof(void*));
            } while (buffer_ptr != end_ptr);
        }
        
        manager_ptr = (BufferManager**)current->next;
    } while (true);
}

// ========== 函数5: 浮点数转字符串 ==========
/**
 * 将浮点数转换为字符串
 * @param value 浮点数值
 * @param buffer 输出缓冲区
 * @param precision 精度
 * @param exponent 指数输出
 * @param sign 符号输出
 * @param end_ptr 结束位置输出
 * @param format_flag 格式标志
 * @return 转换后的字符串指针
 */
char* double_to_string(double value, char *buffer, int precision, 
                      int *exponent, uint32_t *sign, long *end_ptr, char format_flag) {
    *exponent = 0;
    uint32_t high_bits = (uint32_t)((uint64_t)value >> 32);
    
    // 处理特殊值
    if (is_special_float_value(value, high_bits)) {
        return handle_special_float_value(value, buffer, exponent, sign, end_ptr);
    }
    
    // 处理符号
    bool is_negative = (value < 0.0);
    if (is_negative) {
        value = -value;
    }
    *sign = (uint32_t)is_negative;
    
    // 规范化数值
    int exp = *exponent;
    if (value >= 1.0) {
        do {
            exp++;
            value /= 10.0;
        } while (value >= 1.0);
    } else if (value < 0.1 && value >= 0.1) {
        // 已经在正确范围内
    } else {
        do {
            value *= 10.0;
            exp--;
        } while (value < 0.1);
    }
    *exponent = exp;
    
    // 转换数字
    return convert_normalized_double(value, buffer, precision, exponent, sign, end_ptr, format_flag);
}

// ========== 函数6: 内存清零 ==========
/**
 * 高效的内存清零函数
 * @param ptr 内存指针
 * @param size 大小
 */
void optimized_memset_zero(void *ptr, long size) {
    if (size == 0) return;
    
    uint64_t *qword_ptr = (uint64_t*)ptr;
    uint64_t *end_ptr = (uint64_t*)((char*)ptr + size);
    
    // 处理未对齐的开始部分
    if (((uintptr_t)ptr & 7) != 0) {
        uint8_t *byte_ptr = (uint8_t*)ptr;
        size_t align_bytes = 8 - ((uintptr_t)ptr & 7);
        
        for (size_t i = 0; i < align_bytes && byte_ptr < (uint8_t*)end_ptr; i++) {
            *byte_ptr++ = 0;
        }
        qword_ptr = (uint64_t*)byte_ptr;
    }
    
    // 批量清零8字节对齐的部分
    while (qword_ptr + 1 <= end_ptr) {
        *qword_ptr++ = 0;
    }
    
    // 处理剩余字节
    uint8_t *remaining_ptr = (uint8_t*)qword_ptr;
    while (remaining_ptr < (uint8_t*)end_ptr) {
        *remaining_ptr++ = 0;
    }
}

// ========== 函数7: 调试信息输出 ==========
/**
 * 输出调试信息和堆栈跟踪
 */
void output_debug_info_and_stack_trace(/* 参数列表 */) {
    // 初始化调试输出缓冲区
    char debug_buffer[0x118];
    optimized_memset_zero(debug_buffer, sizeof(debug_buffer));
    
    // 设置输出格式
    setup_debug_output_format();
    
    // 输出堆栈跟踪
    output_stack_trace();
    
    // 输出寄存器状态
    output_register_state();
    
    // 输出内存映射
    output_memory_maps();
}

// ========== 函数8: 区域处理 ==========
/**
 * 处理原始区域数据
 */
void process_raw_regions(void) {
    FILE *region_file = open_region_file("/path/to/regions");
    if (!region_file) {
        fatal_error("Cannot open region file");
    }
    
    // 获取文件大小
    fseek(region_file, 0, SEEK_END);
    long file_size = ftell(region_file);
    fseek(region_file, 0, SEEK_SET);
    
    // 处理每个区域
    while (ftell(region_file) < file_size) {
        RegionHeader header;
        fread(&header, sizeof(header), 1, region_file);
        
        if (header.magic != REGION_MAGIC_NUMBER) {
            fatal_error("Invalid region magic number");
        }
        
        process_region_by_version(&header, region_file);
    }
    
    fclose(region_file);
}

// ========== 函数9: 崩溃处理 ==========
/**
 * 处理程序崩溃，生成崩溃报告
 */
void handle_program_crash(/* 信号参数 */) {
    // 创建崩溃转储文件
    char crash_filename[256];
    generate_crash_filename(crash_filename, sizeof(crash_filename));
    
    FILE *crash_file = fopen(crash_filename, "w");
    if (crash_file) {
        // 输出崩溃信息
        output_crash_header(crash_file);
        output_host_call_stack(crash_file);
        output_guest_context(crash_file);
        output_memory_maps(crash_file);
        output_environment_info(crash_file);
        
        fclose(crash_file);
        printf("Crash dump saved to \"%s\"\n", crash_filename);
    }
    
    // 生成minidump
    generate_minidump();
}

// ========== 函数10-12: 辅助函数 ==========
/**
 * 主机栈管理
 */
uint64_t manage_host_stack(uint64_t param1, uint64_t param2) {
    acquire_stack_mutex();
    
    uint64_t result = allocate_or_free_stack_memory(param1, param2);
    
    release_stack_mutex();
    return result;
}

/**
 * 生成指令
 */
void generate_instruction_type1(long context, uint32_t op1, uint32_t op2, uint32_t op3) {
    uint32_t instruction = 0x92800000 | 
                          ((op2 & 0xffff) << 5) | 
                          ((op1 & 3) << 29) | 
                          (op3 & 0x1f);
    
    emit_instruction(context, instruction);
}

void generate_instruction_type2(long context, uint32_t op1, uint32_t op2, 
                               uint32_t op3, uint32_t op4, int op5, 
                               uint32_t op6, uint32_t op7) {
    uint32_t size_bits = (op1 & 0xff) == 0 ? 4 : 8;
    
    uint32_t instruction = 0x28000000 |
                          (op1 << 31) |
                          ((op2 & 1) << 22) |
                          ((op7 & 0x1f) << 10) |
                          (op6 & 0x1f) |
                          ((op4 & 0x1f) << 5) |
                          encode_immediate(op5, size_bits) << 15 |
                          ((op3 & 3) << 23);
    
    emit_instruction(context, instruction);
}

// ========== DWARF解析相关函数 ==========
/**
 * 解析DWARF调用帧信息
 */
bool parse_dwarf_cfi(long *fde_info, long *cie_info, long pc_value, uint32_t *reg_states) {
    // 实现DWARF CFI解析逻辑
    return execute_cfi_instructions(fde_info, cie_info, pc_value, reg_states);
}

/**
 * 复制24字节数据（优化版本）
 */
void copy_24_bytes_optimized(uint64_t *dest, uint64_t *src) {
    if (((uintptr_t)dest | (uintptr_t)src) & 7) {
        // 未对齐的情况
        handle_unaligned_copy(dest, src, 24);
    } else {
        // 8字节对齐的快速复制
        dest[0] = src[0];
        dest[1] = src[1];
        dest[2] = src[2];
    }
}


// 继续重构后的代码

#include <stdint.h>
#include <stdbool.h>

// ========== ARM64指令生成器 ==========

/**
 * 生成ARM64指令类型3 - 带立即数的算术指令
 * @param context 代码生成上下文
 * @param op1 操作码1
 * @param op2 操作码2
 * @param op3 操作码3
 * @param shift_amount 移位量
 * @param reg1 寄存器1
 * @param reg2 寄存器2
 */
void generate_arm64_arithmetic_imm(long context, uint32_t op1, uint32_t op2,
                                  uint32_t op3, int shift_amount, uint32_t reg1, uint32_t reg2) {
    uint32_t instruction = 0xa8000000 |
                          ((op1 & 1) << 22) |
                          ((reg2 & 0x1f) << 10) |
                          (reg1 & 0x1f) |
                          ((op3 & 0x1f) << 5) |
                          ((shift_amount >> 3 & 0x7f) << 15) |
                          ((op2 & 3) << 23);

    emit_instruction_to_context(context, instruction);
}

/**
 * 生成ARM64加载/存储指令
 * @param context 代码生成上下文
 * @param op1 操作码1
 * @param op2 操作码2
 * @param reg1 目标寄存器
 * @param reg2 基址寄存器
 * @param reg3 偏移寄存器
 */
void generate_arm64_load_store(long context, uint32_t op1, uint32_t op2,
                              uint32_t reg1, uint32_t reg2, uint32_t reg3) {
    uint32_t instruction = 0x40000000 | 0x11000000 |
                          (op1 << 31) |
                          ((op2 & 1) << 29) |
                          ((reg2 & 0xfff) << 10) |
                          ((reg2 >> 31) << 22) |
                          (reg3 & 0x1f) |
                          ((reg1 & 0x1f) << 5);

    emit_instruction_to_context(context, instruction);
}

/**
 * 生成ARM64移位指令
 * @param context 代码生成上下文
 * @param reg_src 源寄存器
 * @param is_64bit 是否为64位操作
 * @param reg1 寄存器1
 * @param reg2 寄存器2
 * @param reg_dst 目标寄存器
 */
void generate_arm64_shift_instruction(long context, uint32_t reg_src, uint32_t is_64bit,
                                     uint32_t reg1, uint32_t reg2, uint32_t reg_dst) {
    uint32_t reg_encoded = reg_src;

    // 特殊处理寄存器16
    if (is_64bit && reg_src == 0x10) {
        reg_encoded = 1;
    }

    // 位反转操作用于编码
    uint32_t reversed = bit_reverse_32(reg_encoded);
    uint32_t shift_type = is_64bit ? 3 : 1;

    uint32_t instruction = 0x39000000 |
                          ((is_64bit & 1) << 26) |
                          ((reg2 >> bit_count_leading_zeros(reversed)) & 0xfff) << 10 |
                          (shift_type << 22) |
                          (reg_dst & 0x1f) |
                          ((reg1 & 0x1f) << 5);

    emit_instruction_to_context(context, instruction);
}

/**
 * 生成ARM64比较指令
 * @param context 代码生成上下文
 * @param reg_src 源寄存器
 * @param op_type 操作类型
 * @param reg1 寄存器1
 * @param reg2 寄存器2
 * @param reg_dst 目标寄存器
 */
void generate_arm64_compare_instruction(long context, uint32_t reg_src, uint32_t op_type,
                                       uint32_t reg1, uint32_t reg2, uint32_t reg_dst) {
    uint32_t reversed = bit_reverse_32(reg_src);

    // 特殊处理寄存器16
    if (reg_src == 0x10) {
        op_type |= 2;
        reg_src = 1;
    }

    uint32_t instruction = 0x3d000000 |
                          (bit_count_leading_zeros(reversed) << 30) |
                          ((reg2 >> bit_count_leading_zeros(bit_reverse_32(reg_src))) & 0xfff) << 10 |
                          ((op_type & 3) << 22) |
                          (reg_dst & 0x1f) |
                          ((reg1 & 0x1f) << 5);

    emit_instruction_to_context(context, instruction);
}

// ========== 内存管理相关函数 ==========

/**
 * 清理内存区域中的过期条目
 * @param region_list 区域列表指针
 * @param unused_param 未使用参数
 * @param threshold 清理阈值
 */
void cleanup_memory_regions(uint64_t *region_list, uint64_t unused_param, uint64_t threshold) {
    void *current_node = find_memory_node_by_threshold(threshold);

    if (current_node == NULL || get_node_threshold(current_node) > threshold) {
        return;
    }

    // 遍历并清理符合条件的节点
    void *next_node = find_next_node_in_tree(current_node);

    if (*region_list != 0) {
        uint64_t node_offset = get_node_offset(current_node);

        // 清理关联的内存块
        cleanup_associated_memory_blocks(region_list, current_node, node_offset);
    }

    // 从树中移除节点
    remove_node_from_tree(region_list, current_node);

    // 继续清理后续节点
    if (next_node != NULL) {
        cleanup_remaining_nodes(region_list, next_node, threshold);
    }
}

/**
 * 系统调用包装 - 绑定操作
 * @param fd 文件描述符
 * @param addr 地址参数
 */
void syscall_bind_wrapper(int fd, uint64_t addr) {
    uint64_t result = perform_syscall(0x23, (long)fd, addr, 0);

    if (result > 0xfffff000) {
        int *errno_ptr = get_errno_location();
        *errno_ptr = -(int)result;
    }
}

// ========== 浮点数比较和转换 ==========

/**
 * 比较两个扩展精度浮点数
 * @param val1 第一个浮点数
 * @param exp1 第一个指数
 * @param val2 第二个浮点数
 * @param exp2 第二个指数
 * @param quiet_nan_flag 静默NaN标志
 * @param status_ptr 状态指针
 * @return 比较结果
 */
uint64_t compare_extended_float(uint64_t val1, uint32_t exp1, uint64_t val2, uint32_t exp2,
                               int quiet_nan_flag, long status_ptr) {
    uint32_t exp1_masked = exp1 & 0x7fff;
    uint32_t exp2_masked = exp2 & 0x7fff;

    // 检查特殊值
    FloatClass class1 = classify_float_value(val1, exp1_masked);
    FloatClass class2 = classify_float_value(val2, exp2_masked);

    // 处理NaN情况
    if (class1 == FLOAT_NAN || class2 == FLOAT_NAN) {
        if (!quiet_nan_flag) {
            set_float_exception(status_ptr, FLOAT_EXCEPTION_INVALID);
            return 2;
        }
        set_float_exception(status_ptr, FLOAT_EXCEPTION_INVALID);
        return 2;
    }

    // 处理符号
    bool sign1 = (exp1 >> 15) != 0;
    bool sign2 = (exp2 >> 15) != 0;

    // 处理零值
    if (class1 == FLOAT_ZERO && class2 == FLOAT_ZERO) {
        return 0; // 相等
    }

    // 处理符号不同的情况
    if (sign1 != sign2) {
        return sign1 ? 0xffffffff : 1;
    }

    // 规范化并比较
    uint64_t norm_val1 = val1, norm_val2 = val2;
    uint32_t norm_exp1 = exp1_masked, norm_exp2 = exp2_masked;

    if (class1 == FLOAT_DENORMAL) {
        normalize_float(&norm_val1, &norm_exp1);
    }
    if (class2 == FLOAT_DENORMAL) {
        normalize_float(&norm_val2, &norm_exp2);
    }

    // 比较指数和尾数
    if (norm_exp1 == norm_exp2) {
        if (norm_val1 == norm_val2) return 0;
        return (sign1 == 0) ? (norm_val1 > norm_val2 ? 1 : 0xffffffff) :
                             (norm_val1 > norm_val2 ? 0xffffffff : 1);
    }

    return (sign1 == 0) ? (norm_exp1 > norm_exp2 ? 1 : 0xffffffff) :
                         (norm_exp1 > norm_exp2 ? 0xffffffff : 1);
}

/**
 * 将扩展精度浮点数转换为32位整数
 * @param mantissa 尾数
 * @param exponent 指数
 * @param status_ptr 状态指针
 * @return 转换后的整数
 */
uint64_t convert_float_to_int32(uint64_t mantissa, uint32_t exponent, long status_ptr) {
    uint32_t sign = (exponent >> 15) & 1;
    uint32_t exp_value = exponent & 0x7fff;

    // 处理零值
    if (exp_value == 0) {
        bool is_zero = (mantissa == 0);
        uint64_t result = is_zero ? 0 : 1;

        int rounding_mode = get_rounding_mode(status_ptr);
        if (rounding_mode == 0) {
            return result + 0x40;
        }
        return result + 0x40;
    }

    // 处理特殊值
    if (mantissa >= 0 && exp_value == 0x7fff) {
        set_float_exception(status_ptr, FLOAT_EXCEPTION_INVALID);
        return 0x80000000;
    }

    // 计算移位量
    uint32_t shift_amount = 0x4037 - exp_value;
    if (shift_amount < 1) shift_amount = 1;

    if (exp_value == 0x7fff) {
        if ((mantissa & 0x7fffffffffffffff) != 0) {
            sign = 0; // NaN情况
        }
    } else if (shift_amount > 0x3f) {
        // 下溢情况
        int rounding_mode = get_rounding_mode(status_ptr);
        uint64_t result = (mantissa != 0) ? 1 : 0;
        return rounding_mode == 0 ? result + 0x40 : result + 0x40;
    }

    // 执行移位和舍入
    uint64_t shifted_value = perform_right_shift_with_sticky(mantissa, shift_amount);
    return round_to_int32(shifted_value, sign, status_ptr);
}

// ========== 信号处理 ==========

/**
 * 设置信号掩码
 * @param signal_mask 信号掩码
 */
void set_signal_mask(uint64_t signal_mask) {
    uint64_t filtered_mask = signal_mask;
    uint64_t current_mask = signal_mask;
    uint32_t mask_count = 0;

    // 过滤不可屏蔽的信号
    for (uint64_t i = 0; i < 64; i++) {
        uint64_t bit_mask = global_signal_mask >> (i & 0x3f);
        uint32_t bit_set = (uint32_t)bit_mask & 1;

        if (bit_set == 0) {
            uint64_t clear_bit = 1UL << (i & 0x3f);
            current_mask &= ~clear_bit;
            mask_count = bit_set;
        }
    }

    uint64_t final_mask = mask_count != 0 ? current_mask : signal_mask;

    // 获取当前上下文
    uint64_t *context_ptr = get_current_thread_context();
    context_ptr[0x91] = 0; // 清除信号标志

    // 执行系统调用设置信号掩码
    uint64_t result = perform_syscall(0x87, 2, &final_mask, 0, 8);

    if (result >= 0xfffffffffffff001) {
        int *errno_ptr = get_errno_location();
        *errno_ptr = -(int)result;
        fatal_error("Failed to set signal mask");
    }

    if ((int)result != 0) {
        fatal_error("Failed to set signal mask");
    }
}

// ========== 代码生成辅助函数 ==========

/**
 * 生成带寄存器编码的指令
 * @param context 代码生成上下文
 * @param opcode 操作码
 * @param sub_opcode 子操作码
 * @param param1 参数1
 * @param param2 参数2
 * @param param3 参数3
 * @param reg_encoding 寄存器编码
 */
void generate_encoded_instruction(long context, uint16_t opcode, uint16_t sub_opcode,
                                 uint32_t param1, uint32_t param2, uint32_t param3,
                                 uint32_t reg_encoding) {
    // 计算寄存器编码
    uint32_t encoded_reg = bit_reverse_32(reg_encoding);
    uint32_t reg_bits = bit_count_leading_zeros(encoded_reg) & 7;

    // 构建指令
    InstructionBuilder builder;
    init_instruction_builder(&builder, context);

    set_instruction_opcode(&builder, opcode);
    set_instruction_params(&builder, param1, param2, param3);
    set_instruction_register_encoding(&builder, reg_bits);
    set_instruction_sub_opcode(&builder, sub_opcode);

    emit_built_instruction(&builder);
}

// ========== Poll事件处理 ==========

/**
 * 格式化poll事件标志
 * @param buffer 输出缓冲区
 * @param events 事件标志
 */
void format_poll_events(long *buffer, uint16_t events) {
    uint32_t event_mask = (uint32_t)(short)events;

    // 定义事件标志映射
    static const struct {
        uint32_t flag;
        const char *name;
    } poll_flags[] = {
        {0x0001, "POLLIN|"},
        {0x0002, "POLLPRI|"},
        {0x0004, "POLLOUT|"},
        {0x0008, "POLLERR|"},
        {0x0010, "POLLHUP|"},
        {0x0020, "POLLNVAL|"},
        {0x0040, "POLLRDNORM|"},
        {0x0080, "POLLRDBAND|"},
        {0x0100, "POLLWRNORM|"},
        {0x0200, "POLLWRBAND|"},
        {0x0400, "POLLMSG|"},
        {0x1000, "POLLREMOVE|"},
        {0x2000, "POLLRDHUP|"}
    };

    bool has_flags = false;

    // 输出匹配的标志
    for (size_t i = 0; i < sizeof(poll_flags) / sizeof(poll_flags[0]); i++) {
        if (event_mask & poll_flags[i].flag) {
            append_to_buffer(buffer, poll_flags[i].name);
            has_flags = true;
        }
    }

    // 处理未知标志
    uint32_t unknown_flags = event_mask & 0xffffc800;
    if (unknown_flags != 0) {
        append_formatted_to_buffer(buffer, "0x%x", unknown_flags);
        return;
    }

    // 如果没有标志，输出0
    if (!has_flags) {
        append_to_buffer(buffer, "0");
        return;
    }

    // 移除最后的'|'
    remove_trailing_separator(buffer);
}

/**
 * 更新poll事件结果
 * @param input_events 输入事件
 * @param result_events 结果事件指针
 */
void update_poll_events(uint32_t input_events, uint16_t *result_events) {
    uint32_t filtered_events = input_events & (~(*result_events));
    uint16_t new_events = result_events[1] | 0x8080;

    // 根据输入事件更新结果
    if ((filtered_events & 0x3f) == 0) {
        new_events = result_events[1];
    }

    if ((input_events & 1) == 0) {
        if ((input_events >> 2) & 1) {
            result_events[1] = new_events | 4;
            return;
        }
        if ((input_events >> 1) & 1) {
            new_events |= 2;
            result_events[1] = new_events;
            if (((filtered_events & 0xffff) >> 1) & 1) {
                return;
            }
        }
        new_events |= (uint16_t)input_events;
        result_events[1] = new_events;
        filtered_events = input_events >> 5;
    } else {
        new_events |= (uint16_t)input_events;
        result_events[1] = new_events;
        filtered_events = input_events >> 6;
    }

    // 特殊处理某些事件组合
    if ((filtered_events & 1) && ((input_events >> 9) & 1) == 0) {
        result_events[1] = new_events & 0xfdff;
    }
}

// ========== 辅助函数 ==========

/**
 * 32位整数位反转
 */
static uint32_t bit_reverse_32(uint32_t value) {
    value = ((value & 0xaaaaaaaa) >> 1) | ((value & 0x55555555) << 1);
    value = ((value & 0xcccccccc) >> 2) | ((value & 0x33333333) << 2);
    value = ((value & 0xf0f0f0f0) >> 4) | ((value & 0x0f0f0f0f) << 4);
    value = ((value & 0xff00ff00) >> 8) | ((value & 0x00ff00ff) << 8);
    return (value >> 16) | (value << 16);
}

/**
 * 计算前导零个数
 */
static uint32_t bit_count_leading_zeros(uint32_t value) {
    return __builtin_clz(value);
}

/**
 * 向代码上下文发射指令
 */
static void emit_instruction_to_context(long context, uint32_t instruction) {
    if (*(int *)(context + 0x30) == 1) {
        *(uint32_t *)(*(long *)(context + 0x40) + (ulong)*(uint32_t *)(context + 0x48)) = instruction;
        *(int *)(context + 0x48) += 4;
    } else {
        *(uint32_t *)(*(long *)(context + 0x10) + (ulong)*(uint32_t *)(context + 0x18)) = instruction;
        *(int *)(context + 0x18) += 4;
    }
}

// 指令解码和处理函数
void decode_and_execute_instruction(int *processor_state, uint *instruction_ptr)
{
    uint instruction = *instruction_ptr;
    uint flags = processor_state[0x17];
    bool is_thumb_mode = (flags >> 9) & 1;
    bool has_extension = flags & 0x2000;

    if (!is_thumb_mode) {
        // ARM 模式指令处理
        if (!has_extension) {
            // 标准 ARM 指令集
            process_arm_instructions(processor_state, instruction);
        } else {
            // 扩展 ARM 指令集
            process_extended_arm_instructions(processor_state, instruction);
        }
    } else {
        // Thumb 模式指令处理
        process_thumb_instructions(processor_state, instruction, has_extension);
    }

    // 更新处理器状态
    update_processor_flags(processor_state, flags);
}

// ARM 指令处理
void process_arm_instructions(int *processor_state, uint instruction)
{
    for (int i = 1; i < 0x4a; i++) {
        if ((instruction & instruction_masks[i].mask) == instruction_masks[i].pattern) {
            processor_state[0x16] = i;
            int result = arm_instruction_handlers[i-1](processor_state);

            if (*processor_state == 0x1c3 || result != 2) {
                return;
            }

            *processor_state = 0x1c3;
            return;
        }
    }

    // 未识别的指令
    *processor_state = 0x1c3;
}

// 扩展 ARM 指令处理
void process_extended_arm_instructions(int *processor_state, uint instruction)
{
    for (int i = 0xb2; i < 0xf8; i++) {
        if ((instruction & extended_masks[i-0xb2].mask) == extended_masks[i-0xb2].pattern) {
            processor_state[0x16] = i;
            int result = extended_handlers[i-0xb2](processor_state);

            if (*processor_state == 0x41b || result != 2) {
                return;
            }

            *processor_state = 0x41b;
            return;
        }
    }

    *processor_state = 0x41b;
}

// Thumb 指令处理
void process_thumb_instructions(int *processor_state, uint instruction, bool has_extension)
{
    ushort thumb_inst = (ushort)instruction;
    uint full_instruction = (uint)thumb_inst;

    // 检查是否为 32 位 Thumb 指令
    if ((thumb_inst & 0xe000) == 0xe000 && (thumb_inst & 0xf800) != 0xe000) {
        full_instruction = CONCAT22(thumb_inst, *(ushort*)((long)&instruction + 2));

        if (has_extension) {
            process_extended_thumb_instructions(processor_state, full_instruction);
        } else {
            process_standard_thumb_instructions(processor_state, full_instruction);
        }
    } else {
        // 16 位 Thumb 指令
        if (has_extension) {
            process_extended_thumb_instructions(processor_state, full_instruction);
        } else {
            process_16bit_thumb_instructions(processor_state, full_instruction);
        }
    }
}

// 计算指令长度
int calculate_instruction_length(uint param_1)
{
    if ((param_1 >> 0x15) & 1) {
        // 长指令格式
        return (param_1 & 0x4000) ? 0x40 : 0x20;
    } else {
        // 短指令格式
        return (param_1 & 0x4000) ? 0x20 : 0x10;
    }
}

// 检查指令有效性
uint validate_instruction(ulong param_1)
{
    uint valid = (uint)(param_1 >> 2) & 1;
    if (param_1 & 1) {
        valid = 0;  // 无效指令
    }
    return valid;
}

// 存储指令到缓冲区
void store_instruction_to_buffer(long context, undefined8 *instruction,
                                char opcode, ulong address)
{
    uint buffer_index = *(uint *)(context + 0x3538);

    // 存储指令数据
    *(undefined8 *)(context + (ulong)buffer_index * 8 + 0x18) = *instruction;
    *(uint *)(context + 0x3538) = buffer_index + 1;

    // 生成相应的机器码
    generate_machine_code(context, 0x73, buffer_index & 0xffff | 0x1050000, 0x10011);

    // 处理地址计算
    uint reversed_opcode = reverse_bits(opcode);
    emit_branch_instruction(context, 0, address & 0xffffffff, 0,
                           calculate_branch_offset(reversed_opcode) | 0x40000,
                           0x10012);
}

// 位反转辅助函数
uint reverse_bits(char value)
{
    uint result = ((int)value & 0xaaaaaaaa) >> 1 | ((int)value & 0x55555555) << 1;
    result = (result & 0xcccccccc) >> 2 | (result & 0x33333333) << 2;
    result = (result & 0xf0f0f0f0) >> 4 | (result & 0xf0f0f0f) << 4;
    result = (result & 0xff00ff00) >> 8 | (result & 0xff00ff) << 8;
    return LZCOUNT(result >> 0x10 | result << 0x10);
}

// 生成内存操作指令
void generate_memory_operation(long context, long *operands, char size,
                              byte offset, ulong base_addr, int reg_index, long target_addr)
{
    long source_addr = *operands + (ulong)offset;
    ulong effective_addr = (target_addr - (base_addr & 0xffffffff)) + source_addr;

    // 根据操作大小调整地址
    ulong final_addr = effective_addr;
    if (size != 8) {
        final_addr = effective_addr & 0xffff;
        if (size == 4) {
            final_addr = effective_addr & 0xffffffff;
        }
    }

    // 处理操作数配置
    uint config = *(uint *)(operands + 2);
    bool swap_operands = config & 1;
    uint src_reg = (config >> 2) & 1;
    uint dst_reg = (config >> 3) & 1;

    if (swap_operands) {
        // 交换源和目标
        long temp = final_addr + (base_addr & 0xffffffff);
        final_addr = source_addr;
        source_addr = temp;
        uint temp_reg = src_reg;
        src_reg = dst_reg;
        dst_reg = temp_reg;
    }

    // 生成指令序列
    emit_load_store_pair(context, source_addr, final_addr, reg_index, src_reg, dst_reg);
}

// 生成加载/存储对指令
void emit_load_store_pair(long context, long addr1, long addr2, int reg, uint src, uint dst)
{
    uint buffer_index = *(uint *)(context + 0x3538);
    short reg_pair = (short)buffer_index;

    // 存储地址对
    *(long *)(context + (ulong)buffer_index * 8 + 0x18) = addr2;
    *(long *)(context + (ulong)(buffer_index + 1) * 8 + 0x18) = addr1;
    *(uint *)(context + 0x3538) = buffer_index + 2;

    // 生成指令
    emit_instruction_with_regs(context, reg_pair + 1, 0x105, reg_pair, 0x105,
                              (short)reg, 4, src, dst);
}

// 处理操作数编码
uint encode_operand(ushort *operand_data, long context, long config, uint op_type)
{
    uint reg_val, size_val, type_val;
    int operand_size = 8;

    if (op_type == 5) {
        // 立即数操作
        setup_immediate_operand(operand_data, context, 0x37);
        reg_val = (uint)(byte)operand_data[1];
        size_val = (uint)*operand_data;
        type_val = (uint)*(byte*)((long)operand_data + 3);
    } else if (op_type == 4) {
        // 寄存器操作
        setup_register_operand(operand_data, context, 0x34);
        reg_val = (uint)(byte)operand_data[1];
        size_val = (uint)*operand_data;
        type_val = (uint)*(byte*)((long)operand_data + 3);
    } else {
        // 其他操作类型
        handle_other_operand_types(operand_data, context, config, op_type);
        reg_val = (uint)(byte)operand_data[1];
        size_val = (uint)*operand_data;
        type_val = (uint)*(byte*)((long)operand_data + 3);
    }

    return size_val | (reg_val << 0x10) | (type_val << 0x18);
}

// 生成条件分支
void generate_conditional_branch(long context, long config, long target, uint condition)
{
    uint buffer_index = *(uint *)(context + 0x3544);
    *(uint *)(context + 0x3544) = buffer_index + 1;
    uint branch_reg = buffer_index & 0xffff;

    // 设置分支目标
    *(undefined2 *)(context + (ulong)buffer_index * 2 + 0x4424) = 0;

    // 生成分支指令
    emit_branch_with_condition(context, 0xc, condition, 0x10026, branch_reg | 0x20000);
}

// 生成算术运算指令
void generate_arithmetic_operation(long context, uint op_code, uint src1, uint src2,
                                  uint dst, int operation_type)
{
    // 位操作用于指令编码
    uint encoded_src1 = reverse_and_count_bits(src1);
    uint instruction = encode_arithmetic_instruction(op_code, src2, dst, operation_type, encoded_src1);

    emit_raw_instruction(context, instruction);
}

// 编码算术指令
uint encode_arithmetic_instruction(uint opcode, uint src, uint dst, int type, uint encoded_val)
{
    return 0xe000000 | (dst & 0x1f) | ((src & 0x1f) << 5) |
           ((encoded_val & 0x1f) << 0x10) | ((type & 0xf) << 0xc);
}

// 发射原始指令
void emit_raw_instruction(long context, uint instruction)
{
    if (*(int *)(context + 0x30) == 1) {
        *(uint *)(*(long *)(context + 0x40) + (ulong)*(uint *)(context + 0x48)) = instruction;
        *(int *)(context + 0x48) += 4;
    } else {
        *(uint *)(*(long *)(context + 0x10) + (ulong)*(uint *)(context + 0x18)) = instruction;
        *(int *)(context + 0x18) += 4;
    }
}

// 函数调用处理
void handle_function_call(uint function_id, long *context)
{
    // 保存当前状态
    save_processor_state(context);

    // 设置调用参数
    setup_call_parameters(context, function_id);

    // 执行函数调用
    execute_function_call(context, function_id);

    // 恢复状态
    restore_processor_state(context);
}

// 添加指令到队列
void add_instruction_to_queue(long context, undefined2 opcode, undefined4 operand1,
                             undefined4 operand2, undefined4 operand3,
                             undefined4 operand4, undefined1 flags)
{
    uint queue_index = *(uint *)(context + 0x10);
    long queue_base = *(long *)(context + 8);
    *(uint *)(context + 0x10) = queue_index + 1;

    long instruction_slot = queue_base + (ulong)queue_index * 0x28;

    // 填充指令数据
    *(undefined2 *)(instruction_slot + 0x1c) = opcode;
    *(undefined4 *)(instruction_slot) = operand1;
    *(undefined4 *)(instruction_slot + 4) = operand2;
    *(undefined4 *)(instruction_slot + 8) = operand3;
    *(undefined4 *)(instruction_slot + 0xc) = operand4;
    *(undefined1 *)(instruction_slot + 0x1e) = 0;
    *(undefined1 *)(instruction_slot + 0x1f) = flags;

    // 处理指令
    process_queued_instruction(context);
}

// 添加复杂指令到队列（带位操作编码）
void add_complex_instruction_to_queue(long context, undefined2 opcode, undefined2 sub_opcode,
                                     undefined4 operand1, undefined4 operand2,
                                     uint param6, uint param7, uint param8)
{
    uint queue_index = *(uint *)(context + 0x10);
    long queue_base = *(long *)(context + 8);
    *(uint *)(context + 0x10) = queue_index + 1;

    long instruction_slot = queue_base + (ulong)queue_index * 0x28;

    // 对参数进行位反转编码
    uint encoded_param6 = reverse_bits_32(param6);
    uint encoded_param7 = reverse_bits_32(param7);
    uint encoded_param8 = reverse_bits_32(param8);

    // 填充指令数据
    *(undefined2 *)(instruction_slot + 0x1c) = opcode;
    *(undefined4 *)(instruction_slot) = operand1;
    *(undefined8 *)(instruction_slot + 4) = 0;  // 清零中间字段
    *(undefined4 *)(instruction_slot + 0xc) = operand2;
    *(undefined1 *)(instruction_slot + 0x1e) = 0;
    *(undefined2 *)(instruction_slot + 0x1f) = sub_opcode;

    // 编码位操作参数
    *(uint *)(instruction_slot + 0x21) =
        ((uint)LZCOUNT(encoded_param6 >> 0x10 | encoded_param6 << 0x10) & 7) << 0x10 | 0xffff |
        ((uint)LZCOUNT(encoded_param7 >> 0x10 | encoded_param7 << 0x10) & 7) << 0x13 |
        ((uint)LZCOUNT(encoded_param8 >> 0x10 | encoded_param8 << 0x10) & 7) << 0x16 |
        *(uint *)(instruction_slot + 0x21) & 0xfe000000;

    // 处理指令
    process_queued_instruction(context, instruction_slot);
}

// 内存映射管理函数
void manage_memory_mapping(ulong *mapping_info, undefined8 path, ulong offset)
{
    // 清理现有映射
    if (*mapping_info != 0) {
        uint result = system_call_munmap(0xd7, *mapping_info, mapping_info[1]);
        if (result > 0xfffff000) {
            int *error_ptr = get_errno_location();
            *error_ptr = -result;
        }
        *mapping_info = 0;
        mapping_info[1] = 0;
    }

    // 打开文件
    uint fd = system_call_openat(0x38, 0xffffffffffffff9c, path, 0, 0);
    if (fd >= 0xfffff001) {
        int *error_ptr = get_errno_location();
        *error_ptr = -fd;
        return;
    }

    if (fd != 0xffffffff) {
        char stat_buffer[48];
        uint stat_result = system_call_fstat(0x4f, (long)(int)fd, "", stat_buffer, 0x1000);

        if (stat_result < 0xfffff001) {
            if (stat_result != 0xffffffff) {
                ulong file_size = *(ulong *)(stat_buffer + 0x30);  // st_size

                if (file_size >= 0 && offset < file_size) {
                    ulong map_size = file_size - offset;

                    // 创建内存映射
                    ulong mapped_addr = system_call_mmap(0xde, 0, map_size, 1, 2,
                                                        (long)(int)fd, offset << 0xc);

                    if (mapped_addr < 0xfffffffffffff001) {
                        close_file(fd);

                        if (mapped_addr == 0) {
                            map_size = 0;
                        }

                        *mapping_info = mapped_addr;
                        mapping_info[1] = map_size;
                        return;
                    }

                    int *error_ptr = get_errno_location();
                    *error_ptr = -(int)mapped_addr;
                    close_file(fd);
                    return;
                }
            }
        } else {
            int *error_ptr = get_errno_location();
            *error_ptr = -stat_result;
        }

        close_file(fd);
    }
}

// 内存写入验证函数
void validate_memory_write(undefined8 *buffer_info, ulong position, long src, long size)
{
    // 验证源指针
    if (src == 0) {
        abort_with_message("src/client/minidump_file_writer.cc", 0x153,
                          "UBT: assertion \"src\" failed.\nBreakPad");
    }

    // 验证大小
    if (size == 0) {
        abort_with_message("src/client/minidump_file_writer.cc", 0x154,
                          "UBT: assertion \"size\" failed.\nBreakPad");
    }

    // 验证写入范围
    if (size + (position & 0xffffffff) > (ulong)*(uint *)(buffer_info + 1) + buffer_info[2]) {
        abort_with_message("src/client/minidump_file_writer.cc", 0x155,
                          "UBT: assertion \"pos + size <= position_ + size_\" failed.\nBreakPad");
    }

    // 执行内存复制
    memory_copy(*buffer_info, src, size);
}

// 字符串连接函数
bool concatenate_strings(char *str1, long str2_info, char *output)
{
    char current_char = *str1;
    if (current_char == '\0') {
        *output = '\0';
        return validate_and_append_suffix(str2_info, output, 0);
    }

    ulong str1_len = 0;
    ulong output_pos = 0;

    // 复制第一个字符串
    do {
        ulong next_pos = output_pos + 1;
        str1_len++;

        if (next_pos > 0xfff) {
            // 字符串太长，跳过剩余字符
            if (str1[str1_len] != '\0') {
                while (str1[str1_len] != '\0') {
                    str1_len++;
                }
            }
            output[output_pos] = '\0';
            return str1_len <= 0xfff;
        }

        output[output_pos] = current_char;
        current_char = str1[str1_len];
        output_pos = next_pos;
    } while (current_char != '\0');

    output[output_pos] = '\0';

    return validate_and_append_suffix(str2_info, output, str1_len);
}

// 验证并追加后缀
bool validate_and_append_suffix(long str2_info, char *output, ulong current_len)
{
    // 验证当前长度
    ulong total_len = current_len;
    char *output_end = output + current_len;

    // 添加第二个字符串的内容
    char suffix_char = *(char *)(str2_info + 0x29);
    if (suffix_char == '\0') {
        *output_end = '\0';
        return total_len < 0x1000;
    }

    long suffix_offset = 0;
    ulong append_pos = 0;

    while (suffix_char != '\0') {
        ulong next_pos = append_pos + 1;
        suffix_offset++;

        if (0x1000 - current_len <= next_pos) {
            // 超出缓冲区，跳过剩余字符
            while (*(char *)(str2_info + 0x29 + suffix_offset) != '\0') {
                suffix_offset++;
            }
            break;
        }

        output_end[append_pos] = suffix_char;
        suffix_char = *(char *)(str2_info + 0x29 + suffix_offset);
        append_pos = next_pos;
    }

    output_end[append_pos] = '\0';
    total_len += suffix_offset;

    return total_len < 0x1000;
}

// Linux 转储器处理函数
void process_linux_dumper_mapping(long *dumper, undefined8 *mapping_data, char is_member,
                                 uint mapping_id, undefined8 callback)
{
    // 验证成员映射ID
    if (is_member && *(uint *)(dumper + 0x10c) <= mapping_id) {
        abort_with_message("src/client/linux/minidump_writer/linux_dumper.cc", 0x134,
                          "UBT: assertion \"!member || mapping_id < mappings_.getCount()\" failed.\nBreakPad");
    }

    // 检查特殊路径
    if (*(char *)((long)mapping_data + 0x29) == '/') {
        // 跳过 /dev/ 路径
        if (is_dev_path((char *)((long)mapping_data + 0x29))) {
            return;
        }
    } else if (*(char *)((long)mapping_data + 0x29) == 'l') {
        // 处理 linux-gate.so
        if (is_linux_gate_so((char *)((long)mapping_data + 0x29))) {
            handle_linux_gate_mapping(dumper, mapping_data, callback);
            return;
        }
    }

    // 构建完整路径
    char full_path[4351];
    if (!build_full_path(dumper[2], mapping_data, full_path + 0xff)) {
        return;
    }

    // 处理删除标记的文件
    if (is_deleted_file(full_path + 0xff)) {
        handle_deleted_file_mapping(dumper, mapping_data, full_path, is_member, mapping_id);
    }

    // 创建内存映射并处理
    ulong mapping_addr = 0;
    ulong mapping_size = 0;

    create_file_mapping(&mapping_addr, full_path + 0xff, mapping_data[4]);

    if (mapping_addr != 0 && mapping_size > 3) {
        bool success = process_elf_mapping(mapping_addr, callback);

        if (is_member && success) {
            update_mapping_info(dumper, mapping_id, mapping_data);
        }

        unmap_memory(mapping_addr, mapping_size);
    }
}

// 检查是否为 /dev/ 路径
bool is_dev_path(char *path)
{
    return (path[1] == 'd' && path[2] == 'e' && path[3] == 'v' && path[4] == '/');
}

// 检查是否为 linux-gate.so
bool is_linux_gate_so(char *path)
{
    const char *pattern = "linux-gate.so";
    long i = 1;

    while (pattern[i] == path[i]) {
        i++;
        if (pattern[i] == '\0') {
            return true;
        }
    }
    return false;
}

// 处理 Linux gate 映射
void handle_linux_gate_mapping(long *dumper, undefined8 *mapping_data, undefined8 callback)
{
    long current_pid = dumper[1];
    int system_pid = system_call_getpid(0xac);

    undefined8 gate_data;
    if ((int)current_pid == system_pid) {
        gate_data = *mapping_data;
    } else {
        gate_data = read_process_memory(dumper + 6, mapping_data[1]);

        // 处理不同的内存读取方式
        if (*(code **)(*dumper + 0x30) == process_memory_default) {
            handle_default_memory_read();
        } else {
            (**(code **)(*dumper + 0x30))(dumper, gate_data, (int)dumper[1],
                                         *mapping_data, mapping_data[1]);
        }
    }

    process_gate_data(gate_data, callback);
}

// 数组写入函数
void write_array_element(undefined8 buffer, int base_offset, int element_size,
                        int index, undefined8 data)
{
    if (element_size != 2) {
        abort_with_message("../breakpad/src/client/minidump_file_writer-inl.h", 0x47,
                          "UBT: assertion \"allocation_state_ == ARRAY\" failed.\nBreakPad");
    }

    // 写入数组元素
    memory_copy(buffer, base_offset + index * 0xc, data, 0xc);
}

// 文件内容读取和格式化
void read_and_format_file(long *buffer_info, char *filename, undefined8 format_string)
{
    ulong fd = system_call_openat(0x38, 0xffffffffffffff9c, filename, 0, 0);
    uint fd_int = (uint)fd;

    if (fd_int < 0xfffff001 && (int)fd_int >= 0) {
        char read_buffer[4096];
        ulong bytes_read = system_call_read(fd, read_buffer, 0x1000);

        if (bytes_read == 0xffffffffffffffff) {
            write_error_message(2, "Error: Can't read: ", filename);
        } else {
            // 格式化并写入缓冲区
            format_and_append_to_buffer(buffer_info, format_string,
                                       bytes_read & 0xffffffff, read_buffer);
        }

        close_file(fd & 0xffffffff);
    } else {
        write_error_message(2, "Error: Can't open: ", filename);
    }
}

// 获取保存的寄存器值
undefined8 get_saved_register_value(undefined8 context, long frame_info, uint *register_info)
{
    uint restore_type = *register_info;

    switch (restore_type) {
        case 1:
            return 0;  // 未定义

        case 2:
            return *(undefined8 *)(frame_info + *(long *)(register_info + 2));

        case 4:
            return call_cfa_function(context, register_info[2]);

        case 5: {
            undefined8 *value_ptr = (undefined8 *)get_memory_location(
                *(undefined8 *)(register_info + 2), context, frame_info);
            return *value_ptr;
        }

        case 6:
            return get_memory_location(*(undefined8 *)(register_info + 2), context, frame_info);

        default:
            log_error("libunwind: %s - %s\n", "getSavedRegister",
                     "unsupported restore location for register");
            abort_with_message("DwarfInstructions.hpp", 0x67, "libunwind: abort\n");
    }
}

// DWARF CIE 解析函数
char *parse_dwarf_cie(uint *cie_data, long *cie_info)
{
    *cie_info = (long)cie_data;
    *(undefined4 *)(cie_info + 3) = 0xff00;  // 初始化寄存器状态
    cie_info[4] = 0;  // 清零增强数据
    cie_info[5] = 0;  // 清零代码对齐
    *(undefined2 *)(cie_info + 6) = 0;  // 清零标志

    uint *data_ptr = cie_data + 1;
    ulong cie_length = (ulong)*cie_data;
    long cie_end = cie_length + (long)data_ptr;

    // 处理扩展长度格式
    if (cie_length == 0xffffffff) {
        cie_length = *(ulong *)(cie_data + 1);
        data_ptr = cie_data + 3;
        cie_end = (long)data_ptr + cie_length;
    }

    if (cie_length == 0) {
        return NULL;  // 空 CIE
    }

    // 验证 CIE ID
    uint cie_id = *data_ptr;
    if (cie_id != 0) {
        return "CIE ID is not zero";
    }

    // 检查版本
    uint version = data_ptr[1];
    if ((version & 0xfd) != 1) {
        return "CIE version is not 1 or 3";
    }

    // 解析增强字符串
    char *augmentation_ptr = (char *)((long)data_ptr + 5);
    char *string_end = augmentation_ptr + 1;

    while (*augmentation_ptr != '\0') {
        augmentation_ptr = string_end;
        string_end++;
    }

    // 解析代码和数据对齐因子
    undefined4 code_align = parse_uleb128(&string_end, cie_end);
    *(undefined4 *)(cie_info + 5) = code_align;

    undefined4 data_align = parse_sleb128(&string_end, cie_end);
    *(undefined4 *)((long)cie_info + 0x2c) = data_align;

    // 解析返回地址寄存器
    ulong return_reg;
    if (version == 1) {
        string_end++;
        return_reg = (ulong)(byte)*string_end;
    } else {
        return_reg = parse_uleb128(&string_end, cie_end);
    }

    if (return_reg > 0xfe) {
        abort_with_message("DwarfParser.hpp", 0x160,
                          "UBT: assertion \"raReg < 255 && \"return address register too large\"\" failed.\nlibunwind: assert\n");
    }

    *(char *)((long)cie_info + 0x32) = (char)return_reg;

    // 处理增强数据
    if (*(byte *)((long)data_ptr + 5) == 0x7a) {
        parse_augmentation_data(&string_end, cie_end, cie_info);
    }

    cie_info[1] = cie_end - *cie_info;
    cie_info[2] = (long)string_end;

    return NULL;  // 成功
}

// 解析增强数据
void parse_augmentation_data(char **data_ptr, long end_ptr, long *cie_info)
{
    parse_uleb128(data_ptr, end_ptr);  // 跳过增强数据长度

    byte *aug_ptr = (byte *)((long)*data_ptr - 1);
    char *current_ptr = *data_ptr;

    while (*aug_ptr != 0) {
        switch (*aug_ptr) {
            case 0x52:  // 'R' - FDE 编码
                *(byte *)(cie_info + 3) = (byte)parse_byte(&current_ptr, 1);
                break;

            case 0x4c:  // 'L' - LSDA 编码
                *(byte *)((long)cie_info + 0x19) = (byte)parse_byte(&current_ptr, 1);
                break;

            case 0x50:  // 'P' - 个性例程
                {
                    byte encoding = (byte)parse_byte(&current_ptr, 1);
                    *(byte *)((long)cie_info + 0x1a) = encoding;
                    *(char *)((long)cie_info + 0x1b) = (char)current_ptr - (char)cie_info;

                    long personality = parse_encoded_value(&current_ptr, end_ptr, encoding, 0);
                    cie_info[4] = personality;
                }
                break;

            case 0x53:  // 'S' - 信号帧
                *(undefined1 *)(cie_info + 6) = 1;
                break;

            case 0x7a:  // 'z' - 有增强数据
                *(undefined1 *)((long)cie_info + 0x31) = 1;
                break;
        }

        aug_ptr++;
    }
}

// 查找 FDE 函数
bool find_fde_for_pc(ulong pc, uint *fde_table, long table_size, uint *start_fde,
                    ulong *fde_info, long cie_info)
{
    if (start_fde == NULL) {
        start_fde = fde_table;
    }

    uint *table_end = (uint *)(table_size + (long)fde_table);
    if (table_size == -1) {
        table_end = (uint *)0xffffffffffffffff;
    }

    if (start_fde >= table_end) {
        return false;
    }

    // 搜索 FDE 表
    ulong *current_entry = (ulong *)(start_fde + 1);
    ulong entry_length = (ulong)*start_fde;

    while (entry_length != 0) {
        uint *current_fde = start_fde;
        uint *next_fde = (uint *)(entry_length + (long)current_entry);

        if ((uint)*current_entry != 0) {
            // 找到有效的 FDE
            uint *cie_ptr = (uint *)((long)current_entry - (ulong)(uint)*current_entry);

            if (fde_table <= cie_ptr && cie_ptr < table_end) {
                char *parse_result = parse_dwarf_cie(cie_ptr, cie_info);
                if (parse_result == NULL) {
                    // 解析 FDE 内容
                    current_entry = (ulong *)((long)current_entry + 4);
                    ulong pc_begin = parse_encoded_value(&current_entry, next_fde,
                                                        *(undefined1 *)(cie_info + 0x18), 0);
                    long pc_range = parse_encoded_value(&current_entry, next_fde,
                                                       *(byte *)(cie_info + 0x18) & 0xf, 0);

                    if (pc_begin <= pc && pc <= pc_begin + pc_range) {
                        // 找到匹配的 FDE
                        setup_fde_info(fde_info, current_fde, next_fde, current_entry,
                                      pc_begin, pc_range, cie_info);
                        return true;
                    }
                }
            }
        }

        if (table_end <= next_fde) {
            return false;
        }

        // 移动到下一个条目
        current_entry = (ulong *)(next_fde + 1);
        entry_length = (ulong)*next_fde;
        start_fde = next_fde;
    }

    return false;
}

// 设置 FDE 信息
void setup_fde_info(ulong *fde_info, uint *fde_start, uint *fde_end, ulong *instructions,
                   ulong pc_begin, long pc_range, long cie_info)
{
    fde_info[5] = 0;  // 清零 LSDA

    ulong *inst_ptr = instructions;

    // 处理增强数据
    if (*(char *)(cie_info + 0x31) != '\0') {
        long aug_length = parse_uleb128(&instructions, fde_end);
        ulong *aug_end = (ulong *)(aug_length + (long)instructions);

        if (*(byte *)(cie_info + 0x19) != 0xff) {
            long lsda_length = parse_encoded_value(&instructions, fde_end,
                                                  *(byte *)(cie_info + 0x19) & 0xf, 0);
            if (lsda_length != 0) {
                instructions = inst_ptr;
                ulong lsda_addr = parse_encoded_value(&instructions, fde_end,
                                                     *(undefined1 *)(cie_info + 0x19), 0);
                fde_info[5] = lsda_addr;
            }
        }

        inst_ptr = aug_end;
    }

    // 设置 FDE 信息结构
    *fde_info = (ulong)fde_start;
    fde_info[1] = (long)fde_end - (long)fde_start;
    fde_info[2] = (ulong)inst_ptr;
    fde_info[3] = pc_begin;
    fde_info[4] = pc_begin + pc_range;
}

// EH 帧头解析
undefined8 parse_eh_frame_header(char *header, undefined8 base_addr, undefined8 *header_info)
{
    char *data_ptr = header + 1;

    // 检查版本
    if (*header != '\x01') {
        log_error("libunwind: Unsupported .eh_frame_hdr version\n");
        return 0;
    }

    data_ptr = header + 4;
    char eh_frame_ptr_enc = header[1];
    char fde_count_enc = header[2];
    *(char *)(header_info + 3) = header[3];  // 表编码

    // 解析 eh_frame_ptr
    undefined8 eh_frame_ptr = parse_encoded_value(&data_ptr, base_addr, eh_frame_ptr_enc, header);
    *header_info = eh_frame_ptr;

    // 解析 FDE 计数
    undefined8 fde_count = 0;
    if (fde_count_enc != -1) {
        fde_count = parse_encoded_value(&data_ptr, base_addr, fde_count_enc, header);
    }
    header_info[1] = fde_count;
    header_info[2] = data_ptr;  // 表开始位置

    return 1;
}

// 内存访问函数（写入字节）
void write_memory_byte(long *memory_context, undefined1 value)
{
    long memory_descriptor = *memory_context;
    uint flags = *(uint *)(memory_descriptor + 0x30);

    if ((flags & 1) == 0) {
        // 直接内存访问
        uint reg_index = *(uint *)(memory_descriptor + 8) & 0x7fffffff;

        if (*(uint *)(memory_descriptor + 8) + 0x7ffffffc < 4) {
            *(undefined1 *)(memory_context[1] + (ulong)(reg_index - 4) * 8 + 0x21) = value;
        } else {
            *(undefined1 *)(memory_context[1] + (ulong)reg_index * 8 + 0x20) = value;
        }
        return;
    }

    // 计算有效地址
    undefined1 *effective_addr = calculate_effective_address(memory_context);

    // 根据内存类型执行写入
    int memory_type = *(int *)(memory_descriptor + 0x2c);
    if (memory_type - 4U < 2) {
        // 检查内存保护
        if (check_memory_protection()) {
            *effective_addr = value;
            return;
        }
    }

    // 使用系统调用进行内存写入
    perform_system_memory_write(effective_addr, value, memory_type);
}

// 计算有效地址
undefined1 *calculate_effective_address(long *memory_context)
{
    long memory_descriptor = *memory_context;
    uint flags = *(uint *)(memory_descriptor + 0x30);

    undefined1 *base_addr = (undefined1 *)(long)*(int *)(memory_descriptor + 0x1c);

    // 应用各种地址修饰符
    if ((flags >> 3) & 1) {
        base_addr += *(long *)(memory_context[1] + 0xa8) +
                    (ulong)*(byte *)(memory_descriptor + 0x2a);
    }

    if ((flags >> 1) & 1) {
        base_addr += *(long *)(memory_context[1] +
                              ((ulong)*(uint *)(memory_descriptor + 0xc) + 4) * 8);
    }

    if ((flags >> 2) & 1) {
        base_addr += (*(long *)(memory_context[1] +
                               ((ulong)*(uint *)(memory_descriptor + 0x10) + 4) * 8) <<
                     ((ulong)*(uint *)(memory_descriptor + 0x14) & 0x3f));
    }

    // 应用大小掩码
    int size_flags = (flags >> 0x10 & 1) + (flags >> 5 & 1);
    if (size_flags == 0) {
        return (undefined1 *)((ulong)base_addr & 0xffff);
    } else if (size_flags == 1) {
        return (undefined1 *)((ulong)base_addr & 0xffffffff);
    } else {
        return base_addr;
    }
}

// 位反转计算函数
int calculate_bit_reverse_shift(uint value)
{
    uint reversed = reverse_bits_32(value);
    return 1 << (ulong)((int)LZCOUNT(reversed >> 0x10 | reversed << 0x10) - 1U & 0x1f);
}

// 信号处理设置
void setup_signal_handler(byte signal_num, undefined8 handler, undefined8 data, int context_offset)
{
    if (signal_num == 0) {
        return;
    }

    // 设置信号处理结构
    undefined8 signal_info[4];
    signal_info[0] = (ulong)signal_num;
    signal_info[1] = 0;
    signal_info[2] = 0;
    signal_info[3] = handler;

    // 注册信号处理器
    register_signal_handler(context_offset + 0x184, signal_info);

    // 清零全局信号状态
    *(undefined8 *)(get_signal_context_base() + 0x750d0) = 0;
}

// 浮点运算和状态更新
void perform_floating_point_operation(undefined8 context, undefined2 op1, undefined8 data1,
                                     undefined2 op2, char is_signed, ushort *status_flags)
{
    // 设置操作参数
    undefined4 operation_params[8];
    operation_params[0] = 0x50;  // 操作类型
    operation_params[2] = 0;     // 清零
    operation_params[4] = 0x100000000;  // 标志
    operation_params[6] = 0;     // 保留

    operation_params[5] = *status_flags & 0x3f;        // 舍入模式
    operation_params[3] = *status_flags >> 10 & 3;     // 精度控制

    // 执行浮点操作
    int result;
    if (is_signed == '\0') {
        result = execute_fp_operation(context, op1, data1, op2, 0, operation_params);
    } else {
        result = execute_fp_operation(context, op1, data1, op2, 1, operation_params);
    }

    // 更新状态标志
    ushort new_flags = status_flags[1] & 0xb8ff;
    if (result + 1U < 4) {
        new_flags |= *(ushort *)(&status_lookup_table + (ulong)(result + 1U) * 2);
    }
    status_flags[1] = new_flags;

    // 更新异常状态
    update_fp_exception_status(operation_params[2], status_flags);
}

// 浮点数转换函数
ulong convert_float_to_int(ulong mantissa, uint exponent, char to_signed, ushort *status_flags)
{
    uint exp_mask = exponent & 0xffff;
    uint adjusted_exp = exponent & 0x7fff;

    if (to_signed != '\0') {
        // 有符号转换
        if (adjusted_exp == 0) {
            undefined4 status = mantissa ? 0x20 : 0;
            update_fp_status(status, status_flags);
            return 0;
        }

        if ((long)mantissa < 0) {
            if ((int)(adjusted_exp - 0x403e) < 0) {
                if (adjusted_exp > 0x3ffe) {
                    ulong shifted = mantissa >> ((ulong)(0x403e - adjusted_exp) & 0x3f);
                    ulong result = (exp_mask >> 0xf == 0) ? shifted : -shifted;

                    bool has_remainder = (mantissa << ((ulong)(adjusted_exp - 0x403e) & 0x3f)) != 0;
                    update_fp_status((ulong)has_remainder << 5, status_flags);
                    return result;
                }

                update_fp_status(0x20, status_flags);
                return 0;
            } else {
                bool is_valid = (mantissa & 0x7fffffffffffffff) != 0 || exp_mask != 0xc03e;
                update_fp_status(is_valid ? 1 : 0, status_flags);
                return 0x8000000000000000;
            }
        }

        update_fp_status(1, status_flags);
        return 0x8000000000000000;
    }

    // 无符号转换逻辑
    return perform_unsigned_conversion(mantissa, adjusted_exp, exp_mask, status_flags);
}

// 执行无符号转换
ulong perform_unsigned_conversion(ulong mantissa, uint exponent, uint exp_mask, ushort *status_flags)
{
    ushort rounding_mode = *status_flags >> 10;
    ushort rounding_type = rounding_mode & 3;

    if (exponent == 0) {
        ulong remainder = (ulong)(mantissa != 0);
        ulong result = 0;

        if ((rounding_mode & 3) == 0) {
            update_fp_status(0, status_flags);
            return result;
        }

        return apply_rounding(mantissa, result, remainder, rounding_type, exp_mask, status_flags);
    }

    if ((long)mantissa < 0) {
        update_fp_status(1, status_flags);
        return 0x8000000000000000;
    }

    // 处理指数范围
    uint shift_amount = 0x403e - exponent;
    if ((int)shift_amount < 1) {
        if (shift_amount != 0) {
            update_fp_status(1, status_flags);
            return 0x8000000000000000;
        }

        return handle_no_shift_conversion(mantissa, rounding_mode, exp_mask, status_flags);
    }

    return handle_shift_conversion(mantissa, shift_amount, rounding_type, exp_mask, status_flags);
}

// 进程信息获取
ulong get_process_info(undefined8 process_handle, undefined1 *info_buffer)
{
    *info_buffer = 0;

    // 获取进程路径
    int path_result = get_process_path(process_handle, process_path_buffer);
    ulong result = (ulong)path_result;

    if (result >= 0xfffffffffffff001) {
        return result;  // 错误
    }

    if (process_path_buffer[0] == '\0') {
        return 0xfffffffffffffffe;  // 空路径
    }

    // 初始化进程上下文
    *info_buffer = 0;
    initialize_process_context(&process_context);

    // 打开进程
    result = open_process(&process_context, 0xffffff9c, process_path_buffer);
    if (result > 0xffe) {
        result = 0;
        *info_buffer = (process_context.thread_info != 0);
    }

    // 清理资源
    cleanup_process_context(&process_context);

    return result;
}


#include <stdint.h>
#include <stdbool.h>

// 定义常量
#define PAGE_SIZE 0x1000
#define MAX_BREAKPOINTS 16
#define CODE_CACHE_SIZE 0x8800000
#define STACK_ALIGNMENT 16

// 结构体定义
typedef struct {
    uint64_t base;
    uint64_t size;
    uint32_t flags;
} MemoryRegion;

typedef struct {
    char* format_string;
    void* args;
    size_t arg_count;
} FormatContext;

typedef struct {
    uint32_t eax, ebx, ecx, edx;
    uint32_t esi, edi, esp, ebp;
    uint32_t eip, eflags;
} CPUState;

// 函数声明
static bool validate_page_size(void);
static void initialize_ubtipc(void);
static void parse_command_line_args(uint32_t argc, char** argv);
static void setup_cpu_features(void);
static void initialize_memory_pools(void);
static void setup_code_cache(void);
static void configure_breakpoints(void);
static void initialize_function_tables(void);

// 主初始化函数
void initialize_exagear_system(uint32_t argc, char** argv) {
    // 验证页面大小
    if (!validate_page_size()) {
        fatal_error("Page size mismatch: expected %d, got %ld",
                   PAGE_SIZE, get_kernel_page_size());
    }

    // 保存命令行参数
    global_argc = argc;
    global_argv = argv;

    // 初始化UBTIPC
    initialize_ubtipc();

    // 解析命令行参数
    parse_command_line_args(argc, argv);

    // 检查版本和帮助选项
    if (show_version_flag) {
        print_version_info();
        exit(0);
    }

    // 初始化内存管理
    initialize_memory_pools();

    // 设置CPU特性
    setup_cpu_features();

    // 配置断点
    configure_breakpoints();

    // 初始化代码缓存
    setup_code_cache();

    // 初始化函数表
    initialize_function_tables();

    // 启动主执行循环
    start_execution_loop();
}

static bool validate_page_size(void) {
    long kernel_page_size = get_auxv_value(AT_PAGESZ);
    if (kernel_page_size == 0) {
        warning("Kernel didn't pass AT_PAGESZ auxv");
        return false;
    }
    return kernel_page_size == PAGE_SIZE;
}

static void initialize_ubtipc(void) {
    void* ubtipc_mem = mmap_anonymous(0x80, PROT_READ | PROT_WRITE);
    if (ubtipc_mem == MAP_FAILED) {
        fatal_error("Failed to initialize ubtipc");
    }

    memcpy(ubtipc_mem, "UBTIPC1", 8);
    *(uint64_t*)((char*)ubtipc_mem + 8) = 1;

    global_ubtipc_ptr = ubtipc_mem;
}

static void parse_command_line_args(uint32_t argc, char** argv) {
    uint32_t i = 1;

    // 跳过 "--" 分隔符
    while (i < argc && strcmp(argv[i], "--") == 0) {
        i++;
    }

    // 保存剩余参数给目标程序
    global_target_argc = argc - i;
    global_target_argv = &argv[i];

    // 查找目标可执行文件
    for (uint32_t j = 1; j < argc; j++) {
        if (strcmp(argv[j], "--") != 0) {
            global_target_executable = argv[j];
            global_target_argv = &argv[j + 1];
            global_target_argc = 1;
            global_target_argv[1] = NULL;
            break;
        }
    }
}

static void setup_cpu_features(void) {
    // 设置CPU型号和特性
    if (cpu_model == CPU_MODEL_INTEL) {
        setup_intel_cpu_features();
    } else if (cpu_model == CPU_MODEL_AMD) {
        setup_amd_cpu_features();
    } else {
        fatal_error("Unknown CPU model");
    }

    // 配置缓存层次结构
    configure_cache_hierarchy();

    // 设置CPUID响应
    setup_cpuid_responses();
}

static void initialize_memory_pools(void) {
    // 创建主内存池
    void* memory_pool = mmap_fixed(MEMORY_POOL_BASE, MEMORY_POOL_SIZE,
                                  PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS);
    if (memory_pool == MAP_FAILED) {
        fatal_error("Failed to initialize memory pool");
    }

    global_memory_pool.base = (uint64_t)memory_pool;
    global_memory_pool.end = global_memory_pool.base + MEMORY_POOL_SIZE;

    // 初始化内存分配器
    initialize_memory_allocator(&global_memory_pool);
}

static void configure_breakpoints(void) {
    if (!debug_breakpoints_enabled) {
        return;
    }

    for (int i = 0; i < breakpoint_count && i < MAX_BREAKPOINTS; i++) {
        uint64_t addr = parse_hex_address(breakpoint_addresses[i]);
        if (addr != 0) {
            if (breakpoint_table_count >= MAX_BREAKPOINTS) {
                error("Too many breakpoints");
                exit(1);
            }
            breakpoint_table[breakpoint_table_count++] = addr;
        }
    }
}

static void setup_code_cache(void) {
    // 设置代码缓存权限
    int result = mprotect(code_cache_base, CODE_CACHE_SIZE,
                         PROT_READ | PROT_WRITE | PROT_EXEC);
    if (result != 0) {
        fatal_error("Failed to set permissions on code cache");
    }

    // 如果支持大页面，尝试使用
    if (hugepage_mode == HUGEPAGE_MADVISE) {
        madvise(code_cache_base, CODE_CACHE_SIZE, MADV_HUGEPAGE);
    }

    // 重置READ_IMPLIES_EXEC标志
    reset_read_implies_exec_flag();
}

static void initialize_function_tables(void) {
    // 初始化指令处理函数表
    initialize_instruction_handlers();

    // 初始化系统调用处理函数表
    initialize_syscall_handlers();

    // 初始化中断处理函数表
    initialize_interrupt_handlers();

    // 初始化内存管理函数表
    initialize_memory_handlers();
}

// 辅助函数
static void fatal_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(1);
}

static void warning(const char* format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "Warning: ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

static void print_version_info(void) {
    printf("%s\nRevision %s. Build: %s\n",
           "Dynamic binary translator",
           version_string,
           "Release");
}

// 格式化参数解析函数
void parse_format_arguments(const char* format, void* args,
                           long* memory_region, size_t* region_size) {
    if (!format) return;

    FormatContext ctx = {0};
    ctx.format_string = (char*)format;

    // 分析格式字符串，确定参数类型和数量
    analyze_format_string(&ctx);

    // 如果需要超过8个参数，分配内存区域
    if (ctx.arg_count > 8) {
        size_t needed_size = (ctx.arg_count + 1) * 16;
        *region_size = needed_size;
        *memory_region = mmap_anonymous(needed_size, PROT_READ | PROT_WRITE);
        if (*memory_region == -1) {
            return;
        }
    }

    // 复制参数到内存区域
    copy_arguments_to_region(&ctx, args, *memory_region);
}

static void analyze_format_string(FormatContext* ctx) {
    const char* p = ctx->format_string;
    ctx->arg_count = 0;

    while (*p) {
        if (*p == '%' && *(p + 1) != '%') {
            p++; // 跳过 '%'

            // 跳过标志
            while (*p && strchr(" #'+0-", *p)) p++;

            // 跳过宽度
            while (*p && isdigit(*p)) p++;

            // 跳过精度
            if (*p == '.') {
                p++;
                while (*p && isdigit(*p)) p++;
            }

            // 处理长度修饰符
            bool is_long = false, is_long_long = false;
            if (*p == 'l') {
                is_long = true;
                p++;
                if (*p == 'l') {
                    is_long_long = true;
                    p++;
                }
            }

            // 处理转换说明符
            if (*p) {
                ctx->arg_count++;
                p++;
            }
        } else {
            p++;
        }
    }
}

static void copy_arguments_to_region(FormatContext* ctx, void* args,
                                   long memory_region) {
    // 实现参数复制逻辑
    // 这里需要根据具体的调用约定来实现
}

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

// 常量定义
const char* EXAGEAR_BINFMT_FLAG = "--ubt-launched-via-binfmt-misc";
const char* ARG_SEPARATOR = "--";
const char* PROGRAM_ARG_PLACEHOLDER = "--first-arg-placeholder";
const char* EXAGEAR_BINARY_ARG = "--program-fd";

// 配置路径
const char* CONFIG_PATH_TEMPLATE = "/etc/exagear-%s.conf";
const char* GUEST_CONFIG_TEMPLATE = "/etc/exagear-guest-%s.conf";
const char* SHARED_CONFIG_PATH = "/opt/exagear/shared/exagear-x86_64.conf";

// 结构体定义
struct ExagearConfig {
    char guest_image_name[256];
    char foreign_arch[20];
    char ubt_binary[4096];
    char vpaths_list[4096];
    char opaths_list[4096];
    char utmp_list[4096];
};

struct ArgumentProcessor {
    char** argv;
    int argc;
    int current_pos;
};

// 函数声明
static void initialize_system();
static void process_arguments(int argc, char** argv);
static void handle_binfmt_launch(int argc, char** argv, int fd,
                                void* param4, void* param5,
                                void* param6, void* param7);
static bool find_exagear_directory(const char* binary_path, char* result_path);
static int load_config(const char* config_path, const char* key,
                      char* buffer, size_t buffer_size);
static void setup_environment_variables();
static char** build_final_argv(int* final_argc);

// 主函数 - 重构后的 FUN_8010001f9850
void exagear_main(int argc, char** argv) {
    // 初始化系统
    initialize_system();

    // 处理命令行参数
    process_arguments(argc, argv);
}

// 重构后的 FUN_8010001feae0
void handle_binfmt_launch(int argc, char** argv, int fd,
                         void* param4, void* param5,
                         void* param6, void* param7) {
    char binary_path[4096];
    char exagear_dir[4096];
    char config_path[256];
    struct ExagearConfig config = {0};

    // 标记为通过 binfmt_misc 启动
    DAT_801000400d0c = 1;

    // 读取二进制文件路径
    if (!read_binary_path_from_fd(fd, binary_path, sizeof(binary_path))) {
        error_exit("Failed to read the path to the program being started.\n");
    }

    // 查找 ExaGear 目录
    if (!find_exagear_directory(binary_path, exagear_dir)) {
        error_exit("The file '%s' belongs to no guest image and there is no default guest image.\n",
                  binary_path);
    }

    // 加载配置
    load_exagear_config(exagear_dir, &config);

    // 构建新的参数列表
    char** new_argv;
    int new_argc = build_argument_list(argc, argv, &config, binary_path, &new_argv);

    // 启动 ExaGear
    exagear_main(new_argc, new_argv);
}

// 初始化系统
static void initialize_system() {
    long page_size = get_auxiliary_vector_value(AT_PAGESZ);

    if (page_size == 0) {
        log_warning("Warning: kernel didn't pass AT_PAGESZ auxv.\n");
    } else if (page_size != 0x1000) {
        error_exit("Exagear is built with PAGE_SIZE == %d but kernel has PAGE_SIZE == %ld. "
                  "You have to install proper exagear version.\n", 0x1000, page_size);
    }

    // 保存原始参数
    DAT_801000400d88 = argc;
    DAT_801000400d90 = argv;

    // 初始化 IPC
    initialize_ipc();

    // 初始化内存池
    initialize_memory_pool();

    // 设置 CPU 信息
    setup_cpu_info();

    // 初始化其他子系统
    initialize_subsystems();
}

// 处理命令行参数
static void process_arguments(int argc, char** argv) {
    struct ArgumentProcessor processor = {argv, argc, 1};

    // 跳过程序名
    if (argc < 2) {
        return;
    }

    // 查找参数分隔符
    int separator_pos = find_argument_separator(&processor);

    if (separator_pos != -1) {
        // 处理 ExaGear 特定参数
        process_exagear_arguments(&processor, separator_pos);

        // 处理目标程序参数
        process_target_arguments(&processor, separator_pos);
    }

    // 启动目标程序
    start_target_program(&processor);
}

// 查找 ExaGear 目录
static bool find_exagear_directory(const char* binary_path, char* result_path) {
    char current_path[4096];
    char* path_component;

    strncpy(current_path, binary_path, sizeof(current_path) - 1);
    current_path[sizeof(current_path) - 1] = '\0';

    // 从二进制路径向上查找 .exagear 目录
    path_component = current_path;
    while ((path_component = strchr(path_component + 1, '/')) != NULL) {
        *path_component = '\0';

        // 检查是否存在 .exagear 目录
        if (check_exagear_directory(current_path)) {
            strncpy(result_path, current_path, 4096);
            return true;
        }

        *path_component = '/';
    }

    return false;
}

// 检查 ExaGear 目录是否存在
static bool check_exagear_directory(const char* path) {
    char exagear_path[4096];
    snprintf(exagear_path, sizeof(exagear_path), "%s/.exagear", path);

    return (access(exagear_path, F_OK) == 0);
}

// 加载配置文件
static int load_config(const char* config_path, const char* key,
                      char* buffer, size_t buffer_size) {
    FILE* config_file = fopen(config_path, "r");
    if (!config_file) {
        return -1;
    }

    char line[1024];
    size_t key_len = strlen(key);

    while (fgets(line, sizeof(line), config_file)) {
        // 跳过注释和空行
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        // 查找键值对
        if (strncmp(line, key, key_len) == 0 && line[key_len] == '=') {
            strncpy(buffer, line + key_len + 1, buffer_size - 1);
            buffer[buffer_size - 1] = '\0';

            // 移除换行符
            char* newline = strchr(buffer, '\n');
            if (newline) {
                *newline = '\0';
            }

            fclose(config_file);
            return 0;
        }
    }

    fclose(config_file);
    return -1;
}

// 加载 ExaGear 配置
static void load_exagear_config(const char* exagear_dir, struct ExagearConfig* config) {
    char config_path[256];

    // 构建配置文件路径
    snprintf(config_path, sizeof(config_path), "%s/.exagear/vpaths-list", exagear_dir);
    if (strlen(config_path) >= sizeof(config->vpaths_list)) {
        error_exit("Configuration path too long\n");
    }
    strncpy(config->vpaths_list, config_path, sizeof(config->vpaths_list) - 1);

    snprintf(config_path, sizeof(config_path), "%s/.exagear/opaths-list", exagear_dir);
    strncpy(config->opaths_list, config_path, sizeof(config->opaths_list) - 1);

    snprintf(config_path, sizeof(config_path), "%s/.exagear/utmp-list", exagear_dir);
    strncpy(config->utmp_list, config_path, sizeof(config->utmp_list) - 1);
}

// 构建参数列表
static int build_argument_list(int argc, char** argv,
                              const struct ExagearConfig* config,
                              const char* binary_path,
                              char*** result_argv) {
    int new_argc = 0;
    char** new_argv;

    // 计算所需的参数数量
    int estimated_argc = argc + 20; // 为 ExaGear 参数预留空间

    // 分配内存
    new_argv = malloc(estimated_argc * sizeof(char*));
    if (!new_argv) {
        error_exit("Memory allocation failed\n");
    }

    // 添加程序名
    new_argv[new_argc++] = argv[0];

    // 添加 ExaGear 参数
    new_argv[new_argc++] = "--path";
    new_argv[new_argc++] = strdup(exagear_dir);

    new_argv[new_argc++] = "--vpaths-list";
    new_argv[new_argc++] = strdup(config->vpaths_list);

    new_argv[new_argc++] = "--opaths-list";
    new_argv[new_argc++] = strdup(config->opaths_list);

    new_argv[new_argc++] = "--utmp-paths-list";
    new_argv[new_argc++] = strdup(config->utmp_list);

    new_argv[new_argc++] = "-f";
    new_argv[new_argc++] = strdup(binary_path);

    new_argv[new_argc++] = "--use-binfmt_misc";

    new_argv[new_argc++] = "--program-fd";
    new_argv[new_argc++] = "3"; // 假设 fd 为 3

    // 添加分隔符
    new_argv[new_argc++] = "--";

    // 添加原始参数（跳过程序名）
    for (int i = 1; i < argc; i++) {
        new_argv[new_argc++] = argv[i];
    }

    new_argv[new_argc] = NULL;

    *result_argv = new_argv;
    return new_argc;
}

// 读取二进制文件路径
static bool read_binary_path_from_fd(int fd, char* buffer, size_t buffer_size) {
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

    ssize_t len = readlink(fd_path, buffer, buffer_size - 1);
    if (len == -1) {
        return false;
    }

    buffer[len] = '\0';
    return true;
}

// 错误退出
static void error_exit(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(127);
}

// 警告日志
static void log_warning(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

bool expand_guest_stack(process_handle_t process, ulong address) {
    // 获取锁
    acquire_lock(&global_lock, "lkv_mman.cc", 0x7e2);

    // 查找进程内存映射
    memory_mapping_t* mapping = find_memory_mapping(&memory_manager, process);
    if (!mapping || !(mapping->flags & STACK_FLAG)) {
        release_lock(&global_lock);
        return false;
    }

    // 计算页对齐的地址
    ulong page_aligned_addr = address & PAGE_MASK;
    if (page_aligned_addr >= mapping->stack_base) {
        release_lock(&global_lock);
        return false;
    }

    // 检查资源限制
    ulong expansion_size = mapping->stack_base - page_aligned_addr;
    if (!check_memory_limits(expansion_size)) {
        release_lock(&global_lock);
        return false;
    }

    // 执行栈扩展
    if (can_expand_stack(mapping, page_aligned_addr)) {
        ulong new_pages = allocate_memory_pages(
            page_aligned_addr,
            expansion_size,
            mapping->protection_flags,
            MAP_ANONYMOUS | MAP_PRIVATE
        );

        if (new_pages == page_aligned_addr) {
            // 更新内存映射统计
            if (memory_tracking_enabled) {
                update_memory_tracking(address & LARGE_PAGE_MASK,
                                     (page_aligned_addr + expansion_size) & LARGE_PAGE_MASK);
            }
            release_lock(&global_lock);
            return true;
        }
    }

    release_lock(&global_lock);
    return false;
}


bool expand_guest_stack(process_handle_t process, ulong address) {
    // 获取锁
    acquire_lock(&global_lock, "lkv_mman.cc", 0x7e2);

    // 查找进程内存映射
    memory_mapping_t* mapping = find_memory_mapping(&memory_manager, process);
    if (!mapping || !(mapping->flags & STACK_FLAG)) {
        release_lock(&global_lock);
        return false;
    }

    // 计算页对齐的地址
    ulong page_aligned_addr = address & PAGE_MASK;
    if (page_aligned_addr >= mapping->stack_base) {
        release_lock(&global_lock);
        return false;
    }

    // 检查资源限制
    ulong expansion_size = mapping->stack_base - page_aligned_addr;
    if (!check_memory_limits(expansion_size)) {
        release_lock(&global_lock);
        return false;
    }

    // 执行栈扩展
    if (can_expand_stack(mapping, page_aligned_addr)) {
        ulong new_pages = allocate_memory_pages(
            page_aligned_addr,
            expansion_size,
            mapping->protection_flags,
            MAP_ANONYMOUS | MAP_PRIVATE
        );

        if (new_pages == page_aligned_addr) {
            // 更新内存映射统计
            if (memory_tracking_enabled) {
                update_memory_tracking(address & LARGE_PAGE_MASK,
                                     (page_aligned_addr + expansion_size) & LARGE_PAGE_MASK);
            }
            release_lock(&global_lock);
            return true;
        }
    }

    release_lock(&global_lock);
    return false;
}

uint64_t perform_memory_operation_read(process_t* process, ulong address,
                                      memory_region_t* region, operation_type_t op_type) {
    if (!(region->flags & REGION_ACTIVE)) {
        return 0;
    }

    // 设置操作参数
    memory_operation_t operation = {0};
    operation.page_size = calculate_page_size(region->flags);
    operation.target_register = region->target_register;
    operation.operation_type = op_type;

    setup_memory_operation(&operation, process, address, region);
    return execute_read_operation(&operation, process, address, region->target_register);
}

uint64_t perform_memory_operation_write(process_t* process, ulong address,
                                       memory_region_t* region, operation_type_t op_type) {
    if (!(region->flags & REGION_ACTIVE)) {
        return 0;
    }

    memory_operation_t operation = {0};
    operation.page_size = calculate_page_size(region->flags);
    operation.target_register = region->target_register;
    operation.operation_type = op_type;

    setup_memory_operation(&operation, process, address, region);
    return execute_write_operation(&operation, process, address, region->target_register);
}

uint32_t encode_register_reference(register_info_t* reg_info, processor_context_t* context) {
    if (reg_info->encoding_type != COMPLEX_ENCODING) {
        // 简单编码：直接使用寄存器值
        uint8_t reg_id = reg_info->register_id;
        uint32_t base_reg = reg_info->base_register;
        uint32_t index_reg = reg_info->index_register;
        uint32_t scale = reg_info->scale_factor;

        if (is_simple_register_reference(reg_info)) {
            return encode_simple_register(reg_id, base_reg, index_reg);
        }

        return encode_complex_register(base_reg, index_reg, scale);
    }

    // 复杂编码：需要分配新的寄存器槽位
    uint32_t slot_id = allocate_register_slot(context);
    context->register_slots[slot_id] = 0;

    setup_register_encoding(reg_info, context, slot_id | COMPLEX_REGISTER_FLAG);

    return slot_id | (ADDRESSING_MODE_COMPLEX << 16) | (SCALE_FACTOR_2 << 24);
}



void manage_register_allocation(execution_context_t* context, register_id_t reg_id) {
    processor_state_t* state = context->processor_state;

    // 清除寄存器使用标志
    state->register_usage &= ~(1 << reg_id);

    // 计算寄存器优先级
    uint32_t priority = calculate_register_priority(state, reg_id);

    if (is_register_cached(state, priority)) {
        // 管理寄存器缓存
        manage_register_cache(state, reg_id, priority);
    }

    // 更新寄存器分配策略
    update_allocation_strategy(context, reg_id);
}

void manage_register_cache(processor_state_t* state, register_id_t reg_id, uint32_t priority) {
    uint32_t cache_slots = state->cache_slot_count;

    if (cache_slots == 0) {
        cache_slots = 1;
    } else {
        // 重新排列缓存槽位
        rearrange_cache_slots(state, reg_id, priority, cache_slots);
    }

    // 更新缓存配置
    state->cache_registers[cache_slots - 1] = priority;
    state->cache_slot_count = cache_slots;
}


uint32_t encode_instruction_type1(bool flag1, uint32_t field1, uint32_t field2,
                                 bool flag2, bool flag3) {
    return (field1 & 0x7) << 12 |     // 3位字段1，位置12-14
           (field2 & 0xF) << 8 |      // 4位字段2，位置8-11
           (flag1 ? 1 : 0) << 6 |     // 标志1，位置6
           0x18 |                     // 基础操作码
           (flag2 ? 1 : 0) << 7 |     // 标志2，位置7
           (flag3 ? 1 : 0) << 15;     // 标志3，位置15
}

uint32_t encode_instruction_type2(bool flag1, uint32_t field1, uint32_t field2,
                                 bool flag2, bool flag3) {
    return (field1 & 0x7) << 12 |     // 3位字段1，位置12-14
           (field2 & 0xF) << 8 |      // 4位字段2，位置8-11
           (flag1 ? 1 : 0) << 6 |     // 标志1，位置6
           0x10 |                     // 不同的基础操作码
           (flag2 ? 1 : 0) << 7 |     // 标志2，位置7
           (flag3 ? 1 : 0) << 15;     // 标志3，位置15
}

uint32_t encode_simple_instruction(bool flag, uint32_t field) {
    return (field & 0x7) << 12 |      // 3位字段，位置12-14
           (flag ? 1 : 0) << 6;       // 标志，位置6
}

typedef struct {
    uint32_t flags;
    ulong base_address;
    ulong size;
    uint32_t protection_flags;
    uint32_t target_register;
} memory_region_t;

typedef struct {
    uint32_t register_usage;
    uint32_t cache_slot_count;
    uint32_t cache_registers[8];
    uint32_t allocation_strategy;
} processor_state_t;

typedef struct {
    processor_state_t* processor_state;
    memory_region_t* memory_regions;
    uint32_t region_count;
} execution_context_t;

typedef struct {
    uint8_t register_id;
    uint8_t encoding_type;
    uint32_t base_register;
    uint32_t index_register;
    uint32_t scale_factor;
} register_info_t;


