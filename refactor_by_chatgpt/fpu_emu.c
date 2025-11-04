// x86 FPU 模拟器重构版本

#include <stdint.h>
#include <stdbool.h>

// FPU 寄存器结构
typedef struct {
    uint64_t mantissa;
    uint16_t exponent;
} fpu_register_t;

// FPU 状态结构
typedef struct {
    uint16_t control_word;
    uint16_t status_word;
    uint64_t stack_pointer;
    fpu_register_t stack[8];
    uint64_t segment_bases[6];
    uint64_t segment_limits[6];
} fpu_state_t;

// 获取FPU状态指针
static inline fpu_state_t* get_fpu_state() {
    uint64_t base = ((uint64_t)&stack & 0xfffffffffff80000);
    return (fpu_state_t*)(base + 0x75000);
}

// 字符串比较指令实现
void fpu_string_compare_bytes(bool zero_flag) {
    fpu_state_t* fpu = get_fpu_state();
    
    uint64_t count = fpu->stack[0].mantissa;  // ECX
    uint8_t al_value = fpu->control_word & 0xFF;  // AL
    
    int64_t direction = (fpu->segment_bases[0] == 0) ? -1 : 1;
    uint64_t src_ptr = fpu->segment_bases[1];  // ESI
    uint64_t dst_ptr = fpu->segment_bases[2];  // EDI
    
    uint8_t src_byte, dst_byte = 0;
    
    while (count > 0) {
        // 检查内存边界
        if (fpu->segment_limits[0] < src_ptr) {
            handle_memory_fault(0xd, 0);
        }
        
        src_byte = *(uint8_t*)(src_ptr + fpu->segment_bases[3]);
        src_ptr -= direction;
        count--;
        
        // 更新寄存器状态
        fpu->stack[0].mantissa = count;
        fpu->segment_bases[1] = src_ptr;
        
        // 比较条件检查
        if ((al_value == src_byte) != zero_flag) {
            break;
        }
    }
    
    if (count != 0) {
        update_flags(al_value, src_byte, 0x7d);
    }
}

// 16位字符串比较
void fpu_string_compare_words(bool zero_flag) {
    fpu_state_t* fpu = get_fpu_state();
    
    uint64_t count = fpu->stack[0].mantissa;
    uint16_t ax_value = fpu->control_word & 0xFFFF;
    
    int64_t direction = (fpu->segment_bases[0] == 0) ? -2 : 2;
    uint64_t src_ptr = fpu->segment_bases[1];
    
    uint16_t src_word, dst_word = 0;
    
    while (count > 0) {
        if (fpu->segment_limits[0] < src_ptr + 1) {
            handle_memory_fault(0xd, 0);
        }
        
        src_word = *(uint16_t*)(src_ptr + fpu->segment_bases[3]);
        src_ptr -= direction;
        count--;
        
        fpu->stack[0].mantissa = count;
        fpu->segment_bases[1] = src_ptr;
        
        if ((ax_value == src_word) != zero_flag) {
            break;
        }
    }
    
    if (count != 0) {
        update_flags_16(ax_value, src_word, 0x7d);
    }
}

// 32位字符串比较
void fpu_string_compare_dwords(bool zero_flag) {
    fpu_state_t* fpu = get_fpu_state();
    
    uint64_t count = fpu->stack[0].mantissa;
    uint32_t eax_value = fpu->control_word & 0xFFFFFFFF;
    
    int64_t direction = (fpu->segment_bases[0] == 0) ? -4 : 4;
    uint64_t src_ptr = fpu->segment_bases[1];
    
    uint32_t src_dword, dst_dword = 0;
    
    while (count > 0) {
        if (fpu->segment_limits[0] < src_ptr + 3) {
            handle_memory_fault(0xd, 0);
        }
        
        src_dword = *(uint32_t*)(src_ptr + fpu->segment_bases[3]);
        src_ptr -= direction;
        count--;
        
        fpu->stack[0].mantissa = count;
        fpu->segment_bases[1] = src_ptr;
        
        if ((eax_value == src_dword) != zero_flag) {
            break;
        }
    }
    
    if (count != 0) {
        update_flags_32(eax_value, src_dword, 0x7d);
    }
}

// 浮点数转换为整数
void fpu_float_to_int(int32_t* result, bool pop_stack) {
    fpu_state_t* fpu = get_fpu_state();
    
    uint16_t old_control = fpu->control_word;
    uint16_t status = fpu->status_word & 0xfdff;
    
    fpu_register_t* top_reg = &fpu->stack[fpu->stack_pointer & 7];
    uint16_t exponent = top_reg->exponent;
    uint64_t mantissa = top_reg->mantissa;
    
    uint32_t exp_value = exponent & 0x7fff;
    int32_t int_result = 0x80000000;  // 默认无效值
    
    if (exp_value == 0) {
        // 零或非规格化数
        if (mantissa != 0) {
            set_fpu_exception(0x20, &old_control);
        }
        int_result = 0;
    } else if (mantissa < 0 && exp_value < 0x401f) {
        // 可转换范围内的数
        if (exp_value < 0x3fff) {
            set_fpu_exception(0x20, &old_control);
            int_result = 0;
        } else {
            // 执行实际转换
            uint64_t shifted = mantissa >> (0x403e - exp_value);
            int32_t temp = (int32_t)shifted;
            
            if (exponent >> 15 != 0) {
                temp = -temp;
            }
            
            // 检查溢出
            if ((exponent >> 15) == (temp >> 31)) {
                set_fpu_exception((mantissa != (shifted << (0x403e - exp_value))) ? 0x20 : 0, 
                                &old_control);
                int_result = temp;
            } else {
                set_fpu_exception(1, &old_control);
            }
        }
    } else {
        set_fpu_exception(1, &old_control);
    }
    
    *result = int_result;
    
    if (pop_stack) {
        fpu_pop_stack();
    }
    
    fpu->status_word = status;
}

// BCD转浮点数
void fpu_bcd_to_float(uint64_t bcd_addr, uint32_t segment) {
    fpu_state_t* fpu = get_fpu_state();
    
    // 检查内存访问权限
    check_memory_access(segment, bcd_addr, 10);
    
    uint8_t sign_byte = read_memory_byte(bcd_addr + 9, segment);
    uint64_t bcd_value = 0;
    
    // 从BCD格式转换为二进制
    for (int i = 8; i >= 0; i--) {
        uint8_t bcd_byte = read_memory_byte(bcd_addr + i, segment);
        bcd_value = bcd_value * 10 + (bcd_byte >> 4);
        bcd_value = bcd_value * 10 + (bcd_byte & 0xf);
    }
    
    // 转换为浮点格式并压入栈
    if (bcd_value != 0) {
        int leading_zeros = count_leading_zeros(bcd_value);
        uint16_t exponent = 0x403e - leading_zeros;
        uint64_t mantissa = bcd_value << leading_zeros;
        
        if (sign_byte & 0x80) {
            exponent |= 0x8000;
        }
        
        fpu_push_float(mantissa, exponent);
    } else {
        fpu_push_float(0, 0);
    }
}

// 浮点数转BCD
void fpu_float_to_bcd(uint64_t bcd_addr, uint32_t segment) {
    fpu_state_t* fpu = get_fpu_state();
    
    fpu_register_t* top_reg = &fpu->stack[fpu->stack_pointer & 7];
    double float_val = convert_to_double(top_reg->mantissa, top_reg->exponent);
    
    // 检查特殊值
    uint32_t exp_bits = (uint32_t)(*(uint64_t*)&float_val >> 52) & 0x7ff;
    if (exp_bits == 0x7ff || fabs(float_val) > 999999999999999999.0) {
        set_fpu_exception(0, NULL);
        // 写入无效BCD
        write_memory_qword(bcd_addr, 0xc000000000000000, segment);
        write_memory_word(bcd_addr + 8, 0xffff, segment);
        fpu_pop_stack();
        return;
    }
    
    // 转换为BCD格式
    uint64_t int_val = (uint64_t)fabs(float_val);
    uint8_t sign = (float_val < 0) ? 0x80 : 0;
    
    // 写入BCD数据
    for (int i = 0; i < 9; i++) {
        uint8_t digit1 = int_val % 10;
        int_val /= 10;
        uint8_t digit2 = int_val % 10;
        int_val /= 10;
        
        write_memory_byte(bcd_addr + i, digit1 | (digit2 << 4), segment);
    }
    
    write_memory_byte(bcd_addr + 9, sign, segment);
    fpu_pop_stack();
}

// 三角函数 - 正弦和余弦
void fpu_sincos() {
    fpu_state_t* fpu = get_fpu_state();
    
    fpu_register_t* top_reg = &fpu->stack[fpu->stack_pointer & 7];
    double angle = convert_to_double(top_reg->mantissa, top_reg->exponent);
    
    uint32_t abs_exp = get_abs_exponent(angle);
    
    if (fabs(angle) < 2e63) {
        fpu->status_word &= ~0x400;  // 清除C2标志
        
        double sin_val, cos_val;
        
        if (abs_exp < 0x3fe921fc) {
            // 小角度，直接计算
            sin_val = calculate_sin_small_angle(angle);
            cos_val = sqrt(1.0 - sin_val * sin_val);
        } else if (abs_exp < 0x7ff00000) {
            // 大角度，需要范围缩减
            uint32_t quadrant = reduce_angle_range(&angle);
            
            double sin_reduced = calculate_sin_small_angle(angle);
            double cos_reduced = sqrt(1.0 - sin_reduced * sin_reduced);
            
            // 根据象限调整符号
            switch (quadrant & 3) {
                case 0: sin_val = sin_reduced; cos_val = cos_reduced; break;
                case 1: sin_val = cos_reduced; cos_val = -sin_reduced; break;
                case 2: sin_val = -sin_reduced; cos_val = -cos_reduced; break;
                case 3: sin_val = -cos_reduced; cos_val = sin_reduced; break;
            }
        } else {
            // 无穷大或NaN
            sin_val = cos_val = angle - angle;  // 产生NaN
        }
        
        // 更新栈
        convert_from_double(sin_val, &top_reg->mantissa, &top_reg->exponent);
        fpu_push_float_from_double(cos_val);
    } else {
        fpu->status_word |= 0x400;  // 设置C2标志表示参数过大
    }
}

// 浮点数加法
void fpu_add() {
    fpu_state_t* fpu = get_fpu_state();
    
    fpu_register_t* st0 = &fpu->stack[fpu->stack_pointer & 7];
    fpu_register_t* st1 = &fpu->stack[(fpu->stack_pointer + 1) & 7];
    
    // 执行加法运算
    perform_fp_add(st0->mantissa, st0->exponent, 
                   st1->mantissa, st1->exponent, st1);
    
    fpu->stack_pointer = (fpu->stack_pointer + 1) & 7;
}

// 浮点数减法  
void fpu_subtract() {
    fpu_state_t* fpu = get_fpu_state();
    
    fpu_register_t* st0 = &fpu->stack[fpu->stack_pointer & 7];
    fpu_register_t* st1 = &fpu->stack[(fpu->stack_pointer + 1) & 7];
    
    // 执行减法运算（加法的相反数）
    uint16_t neg_exp = st1->exponent ^ 0x8000;  // 翻转符号位
    perform_fp_add(st0->mantissa, st0->exponent, 
                   st1->mantissa, neg_exp, st1);
    
    fpu->stack_pointer = (fpu->stack_pointer + 1) & 7;
}

// 初始化FPU
void fpu_init(uint32_t control_word) {
    fpu_state_t* fpu = get_fpu_state();
    
    fpu->control_word = control_word | 0x40;
    fpu->stack_pointer = 0;
    
    // 清空所有寄存器
    for (int i = 0; i < 8; i++) {
        fpu->stack[i].mantissa = 0;
        fpu->stack[i].exponent = 0;
    }
    
    // 清空标签寄存器
    for (int i = 0; i < 8; i++) {
        fpu->segment_bases[5] = 0;  // 标签寄存器区域
    }
}

// 辅助函数：检查内存访问
static void check_memory_access(uint32_t segment, uint64_t addr, size_t size) {
    fpu_state_t* fpu = get_fpu_state();
    
    uint64_t base, limit;
    get_segment_info(segment, &base, &limit);
    
    if (limit < addr + size - 1) {
        handle_memory_fault(0xd, 0);
    }
}

// 辅助函数：设置FPU异常
static void set_fpu_exception(uint32_t exception_mask, uint16_t* control) {
    fpu_state_t* fpu = get_fpu_state();
    
    fpu->status_word |= exception_mask;
    
    if (control && (*control & exception_mask) == 0) {
        // 未屏蔽的异常，触发中断
        trigger_fpu_exception();
    }
}

#include <stdint.h>
#include <stdbool.h>

// 浮点数栈和状态结构
typedef struct {
    uint64_t mantissa;
    uint16_t exponent;
} FloatStackEntry;

typedef struct {
    FloatStackEntry stack[8];
    uint64_t stack_pointer;
    uint16_t control_word;
    uint16_t status_word;
    uint64_t flags;
} FPUState;

// 获取FPU状态基地址
static inline FPUState* get_fpu_state() {
    uint64_t base = ((uint64_t)&__builtin_frame_address(0)) & 0xfffffffffff80000;
    return (FPUState*)(base + 0x75000);
}

// 浮点数常量加载函数
void fpu_load_constant_1() {
    FPUState* fpu = get_fpu_state();
    uint64_t stack_idx = (fpu->stack_pointer - 1) & 7;
    fpu->stack_pointer = stack_idx;

    uint16_t status = fpu->status_word;
    FloatStackEntry* entry = &fpu->stack[stack_idx];

    // 检查控制字中的特殊条件
    if ((fpu->control_word >> 10 & 3) == 2) {
        entry->mantissa = 0x80105c6e79e8 + 1; // 调整后的常量
    } else {
        entry->mantissa = 0x80105c6e79e8;
    }
    entry->exponent = 0x80105c6e79f0;

    fpu->status_word = status & 0xfdff; // 清除某些标志位
}

void fpu_load_constant_2() {
    FPUState* fpu = get_fpu_state();
    uint64_t stack_idx = (fpu->stack_pointer - 1) & 7;
    fpu->stack_pointer = stack_idx;

    uint16_t status = fpu->status_word;
    FloatStackEntry* entry = &fpu->stack[stack_idx];

    uint64_t mantissa = 0x80105c6e79f8;
    uint16_t control = fpu->control_word;

    // 根据控制字调整尾数
    if ((control >> 10 & 1) != 0) {
        mantissa -= 1;
    }

    entry->mantissa = mantissa;
    entry->exponent = 0x80105c6e7a00;
    fpu->status_word = status & 0xfdff;
}

void fpu_load_constant_3() {
    FPUState* fpu = get_fpu_state();
    uint64_t stack_idx = (fpu->stack_pointer - 1) & 7;
    fpu->stack_pointer = stack_idx;

    uint16_t status = fpu->status_word;
    FloatStackEntry* entry = &fpu->stack[stack_idx];

    uint64_t mantissa = 0x80105c6e7a08;
    uint16_t control = fpu->control_word;

    if ((control >> 10 & 1) != 0) {
        mantissa -= 1;
    }

    entry->mantissa = mantissa;
    entry->exponent = 0x80105c6e7a10;
    fpu->status_word = status & 0xfdff;
}

void fpu_load_constant_4() {
    FPUState* fpu = get_fpu_state();
    uint64_t stack_idx = (fpu->stack_pointer - 1) & 7;
    fpu->stack_pointer = stack_idx;

    uint16_t status = fpu->status_word;
    FloatStackEntry* entry = &fpu->stack[stack_idx];

    uint64_t mantissa = 0x80105c6e7a18;
    uint16_t control = fpu->control_word;

    if ((control >> 10 & 1) != 0) {
        mantissa -= 1;
    }

    entry->mantissa = mantissa;
    entry->exponent = 0x80105c6e7a20;
    fpu->status_word = status & 0xfdff;
}

void fpu_load_constant_5() {
    FPUState* fpu = get_fpu_state();
    uint64_t stack_idx = (fpu->stack_pointer - 1) & 7;
    fpu->stack_pointer = stack_idx;

    uint16_t status = fpu->status_word;
    FloatStackEntry* entry = &fpu->stack[stack_idx];

    uint64_t mantissa = 0x80105c6e7a28;
    uint16_t control = fpu->control_word;

    if ((control >> 10 & 1) != 0) {
        mantissa -= 1;
    }

    entry->mantissa = mantissa;
    entry->exponent = 0x80105c6e7a30;
    fpu->status_word = status & 0xfdff;
}

void fpu_load_zero() {
    FPUState* fpu = get_fpu_state();
    uint16_t status = fpu->status_word & 0xfdff;

    uint64_t stack_idx = (fpu->stack_pointer - 1) & 7;
    fpu->stack_pointer = stack_idx;

    FloatStackEntry* entry = &fpu->stack[stack_idx];
    entry->mantissa = 0x80105c6e7a38;
    entry->exponent = 0x80105c6e7a40;

    fpu->status_word = status;
}

// 栈操作函数
void fpu_stack_operation(uint64_t param1, bool should_pop) {
    FPUState* fpu = get_fpu_state();
    uint16_t status = fpu->status_word & 0xfdff;

    if (!should_pop) {
        fpu->status_word = status;
        return;
    }

    // 压入零值
    uint64_t stack_idx = fpu->stack_pointer & 7;
    FloatStackEntry* entry = &fpu->stack[stack_idx];
    entry->mantissa = 0;
    entry->exponent = 0;

    fpu->stack_pointer = (fpu->stack_pointer + 1) & 7;
    fpu->status_word = status;
}

void fpu_adjust_stack_pointer(bool increment) {
    FPUState* fpu = get_fpu_state();

    int64_t current_sp = fpu->stack_pointer;
    uint32_t new_sp;

    if (increment) {
        new_sp = current_sp + 1;
    } else {
        new_sp = current_sp - 1;
    }

    fpu->stack_pointer = new_sp & 7;
    fpu->status_word &= 0xfdff;
}

// 浮点数转换函数
typedef struct {
    uint64_t mantissa;
    uint32_t exponent;
    uint32_t padding;
} Float80;

Float80 convert_float32_to_float80(uint32_t f32_value) {
    Float80 result = {0};

    uint32_t mantissa = f32_value & 0x7fffff;
    uint32_t exponent = (f32_value >> 23) & 0xff;
    int sign = (int)f32_value >> 31;

    if (exponent == 0xff) { // 特殊值处理
        if (mantissa != 0) { // NaN
            validate_float_operation((f32_value >> 22 & 0x1ff) == 0x1fe &&
                                   (f32_value & 0x3fffff) != 0);
            result.exponent = sign * 0x8000 | 0x7fff;
            result.mantissa = ((uint64_t)mantissa << 40) | 0xc000000000000000;
        } else { // 无穷大
            validate_float_operation(false);
            result.exponent = (sign * 0x8000 + 0x7fff) & 0xffff;
            result.mantissa = 0x8000000000000000;
        }
        return result;
    }

    uint32_t result_exp = sign * 0x8000;

    if (exponent == 0) { // 非规格化数
        if (mantissa == 0) {
            result.mantissa = 0;
            result.exponent = result_exp;
            return result;
        }

        // 规格化非规格化数
        int shift_count;
        if ((f32_value & 0x7f0000) == 0) {
            uint32_t temp = mantissa << 16;
            shift_count = 16;
            if (temp < 0x1000000) {
                temp = mantissa << 24;
                shift_count = 24;
            }
        } else {
            shift_count = 8;
            temp = mantissa << 8;
        }

        validate_float_operation(2);
        temp = (shift_count + get_leading_zero_count(temp >> 24)) - 8;
        mantissa = mantissa << (temp & 0x1f);
        exponent = (uint16_t)(1 - (int16_t)temp);
    }

    result.mantissa = (uint64_t)(mantissa | 0x800000) << 40;
    result.exponent = (result_exp + exponent + 0x3f80) & 0xffff;

    validate_float_operation(0);
    return result;
}

// 浮点数比较和验证函数
bool validate_and_compare_floats(uint64_t mantissa1, uint16_t exp1,
                                uint64_t operand, uint64_t* result,
                                uint64_t status_addr, bool strict_mode) {
    uint16_t exp_masked = exp1 & 0x7fff;

    if (exp_masked == 0) {
        if (((uint32_t)(operand << 1)) < 0xff000001) {
            return false;
        }

        if (strict_mode) {
            *(uint16_t*)(status_addr + 2) |= 1;
            return true;
        }

        // 处理特殊情况...
        return handle_special_float_case(mantissa1, exp1, operand, result, status_addr);
    }

    // 处理正常浮点数比较...
    return perform_float_comparison(mantissa1, exp1, operand, result, status_addr, strict_mode);
}

// 浮点数算术运算
void fpu_add_float32(uint32_t* operand, bool should_pop, bool reverse_order) {
    FPUState* fpu = get_fpu_state();
    uint32_t value = *operand;

    uint16_t control = fpu->control_word;
    uint64_t stack_idx = fpu->stack_pointer & 7;
    uint16_t status = fpu->status_word & 0xfdff;

    FloatStackEntry* entry = &fpu->stack[stack_idx];
    uint16_t st0_exp = entry->exponent;
    uint64_t st0_mantissa = entry->mantissa;

    Float80 converted;
    bool needs_conversion = validate_and_compare_floats(
        st0_mantissa, st0_exp, value, (uint64_t*)&converted,
        (uint64_t)&control, false);

    if (!needs_conversion) {
        converted = convert_float32_to_float80(value);

        uint64_t* op1 = reverse_order ? (uint64_t*)&converted : &st0_mantissa;
        uint64_t* op2 = reverse_order ? &st0_mantissa : (uint64_t*)&converted;

        Float80 result = perform_float_addition(*op1, op1[1], *op2, op2[1], &control);
        entry->mantissa = result.mantissa;
        entry->exponent = result.exponent & 0xffff;
    }

    if (should_pop) {
        handle_fpu_exception();
    }

    fpu->status_word = status;
}

// 类似地实现其他算术运算函数...
void fpu_subtract_float32(uint32_t* operand, bool should_pop, bool reverse_order) {
    // 实现减法，类似加法但使用减法运算
}

void fpu_multiply_float32(uint32_t* operand, bool should_pop, bool reverse_order) {
    // 实现乘法
}

void fpu_divide_float32(uint32_t* operand, bool should_pop, bool reverse_order) {
    // 实现除法
}

// 比较运算
void fpu_compare_floats(int stack_offset1, int stack_offset2, bool should_pop) {
    FPUState* fpu = get_fpu_state();

    int current_sp = fpu->stack_pointer;
    FloatStackEntry* entry1 = &fpu->stack[(stack_offset1 + current_sp) & 7];
    FloatStackEntry* entry2 = &fpu->stack[(stack_offset2 + current_sp) & 7];

    uint16_t control = fpu->control_word;
    uint16_t status = fpu->status_word & 0xfdff;

    // 执行浮点数比较
    int comparison_result = perform_float_comparison_detailed(
        entry1->mantissa, entry1->exponent,
        entry2->mantissa, entry2->exponent,
        false, &control);

    // 更新状态字中的条件码
    status &= 0xb8ff; // 清除条件码位
    if ((uint32_t)(comparison_result + 1) < 4) {
        status |= get_condition_code_flags(comparison_result + 1);
    }

    validate_float_operation(0);

    if (should_pop) {
        handle_fpu_exception();
    }

    fpu->status_word = status;
}

// 超越函数
void fpu_compute_sine_cosine() {
    FPUState* fpu = get_fpu_state();

    uint64_t stack_idx = fpu->stack_pointer & 7;
    FloatStackEntry* entry = &fpu->stack[stack_idx];

    uint16_t control = fpu->control_word;
    uint16_t status = fpu->status_word & 0xfdff;

    // 计算正弦和余弦
    Float80 sine_result, cosine_result;
    compute_sine_cosine_pair(entry->mantissa, entry->exponent,
                           &sine_result, &cosine_result, &control);

    // 将结果压入栈
    entry->mantissa = sine_result.mantissa;
    entry->exponent = sine_result.exponent;

    uint64_t new_stack_idx = (fpu->stack_pointer - 1) & 7;
    fpu->stack_pointer = new_stack_idx;

    FloatStackEntry* cos_entry = &fpu->stack[new_stack_idx];
    cos_entry->mantissa = cosine_result.mantissa;
    cos_entry->exponent = cosine_result.exponent;

    fpu->status_word = status;
}

void fpu_compute_arctangent() {
    FPUState* fpu = get_fpu_state();

    uint64_t stack_idx1 = fpu->stack_pointer & 7;
    uint64_t stack_idx2 = (fpu->stack_pointer + 1) & 7;

    FloatStackEntry* y_entry = &fpu->stack[stack_idx1];
    FloatStackEntry* x_entry = &fpu->stack[stack_idx2];

    uint16_t control = fpu->control_word;
    uint16_t status = fpu->status_word & 0xfdff;

    // 计算 atan2(y, x)
    Float80 result = compute_arctangent2(
        y_entry->mantissa, y_entry->exponent,
        x_entry->mantissa, x_entry->exponent, &control);

    // 将结果存储到栈顶
    x_entry->mantissa = result.mantissa;
    x_entry->exponent = result.exponent;

    validate_float_operation(0);
    fpu->status_word = status;
}

// 其他数学函数的实现...
void fpu_compute_logarithm() {
    // 实现对数计算
}

void fpu_compute_exponential() {
    // 实现指数计算
}

void fpu_compute_square_root() {
    // 实现平方根计算
}

// 浮点数平方根运算
void float_sqrt(void) {
    ulong base_addr = get_base_address();
    ushort control_word = *(ushort *)(base_addr + FPU_CONTROL_OFFSET);
    long fpu_stack_ptr = base_addr + get_fpu_stack_offset();
    ushort status_word = *(ushort *)(base_addr + FPU_STATUS_OFFSET) & STATUS_MASK;

    ushort exponent = *(ushort *)(fpu_stack_ptr + EXPONENT_OFFSET);
    ulong mantissa = *(ulong *)(fpu_stack_ptr + MANTISSA_OFFSET);

    // 设置精度控制
    uint precision_control = get_precision_control(control_word);

    FloatingPointValue result;
    uint exception_flags = 0;

    if (is_zero_or_denormal(exponent)) {
        if (mantissa == 0) {
            // sqrt(0) = 0
            result = create_zero_value(exponent);
        } else if (is_negative(mantissa)) {
            // sqrt(负数) = NaN
            exception_flags = INVALID_OPERATION;
            result = create_nan_value();
        } else {
            // 处理非规格化数
            normalize_denormal(&mantissa, &exponent);
            result = compute_sqrt_normalized(mantissa, exponent, precision_control);
        }
    } else if (is_special_value(exponent)) {
        if (is_infinity(exponent, mantissa)) {
            if (is_negative(mantissa)) {
                // sqrt(-∞) = NaN
                exception_flags = INVALID_OPERATION;
                result = create_nan_value();
            } else {
                // sqrt(+∞) = +∞
                result = create_infinity_value(false);
            }
        } else {
            // NaN 传播
            result = propagate_nan(mantissa, exponent);
        }
    } else if (is_negative(mantissa)) {
        // sqrt(负数) = NaN
        exception_flags = INVALID_OPERATION;
        result = create_nan_value();
    } else {
        // 正常数的平方根计算
        result = compute_sqrt_normalized(mantissa, exponent, precision_control);
    }

    update_fpu_flags(exception_flags, &control_word);
    store_fpu_result(base_addr, result);
    update_status_word(base_addr, status_word);
}

// 浮点数除法运算
FloatingPointValue float_divide(ulong dividend_mantissa, uint dividend_exp,
                               ulong divisor_mantissa, uint divisor_exp,
                               ushort *control_word) {
    uint precision = get_precision_control(*control_word);
    uint exception_flags = 0;

    // 处理特殊情况
    if (is_zero_or_denormal(dividend_exp)) {
        if (is_zero_or_denormal(divisor_exp)) {
            if (divisor_mantissa == 0) {
                if (dividend_mantissa == 0) {
                    // 0/0 = NaN
                    exception_flags = INVALID_OPERATION;
                    return create_nan_value();
                } else {
                    // x/0 = ±∞
                    exception_flags = DIVIDE_BY_ZERO;
                    bool sign = get_sign(dividend_mantissa) ^ get_sign(divisor_mantissa);
                    return create_infinity_value(sign);
                }
            }
            // 处理非规格化数
            normalize_if_needed(&dividend_mantissa, &dividend_exp);
            normalize_if_needed(&divisor_mantissa, &divisor_exp);
        }
    }

    // 执行除法运算
    FloatingPointValue result = perform_division(
        dividend_mantissa, dividend_exp,
        divisor_mantissa, divisor_exp,
        precision
    );

    update_fpu_flags(exception_flags, control_word);
    return result;
}

// 浮点数转换为整数
void float_to_int(void *result, bool round_to_zero, bool is_signed) {
    ulong base_addr = get_base_address();
    ushort control_word = *(ushort *)(base_addr + FPU_CONTROL_OFFSET);
    long fpu_stack_ptr = base_addr + get_fpu_stack_offset();
    ushort status_word = *(ushort *)(base_addr + FPU_STATUS_OFFSET) & STATUS_MASK;

    ushort exponent = *(ushort *)(fpu_stack_ptr + EXPONENT_OFFSET);
    long mantissa = *(long *)(fpu_stack_ptr + MANTISSA_OFFSET);

    uint exception_flags = 0;
    int int_result;

    if (is_zero_or_denormal(exponent) && mantissa == 0) {
        int_result = 0;
    } else if (is_special_value(exponent)) {
        // 无穷大或NaN转换为整数
        exception_flags = INVALID_OPERATION;
        int_result = INT_INDEFINITE;
    } else {
        // 执行浮点到整数的转换
        int_result = convert_float_to_int(mantissa, exponent,
                                        round_to_zero, is_signed,
                                        &exception_flags);
    }

    *(int*)result = int_result;
    update_fpu_flags(exception_flags, &control_word);
    update_status_word(base_addr, status_word);
}

// 浮点数比较运算
void float_compare(int stack_offset1, int stack_offset2, ulong compare_flags) {
    ulong base_addr = get_base_address();

    // 获取两个操作数
    FloatingPointValue op1 = get_fpu_stack_value(base_addr, stack_offset1);
    FloatingPointValue op2 = get_fpu_stack_value(base_addr, stack_offset2);

    CompareMode mode = (compare_flags >> 2) & 3;
    bool negate_result = (compare_flags >> 4) & 1;
    bool set_flags_only = (compare_flags >> 6) & 1;

    uint compare_result = 0;
    uint exception_flags = 0;

    // 执行比较
    if (mode == COMPARE_EQUAL) {
        compare_result = perform_equality_compare(op1, op2, &exception_flags);
    } else if (mode == COMPARE_LESS_THAN) {
        compare_result = perform_less_than_compare(op1, op2, &exception_flags);
    } else if (mode == COMPARE_ORDERED) {
        compare_result = perform_ordered_compare(op1, op2, &exception_flags);
    } else {
        compare_result = perform_unordered_compare(op1, op2, &exception_flags);
    }

    if (negate_result) {
        compare_result = ~compare_result;
    }

    // 更新状态
    update_compare_flags(base_addr, compare_result, set_flags_only);
    update_fpu_flags(exception_flags, NULL);
}

// 向量比较运算（SIMD）
void vector_compare(int element_count, int result_dest, ulong compare_config) {
    ulong base_addr = get_base_address();

    // 解析配置参数
    bool byte_elements = !(compare_config & 1);
    bool signed_elements = (compare_config >> 1) & 1;
    CompareMode mode = (compare_config >> 2) & 3;
    bool negate_result = (compare_config >> 4) & 1;
    bool find_first_match = (compare_config >> 6) & 1;

    // 获取向量数据
    VectorData vec1 = load_vector_data(base_addr, VECTOR1_OFFSET);
    VectorData vec2 = load_vector_data(base_addr, VECTOR2_OFFSET);

    uint result_mask = 0;

    if (byte_elements) {
        result_mask = compare_byte_vectors(vec1, vec2, mode, element_count);
    } else {
        result_mask = compare_word_vectors(vec1, vec2, mode, element_count);
    }

    if (negate_result) {
        result_mask = ~result_mask;
    }

    // 存储结果
    if (result_dest == 0) {
        store_compare_result_flags(base_addr, result_mask, find_first_match);
    } else {
        store_compare_result_vector(base_addr, result_mask, byte_elements);
    }

    update_vector_flags(base_addr, result_mask != 0, result_mask & 1);
}

// 辅助函数
static ulong get_base_address(void) {
    return (ulong)&stack_var & BASE_ADDRESS_MASK;
}

static uint get_precision_control(ushort control_word) {
    if ((control_word >> 8 & 3) == 2) {
        return PRECISION_64_BIT;
    } else if ((control_word >> 8 & 1) != 0) {
        return PRECISION_80_BIT;
    } else {
        return PRECISION_32_BIT;
    }
}

static bool is_zero_or_denormal(ushort exponent) {
    return (exponent & EXPONENT_MASK) == 0;
}

static bool is_special_value(ushort exponent) {
    return (exponent & EXPONENT_MASK) == EXPONENT_MASK;
}

static FloatingPointValue create_nan_value(void) {
    FloatingPointValue result;
    result.mantissa = NAN_MANTISSA;
    result.exponent = NAN_EXPONENT;
    return result;
}

static void update_fpu_flags(uint exception_flags, ushort *control_word) {
    if (exception_flags != 0) {
        // 更新异常标志
        // 具体实现取决于FPU架构
    }
}
