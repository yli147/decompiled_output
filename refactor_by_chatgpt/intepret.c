// 数据类型定义
typedef enum {
    DATA_TYPE_BYTE = 1,
    DATA_TYPE_WORD = 2, 
    DATA_TYPE_DWORD = 4,
    DATA_TYPE_QWORD = 8
} DataType;

typedef struct {
    long instruction_ptr;
    long context_ptr;
} ExecutionContext;

typedef struct {
    uint32_t flags;
    uint32_t reg_index;
    uint32_t src_reg;
    uint32_t dst_reg;
    DataType data_type;
    DataType operand_type;
    uint8_t next_instruction;
    // ... 其他字段
} Instruction;

// 辅助函数声明
ulong read_memory_value(ExecutionContext *ctx);
void write_memory_value(ExecutionContext *ctx, ulong value);
ulong get_register_value(ExecutionContext *ctx);
void set_register_value(ExecutionContext *ctx, ulong value);
void update_flags(ExecutionContext *ctx, ulong result, uint32_t operation);

// 重构后的主要函数

/**
 * 从内存或寄存器读取值
 */
ulong read_operand_value(ExecutionContext *ctx) {
    Instruction *instr = (Instruction *)ctx->instruction_ptr;
    long *context = (long *)ctx->context_ptr;
    
    if (!(instr->flags & 0x1)) {
        // 直接寄存器访问
        ulong value = context[1][((ulong)instr->reg_index + 4) * 8];
        
        switch (instr->operand_type) {
            case DATA_TYPE_WORD:
                return value & 0xFFFF;
            case DATA_TYPE_DWORD:
                return value & 0xFFFFFFFF;
            default:
                return value;
        }
    } else {
        // 内存访问
        return read_memory_value(ctx);
    }
}

/**
 * 向内存或寄存器写入值
 */
void write_operand_value(ExecutionContext *ctx, ulong value) {
    Instruction *instr = (Instruction *)ctx->instruction_ptr;
    long *context = (long *)ctx->context_ptr;
    
    if (!(instr->flags & 0x1)) {
        // 直接寄存器访问
        long reg_offset = context[1] + ((ulong)instr->reg_index * 8);
        
        switch (instr->operand_type) {
            case DATA_TYPE_WORD:
                *(uint16_t *)(reg_offset + 0x20) = (uint16_t)value;
                break;
            case DATA_TYPE_DWORD:
                *(ulong *)(reg_offset + 0x20) = value & 0xFFFFFFFF;
                break;
            default:
                *(ulong *)(reg_offset + 0x20) = value;
                break;
        }
    } else {
        // 内存访问
        write_memory_value(ctx, value);
    }
}

/**
 * 算术加法指令
 */
long execute_add_instruction(ExecutionContext *ctx) {
    Instruction *instr = (Instruction *)ctx->instruction_ptr;
    long *context = (long *)ctx->context_ptr;
    
    // 读取操作数
    ulong dst_value = *(ulong *)(context[1] + 0x20);
    ulong operand_value = get_operand_value(ctx);
    
    // 根据数据类型截取值
    switch (instr->data_type) {
        case DATA_TYPE_WORD:
            dst_value &= 0xFFFF;
            break;
        case DATA_TYPE_DWORD:
            dst_value &= 0xFFFFFFFF;
            break;
    }
    
    // 执行加法
    ulong result = dst_value + operand_value;
    
    // 写回结果
    switch (instr->data_type) {
        case DATA_TYPE_WORD:
            *(ulong *)(context[1] + 0x20) = 
                (*(ulong *)(context[1] + 0x20) & 0xFFFFFFFFFFFF0000) | (result & 0xFFFF);
            break;
        case DATA_TYPE_DWORD:
            *(ulong *)(context[1] + 0x20) = result & 0xFFFFFFFF;
            break;
        default:
            *(ulong *)(context[1] + 0x20) = result;
            break;
    }
    
    // 更新标志位
    update_flags(context, result, OPERATION_ADD);
    
    // 返回下一条指令地址
    return (ulong)instr->next_instruction + *(long *)(context[1] + 0xA8);
}

/**
 * 算术减法指令
 */
long execute_sub_instruction(ExecutionContext *ctx) {
    Instruction *instr = (Instruction *)ctx->instruction_ptr;
    long *context = (long *)ctx->context_ptr;
    
    ulong dst_value = *(ulong *)(context[1] + 0x20);
    ulong operand_value = get_operand_value(ctx);
    
    switch (instr->data_type) {
        case DATA_TYPE_WORD:
            dst_value &= 0xFFFF;
            break;
        case DATA_TYPE_DWORD:
            dst_value &= 0xFFFFFFFF;
            break;
    }
    
    ulong result = dst_value - operand_value;
    
    switch (instr->data_type) {
        case DATA_TYPE_WORD:
            *(ulong *)(context[1] + 0x20) = 
                (*(ulong *)(context[1] + 0x20) & 0xFFFFFFFFFFFF0000) | (result & 0xFFFF);
            break;
        case DATA_TYPE_DWORD:
            *(ulong *)(context[1] + 0x20) = result & 0xFFFFFFFF;
            break;
        default:
            *(ulong *)(context[1] + 0x20) = result;
            break;
    }
    
    update_flags(context, result, OPERATION_SUB);
    return (ulong)instr->next_instruction + *(long *)(context[1] + 0xA8);
}

/**
 * 位运算AND指令
 */
long execute_and_instruction(ExecutionContext *ctx) {
    Instruction *instr = (Instruction *)ctx->instruction_ptr;
    long *context = (long *)ctx->context_ptr;
    
    ulong dst_value = *(ulong *)(context[1] + 0x20);
    ulong operand_value = get_operand_value(ctx);
    
    switch (instr->data_type) {
        case DATA_TYPE_WORD:
            dst_value &= 0xFFFF;
            break;
        case DATA_TYPE_DWORD:
            dst_value &= 0xFFFFFFFF;
            break;
    }
    
    ulong result = dst_value & operand_value;
    
    switch (instr->data_type) {
        case DATA_TYPE_WORD:
            *(ulong *)(context[1] + 0x20) = 
                (*(ulong *)(context[1] + 0x20) & 0xFFFFFFFFFFFF0000) | (result & 0xFFFF);
            break;
        case DATA_TYPE_DWORD:
            *(ulong *)(context[1] + 0x20) = result & 0xFFFFFFFF;
            break;
        default:
            *(ulong *)(context[1] + 0x20) = result;
            break;
    }
    
    update_flags(context, result, OPERATION_AND);
    return (ulong)instr->next_instruction + *(long *)(context[1] + 0xA8);
}

/**
 * 乘法指令
 */
long execute_mul_instruction(ExecutionContext *ctx) {
    Instruction *instr = (Instruction *)ctx->instruction_ptr;
    long *context = (long *)ctx->context_ptr;
    
    ulong dst_value = *(ulong *)(context[1] + 0x20);
    ulong operand_value = read_operand_value(ctx);
    
    switch (instr->data_type) {
        case DATA_TYPE_WORD: {
            uint32_t result = (uint16_t)dst_value * (uint16_t)operand_value;
            *(uint16_t *)(context[1] + 0x20) = (uint16_t)result;
            *(uint16_t *)(context[1] + 0x30) = (uint16_t)(result >> 16);
            break;
        }
        case DATA_TYPE_DWORD: {
            uint64_t result = (uint32_t)dst_value * (uint32_t)operand_value;
            *(uint32_t *)(context[1] + 0x20) = (uint32_t)result;
            *(uint32_t *)(context[1] + 0x30) = (uint32_t)(result >> 32);
            break;
        }
        default: {
            // 64位乘法需要特殊处理
            ulong result_low = dst_value * operand_value;
            // 计算高位部分...
            *(ulong *)(context[1] + 0x20) = result_low;
            break;
        }
    }
    
    update_flags(context, dst_value, OPERATION_MUL);
    return (ulong)instr->next_instruction + *(long *)(context[1] + 0xA8);
}

/**
 * 数据移动指令
 */
long execute_mov_instruction(ExecutionContext *ctx) {
    Instruction *instr = (Instruction *)ctx->instruction_ptr;
    long *context = (long *)ctx->context_ptr;
    
    // 根据指令类型读取源值
    ulong src_value;
    switch (instr->operand_type) {
        case DATA_TYPE_BYTE:
            src_value = (ulong)*(uint8_t *)(instr + 0x20);
            break;
        case DATA_TYPE_WORD:
            src_value = (ulong)*(uint16_t *)(instr + 0x20);
            break;
        case DATA_TYPE_DWORD:
            src_value = (ulong)*(uint32_t *)(instr + 0x20);
            break;
        default:
            src_value = *(ulong *)(instr + 0x20);
            break;
    }
    
    // 写入目标
    write_operand_value(ctx, src_value);
    
    return (ulong)instr->next_instruction + *(long *)(context[1] + 0xA8);
}

/**
 * 更新标志位的辅助函数
 */
void update_flags(long *context, ulong result, uint32_t operation) {
    // 计算标志位
    uint32_t flags = 0;
    
    // 零标志
    if (result == 0) flags |= FLAG_ZERO;
    
    // 符号标志
    if ((long)result < 0) flags |= FLAG_SIGN;
    
    // 奇偶标志
    uint8_t parity = 0;
    ulong temp = result & 0xFF;
    while (temp) {
        parity ^= 1;
        temp &= temp - 1;
    }
    if (!parity) flags |= FLAG_PARITY;
    
    // 存储标志位
    *(ulong *)(context[1] + 0xD0) = operation | flags;
    *(ulong *)(context[1] + 0xC0) = result;
}

// 定义操作类型枚举
typedef enum {
    OP_ADD = 0,
    OP_SUB,
    OP_CMP,
    OP_AND,
    OP_OR,
    OP_XOR,
    OP_EXCHANGE,
    OP_DIV_UNSIGNED,
    OP_DIV_SIGNED,
    OP_ADD_WITH_CARRY
} operation_type_t;

// 定义数据类型枚举
typedef enum {
    TYPE_BYTE = 1,
    TYPE_WORD = 2,
    TYPE_DWORD = 4,
    TYPE_QWORD = 8
} data_type_t;

// 通用的操作执行函数
static ulong execute_operation(long *param_1, operation_type_t op_type, bool use_memory) {
    long lVar = *param_1;
    long lVar2 = param_1[1];
    char data_type = *(char *)(lVar + 0x29);
    uint flags = *(uint *)(lVar + 0x30);

    // 获取操作数
    ulong operand1, operand2;

    if (use_memory) {
        // 从内存获取第一个操作数
        uint addr = *(uint *)(lVar + 4) & 0x7fffffff;
        if (*(uint *)(lVar + 4) + 0x7ffffffc < 4) {
            operand1 = get_memory_value(param_1, addr - 4, data_type, true);
        } else {
            operand1 = get_memory_value(param_1, addr, data_type, false);
        }

        // 获取第二个操作数
        if ((flags >> 7 & 1) != 0) {
            operand2 = get_register_or_immediate(param_1, operand1);
        } else {
            operand2 = get_second_operand(param_1, flags);
        }
    } else {
        // 从寄存器获取操作数
        operand1 = get_register_value(param_1, data_type);
        operand2 = get_second_operand(param_1, flags);
    }

    // 执行操作
    ulong result = perform_operation(operand1, operand2, op_type);

    // 存储结果
    if ((flags >> 7 & 1) == 0) {
        store_result(param_1, result, use_memory);
    }

    // 设置标志位和调试信息
    set_operation_flags(param_1, op_type, result, operand1, operand2);

    return (ulong)*(byte *)(lVar + 0x2a) + *(long *)(lVar2 + 0xa8);
}

// 获取内存值的辅助函数
static ulong get_memory_value(long *param_1, uint addr, char data_type, bool is_stack) {
    long base = param_1[1];
    if (is_stack) {
        return *(ulong *)(base + (ulong)addr * 8 + 0x21);
    } else {
        return *(ulong *)(base + (ulong)addr * 8 + 0x20);
    }
}

// 获取寄存器值的辅助函数
static ulong get_register_value(long *param_1, char data_type) {
    long lVar = *param_1;
    switch (data_type) {
        case 1: return (ulong)*(char *)(lVar + 0x20);
        case 2: return (ulong)*(short *)(lVar + 0x20);
        case 4: return (ulong)*(int *)(lVar + 0x20);
        default: return 0;
    }
}

// 执行具体操作的函数
static ulong perform_operation(ulong op1, ulong op2, operation_type_t op_type) {
    switch (op_type) {
        case OP_ADD:
            return op1 + op2;
        case OP_SUB:
            return op1 - op2;
        case OP_CMP:
            return op1 - op2; // 比较操作
        case OP_AND:
            return op1 & op2;
        case OP_OR:
            return op1 | op2;
        case OP_XOR:
            return op1 ^ op2;
        case OP_DIV_UNSIGNED:
            return (op2 != 0) ? op1 / op2 : 0;
        case OP_DIV_SIGNED:
            return (op2 != 0) ? (long)op1 / (long)op2 : 0;
        default:
            return 0;
    }
}

// 存储结果的函数
static void store_result(long *param_1, ulong result, bool use_memory) {
    if (use_memory) {
        store_to_memory(param_1, result);
    } else {
        store_to_register(param_1, result);
    }
}

// 设置操作标志位
static void set_operation_flags(long *param_1, operation_type_t op_type,
                               ulong result, ulong op1, ulong op2) {
    long base = param_1[1];

    // 计算操作类型标识
    uint type_bits = get_operation_type_bits(op_type);

    *(ulong *)(base + 0xd0) = (ulong)((int)LZCOUNT(type_bits) + get_base_offset(op_type));
    *(ulong *)(base + 0xc0) = result;
    *(ulong *)(base + 200) = op1; // 或者 op2，根据具体操作
}

// 重构后的具体函数实现
long FUN_8010000c6c0c(long *param_1) {
    return execute_operation(param_1, OP_ADD, true);
}

long FUN_8010000c6c10(long *param_1) {
    return execute_operation(param_1, OP_ADD, true);
}

long FUN_8010000c6fcc(long *param_1) {
    return execute_operation(param_1, OP_CMP, true);
}

long FUN_8010000c714c(long *param_1) {
    return execute_operation(param_1, OP_CMP, false);
}

long FUN_8010000c72fc(long *param_1) {
    return execute_operation(param_1, OP_SUB, true);
}

long FUN_8010000c73d4(long *param_1) {
    return execute_operation(param_1, OP_SUB, false);
}

long FUN_8010000c758c(long *param_1) {
    return execute_operation(param_1, OP_DIV_UNSIGNED, false);
}

long FUN_8010000c7710(long *param_1) {
    return execute_operation(param_1, OP_DIV_SIGNED, false);
}

long FUN_8010000c78a0(long *param_1) {
    return execute_operation(param_1, OP_AND, true);
}

long FUN_8010000c7bac(long *param_1) {
    return execute_operation(param_1, OP_AND, true);
}

long FUN_8010000c8194(long *param_1) {
    return execute_operation(param_1, OP_AND, false);
}

long FUN_8010000c87b0(long *param_1) {
    return execute_operation(param_1, OP_OR, true);
}

long FUN_8010000c8ab0(long *param_1) {
    return execute_operation(param_1, OP_OR, true);
}

long FUN_8010000c9084(long *param_1) {
    return execute_operation(param_1, OP_OR, false);
}

long FUN_8010000c96a4(long *param_1) {
    return execute_operation(param_1, OP_EXCHANGE, true);
}

long FUN_8010000c99fc(long *param_1) {
    return execute_operation(param_1, OP_EXCHANGE, true);
}

long FUN_8010000c9df0(long *param_1) {
    return execute_operation(param_1, OP_XOR, true);
}

long FUN_8010000c9f6c(long *param_1) {
    return execute_operation(param_1, OP_XOR, false);
}

long FUN_8010000ca11c(long *param_1) {
    return execute_operation(param_1, OP_XOR, true);
}

long FUN_8010000ca1f4(long *param_1) {
    return execute_operation(param_1, OP_XOR, false);
}

long FUN_8010000ca3ac(long *param_1) {
    return execute_operation(param_1, OP_ADD_WITH_CARRY, true);
}

// 虚拟机状态结构
typedef struct {
    long *instruction_ptr;  // 指令指针
    long *context_ptr;      // 上下文指针
} vm_state_t;

// 指令结构
typedef struct {
    uint32_t opcode;
    uint32_t operand1;
    uint32_t operand2;
    uint32_t flags;
    // ... 其他字段
} instruction_t;

// 上下文结构
typedef struct {
    uint8_t registers[0x500];  // 寄存器区域
    uint64_t result_reg;       // 结果寄存器 (offset 0xc0)
    uint64_t status_reg;       // 状态寄存器 (offset 0xd0)
    uint64_t operand_reg;      // 操作数寄存器 (offset 0xc8)
    uint64_t base_addr;        // 基地址 (offset 0xa8)
    bool carry_flag;           // 进位标志 (offset 0x500)
} vm_context_t;

// 获取操作数值
static uint64_t get_operand_value(vm_state_t *state, uint8_t operand_type, uint32_t operand_data) {
    switch (operand_type) {
        case 0x01: return (int8_t)operand_data;   // 8位有符号
        case 0x02: return (int16_t)operand_data;  // 16位有符号
        case 0x04: return (int32_t)operand_data;  // 32位有符号
        default:   return operand_data;           // 64位
    }
}

// 设置标志位
static void set_flags(vm_context_t *ctx, uint64_t result, uint64_t operand) {
    ctx->result_reg = result;
    ctx->operand_reg = operand;
}

// ADD指令 - 加法运算
long vm_add_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t *)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t *)state->context_ptr[1];

    // 获取第一个操作数
    uint64_t operand1 = get_register_value(ctx, instr->operand1);

    // 处理进位标志
    if (ctx->carry_flag) {
        operand1 += 1;
    }

    // 获取第二个操作数
    uint64_t operand2;
    if (instr->flags & 0x80) {
        // 内存操作数
        operand2 = get_memory_operand(state, operand1 & 0xff);
    } else {
        // 寄存器操作数
        operand2 = get_register_operand(state);
    }

    // 执行加法
    uint64_t result = (operand1 + operand2) & 0xff;

    // 更新内存/寄存器
    update_result(state, result);

    // 设置状态
    ctx->status_reg = 0x35;  // ADD指令标识
    set_flags(ctx, result, operand1);

    return get_next_instruction_address(state);
}

// SUB指令 - 减法运算
long vm_sub_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t *)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t *)state->context_ptr[1];

    uint64_t operand1 = get_register_value(ctx, instr->operand1);

    if (ctx->carry_flag) {
        operand1 += 1;
    }

    uint64_t operand2;
    if (instr->flags & 0x80) {
        operand2 = get_memory_operand(state, operand1 & 0xff);
    } else {
        operand2 = get_register_operand(state);
    }

    // 执行减法
    uint64_t result = (operand1 - operand2) & 0xff;

    update_result(state, result);

    ctx->status_reg = 0x39;  // SUB指令标识
    set_flags(ctx, result, operand1);

    return get_next_instruction_address(state);
}

// MUL指令 - 乘法运算
long vm_mul_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t *)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t *)state->context_ptr[1];

    uint64_t operand1 = get_register_value(ctx, instr->operand1);
    uint64_t operand2 = get_register_value(ctx, instr->operand2);

    // 执行乘法
    uint64_t result_low, result_high;
    if (instr->operand_size == 2) {
        // 16位乘法
        uint32_t product = (uint16_t)operand1 * (uint16_t)operand2;
        result_low = product & 0xffff;
        result_high = product >> 16;
    } else if (instr->operand_size == 4) {
        // 32位乘法
        uint64_t product = (uint32_t)operand1 * (uint32_t)operand2;
        result_low = product & 0xffffffff;
        result_high = product >> 32;
    } else {
        // 64位乘法
        // 需要使用128位运算
        result_low = operand1 * operand2;
        result_high = multiply_high_64(operand1, operand2);
    }

    // 存储结果
    store_register(ctx, instr->dest_reg, result_low);
    store_register(ctx, instr->dest_reg + 1, result_high);

    return get_next_instruction_address(state);
}

// SHL指令 - 左移运算
long vm_shl_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t *)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t *)state->context_ptr[1];

    uint64_t value = get_register_operand(state);
    uint32_t shift_count = get_shift_count(instr);

    if (shift_count == 0) {
        // 无移位
        update_result(state, value);
        return get_next_instruction_address(state);
    }

    // 执行左移
    uint64_t result = value << (shift_count & 0x1f);

    update_result(state, result);

    ctx->status_reg = 0x1d;  // SHL指令标识
    set_flags(ctx, value, shift_count);

    return get_next_instruction_address(state);
}

// SHR指令 - 右移运算
long vm_shr_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t *)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t *)state->context_ptr[1];

    uint64_t value = get_register_operand(state);
    uint32_t shift_count = get_shift_count(instr);

    if (shift_count == 0) {
        update_result(state, value);
        return get_next_instruction_address(state);
    }

    // 执行右移
    uint64_t result = value >> (shift_count & 0x1f);

    update_result(state, result);

    ctx->status_reg = 0x21;  // SHR指令标识
    set_flags(ctx, value, shift_count);

    return get_next_instruction_address(state);
}

// ROL指令 - 循环左移
long vm_rol_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t *)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t *)state->context_ptr[1];

    uint64_t value = get_register_operand(state);
    uint32_t rotate_count = get_rotate_count(instr) & 7;  // 只取低3位

    if (rotate_count == 0) {
        update_result(state, value);
        return get_next_instruction_address(state);
    }

    // 执行8位循环左移
    uint8_t byte_val = (uint8_t)value;
    uint8_t result = (byte_val << rotate_count) | (byte_val >> (8 - rotate_count));

    update_result(state, result);

    ctx->status_reg = 0x25;  // ROL指令标识
    set_flags(ctx, value, rotate_count);

    return get_next_instruction_address(state);
}

// ROR指令 - 循环右移
long vm_ror_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t *)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t *)state->context_ptr[1];

    uint64_t value = get_register_operand(state);
    uint32_t rotate_count = get_rotate_count(instr) & 7;

    if (rotate_count == 0) {
        update_result(state, value);
        return get_next_instruction_address(state);
    }

    // 执行8位循环右移
    uint8_t byte_val = (uint8_t)value;
    uint8_t result = (byte_val >> rotate_count) | (byte_val << (8 - rotate_count));

    update_result(state, result);

    ctx->status_reg = 0x29;  // ROR指令标识
    set_flags(ctx, value, rotate_count);

    return get_next_instruction_address(state);
}

// BSWAP指令 - 字节序交换
long vm_bswap_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t *)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t *)state->context_ptr[1];

    uint64_t value = get_register_value(ctx, instr->operand1);
    uint64_t result;

    switch (instr->operand_size) {
        case 2:  // 16位字节交换
            result = ((value & 0xff) << 8) | ((value & 0xff00) >> 8);
            break;
        case 4:  // 32位字节交换
            result = __builtin_bswap32((uint32_t)value);
            break;
        default: // 64位字节交换
            result = __builtin_bswap64(value);
            break;
    }

    store_register(ctx, instr->dest_reg, result);

    return get_next_instruction_address(state);
}

// CMP指令 - 比较运算
long vm_cmp_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t *)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t *)state->context_ptr[1];

    uint64_t operand1 = get_register_value(ctx, instr->operand1);
    uint64_t operand2 = get_register_value(ctx, instr->operand2);

    // 执行比较（实际是减法，但不保存结果）
    uint64_t result = operand1 - operand2;

    // 设置标志位
    ctx->status_reg = 0x0d;  // CMP指令标识
    set_flags(ctx, operand1, operand2);

    return get_next_instruction_address(state);
}

// BIT指令 - 位测试
long vm_bit_test_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t *)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t *)state->context_ptr[1];

    uint64_t value = get_register_value(ctx, instr->operand1);
    uint32_t bit_pos = get_bit_position(instr);
    uint32_t operand_size = instr->operand_size * 8;

    // 测试指定位
    bool bit_set = (value & (1ULL << (bit_pos & (operand_size - 1)))) != 0;

    ctx->carry_flag = bit_set;

    return get_next_instruction_address(state);
}

// 辅助函数实现
static uint64_t get_register_value(vm_context_t *ctx, uint32_t reg_index) {
    return *(uint64_t *)&ctx->registers[reg_index * 8];
}

static void store_register(vm_context_t *ctx, uint32_t reg_index, uint64_t value) {
    *(uint64_t *)&ctx->registers[reg_index * 8] = value;
}

static uint64_t get_next_instruction_address(vm_state_t *state) {
    instruction_t *instr = (instruction_t *)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t *)state->context_ptr[1];

    return (uint64_t)instr->next_addr + ctx->base_addr;
}

// 位选择操作 - 根据掩码选择位
long bit_select_operation(long *param_1) {
    long *local_8 = param_1;
    ulong mask = FUN_8010000c2af0(&local_8);

    long instruction = *param_1;
    long context = param_1[1];
    char data_type = *(char *)(instruction + 0x29);

    // 获取目标地址的值
    long target_addr = context + (ulong)*(uint *)(instruction + 0x18) * 8;
    ulong target_value;

    if (data_type == '\x02') {
        target_value = (ulong)*(ushort *)(target_addr + 0x20);
    } else if (data_type == '\x04') {
        target_value = *(ulong *)(target_addr + 0x20) & 0xffffffff;
    } else {
        target_value = *(ulong *)(target_addr + 0x20);
    }

    // 执行位选择操作
    ulong result = 0;
    ulong bit_count = 0;
    uint bit_width = ((int)data_type & 0x1f) ? (int)data_type << 3 : 0;

    if (bit_width == 0) return get_next_instruction_address(param_1);

    for (ulong i = 0; i < bit_width; i++) {
        if ((mask >> (i & 0x3f)) & 1) {
            if ((target_value >> (i & 0x3f)) & 1) {
                result |= 1L << (bit_count & 0x3f);
            }
            bit_count++;
        }
    }

    // 存储结果
    store_result_by_type(param_1, result, data_type);
    return get_next_instruction_address(param_1);
}

// 位旋转操作
long bit_rotate_operation(long *param_1) {
    long *local_8 = param_1;
    ulong value = FUN_8010000c2af0(&local_8);

    long instruction = *param_1;
    char shift_type = *(char *)(instruction + 0x28);
    char data_type = *(char *)(instruction + 0x29);

    ulong shift_amount;
    if (shift_type == '\x01') {
        shift_amount = (ulong)*(byte *)(instruction + 0x20);
    } else if (shift_type == '\x02') {
        shift_amount = (ulong)*(ushort *)(instruction + 0x20);
    } else if (shift_type == '\x04') {
        shift_amount = (ulong)*(uint *)(instruction + 0x20);
    } else {
        shift_amount = 0;
    }

    // 执行旋转操作
    ulong result;
    if (data_type == '\b') {
        result = value >> (shift_amount & 0x3f) | value << (0x40 - (shift_amount & 0x3f));
    } else {
        uint bit_width = (int)data_type * 8;
        result = value << ((ulong)(bit_width - (shift_amount & 0x1f)) & 0x3f) |
                 value >> (shift_amount & 0x1f);
    }

    store_result_by_type(param_1, result, data_type);
    return get_next_instruction_address(param_1);
}

// 算术右移
long arithmetic_right_shift(long *param_1) {
    long *local_8 = param_1;
    long value = FUN_8010000c2af0(&local_8);

    long instruction = *param_1;
    char data_type = *(char *)(instruction + 0x29);
    ulong shift_amount = get_shift_amount_from_register(param_1, instruction);

    long result;
    if (data_type == '\x02') {
        result = (short)value >> (shift_amount & 0x1f);
        *(short *)(get_result_address(param_1) + 0x20) = (short)result;
    } else if (data_type == '\x04') {
        result = (int)value >> (shift_amount & 0x1f);
        *(ulong *)(get_result_address(param_1) + 0x20) = result & 0xffffffff;
    } else {
        result = data_type == '\b' ? value >> (shift_amount & 0x3f) :
                                    (long)((int)value) >> (shift_amount & 0x1f);
        *(long *)(get_result_address(param_1) + 0x20) = result;
    }

    return get_next_instruction_address(param_1);
}

// 逻辑右移
long logical_right_shift(long *param_1) {
    long *local_8 = param_1;
    ulong value = FUN_8010000c2af0(&local_8);

    long instruction = *param_1;
    char data_type = *(char *)(instruction + 0x29);
    ulong shift_amount = get_shift_amount_from_register(param_1, instruction);

    ulong mask = (data_type == '\b') ? 0x3f : 0x1f;
    ulong result = value >> (shift_amount & mask);

    store_result_by_type(param_1, result, data_type);
    return get_next_instruction_address(param_1);
}

// 左移
long left_shift(long *param_1) {
    long *local_8 = param_1;
    long value = FUN_8010000c2af0(&local_8);

    long instruction = *param_1;
    char data_type = *(char *)(instruction + 0x29);
    ulong shift_amount = get_shift_amount_from_register(param_1, instruction);

    ulong mask = (data_type == '\b') ? 0x3f : 0x1f;
    long result = value << (shift_amount & mask);

    if (data_type == '\x04') {
        *(ulong *)(get_result_address(param_1) + 0x20) = (ulong)(uint)result;
    } else {
        *(long *)(get_result_address(param_1) + 0x20) = result;
    }

    return get_next_instruction_address(param_1);
}

// 条件分支指令
long conditional_branch(long *param_1) {
    long *local_8 = param_1;
    long condition_value = FUN_8010000c2af0(&local_8);

    FUN_8010000c2900(); // 可能是某种状态更新

    local_8 = param_1;
    FUN_8010000c3050(&local_8, condition_value + 1);

    // 设置分支相关的状态
    uint status_bits = calculate_status_bits(param_1);
    *(ulong *)(param_1[1] + 0xd0) = (ulong)(LZCOUNT(status_bits) + 0x41);
    *(long *)(param_1[1] + 0xc0) = condition_value + 1;
    *(undefined8 *)(param_1[1] + 200) = 0;

    return get_next_instruction_address(param_1);
}

// 无条件跳转
long unconditional_jump(long *param_1) {
    long instruction = *param_1;
    char addr_type = *(char *)(instruction + 0x28);
    long jump_target;

    if (addr_type == '\x01') {
        jump_target = (long)*(char *)(instruction + 0x20);
    } else if (addr_type == '\x02') {
        jump_target = (long)*(short *)(instruction + 0x20);
    } else if (addr_type == '\x04') {
        jump_target = (long)*(int *)(instruction + 0x20);
    } else {
        jump_target = 0;
    }

    return (ulong)*(byte *)(instruction + 0x2a) +
           *(long *)(param_1[1] + 0xa8) + jump_target;
}

// 条件分支指令
long conditional_branch(long *param_1) {
    long *local_8 = param_1;
    long condition_value = FUN_8010000c2af0(&local_8);

    FUN_8010000c2900(); // 可能是某种状态更新

    local_8 = param_1;
    FUN_8010000c3050(&local_8, condition_value + 1);

    // 设置分支相关的状态
    uint status_bits = calculate_status_bits(param_1);
    *(ulong *)(param_1[1] + 0xd0) = (ulong)(LZCOUNT(status_bits) + 0x41);
    *(long *)(param_1[1] + 0xc0) = condition_value + 1;
    *(undefined8 *)(param_1[1] + 200) = 0;

    return get_next_instruction_address(param_1);
}

// 无条件跳转
long unconditional_jump(long *param_1) {
    long instruction = *param_1;
    char addr_type = *(char *)(instruction + 0x28);
    long jump_target;

    if (addr_type == '\x01') {
        jump_target = (long)*(char *)(instruction + 0x20);
    } else if (addr_type == '\x02') {
        jump_target = (long)*(short *)(instruction + 0x20);
    } else if (addr_type == '\x04') {
        jump_target = (long)*(int *)(instruction + 0x20);
    } else {
        jump_target = 0;
    }

    return (ulong)*(byte *)(instruction + 0x2a) +
           *(long *)(param_1[1] + 0xa8) + jump_target;
}

// 获取下一条指令地址
static inline long get_next_instruction_address(long *param_1) {
    return (ulong)*(byte *)(*param_1 + 0x2a) + *(long *)(param_1[1] + 0xa8);
}

// 根据数据类型存储结果
static void store_result_by_type(long *param_1, ulong value, char data_type) {
    long result_addr = get_result_address(param_1);

    if (data_type == '\x02') {
        *(short *)(result_addr + 0x20) = (short)value;
    } else if (data_type == '\x04') {
        *(ulong *)(result_addr + 0x20) = value & 0xffffffff;
    } else {
        *(ulong *)(result_addr + 0x20) = value;
    }
}

// 获取结果存储地址
static long get_result_address(long *param_1) {
    return param_1[1] + (ulong)*(uint *)(*param_1 + 4) * 8;
}

// 计算状态位
static uint calculate_status_bits(long *param_1) {
    uint bits = ((int)*(char *)(*param_1 + 0x29) & 0xaaaaaaaaU) >> 1 |
                ((int)*(char *)(*param_1 + 0x29) & 0x55555555U) << 1;
    bits = (bits & 0xcccccccc) >> 2 | (bits & 0x33333333) << 2;
    bits = (bits & 0xf0f0f0f0) >> 4 | (bits & 0xf0f0f0f) << 4;
    bits = (bits & 0xff00ff00) >> 8 | (bits & 0xff00ff) << 8;
    return bits >> 0x10 | bits << 0x10;
}

// 公共数据结构和常量定义
typedef struct {
    long *instruction_ptr;
    long *context_ptr;
} vm_state_t;

typedef struct {
    uint32_t opcode;
    uint32_t flags;
    uint32_t operand1;
    uint32_t operand2;
    uint32_t operand3;
    uint32_t operand4;
    uint32_t operand5;
    uint8_t size;
    uint8_t next_offset;
    // ... 其他字段
} instruction_t;

typedef struct {
    uint64_t registers[32];  // 通用寄存器
    uint64_t stack_pointer;
    uint64_t base_pointer;
    uint64_t program_counter;
    uint8_t flags[16];       // 各种标志位
    uint64_t memory_base;
    // ... 其他上下文字段
} vm_context_t;

// 公共辅助函数
static inline uint64_t get_next_pc(vm_state_t *state) {
    instruction_t *instr = (instruction_t*)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t*)state->context_ptr[1];
    return (uint64_t)instr->next_offset + ctx->program_counter;
}

static inline void update_stack_pointer(vm_context_t *ctx, instruction_t *instr, int direction) {
    uint32_t size = (uint32_t)instr->size;
    uint64_t offset = direction > 0 ? size : -size;
    
    if ((instr->flags & 0x10000) != 0) {
        ctx->stack_pointer = (int64_t)ctx->stack_pointer + offset;
    } else {
        ctx->stack_pointer = (uint64_t)((int32_t)ctx->stack_pointer + (int32_t)offset);
    }
}

static uint64_t read_memory_value(vm_context_t *ctx, uint64_t addr, uint8_t size, uint32_t mem_flags) {
    uint64_t *ptr = (uint64_t*)addr;
    
    // 检查内存访问权限
    if (mem_flags - 4 > 1) {
        // 使用内存管理单元检查
        if (should_use_mmu() && (get_mmu_flags() & 1) != 0) {
            return read_direct_memory(ptr, size);
        }
    }
    
    // 通过内存管理器读取
    uint64_t base = get_memory_base();
    uint64_t limit = get_memory_limit();
    
    if (limit < addr + size - 1) {
        trigger_exception(0xd, 0);  // 内存访问异常
        return 0;
    }
    
    return read_managed_memory(addr + base, size);
}

static void write_memory_value(vm_context_t *ctx, uint64_t addr, uint64_t value, uint8_t size, uint32_t mem_flags) {
    // 类似read_memory_value的实现
    if (mem_flags - 4 > 1) {
        if (should_use_mmu() && (get_mmu_flags() & 1) != 0) {
            write_direct_memory((void*)addr, value, size);
            return;
        }
    }
    
    uint64_t base = get_memory_base();
    uint64_t limit = get_memory_limit();
    
    if (limit < addr + size - 1) {
        trigger_exception(0xd, 0);
        return;
    }
    
    write_managed_memory(addr + base, value, size);
}

// 重构后的指令处理函数

// 内存读取指令 (原FUN_8010000d9624等)
static uint64_t vm_load_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t*)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t*)state->context_ptr[1];
    
    uint8_t size = instr->size;
    uint32_t flags = instr->flags;
    uint64_t addr;
    
    // 计算地址
    if ((flags & 0x10000) != 0) {
        addr = ctx->stack_pointer;
    } else {
        addr = (uint32_t)ctx->stack_pointer;
    }
    
    // 读取值
    uint64_t value = read_memory_value(ctx, addr, size, instr->operand5);
    
    // 更新栈指针
    update_stack_pointer(ctx, instr, 1);
    
    // 将值推入栈
    push_to_stack(state, value);
    
    return get_next_pc(state);
}

// 内存写入指令 (原FUN_8010000d9ca0等)
static uint64_t vm_store_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t*)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t*)state->context_ptr[1];
    
    // 从栈中弹出值
    uint64_t value = pop_from_stack(state);
    
    uint8_t size = instr->size;
    uint32_t flags = instr->flags;
    uint64_t addr;
    
    // 计算地址
    if ((flags & 0x10000) != 0) {
        addr = ctx->stack_pointer - size;
    } else {
        addr = (uint32_t)(ctx->stack_pointer - size);
    }
    
    // 写入值
    write_memory_value(ctx, addr, value, size, instr->operand5);
    
    // 更新栈指针
    update_stack_pointer(ctx, instr, -1);
    
    return get_next_pc(state);
}

// 算术运算指令
static uint64_t vm_arithmetic_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t*)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t*)state->context_ptr[1];
    
    uint64_t operand2 = pop_from_stack(state);
    uint64_t operand1 = pop_from_stack(state);
    uint64_t result = 0;
    
    switch (instr->opcode) {
        case OP_ADD:
            result = operand1 + operand2;
            break;
        case OP_SUB:
            result = operand1 - operand2;
            break;
        case OP_MUL:
            result = operand1 * operand2;
            break;
        case OP_DIV:
            if (operand2 == 0) {
                trigger_exception(DIVIDE_BY_ZERO, get_next_pc(state));
                return get_next_pc(state);
            }
            result = operand1 / operand2;
            break;
        // ... 其他运算
    }
    
    push_to_stack(state, result);
    return get_next_pc(state);
}

// 条件跳转指令
static uint64_t vm_conditional_jump(vm_state_t *state) {
    instruction_t *instr = (instruction_t*)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t*)state->context_ptr[1];
    
    bool condition = false;
    
    switch (instr->opcode) {
        case OP_JZ:  // 零标志跳转
            condition = ctx->flags[FLAG_ZERO] != 0;
            break;
        case OP_JNZ: // 非零标志跳转
            condition = ctx->flags[FLAG_ZERO] == 0;
            break;
        case OP_JC:  // 进位标志跳转
            condition = ctx->flags[FLAG_CARRY] != 0;
            break;
        // ... 其他条件
    }
    
    if (condition) {
        return calculate_jump_target(state);
    }
    
    return get_next_pc(state);
}

// 系统调用指令
static uint64_t vm_system_call(vm_state_t *state) {
    instruction_t *instr = (instruction_t*)state->instruction_ptr[0];
    vm_context_t *ctx = (vm_context_t*)state->context_ptr[1];
    
    uint32_t syscall_num = get_syscall_number(instr);
    
    switch (syscall_num) {
        case SYS_EXIT:
            trigger_exception(1, 0);
            break;
        case SYS_ABORT:
            trigger_exception(3, get_next_pc(state));
            break;
        case SYS_DEBUG:
            handle_debug_syscall(state);
            break;
        default:
            trigger_exception(0xd, 0);  // 非法系统调用
            break;
    }
    
    return get_next_pc(state);
}

// 指令分发表
typedef uint64_t (*instruction_handler_t)(vm_state_t *state);

static const instruction_handler_t instruction_handlers[] = {
    [OP_LOAD]     = vm_load_instruction,
    [OP_STORE]    = vm_store_instruction,
    [OP_ADD]      = vm_arithmetic_instruction,
    [OP_SUB]      = vm_arithmetic_instruction,
    [OP_MUL]      = vm_arithmetic_instruction,
    [OP_DIV]      = vm_arithmetic_instruction,
    [OP_JZ]       = vm_conditional_jump,
    [OP_JNZ]      = vm_conditional_jump,
    [OP_SYSCALL]  = vm_system_call,
    // ... 其他指令
};

// 主执行函数
uint64_t execute_instruction(vm_state_t *state) {
    instruction_t *instr = (instruction_t*)state->instruction_ptr[0];
    
    if (instr->opcode >= ARRAY_SIZE(instruction_handlers) || 
        instruction_handlers[instr->opcode] == NULL) {
        trigger_exception(ILLEGAL_INSTRUCTION, get_next_pc(state));
        return get_next_pc(state);
    }
    
    return instruction_handlers[instr->opcode](state);
}
