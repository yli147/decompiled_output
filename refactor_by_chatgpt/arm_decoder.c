// ARM64指令解码器重构版本

#include <stdint.h>
#include <stdbool.h>

// 基础类型定义
typedef uint64_t ulong;
typedef uint32_t uint;
typedef int32_t int32;
typedef uint8_t byte;

// 指令解码结果结构体
typedef struct {
    uint32_t opcode;
    uint32_t operand_size;
    uint32_t reg_count;
    uint32_t operands[4];
    bool is_64bit;
    bool sets_flags;
    uint32_t flags;
} instruction_t;

// 寄存器类型枚举
typedef enum {
    REG_TYPE_W = 0,  // 32位寄存器
    REG_TYPE_X = 1   // 64位寄存器
} reg_type_t;

// 移位类型枚举
typedef enum {
    SHIFT_LSL = 0,
    SHIFT_LSR = 1,
    SHIFT_ASR = 2,
    SHIFT_ROR = 3
} shift_type_t;

// 条件码枚举
typedef enum {
    COND_EQ = 0, COND_NE = 1, COND_CS = 2, COND_CC = 3,
    COND_MI = 4, COND_PL = 5, COND_VS = 6, COND_VC = 7,
    COND_HI = 8, COND_LS = 9, COND_GE = 10, COND_LT = 11,
    COND_GT = 12, COND_LE = 13, COND_AL = 14, COND_NV = 15
} condition_t;

// 工具函数：提取位域
static inline uint32_t extract_bits(uint32_t value, int start, int length) {
    return (value >> start) & ((1U << length) - 1);
}

// 工具函数：符号扩展
static inline int32_t sign_extend(uint32_t value, int bits) {
    uint32_t sign_bit = 1U << (bits - 1);
    return (value ^ sign_bit) - sign_bit;
}

// 工具函数：检查寄存器类型
static inline reg_type_t get_reg_type(uint32_t instruction) {
    return (instruction & 0x80000000) ? REG_TYPE_X : REG_TYPE_W;
}

// 解码MOV立即数指令
static int decode_mov_immediate(instruction_t *instr, uint32_t raw_instr) {
    // 提取字段
    uint32_t rd = extract_bits(raw_instr, 0, 5);
    uint32_t imm16 = extract_bits(raw_instr, 5, 16);
    uint32_t hw = extract_bits(raw_instr, 21, 2);
    bool is_64bit = (raw_instr & 0x80000000) != 0;
    uint32_t opc = extract_bits(raw_instr, 29, 2);
    
    // 验证指令格式
    if (extract_bits(raw_instr, 23, 6) != 0x25) {
        return -1; // 无效指令
    }
    
    // 设置指令信息
    instr->is_64bit = is_64bit;
    instr->operands[0] = rd;
    
    // 计算立即数
    uint64_t immediate = (uint64_t)imm16 << (hw * 16);
    
    switch (opc) {
        case 0: // MOVN
            instr->opcode = 0x290; // MOVN操作码
            instr->operands[1] = is_64bit ? ~immediate : (~immediate & 0xFFFFFFFF);
            break;
        case 2: // MOVZ
            instr->opcode = 0x291; // MOVZ操作码
            instr->operands[1] = immediate;
            break;
        case 3: // MOVK
            instr->opcode = 0x292; // MOVK操作码
            instr->operands[1] = immediate;
            instr->operands[2] = hw; // 保存hw字段用于MOVK
            break;
        default:
            return -1; // 无效操作码
    }
    
    instr->reg_count = (opc == 3) ? 3 : 2;
    return 0;
}

// 解码算术逻辑指令（寄存器操作数）
static int decode_arithmetic_register(instruction_t *instr, uint32_t raw_instr) {
    // 提取字段
    uint32_t rd = extract_bits(raw_instr, 0, 5);
    uint32_t rn = extract_bits(raw_instr, 5, 5);
    uint32_t imm6 = extract_bits(raw_instr, 10, 6);
    uint32_t rm = extract_bits(raw_instr, 16, 5);
    uint32_t shift = extract_bits(raw_instr, 22, 2);
    bool is_64bit = (raw_instr & 0x80000000) != 0;
    bool set_flags = (raw_instr & 0x20000000) != 0;
    uint32_t opc = extract_bits(raw_instr, 29, 2);
    
    // 设置基本信息
    instr->is_64bit = is_64bit;
    instr->sets_flags = set_flags;
    instr->operands[0] = rd;
    instr->operands[1] = rn;
    instr->operands[2] = rm;
    instr->reg_count = 3;
    
    // 处理移位
    if (imm6 != 0) {
        instr->operands[3] = (shift << 6) | imm6;
        instr->reg_count = 4;
    }
    
    // 确定操作码
    switch (opc) {
        case 0: // ADD/ADDS
            instr->opcode = set_flags ? 0x408 : 0x409;
            break;
        case 1: // SUB/SUBS
            instr->opcode = set_flags ? 0x40A : 0x40B;
            break;
        default:
            return -1;
    }
    
    // 特殊情况处理：MOV指令
    if (opc == 1 && rn == 31 && imm6 == 0 && !set_flags) {
        instr->opcode = 0x291; // MOV
        instr->operands[1] = rm;
        instr->reg_count = 2;
    }
    
    return 0;
}

// 解码算术逻辑指令（立即数操作数）
static int decode_arithmetic_immediate(instruction_t *instr, uint32_t raw_instr) {
    // 提取字段
    uint32_t rd = extract_bits(raw_instr, 0, 5);
    uint32_t rn = extract_bits(raw_instr, 5, 5);
    uint32_t imm12 = extract_bits(raw_instr, 10, 12);
    uint32_t shift = extract_bits(raw_instr, 22, 2);
    bool is_64bit = (raw_instr & 0x80000000) != 0;
    bool set_flags = (raw_instr & 0x20000000) != 0;
    uint32_t opc = extract_bits(raw_instr, 29, 2);
    
    // 验证shift字段（只能是0或1）
    if (shift > 1) {
        return -1;
    }
    
    // 计算立即数
    uint32_t immediate = imm12;
    if (shift == 1) {
        immediate <<= 12;
    }
    
    // 设置指令信息
    instr->is_64bit = is_64bit;
    instr->sets_flags = set_flags;
    instr->operands[0] = rd;
    instr->operands[1] = rn;
    instr->operands[2] = immediate;
    instr->reg_count = 3;
    
    // 确定操作码
    switch (opc) {
        case 0: // ADD/ADDS
            instr->opcode = set_flags ? 0x408 : 0x409;
            break;
        case 1: // SUB/SUBS
            instr->opcode = set_flags ? 0x40A : 0x40B;
            break;
        case 2: // AND/ANDS
            instr->opcode = set_flags ? 0x40C : 0x40D;
            break;
        case 3: // ORR
            instr->opcode = 0x40E;
            break;
        default:
            return -1;
    }
    
    return 0;
}

// 解码逻辑指令（位掩码立即数）
static int decode_logical_bitmask(instruction_t *instr, uint32_t raw_instr) {
    // 提取字段
    uint32_t rd = extract_bits(raw_instr, 0, 5);
    uint32_t rn = extract_bits(raw_instr, 5, 5);
    uint32_t imms = extract_bits(raw_instr, 10, 6);
    uint32_t immr = extract_bits(raw_instr, 16, 6);
    uint32_t n = extract_bits(raw_instr, 22, 1);
    bool is_64bit = (raw_instr & 0x80000000) != 0;
    bool set_flags = (raw_instr & 0x20000000) != 0;
    uint32_t opc = extract_bits(raw_instr, 29, 2);
    
    // 解码位掩码（这里简化处理）
    uint64_t bitmask = decode_bitmask(n, imms, immr, is_64bit);
    if (bitmask == 0) {
        return -1; // 无效位掩码
    }
    
    // 设置指令信息
    instr->is_64bit = is_64bit;
    instr->sets_flags = set_flags;
    instr->operands[0] = rd;
    instr->operands[1] = rn;
    instr->operands[2] = (uint32_t)bitmask; // 简化处理
    instr->reg_count = 3;
    
    // 确定操作码
    switch (opc) {
        case 0: // AND/ANDS
            instr->opcode = set_flags ? 0x40C : 0x40D;
            break;
        case 1: // ORR
            instr->opcode = 0x40E;
            break;
        case 2: // EOR
            instr->opcode = 0x40F;
            break;
        default:
            return -1;
    }
    
    return 0;
}

// 解码分支指令
static int decode_branch(instruction_t *instr, uint32_t raw_instr) {
    // 无条件分支
    if ((raw_instr & 0xFC000000) == 0x14000000) {
        // B指令
        int32_t offset = sign_extend(extract_bits(raw_instr, 0, 26), 26) << 2;
        instr->opcode = 0x3F8; // B操作码
        instr->operands[0] = offset;
        instr->reg_count = 1;
        return 0;
    }
    
    // BL指令
    if ((raw_instr & 0xFC000000) == 0x94000000) {
        int32_t offset = sign_extend(extract_bits(raw_instr, 0, 26), 26) << 2;
        instr->opcode = 0x3F9; // BL操作码
        instr->operands[0] = offset;
        instr->reg_count = 1;
        return 0;
    }
    
    // 条件分支
    if ((raw_instr & 0xFF000010) == 0x54000000) {
        int32_t offset = sign_extend(extract_bits(raw_instr, 5, 19), 19) << 2;
        uint32_t cond = extract_bits(raw_instr, 0, 4);
        instr->opcode = 0x3FA; // B.cond操作码
        instr->operands[0] = offset;
        instr->operands[1] = cond;
        instr->reg_count = 2;
        return 0;
    }
    
    return -1;
}

// 主解码函数
int decode_instruction(instruction_t *instr, uint32_t raw_instr) {
    if (!instr) {
        return -1;
    }
    
    // 初始化结构体
    memset(instr, 0, sizeof(instruction_t));
    
    // 根据指令格式进行解码
    uint32_t op0 = extract_bits(raw_instr, 25, 4);
    
    switch (op0) {
        case 0x8: case 0x9: // 数据处理-立即数
            if ((raw_instr & 0x1F800000) == 0x12800000) {
                return decode_mov_immediate(instr, raw_instr);
            } else if ((raw_instr & 0x1F000000) == 0x11000000) {
                return decode_arithmetic_immediate(instr, raw_instr);
            } else if ((raw_instr & 0x1F800000) == 0x12000000) {
                return decode_logical_bitmask(instr, raw_instr);
            }
            break;
            
        case 0xA: case 0xB: // 数据处理-寄存器
            if ((raw_instr & 0x1F200000) == 0x0A000000) {
                return decode_arithmetic_register(instr, raw_instr);
            }
            break;
            
        case 0x5: case 0x7: // 分支指令
            return decode_branch(instr, raw_instr);
            
        default:
            break;
    }
    
    return -1; // 未识别的指令
}

// 位掩码解码辅助函数（简化版本）
static uint64_t decode_bitmask(uint32_t n, uint32_t imms, uint32_t immr, bool is_64bit) {
    // 这里是简化的位掩码解码逻辑
    // 实际实现需要更复杂的算法来处理所有情况
    uint32_t len = 31 - __builtin_clz((n << 6) | (~imms & 0x3f));
    uint32_t levels = (1 << len) - 1;
    uint32_t s = imms & levels;
    uint32_t r = immr & levels;
    
    if (s == levels) {
        return 0; // 无效
    }
    
    uint64_t pattern = (1ULL << (s + 1)) - 1;
    if (r != 0) {
        pattern = (pattern >> r) | (pattern << (len + 1 - r));
        pattern &= (1ULL << (len + 1)) - 1;
    }
    
    // 复制模式到完整宽度
    uint64_t result = 0;
    for (int i = 0; i < (is_64bit ? 64 : 32); i += len + 1) {
        result |= pattern << i;
    }
    
    return is_64bit ? result : (result & 0xFFFFFFFF);
}

// 指令打印函数
void print_instruction(const instruction_t *instr) {
    if (!instr) return;
    
    printf("Opcode: 0x%x, ", instr->opcode);
    printf("64-bit: %s, ", instr->is_64bit ? "yes" : "no");
    printf("Sets flags: %s, ", instr->sets_flags ? "yes" : "no");
    printf("Operands: ");
    
    for (int i = 0; i < instr->reg_count; i++) {
        printf("0x%x ", instr->operands[i]);
    }
    printf("\n");
}
