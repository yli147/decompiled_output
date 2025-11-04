// 指令格式化输出相关的常量和结构定义
#define MAX_INSTRUCTION_LENGTH 24
#define HEX_DUMP_WIDTH 24

// 指令操作数类型枚举
typedef enum {
    OPERAND_NONE = 0,
    OPERAND_REG_REG,
    OPERAND_REG_MEM,
    OPERAND_REG_IMM,
    OPERAND_MEM_REG,
    OPERAND_MEM_IMM,
    OPERAND_BRANCH,
    OPERAND_SEGMENT,
    OPERAND_CONTROL_REG,
    OPERAND_DEBUG_REG,
    OPERAND_MMX,
    OPERAND_XMM,
    OPERAND_STRING_OP,
    OPERAND_FAR_PTR,
    // ... 更多操作数类型
} operand_format_t;

// 指令前缀信息
typedef struct {
    const char* lock_prefix;
    const char* rep_prefix;
    const char* size_suffix;
} instruction_prefix_t;

// 重构后的主函数
void format_x86_instruction(uint32_t *instruction_info, 
                           void *output_buffer, 
                           uint64_t instruction_address, 
                           uint64_t raw_bytes_ptr) {
    
    // 输出十六进制字节码和地址
    print_instruction_header(instruction_info, output_buffer, 
                           instruction_address, raw_bytes_ptr);
    
    // 获取指令前缀和助记符
    instruction_prefix_t prefix = get_instruction_prefix(instruction_info);
    const char* mnemonic = get_instruction_mnemonic(instruction_info);
    
    // 输出指令助记符
    print_instruction_mnemonic(output_buffer, &prefix, mnemonic);
    
    // 根据操作数格式输出操作数
    operand_format_t format = get_operand_format(instruction_info);
    print_instruction_operands(instruction_info, output_buffer, format);
    
    // 输出指令描述
    print_instruction_description(instruction_info, output_buffer);
}

// 输出指令头部（地址和字节码）
static void print_instruction_header(uint32_t *instruction_info,
                                   void *output_buffer,
                                   uint64_t instruction_address,
                                   uint64_t raw_bytes_ptr) {
    
    uint8_t instruction_length = *(uint8_t*)((char*)instruction_info + 0x2a);
    
    if (instruction_address == 0) {
        if (instruction_length == 0) return;
        
        // 输出原始字节
        for (int i = 0; i < instruction_length; i++) {
            uint8_t byte_val = *(uint8_t*)(raw_bytes_ptr + i);
            FUN_80100003ecc4(output_buffer, "%02x ", byte_val);
        }
        
        // 填充空格到固定宽度
        int hex_width = instruction_length * 3; // 每字节3个字符（2位十六进制+空格）
        pad_to_width(output_buffer, hex_width, HEX_DUMP_WIDTH);
    } else {
        // 输出地址
        FUN_80100003ecc4(output_buffer, "0x%.16llx\t", instruction_address);
        
        if (instruction_length != 0) {
            // 输出原始字节
            for (int i = 0; i < instruction_length; i++) {
                uint8_t byte_val = *(uint8_t*)(raw_bytes_ptr + i);
                FUN_80100003ecc4(output_buffer, "%02x ", byte_val);
            }
            
            int hex_width = instruction_length * 3;
            pad_to_width(output_buffer, hex_width, HEX_DUMP_WIDTH);
        } else {
            pad_to_width(output_buffer, 0, HEX_DUMP_WIDTH);
        }
    }
}

// 填充空格到指定宽度
static void pad_to_width(void *output_buffer, int current_width, int target_width) {
    while (current_width < target_width) {
        FUN_80100003ecc4(output_buffer, " ");
        current_width++;
    }
}

// 获取指令前缀信息
static instruction_prefix_t get_instruction_prefix(uint32_t *instruction_info) {
    instruction_prefix_t prefix = {0};
    uint32_t opcode = *instruction_info;
    uint32_t flags = instruction_info[0xc];
    uint32_t operand_size = *(uint8_t*)((char*)instruction_info + 0x29);
    
    // 处理特殊指令的前缀
    switch (opcode) {
        case 0x17c: // SCAS 系列
            prefix.rep_prefix = get_rep_prefix_scas(flags);
            prefix.size_suffix = get_size_suffix(operand_size);
            break;
            
        case 0x17a: // STOS 系列
        case 0x180: // MOVS 系列
        case 0x182: // LODS 系列
            prefix.rep_prefix = get_rep_prefix_simple(flags);
            prefix.size_suffix = get_size_suffix(operand_size);
            break;
            
        case 0x17b: // CMPS 系列
        case 0x17d:
        case 0x17f: // 其他字符串指令
        case 0x181:
            prefix.rep_prefix = get_rep_prefix_cmps(flags);
            prefix.size_suffix = "b"; // 字节操作
            break;
            
        case 0x1e4: // 特殊浮点指令
        case 0x1e5:
            prefix.rep_prefix = "";
            prefix.size_suffix = get_float_size_suffix(operand_size);
            break;
            
        case 0x45e: // 64位指令
        case 0x45f:
        case 0x460:
        case 0x461:
            if (operand_size == 8) {
                prefix.size_suffix = "64";
            }
            break;
            
        default:
            // 检查LOCK前缀
            if (flags & 0x80) {
                prefix.lock_prefix = "lock ";
            }
            
            // 检查VEX前缀
            uint32_t instruction_flags = get_instruction_flags(opcode);
            if (instruction_flags & 0x100000) {
                if (flags & 0x2000) {
                    prefix.rep_prefix = "v";
                } else {
                    prefix.rep_prefix = "";
                }
            }
            break;
    }
    
    if (!prefix.rep_prefix) prefix.rep_prefix = "";
    if (!prefix.lock_prefix) prefix.lock_prefix = "";
    if (!prefix.size_suffix) prefix.size_suffix = "";
    
    return prefix;
}

// 获取REP前缀（SCAS指令）
static const char* get_rep_prefix_scas(uint32_t flags) {
    if (flags & 0x100) return "repe ";
    if (flags & 0x200) return "repne ";
    return "";
}

// 获取REP前缀（简单指令）
static const char* get_rep_prefix_simple(uint32_t flags) {
    if (flags & 0x100) return "rep ";
    return "";
}

// 获取REP前缀（CMPS指令）
static const char* get_rep_prefix_cmps(uint32_t flags) {
    if (flags & 0x100) return "repe ";
    if (flags & 0x200) return "repne ";
    return "";
}

// 获取操作数大小后缀
static const char* get_size_suffix(uint32_t operand_size) {
    switch (operand_size) {
        case 1: return "b";
        case 2: return "w";
        case 4: return "d";
        case 8: return "q";
        default: return "";
    }
}

// 获取浮点数大小后缀
static const char* get_float_size_suffix(uint32_t operand_size) {
    switch (operand_size) {
        case 2: return (const char*)&DAT_80100021f6d8;
        case 4: return (const char*)&DAT_801000232600;
        case 8: return (const char*)&DAT_801000232608;
        default: return "";
    }
}

// 输出指令助记符
static void print_instruction_mnemonic(void *output_buffer, 
                                     instruction_prefix_t *prefix,
                                     const char* mnemonic) {
    FUN_80100003ecc4(output_buffer, "%s%s%s ", 
                     prefix->lock_prefix, 
                     mnemonic, 
                     prefix->size_suffix);
}

// 获取指令助记符
static const char* get_instruction_mnemonic(uint32_t *instruction_info) {
    uint32_t opcode = *instruction_info;
    return (const char*)(&PTR_DAT_801000240378)[opcode * 3];
}

// 获取操作数格式
static operand_format_t get_operand_format(uint32_t *instruction_info) {
    uint32_t opcode = *instruction_info;
    uint64_t format_index = (-(uint64_t)(opcode >> 0x1f) & 0xfffffffe00000000ULL | 
                            (uint64_t)opcode << 1) + (int64_t)(int32_t)opcode;
    
    return *(operand_format_t*)(&DAT_801000240380 + format_index * 8);
}

// 输出指令操作数
static void print_instruction_operands(uint32_t *instruction_info, 
                                     void *output_buffer, 
                                     operand_format_t format) {
    uint32_t operand_size = *(uint8_t*)((char*)instruction_info + 0x29);
    
    switch (format) {
        case 0: // reg, reg
        case 1:
        case 2:
            print_register_operand(instruction_info, output_buffer, operand_size, ", ");
            print_register_operand_src(instruction_info, output_buffer, 
                                     instruction_info[1], operand_size, "");
            break;
            
        case 3: // reg, reg (特殊大小)
            print_register_operand(instruction_info, output_buffer, 2, ", ");
            print_register_operand_src(instruction_info, output_buffer, 
                                     instruction_info[1], 2, "");
            break;
            
        case 4: // reg, imm
            print_register_operand(instruction_info, output_buffer, operand_size, ", ");
            print_immediate_operand(instruction_info, output_buffer, operand_size);
            break;
            
        case 5: // reg, mem
            print_register_operand(instruction_info, output_buffer, operand_size, ", ");
            print_memory_operand(instruction_info, output_buffer, operand_size);
            break;
            
        case 6: // reg, imm8
        case 7:
        case 8:
            print_register_operand(instruction_info, output_buffer, operand_size, ", ");
            print_immediate8_operand(instruction_info, output_buffer, operand_size);
            break;
            
        // ... 处理更多格式
        
        case 0x41: // 相对跳转
        case 0x42:
            print_relative_jump(instruction_info, output_buffer, operand_size);
            break;
            
        case 0x43: // 远跳转
            print_far_pointer(instruction_info, output_buffer, operand_size);
            break;
            
        // ... 更多操作数格式
            
        default:
            // 处理未知格式
            break;
    }
}

// 输出寄存器操作数
static void print_register_operand(uint32_t *instruction_info, void *output_buffer, 
                                  uint32_t size, const char* suffix) {
    FUN_8010001b68b0(instruction_info, output_buffer, size, suffix);
}

// 输出源寄存器操作数
static void print_register_operand_src(uint32_t *instruction_info, void *output_buffer,
                                      uint32_t reg_index, uint32_t size, const char* suffix) {
    FUN_8010001b6530(instruction_info, output_buffer, reg_index, size, suffix);
}

// 输出立即数操作数
static void print_immediate_operand(uint32_t *instruction_info, void *output_buffer, 
                                   uint32_t operand_size) {
    uint64_t immediate_value;
    
    switch (operand_size) {
        case 8:
            immediate_value = *(uint64_t*)(instruction_info + 8);
            break;
        case 4:
            immediate_value = instruction_info[8];
            break;
        case 2:
            immediate_value = (uint16_t)instruction_info[8];
            break;
        default:
            immediate_value = (uint8_t)instruction_info[8];
            break;
    }
    
    FUN_80100003ecc4(output_buffer, "0x%llx", immediate_value);
}

// 输出8位立即数操作数
static void print_immediate8_operand(uint32_t *instruction_info, void *output_buffer,
                                    uint32_t operand_size) {
    uint8_t imm8 = (uint8_t)instruction_info[8];
    uint64_t value;
    
    if (operand_size == 8 || operand_size == 4) {
        value = (int64_t)(int8_t)imm8; // 符号扩展
    } else if (operand_size == 2) {
        value = (int64_t)(int8_t)imm8; // 符号扩展
    } else {
        value = imm8; // 零扩展
    }
    
    FUN_80100003ecc4(output_buffer, "0x%llx", value);
}

// 输出内存操作数
static void print_memory_operand(uint32_t *instruction_info, void *output_buffer, 
                                uint32_t operand_size) {
    FUN_8010001b6bd4(instruction_info, output_buffer, operand_size);
}

// 输出相对跳转地址
static void print_relative_jump(uint32_t *instruction_info, void *output_buffer,
                               uint32_t operand_size) {
    uint64_t base_address = (uint64_t)*(uint8_t*)((char*)instruction_info + 0x2a);
    // 这里需要传入当前指令地址，暂时使用0
    uint64_t target_address = base_address;
    
    if (operand_size == 8) {
        if (instruction_info[0xc] & 0x10000) {
            int32_t offset = (int32_t)instruction_info[8];
            target_address += offset;
            FUN_80100003ecc4(output_buffer, "0x%llx", target_address);
        }
    } else if (operand_size == 4) {
        int32_t offset = (int32_t)instruction_info[8];
        target_address += offset;
        FUN_80100003ecc4(output_buffer, "0x%x", (uint32_t)target_address);
    } else {
        int16_t offset = (int16_t)instruction_info[8];
        target_address += offset;
        FUN_80100003ecc4(output_buffer, "0x%x", (uint32_t)target_address & 0xffff);
    }
}

// 输出远指针
static void print_far_pointer(uint32_t *instruction_info, void *output_buffer,
                             uint32_t operand_size) {
    if (operand_size == 4) {
        uint16_t segment = (uint16_t)instruction_info[9];
        uint32_t offset = instruction_info[8];
        FUN_80100003ecc4(output_buffer, "0x%04x:0x%08x", segment, offset);
    } else if (operand_size == 2) {
        uint16_t segment = *(uint16_t*)((char*)instruction_info + 0x22);
        uint16_t offset = (uint16_t)instruction_info[8];
        FUN_80100003ecc4(output_buffer, "0x%04x:0x%04x", segment, offset);
    } else {
        // 错误情况
        FUN_80100003db60("dcdx86_print.cc", 0x1ff, "printOpndAp: unreachable.\n");
    }
}

// 输出指令描述
static void print_instruction_description(uint32_t *instruction_info, void *output_buffer) {
    uint32_t opcode = *instruction_info;
    uint64_t desc_index = (-(uint64_t)(opcode >> 0x1f) & 0xfffffffe00000000ULL | 
                          (uint64_t)opcode << 1) + (int64_t)(int32_t)opcode;
    
    const char* description = (&PTR_s_add_EbGb_801000240370)[desc_index];
    FUN_80100003ecc4(output_buffer, "  (%s)\n", description);
}

// 获取指令标志
static uint32_t get_instruction_flags(uint32_t opcode) {
    return *(uint32_t*)(&DAT_801000211130 + (int64_t)(int32_t)opcode * 4);
}

// 解码复杂的x86指令格式
uint64_t decode_complex_instruction(int *decoder_state, uint64_t instruction) {
    uint32_t instr_low = (uint32_t)instruction;
    uint64_t bit21_field = instruction >> 0x15;
    uint32_t reg_field = (uint32_t)(instruction >> 0x10) & 0xf;
    uint32_t mod_field = ((uint32_t)(instruction >> 0x16) & 1) << 4 | (uint32_t)(instruction >> 0xc) & 0xf;

    if (reg_field == 0xf) {
        return 2; // 无效寄存器字段
    }

    uint32_t byte_field = (uint32_t)(instruction >> 8);

    if ((instr_low >> 0x17 & 1) == 0) {
        // 处理标准格式
        return decode_standard_format(decoder_state, instruction, instr_low, bit21_field,
                                    reg_field, mod_field, byte_field);
    } else {
        // 处理扩展格式
        return decode_extended_format(decoder_state, instruction, instr_low, bit21_field,
                                    reg_field, mod_field, byte_field);
    }
}

static uint64_t decode_standard_format(int *decoder_state, uint64_t instruction,
                                     uint32_t instr_low, uint64_t bit21_field,
                                     uint32_t reg_field, uint32_t mod_field,
                                     uint32_t byte_field) {
    uint32_t sub_field = byte_field & 0xf;
    if (sub_field > 10) {
        return 2; // 无效子字段
    }

    // 查找操作码和参数
    uint64_t scale_bits = instruction >> 6 & 3;
    uint32_t scale = 1 << scale_bits;
    uint32_t base_val = lookup_base_value(instruction >> 4 & 3);

    int opcode = lookup_opcode(sub_field, bit21_field & 1);

    // 验证特殊情况
    if ((int)scale_bits == 3 && get_size_value(sub_field) != 1) {
        return 2;
    }

    // 设置解码结果
    *decoder_state = opcode;
    decoder_state[6] = reg_field;
    decoder_state[0x17] |= 0x80;

    // 根据子字段设置其他参数
    setup_operands_standard(decoder_state, sub_field, mod_field, scale, opcode);

    return 0;
}

static uint64_t decode_extended_format(int *decoder_state, uint64_t instruction,
                                     uint32_t instr_low, uint64_t bit21_field,
                                     uint32_t reg_field, uint32_t mod_field,
                                     uint32_t byte_field) {
    uint32_t ext_field = byte_field & 3;
    uint64_t mode_bits = instruction >> 10 & 3;
    uint32_t size_field = ext_field + 1;

    // 处理特殊模式
    if ((int)mode_bits == 3) {
        return handle_special_mode(decoder_state, instruction, ext_field, size_field);
    }

    // 标准扩展格式处理
    return handle_extended_mode(decoder_state, instruction, ext_field, size_field, mode_bits);
}
