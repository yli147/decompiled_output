// instruction_decoder.c

typedef struct {
    uint32_t flags;
    uint32_t reg_mask;
} decode_context_t;

/**
 * 解码指令参数
 * @param context 解码上下文
 * @param is_thumb Thumb模式标志
 * @param has_condition 是否有条件码
 * @param instruction 指令字
 * @param param5 参数5
 * @param opcode 输出操作码
 * @param reg_info 输出寄存器信息
 * @return 解码成功返回1，失败返回0
 */
int decode_instruction(decode_context_t *context, char is_thumb, char has_condition,
                      uint32_t instruction, uint32_t param5,
                      uint32_t *opcode, uint32_t *reg_info) {
    uint32_t reg_field, condition_field, mode_field;
    
    if (!is_thumb) {
        // ARM模式解码
        param5 = instruction & 0xFFFFFF7F;
        reg_field = instruction & 3;
        condition_field = ((instruction >> 5) & 4) | 3) ^ 7;
    } else {
        // Thumb模式解码
        condition_field = instruction & 0x1F;
        mode_field = (param5 >> 4) & 8 | ((instruction ^ 0xE0) >> 5);
        reg_field = param5 & 3;
        
        if (mode_field >> 3) {
            context->flags |= 0x8000;
        }
    }
    
    // 设置条件标志
    if ((param5 >> 2) & 1) {
        context->flags |= 0x4000;
    }
    
    // 设置寄存器模式标志
    switch (reg_field) {
        case 2:
            context->flags |= 0x100;
            break;
        case 3:
            context->flags |= 0x200;
            break;
        case 1:
            context->flags |= 0x400;
            break;
        default:
            return 0;
    }
    
    // 根据条件设置操作码
    if (!has_condition) {
        switch (condition_field) {
            case 2:
                *opcode = 5;
                context->flags |= 0x1000;
                break;
            case 3:
                *opcode = 9;
                context->flags |= 0x800;
                break;
            case 1:
                *opcode = 1;
                break;
            default:
                return 0;
        }
    } else {
        switch (condition_field) {
            case 9:
                *opcode = 0xD;
                break;
            case 10:
                *opcode = 0xE;
                break;
            case 8:
                *opcode = 0xC;
                break;
            default:
                return 0;
        }
    }
    
    // 设置寄存器信息
    if (context->flags & 0x10000) {
        *reg_info = mode_field | 0x40;
        context->reg_mask = ~(param5 >> 3) & 0xF;
    } else {
        context->reg_mask = ~(param5 >> 3) & 7;
    }
    
    return 1;
}
