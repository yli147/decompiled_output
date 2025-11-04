// 重构后的代码结构

typedef struct {
    int type;
    long address;
    int size;
    void *left_child;
    void *right_child;
} ASTNode;

typedef struct {
    long start_addr;
    long end_addr;
    long buffer;
    long instructions;
    int length;
    int flags;
    byte feature_flags[3];
    int error_code;
} DisasmBlock;

typedef struct {
    int opcode;
    int flags;
    long address;
    int size;
    byte operand_flags;
    byte condition_flags;
    long operand1;
    long operand2;
} Instruction;

// 主要的反汇编函数
uint disassemble_block(long context, long start_addr, void *config, char is_thumb) {
    uint block_size = is_thumb ? start_addr : start_addr + 0x10;
    
    // 初始化反汇编上下文
    *(int *)(context + 0x24) = 0;
    
    // 设置模式和限制
    uint max_instructions = get_instruction_limit(config);
    byte mode_flags = get_mode_flags(config);
    
    // 主要的反汇编循环
    DisasmBlock *block = (DisasmBlock *)(context + 0x1db0);
    uint instruction_count = 0;
    long current_addr = start_addr;
    
    while (should_continue_disasm(current_addr, block_size, instruction_count, max_instructions)) {
        
        if (instruction_count >= max_instructions) {
            if (!handle_instruction_limit(context, config)) {
                return 0;
            }
            break;
        }
        
        // 解码当前指令
        Instruction *instr = &((Instruction *)(context))[instruction_count];
        if (!decode_instruction(instr, current_addr, config)) {
            if (*(int *)(context + 0x24) == 0) {
                return 0;
            }
            break;
        }
        
        // 处理特殊指令类型
        if (handle_special_instructions(context, instr, current_addr)) {
            instruction_count++;
            current_addr += instr->size;
            continue;
        }
        
        // 分析控制流
        if (!analyze_control_flow(context, instr, current_addr)) {
            return 0;
        }
        
        // 更新地址和计数
        current_addr += instr->size;
        instruction_count++;
        
        // 检查是否需要停止
        if (should_stop_disasm(context, instr)) {
            break;
        }
    }
    
    // 后处理和优化
    if (instruction_count > 0) {
        post_process_block(context, instruction_count);
        return finalize_block(context, start_addr, current_addr);
    }
    
    return 0;
}

// 辅助函数实现

static uint get_instruction_limit(void *config) {
    byte *cfg = (byte *)config;
    uint limit = 100;
    
    if (cfg && cfg[0] != 0) {
        limit = 1;
    }
    
    // 检查系统限制
    if (check_system_limits()) {
        if (limit > 30) {
            limit = 30;
        }
    }
    
    return limit;
}

static bool should_continue_disasm(long addr, uint block_size, uint count, uint max_count) {
    return (count < max_count) && 
           (addr < block_size) && 
           is_valid_address(addr);
}

static bool decode_instruction(Instruction *instr, long addr, void *config) {
    // 清空指令结构
    memset(instr, 0, sizeof(Instruction));
    
    // 设置解码参数
    setup_decoder_params(instr, config);
    
    // 执行指令解码
    int result = perform_instruction_decode(instr, addr);
    
    if (result != 0) {
        return true;
    }
    
    // 处理解码失败
    return handle_decode_failure(instr, addr);
}

static void setup_decoder_params(Instruction *instr, void *config) {
    byte *cfg = (byte *)config;
    
    instr->flags = 0x10030;
    
    if (cfg[0] == 0) {
        instr->flags = 0x10030;
    }
    
    uint mode_flags = 0;
    if (cfg[0] == 0) {
        mode_flags = 0x30;
    }
    
    if (cfg[1] == 0) {
        instr->flags = mode_flags;
    }
    
    uint extended_flags = instr->flags | 0x20000;
    if (cfg[2] == 0) {
        extended_flags = instr->flags;
    }
    
    instr->flags = extended_flags;
}

static bool handle_special_instructions(long context, Instruction *instr, long addr) {
    uint opcode = instr->opcode;
    uint instr_flags = get_instruction_flags(opcode);
    
    // 处理特权指令
    if (instr_flags & PRIVILEGED_FLAG) {
        if (check_privilege_violation(context)) {
            return false;
        }
        update_privilege_state(context);
    }
    
    // 处理系统调用
    if (instr_flags & SYSCALL_FLAG) {
        if (check_syscall_violation(context)) {
            return false;
        }
        update_syscall_state(context);
    }
    
    // 处理异常指令
    if (instr_flags & EXCEPTION_FLAG) {
        update_exception_state(context);
    }
    
    return true;
}

static bool analyze_control_flow(long context, Instruction *instr, long addr) {
    uint opcode = instr->opcode;
    uint flags = get_instruction_flags(opcode);
    
    // 分析分支指令
    if (flags & BRANCH_FLAG) {
        return analyze_branch_instruction(context, instr, addr);
    }
    
    // 分析跳转指令  
    if (flags & JUMP_FLAG) {
        return analyze_jump_instruction(context, instr, addr);
    }
    
    // 分析调用指令
    if (flags & CALL_FLAG) {
        return analyze_call_instruction(context, instr, addr);
    }
    
    return true;
}

static bool analyze_branch_instruction(long context, Instruction *instr, long addr) {
    // 计算分支目标地址
    long target_addr = calculate_branch_target(instr, addr);
    
    // 检查地址有效性
    if (!validate_branch_target(context, target_addr)) {
        return false;
    }
    
    // 更新控制流信息
    update_control_flow_info(context, addr, target_addr, BRANCH_TYPE);
    
    return true;
}

static void post_process_block(long context, uint instruction_count) {
    // 优化指令序列
    optimize_instruction_sequence(context, instruction_count);
    
    // 分析数据流
    analyze_data_flow(context, instruction_count);
    
    // 检测循环结构
    detect_loop_structures(context, instruction_count);
    
    // 标记基本块边界
    mark_basic_block_boundaries(context, instruction_count);
}

static uint finalize_block(long context, long start_addr, long end_addr) {
    // 设置块信息
    DisasmBlock *block = (DisasmBlock *)(context + 0x1db0);
    block->start_addr = start_addr;
    block->end_addr = end_addr - 1;
    
    // 计算块大小和类型
    uint block_type = determine_block_type(context);
    
    // 设置标志位
    set_block_flags(context, block_type);
    
    return 1;
}

// 内存管理相关函数
static void cleanup_ast_node(long context, ASTNode *node) {
    if (!node) return;
    
    // 递归清理子节点
    if (node->left_child) {
        cleanup_ast_node(context, (ASTNode *)node->left_child);
    }
    
    if (node->right_child) {
        cleanup_ast_node(context, (ASTNode *)node->right_child);
    }
    
    // 释放当前节点
    free_ast_node(context, node);
}

static ASTNode *create_ast_node(long context, int type, long addr) {
    ASTNode *node = allocate_ast_node(context);
    if (!node) return NULL;
    
    node->type = type;
    node->address = addr;
    node->size = 8;
    node->left_child = NULL;
    node->right_child = NULL;
    
    return node;
}
