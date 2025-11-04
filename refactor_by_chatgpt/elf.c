// ARM64 Vector Extension Instruction Disassembler
void disasm_vector_ext_instruction(uint32_t instruction, void* context) {
    const char* element_size = (instruction & 0x40000000) ? "16b" : "8b";
    
    uint32_t vd = instruction & 0x1f;
    uint32_t vn = (instruction >> 5) & 0x1f;
    uint32_t vm = (instruction >> 16) & 0x1f;
    uint32_t index = (instruction >> 11) & 0xf;
    
    print_instruction(instruction, context, 
                     "ext\tv%d.%s, v%d.%s, v%d.%s, #%d",
                     vd, element_size, vn, element_size, vm, element_size, index);
}

// ARM64 Vector Load/Store Multiple Structures Disassembler
void disasm_vector_load_store_multiple(uint64_t instruction, void* context) {
    uint32_t instr = instruction & 0xffffffff;
    uint32_t size = (instr >> 14) & 3;
    const char* op = (instruction & 0x400000) ? "ld" : "st";
    
    int num_regs = (((instr >> 13) & 1) << 1 | (instr >> 21) & 1) + 1;
    uint32_t rt = instr & 0x1f;
    uint32_t rn = (instr >> 5) & 0x1f;
    
    char index_str[32] = {0};
    char element_type[8];
    char reg_suffix[8] = "";
    int element_size;
    
    // Determine element type and size based on size field
    switch (size) {
        case 2: // Single/double precision
            if ((instr >> 10) & 1) {
                strcpy(element_type, "d");
                element_size = 8;
            } else {
                snprintf(index_str, sizeof(index_str), "[%d]", 
                        ((instr >> 30) & 1) << 1 | (instr >> 12) & 1);
                strcpy(element_type, "s");
                element_size = 4;
            }
            break;
            
        case 3: // Register form
            if ((instr >> 30) & 1) {
                strcpy(element_type, get_16b_element_type((instr >> 10) & 3));
            } else {
                strcpy(element_type, get_8b_element_type((instr >> 10) & 3));
            }
            strcpy(reg_suffix, "r");
            element_size = 1 << ((instr >> 10) & 3);
            break;
            
        case 1: // Half-word
            snprintf(index_str, sizeof(index_str), "[%d]", 
                    ((instr >> 30) & 1) << 2 | ((instr >> 12) & 1) << 1 | 
                    ((instr >> 10) & 3) >> 1);
            strcpy(element_type, "h");
            element_size = 2;
            break;
            
        default: // Byte
            snprintf(index_str, sizeof(index_str), "[%d]", 
                    ((instr >> 30) & 1) << 3 | ((instr >> 12) & 1) << 2 | 
                    (instr >> 10) & 3);
            strcpy(element_type, "b");
            element_size = 1;
            break;
    }
    
    // Handle post-index addressing
    char post_index[32] = {0};
    if ((instr >> 23) & 1) {
        if (((instr >> 16) & 0x1f) == 0x1f) {
            snprintf(post_index, sizeof(post_index), ", #%d", num_regs * element_size);
        } else {
            snprintf(post_index, sizeof(post_index), ", x%d", (instr >> 16) & 0x1f);
        }
    }
    
    // Generate instruction string based on number of registers
    switch (num_regs) {
        case 1:
            print_instruction(instr, context, "%s1%s\t{ v%d.%s }%s, [x%d]%s",
                            op, reg_suffix, rt, element_type, index_str, rn, post_index);
            break;
        case 2:
            print_instruction(instr, context, "%s2%s\t{ v%d.%s, v%d.%s }%s, [x%d]%s",
                            op, reg_suffix, rt, element_type, (rt + 1) & 0x1f, 
                            element_type, index_str, rn, post_index);
            break;
        case 3:
            print_instruction(instr, context, "%s3%s\t{ v%d.%s, v%d.%s, v%d.%s }%s, [x%d]%s",
                            op, reg_suffix, rt, element_type, (rt + 1) & 0x1f, element_type,
                            (rt + 2) & 0x1f, element_type, index_str, rn, post_index);
            break;
        case 4:
            print_instruction(instr, context, "%s4%s\t{ v%d.%s, v%d.%s, v%d.%s, v%d.%s }%s, [x%d]%s",
                            op, reg_suffix, rt, element_type, (rt + 1) & 0x1f, element_type,
                            (rt + 2) & 0x1f, element_type, (rt + 3) & 0x1f, element_type,
                            index_str, rn, post_index);
            break;
    }
}

// ARM64 Vector Load/Store Single Structure Disassembler
void disasm_vector_load_store_single(uint64_t instruction, void* context) {
    uint32_t instr = instruction & 0xffffffff;
    uint32_t size = (instr >> 10) & 3;
    const char* op = (instruction & 0x400000) ? "ld" : "st";
    
    uint32_t rt = instr & 0x1f;
    uint32_t rn = (instr >> 5) & 0x1f;
    uint32_t opcode = (instr >> 12) & 0xf;
    
    const char* element_type;
    if ((instr >> 30) & 1) {
        element_type = get_16b_element_type(size);
    } else {
        element_type = get_8b_element_type(size);
    }
    
    char post_index[32] = {0};
    if ((instr >> 23) & 1) {
        if (((instr >> 16) & 0x1f) == 0x1f) {
            int element_size = (instr >> 30) & 1 ? 16 : 8;
            snprintf(post_index, sizeof(post_index), ", #%d", 
                    element_size * get_register_count(opcode));
        } else {
            snprintf(post_index, sizeof(post_index), ", x%d", (instr >> 16) & 0x1f);
        }
    }
    
    int reg_count = get_register_count(opcode);
    int opcode_suffix = get_opcode_suffix(opcode);
    
    switch (reg_count) {
        case 1:
            print_instruction(instr, context, "%s%d\t{ v%d.%s }, [x%d]%s",
                            op, opcode_suffix, rt, element_type, rn, post_index);
            break;
        case 2:
            print_instruction(instr, context, "%s%d\t{ v%d.%s, v%d.%s }, [x%d]%s",
                            op, opcode_suffix, rt, element_type, 
                            (rt + 1) & 0x1f, element_type, rn, post_index);
            break;
        case 3:
            print_instruction(instr, context, "%s%d\t{ v%d.%s, v%d.%s, v%d.%s }, [x%d]%s",
                            op, opcode_suffix, rt, element_type, (rt + 1) & 0x1f, element_type,
                            (rt + 2) & 0x1f, element_type, rn, post_index);
            break;
        case 4:
            print_instruction(instr, context, "%s%d\t{ v%d.%s, v%d.%s, v%d.%s, v%d.%s }, [x%d]%s",
                            op, opcode_suffix, rt, element_type, (rt + 1) & 0x1f, element_type,
                            (rt + 2) & 0x1f, element_type, (rt + 3) & 0x1f, element_type, rn, post_index);
            break;
    }
}

// ARM64 Cryptographic Instructions Disassembler
void disasm_crypto_instruction(uint32_t instruction, void* context) {
    uint32_t opcode = (instruction >> 12) & 3;
    uint32_t rd = instruction & 0x1f;
    uint32_t rn = (instruction >> 5) & 0x1f;
    
    const char* mnemonic = get_crypto_mnemonic(opcode);
    print_instruction(instruction, context, "%s\tv%d.16b, v%d.16b", 
                     mnemonic, rd, rn);
}

// ARM64 SHA Instructions Disassembler  
void disasm_sha_instruction(uint32_t instruction, void* context) {
    uint32_t opcode = (instruction >> 12) & 3;
    uint32_t rd = instruction & 0x1f;
    uint32_t rn = (instruction >> 5) & 0x1f;
    
    if (opcode == 0) {
        print_instruction(instruction, context, "sha1h\ts%d, s%d", rd, rn);
    } else if (opcode != 3) {
        const char* mnemonic = get_sha_mnemonic(opcode);
        print_instruction(instruction, context, "%s\tv%d.4s, v%d.4s", 
                         mnemonic, rd, rn);
    }
}

// ARM64 SHA Three-Register Instructions Disassembler
void disasm_sha_three_reg(uint64_t instruction, void* context) {
    uint32_t instr = instruction & 0xffffffff;
    uint32_t opcode = (instr >> 12) & 7;
    uint32_t rd = instr & 0x1f;
    uint32_t rn = (instr >> 5) & 0x1f;
    uint32_t rm = (instr >> 16) & 0x1f;
    
    const char* mnemonic = get_sha_three_reg_mnemonic(opcode);
    
    if (opcode


// ARM64 Vector Extension Instruction Disassembler
void disasm_vector_ext_instruction(uint32_t instruction, void* context) {
    const char* element_size = (instruction & 0x40000000) ? "16b" : "8b";
    
    uint32_t vd = instruction & 0x1f;
    uint32_t vn = (instruction >> 5) & 0x1f;
    uint32_t vm = (instruction >> 16) & 0x1f;
    uint32_t index = (instruction >> 11) & 0xf;
    
    print_instruction(instruction, context, 
                     "ext\tv%d.%s, v%d.%s, v%d.%s, #%d",
                     vd, element_size, vn, element_size, vm, element_size, index);
}

// ARM64 Vector Load/Store Multiple Structures Disassembler
void disasm_vector_load_store_multiple(uint64_t instruction, void* context) {
    uint32_t instr = instruction & 0xffffffff;
    uint32_t size = (instr >> 14) & 3;
    const char* op = (instruction & 0x400000) ? "ld" : "st";
    
    int num_regs = (((instr >> 13) & 1) << 1 | (instr >> 21) & 1) + 1;
    uint32_t rt = instr & 0x1f;
    uint32_t rn = (instr >> 5) & 0x1f;
    
    char index_str[32] = {0};
    char element_type[8];
    char reg_suffix[8] = "";
    int element_size;
    
    // Determine element type and size based on size field
    switch (size) {
        case 2: // Single/double precision
            if ((instr >> 10) & 1) {
                strcpy(element_type, "d");
                element_size = 8;
            } else {
                snprintf(index_str, sizeof(index_str), "[%d]", 
                        ((instr >> 30) & 1) << 1 | (instr >> 12) & 1);
                strcpy(element_type, "s");
                element_size = 4;
            }
            break;
            
        case 3: // Register form
            if ((instr >> 30) & 1) {
                strcpy(element_type, get_16b_element_type((instr >> 10) & 3));
            } else {
                strcpy(element_type, get_8b_element_type((instr >> 10) & 3));
            }
            strcpy(reg_suffix, "r");
            element_size = 1 << ((instr >> 10) & 3);
            break;
            
        case 1: // Half-word
            snprintf(index_str, sizeof(index_str), "[%d]", 
                    ((instr >> 30) & 1) << 2 | ((instr >> 12) & 1) << 1 | 
                    ((instr >> 10) & 3) >> 1);
            strcpy(element_type, "h");
            element_size = 2;
            break;
            
        default: // Byte
            snprintf(index_str, sizeof(index_str), "[%d]", 
                    ((instr >> 30) & 1) << 3 | ((instr >> 12) & 1) << 2 | 
                    (instr >> 10) & 3);
            strcpy(element_type, "b");
            element_size = 1;
            break;
    }
    
    // Handle post-index addressing
    char post_index[32] = {0};
    if ((instr >> 23) & 1) {
        if (((instr >> 16) & 0x1f) == 0x1f) {
            snprintf(post_index, sizeof(post_index), ", #%d", num_regs * element_size);
        } else {
            snprintf(post_index, sizeof(post_index), ", x%d", (instr >> 16) & 0x1f);
        }
    }
    
    // Generate instruction string based on number of registers
    switch (num_regs) {
        case 1:
            print_instruction(instr, context, "%s1%s\t{ v%d.%s }%s, [x%d]%s",
                            op, reg_suffix, rt, element_type, index_str, rn, post_index);
            break;
        case 2:
            print_instruction(instr, context, "%s2%s\t{ v%d.%s, v%d.%s }%s, [x%d]%s",
                            op, reg_suffix, rt, element_type, (rt + 1) & 0x1f, 
                            element_type, index_str, rn, post_index);
            break;
        case 3:
            print_instruction(instr, context, "%s3%s\t{ v%d.%s, v%d.%s, v%d.%s }%s, [x%d]%s",
                            op, reg_suffix, rt, element_type, (rt + 1) & 0x1f, element_type,
                            (rt + 2) & 0x1f, element_type, index_str, rn, post_index);
            break;
        case 4:
            print_instruction(instr, context, "%s4%s\t{ v%d.%s, v%d.%s, v%d.%s, v%d.%s }%s, [x%d]%s",
                            op, reg_suffix, rt, element_type, (rt + 1) & 0x1f, element_type,
                            (rt + 2) & 0x1f, element_type, (rt + 3) & 0x1f, element_type,
                            index_str, rn, post_index);
            break;
    }
}

// ARM64 Vector Load/Store Single Structure Disassembler
void disasm_vector_load_store_single(uint64_t instruction, void* context) {
    uint32_t instr = instruction & 0xffffffff;
    uint32_t size = (instr >> 10) & 3;
    const char* op = (instruction & 0x400000) ? "ld" : "st";
    
    uint32_t rt = instr & 0x1f;
    uint32_t rn = (instr >> 5) & 0x1f;
    uint32_t opcode = (instr >> 12) & 0xf;
    
    const char* element_type;
    if ((instr >> 30) & 1) {
        element_type = get_16b_element_type(size);
    } else {
        element_type = get_8b_element_type(size);
    }
    
    char post_index[32] = {0};
    if ((instr >> 23) & 1) {
        if (((instr >> 16) & 0x1f) == 0x1f) {
            int element_size = (instr >> 30) & 1 ? 16 : 8;
            snprintf(post_index, sizeof(post_index), ", #%d", 
                    element_size * get_register_count(opcode));
        } else {
            snprintf(post_index, sizeof(post_index), ", x%d", (instr >> 16) & 0x1f);
        }
    }
    
    int reg_count = get_register_count(opcode);
    int opcode_suffix = get_opcode_suffix(opcode);
    
    switch (reg_count) {
        case 1:
            print_instruction(instr, context, "%s%d\t{ v%d.%s }, [x%d]%s",
                            op, opcode_suffix, rt, element_type, rn, post_index);
            break;
        case 2:
            print_instruction(instr, context, "%s%d\t{ v%d.%s, v%d.%s }, [x%d]%s",
                            op, opcode_suffix, rt, element_type, 
                            (rt + 1) & 0x1f, element_type, rn, post_index);
            break;
        case 3:
            print_instruction(instr, context, "%s%d\t{ v%d.%s, v%d.%s, v%d.%s }, [x%d]%s",
                            op, opcode_suffix, rt, element_type, (rt + 1) & 0x1f, element_type,
                            (rt + 2) & 0x1f, element_type, rn, post_index);
            break;
        case 4:
            print_instruction(instr, context, "%s%d\t{ v%d.%s, v%d.%s, v%d.%s, v%d.%s }, [x%d]%s",
                            op, opcode_suffix, rt, element_type, (rt + 1) & 0x1f, element_type,
                            (rt + 2) & 0x1f, element_type, (rt + 3) & 0x1f, element_type, rn, post_index);
            break;
    }
}

// ARM64 Cryptographic Instructions Disassembler
void disasm_crypto_instruction(uint32_t instruction, void* context) {
    uint32_t opcode = (instruction >> 12) & 3;
    uint32_t rd = instruction & 0x1f;
    uint32_t rn = (instruction >> 5) & 0x1f;
    
    const char* mnemonic = get_crypto_mnemonic(opcode);
    print_instruction(instruction, context, "%s\tv%d.16b, v%d.16b", 
                     mnemonic, rd, rn);
}

// ARM64 SHA Instructions Disassembler  
void disasm_sha_instruction(uint32_t instruction, void* context) {
    uint32_t opcode = (instruction >> 12) & 3;
    uint32_t rd = instruction & 0x1f;
    uint32_t rn = (instruction >> 5) & 0x1f;
    
    if (opcode == 0) {
        print_instruction(instruction, context, "sha1h\ts%d, s%d", rd, rn);
    } else if (opcode != 3) {
        const char* mnemonic = get_sha_mnemonic(opcode);
        print_instruction(instruction, context, "%s\tv%d.4s, v%d.4s", 
                         mnemonic, rd, rn);
    }
}

// ARM64 SHA Three-Register Instructions Disassembler
void disasm_sha_three_reg(uint64_t instruction, void* context) {
    uint32_t instr = instruction & 0xffffffff;
    uint32_t opcode = (instr >> 12) & 7;
    uint32_t rd = instr & 0x1f;
    uint32_t rn = (instr >> 5) & 0x1f;
    uint32_t rm = (instr >> 16) & 0x1f;
    
    const char* mnemonic = get_sha_three_reg_mnemonic(opcode);
    
    if (opcode < 6) {
        if ((instr >> 14) & 1) {
            print_instruction(instruction, context, "%s\tq%d, q%d, v%d.4s",
                            mnemonic, rd, rn, rm);
        } else if (opcode != 3) {
            print_instruction(instruction, context, "%s\tq%d, s%d, v%d.4s",
                            mnemonic, rd, rn, rm);
        }
    } else if (opcode == 6) {
        print_instruction(instr, context, "%s\tv%d.4s, v%d.4s, v%d.4s",
                         mnemonic, rd, rn, rm);
    }
}

// ELF Dynamic Section Parser
bool parse_elf_dynamic_section(void* context, void* file_data, void* output_buffer) {
    if (!is_valid_elf_header(file_data)) {
        return false;
    }
    
    void* dynamic_section;
    size_t dynamic_size;
    void* string_table;
    size_t string_table_size;
    
    if (!find_elf_section(file_data, ".dynamic", &dynamic_section, &dynamic_size) ||
        !find_elf_section(file_data, ".dynstr", &string_table, &string_table_size)) {
        return false;
    }
    
    bool is_64bit = get_elf_class(file_data) == ELFCLASS64;
    
    if (is_64bit) {
        Elf64_Dyn* dyn_entry = (Elf64_Dyn*)dynamic_section;
        Elf64_Dyn* dyn_end = (Elf64_Dyn*)((char*)dynamic_section + dynamic_size);
        
        while (dyn_entry < dyn_end) {
            if (dyn_entry->d_tag == DT_SONAME) {
                size_t offset = dyn_entry->d_un.d_val;
                if (offset < string_table_size) {
                    copy_string_safe(output_buffer, (char*)string_table + offset, 
                                   min(string_table_size - offset, 255));
                    return true;
                }
            }
            dyn_entry++;
        }
    } else {
        Elf32_Dyn* dyn_entry = (Elf32_Dyn*)dynamic_section;
        Elf32_Dyn* dyn_end = (Elf32_Dyn*)((char*)dynamic_section + dynamic_size);
        
        while (dyn_entry < dyn_end) {
            if (dyn_entry->d_tag == DT_SONAME) {
                size_t offset = dyn_entry->d_un.d_val;
                if (offset < string_table_size) {
                    copy_string_safe(output_buffer, (char*)string_table + offset,
                                   min(string_table_size - offset, 255));
                    return true;
                }
            }
            dyn_entry++;
        }
    }
    
    return false;
}

// Debugger Stack Management
void push_debug_value(debugger_context_t* ctx, uint64_t* value) {
    uint32_t stack_index = ctx->stack_count;
    ctx->stack[stack_index] = *value;
    ctx->stack_count = stack_index + 1;
    
    emit_debug_event(ctx, DEBUG_EVENT_PUSH, stack_index | 0x1050000, DEBUG_BREAKPOINT);
    emit_instruction(ctx, 0, OPCODE_PUSH, 0, 0x40000, 
                    get_debug_register(), get_debug_register(), 
                    get_debug_register(), get_debug_register());
}

// Conditional Debug Value Push
void conditional_push_debug_value(debugger_context_t* ctx, uint64_t* value, 
                                 uint64_t condition, uint32_t flags) {
    if (should_push_value(condition, flags)) {
        push_debug_value(ctx, value);
    }
    emit_instruction(ctx, 0, condition & 0xffffffff, 0, flags, 
                    get_debug_register(), get_debug_register(), 
                    get_debug_register(), get_debug_register());
}

// Debug Event Emission
void emit_debug_event(debugger_context_t* ctx, int event_type, 
                     uint32_t event_id, uint32_t breakpoint_id) {
    if (!(ctx->flags & DEBUG_FLAG_ENABLED)) {
        emit_simple_event(ctx, event_type, event_id);
        return;
    }
    
    if (breakpoint_id == DEBUG_BREAKPOINT) {
        return;
    }
    
    emit_breakpoint_event(ctx, event_type, event_id, breakpoint_id);
}

// Memory Allocation for Debug Context
uint64_t allocate_debug_memory(debugger_context_t** ctx_array, 
                              void* unused, uint16_t flags1, uint16_t flags2) {
    debugger_context_t* main_ctx = ctx_array[1];
    
    if (!(main_ctx->config & CONFIG_ENABLED)) {
        return fallback_memory_allocation(ctx_array[0], main_ctx, main_ctx->default_size);
    }
    
    // Determine memory size based on flags
    uint32_t memory_size = (flags2 & 0xff) ? 4 : 16;
    uint16_t allocation_flags = create_allocation_flags(flags1, flags2, memory_size);
    
    uint64_t memory_id = get_next_memory_id();
    uint32_t allocation_params = prepare_allocation_params(ctx_array[0], ctx_array[2], main_ctx, memory_size);
    
    // Allocate primary memory block
    void* memory_block = allocate_memory_block(ctx_array[0], BLOCK_TYPE_PRIMARY, 
                                              allocation_params, 0, memory_id, 0);
    configure_memory_block(memory_block, allocation_flags, memory_size);
    commit_memory_allocation(ctx_array[0]);
    
    // Allocate secondary memory block if needed
    if (main_ctx->config & CONFIG_DUAL_ALLOCATION) {
        main_ctx->secondary_allocation_flag = 1;
        uint32_t secondary_id = get_next_memory_id();
        uint32_t secondary_params = prepare_allocation_params(ctx_array[0], ctx_array[2], main_ctx, memory_size);
        
        void* secondary_block = allocate_memory_block(ctx_array[0], BLOCK_TYPE_SECONDARY,
                                                     secondary_params, 0, secondary_id, 0);
        configure_memory_block(secondary_block, allocation_flags, memory_size);
        commit_memory_allocation(ctx_array[0]);
        
        memory_id |= (uint64_t)secondary_id << 32;
    }
    
    return memory_id;
}

// Helper functions
static const char* get_16b_element_type(int index) {
    static const char* types[] = {"16b", "8h", "4s", "2d"};
    return types[index & 3];
}

static const char* get_8b_element_type(int index) {
    static const char* types[] = {"8b", "4h", "2s", "1d"};
    return types[index & 3];
}

static int get_register_count(int opcode) {
    static const int counts[] = {0, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2};
    return (opcode < 11) ? counts[opcode] : 0;
}

static int get_opcode_suffix(int opcode) {
    static const int suffixes[] = {0, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2};
    return (opcode < 11) ? suffixes[opcode] : 0;
}

static bool should_push_value(uint64_t condition, uint32_t flags) {
    return (get_condition_flags(condition) & 0x43) != 0;
}

static uint16_t create_allocation_flags(uint16_t flags1, uint16_t flags2, uint32_t size) {
    uint16_t result = 0x10 | ((flags1 & 1) << 6);
    
    if (!(flags2 & 0xff)) {
        result ^= 0x80;  // Toggle bit 7
    }
    
    result |= (count_leading_zeros(bit_reverse(size)) & 7) << 12;
    return result;
}

// ARM Register List Disassembler
void disasm_register_list(uint32_t instruction, void* context, void* output) {
    uint32_t reg_list = instruction & 0xffff;
    uint32_t rn = (instruction >> 16) & 0xf;
    uint32_t writeback = (instruction >> 21) & 1;
    uint32_t load_store = (instruction >> 20) & 1;
    uint32_t user_mode = (instruction >> 22) & 1;
    uint32_t pre_post = (instruction >> 23) & 1;
    uint32_t up_down = (instruction >> 23) & 1;

    char reg_list_str[64] = {0};
    bool first_reg = true;

    // Build register list string
    for (uint32_t i = 0; i < 16; i++) {
        if ((reg_list >> i) & 1) {
            char* pos = reg_list_str;
            if (reg_list_str[0] != '\0') {
                while (*pos != '\0') pos++;
            }

            const char* separator = first_reg ? "" : ",";
            snprintf(pos, sizeof(reg_list_str) - (pos - reg_list_str),
                    "%sr%d", separator, i);
            first_reg = false;
        }
    }

    // Determine instruction mnemonic
    const char* mnemonic;
    const char* suffix = "";
    const char* writeback_suffix = writeback ? "!" : "";

    if (writeback && rn == 13) {  // Stack operations
        if (load_store) {
            if (user_mode) {
                mnemonic = up_down ? "ldmfd" : "ldmea";
            } else {
                mnemonic = "pop";
            }
        } else {
            if (user_mode) {
                mnemonic = up_down ? "stmfd" : "stmea";
            } else {
                mnemonic = "push";
            }
        }
    } else {
        mnemonic = load_store ? "ldm" : "stm";
        suffix = get_addressing_mode_suffix(pre_post, up_down);
    }

    const char* condition = get_condition_suffix(get_processor_mode(context));

    if (strcmp(mnemonic, "push") == 0 || strcmp(mnemonic, "pop") == 0) {
        print_instruction(instruction, output, "%s%s\t{%s}",
                         mnemonic, condition, reg_list_str);
    } else {
        print_instruction(instruction, output, "%s%s%s\tr%d%s, {%s}",
                         mnemonic, suffix, condition, rn, writeback_suffix, reg_list_str);
    }
}

// ARM Coprocessor Instruction Disassembler
void disasm_coprocessor_instruction(uint32_t instruction, void* context, void* output) {
    const char* mnemonic = get_coprocessor_mnemonic(get_instruction_type(context));
    const char* condition = get_condition_suffix(get_processor_mode(context));

    print_instruction(instruction, output, "%s%s.w", mnemonic, condition);
}

// ARM Pack/Unpack Instructions
void disasm_pack_instruction(uint32_t instruction, void* context, void* output) {
    uint32_t rd = (instruction >> 8) & 0xf;
    uint32_t rn = (instruction >> 16) & 0xf;
    uint32_t rm = instruction & 0xf;
    uint32_t tb_bit = (instruction >> 5) & 1;
    uint32_t shift_amount = get_shift_amount(context);

    const char* mnemonic = tb_bit ? "pkhtb" : "pkhbt";
    const char* condition = get_condition_suffix(get_processor_mode(context));

    if (shift_amount == 0) {
        print_instruction(instruction, output, "%s%s\tr%d, r%d, r%d",
                         mnemonic, condition, rd, rn, rm);
    } else {
        const char* shift_type = (instruction & 0x40) ? "asr" : "lsl";
        print_instruction(instruction, output, "%s%s\tr%d, r%d, r%d, %s #%d",
                         mnemonic, condition, rd, rn, rm, shift_type, shift_amount);
    }
}

// Clear Exclusive Instruction
void disasm_clear_exclusive(uint32_t instruction, void* context, void* output) {
    print_instruction(instruction, output, "clrex");
}

// Move to/from Special Register
void disasm_move_special_register(uint32_t instruction, void* context, void* output) {
    uint32_t read_bit = (instruction >> 5) & 1;
    uint32_t mask_bit = (instruction >> 4) & 1;
    uint32_t reg_field = instruction & 0xf;

    if ((read_bit & mask_bit) != 0) {
        print_instruction(instruction, output, "undefined instr");
        return;
    }

    const char* direction = read_bit ? "mrs" : "msr";
    const char* reg_type = mask_bit ? "m" : "s";
    const char* condition = get_condition_suffix(get_processor_mode(context));
    const char* special_reg = get_special_register_name(reg_field);

    print_instruction(instruction, output, "%s%s%s\t%s",
                     direction, reg_type, condition, special_reg);
}

// Table Branch Instructions
void disasm_table_branch(uint32_t instruction, void* context, void* output) {
    uint32_t rn = (instruction >> 16) & 0xf;
    uint32_t rm = instruction & 0xf;
    uint32_t halfword_bit = (instruction >> 4) & 1;

    const char* condition = get_condition_suffix(get_processor_mode(context));

    if (halfword_bit) {
        print_instruction(instruction, output, "tbh%s\t[r%d, r%d, lsl #1]",
                         condition, rn, rm);
    } else {
        print_instruction(instruction, output, "tbb%s\t[r%d, r%d]",
                         condition, rn, rm);
    }
}

// Extend Instructions (SXTB, UXTB, etc.)
void disasm_extend_instruction(uint32_t instruction, void* context, void* output) {
    uint32_t rd = (instruction >> 8) & 0xf;
    uint32_t rn = (instruction >> 16) & 0xf;
    uint32_t rm = instruction & 0xf;
    uint32_t rotation = (instruction >> 4) & 3;

    const char* mnemonic = get_extend_mnemonic(get_instruction_type(context));
    const char* condition = get_condition_suffix(get_processor_mode(context));

    if (rn == 0xf) {
        if (rotation == 0) {
            print_instruction(instruction, output, "%s%s\tr%d, r%d",
                             mnemonic, condition, rd, rm);
        } else {
            print_instruction(instruction, output, "%s%s\tr%d, r%d, ror #%d",
                             mnemonic, condition, rd, rm, rotation * 8);
        }
    } else {
        if (rotation == 0) {
            print_instruction(instruction, output, "%s%s\tr%d, r%d, r%d",
                             mnemonic, condition, rd, rn, rm);
        } else {
            print_instruction(instruction, output, "%s%s\tr%d, r%d, r%d, ror #%d",
                             mnemonic, condition, rd, rn, rm, rotation * 8);
        }
    }
}

// Count Leading Zeros
void disasm_count_leading_zeros(uint32_t instruction, void* context, void* output) {
    uint32_t rd = (instruction >> 8) & 0xf;
    uint32_t rm = instruction & 0xf;
    const char* condition = get_condition_suffix(get_processor_mode(context));

    print_instruction(instruction, output, "clz%s\tr%d, r%d", condition, rd, rm);
}

// CRC32 Instructions
void disasm_crc32_instruction(uint32_t instruction, void* context, void* output) {
    uint32_t rd = (instruction >> 8) & 0xf;
    uint32_t rn = (instruction >> 16) & 0xf;
    uint32_t rm = instruction & 0xf;
    uint32_t size = (instruction >> 4) & 3;
    uint32_t polynomial = (instruction >> 20) & 1;

    const char* poly_suffix = polynomial ? "c" : "";
    const char* size_suffix = get_crc_size_suffix(size);

    if (size < 4) {
        print_instruction(instruction, output, "crc32%s%s\tr%d, r%d, r%d",
                         poly_suffix, size_suffix, rd, rn, rm);
    } else {
        print_instruction(instruction, output, "crc32%serror\tr%d, r%d, r%d",
                         poly_suffix, rd, rn, rm);
    }
}

// Select Instruction
void disasm_select_instruction(uint32_t instruction, void* context, void* output) {
    uint32_t rd = (instruction >> 8) & 0xf;
    uint32_t rn = (instruction >> 16) & 0xf;
    uint32_t rm = instruction & 0xf;
    const char* condition = get_condition_suffix(get_processor_mode(context));

    print_instruction(instruction, output, "sel%s\tr%d, r%d, r%d",
                     condition, rd, rn, rm);
}

// Branch Instructions
void disasm_branch_instruction(uint32_t instruction, void* context, void* output) {
    int32_t offset = get_branch_offset(context);
    const char* condition = get_condition_suffix(get_processor_mode(context));

    const char* sign = (offset < 0) ? "-" : "";
    uint32_t abs_offset = (offset < 0) ? -offset : offset;

    print_instruction(instruction, output, "b%s\t%s0x%x", condition, sign, abs_offset);
}

// Undefined Instruction
void disasm_undefined_instruction(uint32_t instruction, void* context, void* output) {
    uint32_t imm = ((instruction >> 16) & 0xf) << 12 | (instruction & 0xfff);
    const char* condition = get_condition_suffix(get_processor_mode(context));

    print_instruction(instruction, output, "udf%s\t#%d", condition, imm);
}

// ARM Immediate Value Encoding/Decoding
uint64_t decode_arm_immediate(uint64_t value) {
    if ((value >> 12) != 0) {
        uint32_t result = (uint32_t)(value >> 12) | 0x80000000;
        if ((value & 0xfff) != 0 || (value >> 24) != 0) {
            result = 0xffffffff;
        }
        return result;
    }
    return value;
}

// ARM64 Immediate Value Encoding
uint64_t encode_arm64_immediate(uint64_t value, bool is_64bit) {
    uint32_t rotation = 0;

    if (is_64bit || (value >> 32) == (value & 0xffffffff)) {
        // Try different element sizes
        if ((value >> 16 & 0xffff) == (value & 0xffff)) {
            if ((value >> 8 & 0xff) == (value & 0xff)) {
                if ((value & 0xf) == ((value >> 4) & 0xf)) {
                    if ((value & 3) == ((value >> 2) & 3)) {
                        if (try_encode_pattern(value, 2, &rotation)) {
                            return create_encoded_immediate(value, 2, rotation);
                        }
                    } else if (try_encode_pattern(value, 4, &rotation)) {
                        return create_encoded_immediate(value, 4, rotation);
                    }
                } else if (try_encode_pattern(value, 8, &rotation)) {
                    return create_encoded_immediate(value, 8, rotation);
                }
            } else if (try_encode_pattern(value, 16, &rotation)) {
                return create_encoded_immediate(value, 16, rotation);
            }
        } else if (try_encode_pattern(value, 32, &rotation)) {
            if (rotation != 0) {
                value = rotate_right_64(value, 32 - rotation) |
                       rotate_left_64(value, rotation);
            }
            return (63U - count_leading_zeros(value & 0xffffffff)) | (rotation << 6);
        }
    } else if (try_encode_pattern(value, 64, &rotation)) {
        return create_encoded_immediate(value, 64, rotation);
    }

    return 0xffffffff;  // Cannot encode
}

// ARM Operand Parsing
void parse_arm_operand(operand_t* operand, uint32_t instruction) {
    uint32_t operand_type = get_operand_type(instruction);

    switch (operand_type) {
        case OPERAND_IMMEDIATE:
            operand->type = OPERAND_IMMEDIATE;
            operand->value = extract_immediate_value(instruction);
            operand->flags = get_immediate_flags(instruction);
            break;

        case OPERAND_REGISTER:
            operand->type = OPERAND_REGISTER;
            operand->reg = extract_register_number(instruction);
            operand->shift_type = extract_shift_type(instruction);
            operand->shift_amount = extract_shift_amount(instruction);
            break;

        case OPERAND_REGISTER_SHIFTED:
            operand->type = OPERAND_REGISTER_SHIFTED;
            operand->reg = extract_register_number(instruction);
            operand->shift_reg = extract_shift_register(instruction);
            operand->shift_type = extract_shift_type(instruction);
            break;

        case OPERAND_MEMORY:
            operand->type = OPERAND_MEMORY;
            operand->base_reg = extract_base_register(instruction);
            operand->index_reg = extract_index_register(instruction);
            operand->offset = extract_memory_offset(instruction);
            operand->addressing_mode = extract_addressing_mode(instruction);
            break;

        default:
            operand->type = OPERAND_INVALID;
            break;
    }
}

// ARM Instruction Format String Generation
void format_arm_operand(const operand_t* operand, char* buffer, size_t buffer_size) {
    switch (operand->type) {
        case OPERAND_IMMEDIATE:
            snprintf(buffer, buffer_size, "#%d", operand->value);
            break;

        case OPERAND_REGISTER:
            if (operand->shift_amount == 0) {
                const char* sign = operand->negate ? "-" : "";
                snprintf(buffer, buffer_size, "%sr%d", sign, operand->reg);
            } else {
                const char* sign = operand->negate ? "-" : "";
                const char* shift_type = get_shift_type_name(operand->shift_type);
                snprintf(buffer, buffer_size, "%sr%d, %s #%d",
                        sign, operand->reg, shift_type, operand->shift_amount);
            }
            break;

        case OPERAND_REGISTER_SHIFTED:
            {
                const char* sign = operand->negate ? "-" : "";
                const char* shift_type = get_shift_type_name(operand->shift_type);
                snprintf(buffer, buffer_size, "%sr%d, %s r%d",
                        sign, operand->reg, shift_type, operand->shift_reg);
            }
            break;

        default:
            snprintf(buffer, buffer_size, "invalid");
            break;
    }
}

// ARM Load/Store Instruction Disassembler
void disasm_load_store_instruction(uint64_t instruction, void* context, void* output) {
    uint32_t instr = instruction & 0xffffffff;
    uint32_t size = (instr >> 21) & 3;
    uint32_t load_bit = (instr >> 20) & 1;
    uint32_t sign_extend = (instr >> 24) & 1;
    uint32_t rd = (instr >> 12) & 0xf;
    uint32_t rn = (instr >> 16) & 0xf;

    operand_t operand;
    parse_arm_operand(&operand, instr);

    char operand_str[32];
    format_arm_operand(&operand, operand_str, sizeof(operand_str));

    const char* condition = get_condition_suffix(get_processor_mode(context));
    const char* mnemonic = get_load_store_mnemonic(size, load_bit, sign_extend);

    print_instruction(instr, output, "%s%s.w\tr%d, [r%d, %s]",
                     mnemonic, condition, rd, rn, operand_str);
}

// Debug Value Management
void emit_debug_value(debug_context_t* ctx, bool condition, uint32_t value1,
                     uint32_t value2, void* debug_info) {
    uint32_t debug_id = ctx->debug_counter++;
    ctx->debug_values[debug_id] = 0;

    if (condition) {
        emit_debug_instruction(ctx, DEBUG_OP_CONDITIONAL, value1, value2,
                              debug_id | 0x20000, debug_info);
    } else {
        emit_debug_instruction(ctx, DEBUG_OP_UNCONDITIONAL, value1, value2,
                              debug_id | 0x20000, debug_info);
    }
}

// Helper Functions
static const char* get_condition_suffix(int processor_mode) {
    static const char* conditions[] = {
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
        "hi", "ls", "ge", "lt", "gt", "le", "", "nv"
    };
    return conditions[processor_mode & 0xf];
}

static const char* get_addressing_mode_suffix(int pre_post, int up_down) {
    if (pre_post) {
        return up_down ? "ib" : "db";
    } else {
        return up_down ? "ia" : "da";
    }
}

static const char* get_shift_type_name(int shift_type) {
    static const char* shift_types[] = {"lsl", "lsr", "asr", "ror"};
    return shift_types[shift_type & 3];
}

static const char* get_crc_size_suffix(int size) {
    static const char* suffixes[] = {"b", "h", "w", "d"};
    return (size < 4) ? suffixes[size] : "error";
}

static bool try_encode_pattern(uint64_t value, int element_size, uint32_t* rotation) {
    // Implementation for trying to encode immediate patterns
    // This is a simplified version - actual implementation would be more complex
    *rotation = 0;
    return (value != 0) && (count_leading_zeros(value) + count_trailing_zeros(value) >= 32);
}

static uint64_t create_encoded_immediate(uint64_t value, int size, uint32_t rotation) {
    return encode_immediate_pattern(value, size, rotation);
}
