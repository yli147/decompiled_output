#include <stdint.h>
#include <stdbool.h>

// 寄存器上下文结构体
struct CPUContext {
    // 通用寄存器 x0-x30
    uint64_t x_regs[31];
    
    // 浮点寄存器 d0-d31
    uint64_t d_regs[32];
    
    // 特殊寄存器
    uint64_t sp;        // 栈指针
    uint64_t pc;        // 程序计数器
    uint64_t lr;        // 链接寄存器
    uint32_t cpsr;      // 程序状态寄存器
    uint32_t fpsr;      // 浮点状态寄存器
    uint32_t fpcr;      // 浮点控制寄存器
    
    // 其他状态
    uint64_t fault_address;
    uint32_t fault_status;
};

// 执行状态
enum ExecutionState {
    EXEC_CONTINUE = 0,
    EXEC_EXIT,
    EXEC_SYSCALL,
    EXEC_EXCEPTION
};

// 函数指针类型定义
typedef uint64_t (*syscall_handler_t)(uint64_t, uint64_t, uint64_t);
typedef void (*context_switch_callback_t)(uint64_t, void*);

// 全局变量
extern context_switch_callback_t g_context_switch_callback;

// 重构后的主执行循环 - 原 FUN_8010001ff864
void cpu_execution_loop(struct CPUContext* context, uint64_t param2, uint64_t param3) {
    enum ExecutionState exec_state;
    uint64_t syscall_offset;
    void* jump_target;
    
    // 初始化执行环境
    initialize_execution_environment();
    setup_memory_protection();
    
    // 准备上下文
    prepare_execution_context(context);
    setup_signal_handlers(context);
    
    // 主执行循环
    while (true) {
        // 保存当前寄存器状态
        save_cpu_registers(context);
        save_floating_point_registers(context);
        
        // 检查是否有待处理的中断或异常
        jump_target = check_pending_interrupts(1);
        
        // 恢复信号处理状态
        restore_signal_handlers(context);
        
        // 获取当前执行偏移
        syscall_offset = get_current_execution_offset();
        
        // 清理执行状态
        cleanup_execution_state(context);
        
        // 如果有跳转目标，执行跳转
        if (jump_target != NULL) {
            break;
        }
        
        // 执行一个指令周期
        execute_instruction_cycle(context, param3, 
                                *(uint64_t*)(context + syscall_offset));
        
        // 保存浮点寄存器状态
        save_floating_point_registers(context);
        
        // 处理内存管理
        handle_memory_management();
        
        // 处理系统调用
        handle_system_calls();
        
        // 清理和重置
        cleanup_and_reset();
        setup_memory_protection();
        initialize_execution_environment();
        
        // 重新准备执行环境
        prepare_execution_context(context);
        setup_signal_handlers(context);
        restore_execution_state(context);
    }
    
    // 执行跳转目标
    execute_jump_target(jump_target);
}

// 重构后的系统调用处理 - 原 FUN_8010001ff8ac
void handle_syscall_execution(uint64_t param1, uint64_t param2, 
                             uint64_t param3, uint64_t param4, uint64_t param5) {
    struct CPUContext* context = get_current_context();
    void* jump_target;
    syscall_handler_t handler;
    
    // 执行系统调用前的准备
    execute_instruction_cycle(context, 0, 0);
    save_floating_point_registers(context);
    handle_memory_management();
    
    // 获取并执行系统调用处理器
    handler = get_syscall_handler(param5);
    if (handler) {
        handler(param1, param2, param3);
    }
    
    // 系统调用后的清理
    cleanup_syscall_state();
    initialize_execution_environment();
    restore_signal_handlers(context);
    prepare_execution_context(context);
    
    // 继续执行循环
    while (true) {
        save_cpu_registers(context);
        save_floating_point_registers(context);
        
        jump_target = check_pending_interrupts(1);
        
        restore_signal_handlers(context);
        get_current_execution_offset();
        cleanup_execution_state(context);
        
        if (jump_target != NULL) {
            break;
        }
        
        execute_instruction_cycle(context, 0, 0);
        save_floating_point_registers(context);
        handle_memory_management();
        handle_system_calls();
        cleanup_and_reset();
        setup_memory_protection();
        initialize_execution_environment();
        prepare_execution_context(context);
        restore_signal_handlers(context);
        restore_execution_state(context);
    }
    
    execute_jump_target(jump_target);
}

// 简单的函数调用包装器 - 原 FUN_8010001ffa48
uint64_t execute_with_context_save(uint64_t param1, uint64_t param2, 
                                  uint64_t param3, syscall_handler_t handler) {
    struct CPUContext* context = get_current_context();
    uint64_t result;
    
    // 保存上下文
    execute_instruction_cycle(context, 0, 0);
    save_floating_point_registers(context);
    
    // 执行函数
    result = handler(param1);
    
    // 恢复上下文
    restore_signal_handlers(context);
    prepare_execution_context(context);
    
    return result;
}

// 带清理的函数调用包装器 - 原 FUN_8010001ffa80
uint64_t execute_with_cleanup(uint64_t param1, uint64_t param2, 
                             uint64_t param3, syscall_handler_t handler) {
    struct CPUContext* context = get_current_context();
    uint64_t result;
    
    execute_instruction_cycle(context, 0, 0);
    save_floating_point_registers(context);
    
    result = handler(param1);
    
    restore_signal_handlers(context);
    cleanup_execution_state(context);
    
    return result;
}

// 带状态恢复的函数调用 - 原 FUN_8010001ffab8
uint64_t execute_with_state_restore(uint64_t param1, uint64_t param2, 
                                   uint64_t param3, syscall_handler_t handler) {
    struct CPUContext* context = get_current_context();
    uint64_t result;
    
    restore_execution_state(context);
    save_floating_point_registers(context);
    
    result = handler(param1);
    
    restore_signal_handlers(context);
    cleanup_execution_state(context);
    
    return result;
}

// 最小化的函数调用 - 原 FUN_8010001ffaf0
uint64_t execute_minimal(uint64_t param1, uint64_t param2, 
                        uint64_t param3, syscall_handler_t handler) {
    struct CPUContext* context = get_current_context();
    uint64_t result;
    
    restore_execution_state(context);
    result = handler(param1);
    cleanup_execution_state(context);
    
    return result;
}

// 保存完整CPU状态 - 原 FUN_8010001ffb18
uint64_t save_full_cpu_state(struct CPUContext* context) {
    // 保存通用寄存器 x19-x30
    context->x_regs[19] = get_register_x19();
    context->x_regs[20] = get_register_x20();
    context->x_regs[21] = get_register_x21();
    context->x_regs[22] = get_register_x22();
    context->x_regs[23] = get_register_x23();
    context->x_regs[24] = get_register_x24();
    context->x_regs[25] = get_register_x25();
    context->x_regs[26] = get_register_x26();
    context->x_regs[27] = get_register_x27();
    context->x_regs[28] = get_register_x28();
    context->x_regs[29] = get_register_x29();
    context->x_regs[30] = get_register_x30();
    
    // 保存栈指针
    context->sp = get_stack_pointer();
    
    // 保存浮点寄存器 d8-d15
    context->d_regs[8] = get_register_d8();
    context->d_regs[9] = get_register_d9();
    context->d_regs[10] = get_register_d10();
    context->d_regs[11] = get_register_d11();
    context->d_regs[12] = get_register_d12();
    context->d_regs[13] = get_register_d13();
    context->d_regs[14] = get_register_d14();
    context->d_regs[15] = get_register_d15();
    
    // 触发上下文保存完成信号
    signal_context_saved(0xa8);
    
    return 0;
}

// 简单的返回值处理 - 原 FUN_8010001ffb64
uint64_t handle_return_value(uint64_t param1, uint64_t param2) {
    return (param2 == 0) ? 1 : param2;
}

// 系统调用包装器
void supervisor_call_void() {
    call_supervisor(0);
}

uint64_t supervisor_call_with_return(uint64_t param1, uint64_t param2) {
    call_supervisor(0);
    return param2;
}

// 系统调用返回结构体
struct SyscallResult {
    uint64_t value1;
    uint64_t value2;
};

struct SyscallResult supervisor_call_dual_return(uint64_t param1, uint64_t param2, uint64_t param3) {
    struct SyscallResult result;
    call_supervisor(0);
    result.value1 = param2;
    result.value2 = param3;
    return result;
}

// 内存管理相关的系统调用
struct SyscallResult memory_advice_call(uint64_t param1, uint64_t param2, uint64_t param3) {
    struct SyscallResult result;
    call_supervisor(0);
    result.value1 = param2;
    result.value2 = param3;
    return result;
}

// 程序入口点 - 原 entry
void program_entry() {
    uint64_t stack_alignment;
    uint64_t argc;
    char** argv;
    char** envp;
    void* auxv;
    char stack_buffer[512];
    
    // 获取栈对齐信息
    stack_alignment = get_stack_alignment();
    
    // 设置栈对齐
    set_stack_alignment(align_stack_pointer(stack_buffer, stack_alignment));
    
    // 初始化系统
    initialize_runtime();
    setup_signal_handling();
    
    // 调用主函数
    call_main_function(argc, argv, envp, auxv);
}

// 空函数 - 原 FUN_8010001ffcd0
void noop_function() {
    // 什么都不做
}

// 条件跳转处理 - 原 FUN_8010001ffe54
void handle_conditional_jump(uint64_t condition) {
    call_supervisor(0);
    
    if (condition != 0) {
        return;
    }
    
    // 执行跳转到错误处理
    execute_error_handler(0xdc);
}

// 上下文切换回调函数
void context_switch_callback_1() {
    uint64_t context_id = get_current_context_id();
    if (g_context_switch_callback != NULL) {
        g_context_switch_callback(context_id, get_callback_function_1());
    }
}

void context_switch_callback_2() {
    uint64_t context_id = get_current_context_id();
    if (g_context_switch_callback != NULL) {
        g_context_switch_callback(context_id, get_callback_function_2());
    }
}

void context_switch_callback_3() {
    uint64_t context_id = get_current_context_id();
    if (g_context_switch_callback != NULL) {
        g_context_switch_callback(context_id, get_callback_function_3());
    }
}

void context_switch_callback_4() {
    uint64_t context_id = get_current_context_id();
    if (g_context_switch_callback != NULL) {
        g_context_switch_callback(context_id, get_callback_function_4());
    }
}

// 寄存器保存函数
void save_cpu_registers(struct CPUContext* context) {
    // 保存通用寄存器
    context->x_regs[19] = get_register_x19();
    context->x_regs[20] = get_register_x20();
    context->x_regs[21] = get_register_x21();
    context->x_regs[22] = get_register_x22();
    context->x_regs[23] = get_register_x23();
    context->x_regs[24] = get_register_x24();
    context->x_regs[25] = get_register_x25();
    context->x_regs[26] = get_register_x26();
    context->x_regs[27] = get_register_x27();
    context->x_regs[28] = get_register_x28();
    context->x_regs[29] = get_register_x29();
    
    // 保存其他寄存器
    save_additional_registers(context);
}

void save_floating_point_registers(struct CPUContext* context) {
    // 保存浮点寄存器 d16-d31
    for (int i = 16; i < 32; i++) {
        context->d_regs[i] = get_floating_point_register(i);
    }
}

// 获取上下文偏移
uint64_t get_context_offset(struct CPUContext* context) {
    return (uint64_t)context + 0x420;
}

// 信号处理初始化
struct SyscallResult initialize_signal_context(struct CPUContext* context) {
    struct SyscallResult result;
    
    // 初始化信号相关字段
    context->fault_address = 0;
    
    // 保存所有寄存器状态
    save_all_registers(context);
    
    // 设置浮点控制寄存器
    context->fpsr = get_fpsr();
    context->fpcr = get_fpcr();
    
    // 清理其他状态
    clear_additional_state(context);
    
    call_supervisor(0);
    
    result.value1 = 0;
    result.value2 = 0;
    return result;
}

// 清理函数
void cleanup_and_exit() {
    cleanup_runtime_state();
}
