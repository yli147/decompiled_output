// 检查文件描述符是否指向 /proc/self/fd 或 /proc/self/fdinfo
bool is_proc_self_fd(int fd) {
    char fd_path[24];
    char proc_self_path[24];
    char proc_fd_path[4096];
    char proc_self_link[32];
    char readlink_buffer[4096];
    
    // 构建 /proc/self/fd/xxx 路径
    strcpy(fd_path, "/proc/se");
    strcat(fd_path, "lf/fd/xxxxxxxxxx");
    snprintf(proc_fd_path, sizeof(proc_fd_path), "/proc/self/fd/%d", fd);
    
    // 读取符号链接
    ssize_t link_len = readlink(proc_fd_path, readlink_buffer, sizeof(readlink_buffer));
    if (link_len < 0) {
        return false;
    }
    readlink_buffer[link_len] = '\0';
    
    // 读取 /proc/self 链接获取进程ID
    ssize_t self_len = readlink("/proc/self", proc_self_link, sizeof(proc_self_link));
    if (self_len < 0) {
        return false;
    }
    proc_self_link[self_len] = '\0';
    
    // 解析进程ID
    int pid = strtol(proc_self_link, nullptr, 10);
    
    // 构建预期的路径
    char expected_fd_path[24];
    char expected_fdinfo_path[24];
    snprintf(expected_fd_path, sizeof(expected_fd_path), "/proc/%d/fd", pid);
    snprintf(expected_fdinfo_path, sizeof(expected_fdinfo_path), "/proc/%d/fdinfo", pid);
    
    // 检查是否匹配 /proc/pid/fd 路径
    if (strcmp(readlink_buffer, expected_fd_path) == 0) {
        return true;
    }
    
    // 检查是否匹配 /proc/pid/fdinfo 路径
    return strcmp(readlink_buffer, expected_fdinfo_path) == 0;
}

// 处理目录项过滤（getdents系统调用的辅助函数）
void filter_directory_entries() {
    ulong stack_base = get_stack_base();
    void* buffer = get_syscall_arg(0);
    ulong fd = get_syscall_arg(1);
    
    // 检查文件描述符范围
    int fd_int = (int)fd;
    if (fd_int >= 0 && fd_int >= MIN_RESERVED_FD && fd_int < MIN_RESERVED_FD + 6) {
        set_syscall_result(stack_base, -EBADF);
        return;
    }
    
    // 执行系统调用
    ulong result = syscall_getdents(fd, buffer, get_syscall_arg(2));
    if (result > 4095) { // 错误情况
        set_syscall_result(stack_base, result);
        return;
    }
    
    if (result == 0) {
        set_syscall_result(stack_base, 0);
        return;
    }
    
    // 过滤目录项
    if (is_proc_self_fd(fd_int)) {
        result = filter_proc_fd_entries(buffer, result);
    }
    
    set_syscall_result(stack_base, result);
}

// 过滤 /proc/self/fd 目录中的条目
ulong filter_proc_fd_entries(void* buffer, ulong size) {
    ulong filtered_size = 0;
    ulong offset = 0;
    void* write_ptr = buffer;
    
    while (offset < size) {
        struct dirent* entry = (struct dirent*)((char*)buffer + offset);
        bool should_keep = true;
        
        // 检查是否为特殊目录项
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            should_keep = true;
        } else {
            // 解析文件描述符编号
            char* endptr;
            long fd_num = strtol(entry->d_name, &endptr, 10);
            
            // 如果解析失败或者是保留的文件描述符，则过滤掉
            if (*endptr != '\0' || 
                (fd_num >= MIN_RESERVED_FD && fd_num < MIN_RESERVED_FD + 6)) {
                should_keep = false;
            }
        }
        
        if (should_keep) {
            if (write_ptr != entry) {
                memmove(write_ptr, entry, entry->d_reclen);
            }
            write_ptr = (char*)write_ptr + entry->d_reclen;
            filtered_size += entry->d_reclen;
        }
        
        offset += entry->d_reclen;
    }
    
    return filtered_size;
}

// 系统调用：fsync
void syscall_fsync() {
    ulong stack_base = get_stack_base();
    ulong fd_addr = get_syscall_arg(0);
    long fd = get_syscall_arg(1);
    
    // 检查地址有效性
    if (fd_addr != 0 && !is_valid_user_address(fd_addr, 16)) {
        set_syscall_result(stack_base, -EFAULT);
        return;
    }
    
    long result;
    if (has_vdso_fsync()) {
        result = vdso_fsync(fd, fd_addr);
        if (result == -ENOSYS) {
            result = syscall(SYS_fsync, fd, fd_addr);
        }
    } else {
        result = syscall(SYS_fsync, fd, fd_addr);
    }
    
    set_syscall_result(stack_base, result);
}

// 系统调用：fdatasync  
void syscall_fdatasync() {
    ulong stack_base = get_stack_base();
    ulong fd_addr = get_syscall_arg(0);
    long fd = get_syscall_arg(1);
    
    // 检查地址有效性
    if (fd_addr != 0 && !is_valid_user_address(fd_addr, 16)) {
        set_syscall_result(stack_base, -EFAULT);
        return;
    }
    
    long result;
    if (has_vdso_fdatasync()) {
        result = vdso_fdatasync(fd, fd_addr);
        if (result == -ENOSYS) {
            result = syscall(SYS_fdatasync, fd, fd_addr);
        }
    } else {
        result = syscall(SYS_fdatasync, fd, fd_addr);
    }
    
    set_syscall_result(stack_base, result);
}

// 系统调用：sync_file_range
void syscall_sync_file_range() {
    ulong stack_base = get_stack_base();
    ulong fd_addr = get_syscall_arg(0);
    long fd = get_syscall_arg(1);
    
    ulong result = -EFAULT;
    if (fd_addr != 0) {
        if (!is_valid_user_address(fd_addr, 16)) {
            set_syscall_result(stack_base, -EFAULT);
            return;
        }
        
        if (has_vdso_sync_file_range()) {
            result = vdso_sync_file_range(fd, fd_addr);
            if (result == -ENOSYS) {
                result = syscall(SYS_sync_file_range, fd, fd_addr);
            }
        } else {
            result = syscall(SYS_sync_file_range, fd, fd_addr);
        }
        
        if (result < 4097) {
            set_syscall_result(stack_base, result);
            return;
        }
    }
    
    set_syscall_result(stack_base, result);
}

// 系统调用：pselect6
void syscall_pselect6() {
    ulong stack_base = get_stack_base();
    long* fd_sets[3];
    long nfds = get_syscall_arg(0);
    void* timeout = get_syscall_arg(2);
    
    // 检查参数有效性
    if (nfds < 0) {
        set_syscall_result(stack_base, -EINVAL);
        return;
    }
    
    if (nfds > 1000) {
        nfds = 1000;
    }
    
    if (timeout == nullptr) {
        long result = syscall(SYS_pselect6, get_syscall_arg(1), nfds, 0, 0, 0, 0);
        set_syscall_result(stack_base, result);
    } else {
        // 处理带超时的 pselect6
        handle_pselect6_with_timeout(stack_base, nfds, timeout);
    }
}

// 系统调用：clone
void syscall_clone() {
    ulong stack_base = get_stack_base();
    ulong flags = get_syscall_arg(0);
    void* child_stack = get_syscall_arg(1);
    void* ptid = get_syscall_arg(2);
    void* ctid = get_syscall_arg(3);
    void* newtls = get_syscall_arg(4);
    
    // 检查地址有效性
    if ((child_stack != nullptr && !is_valid_user_address(child_stack, 48)) ||
        (ptid != nullptr && !is_valid_user_address(ptid, 4)) ||
        (ctid != nullptr && !is_valid_user_address(ctid, 64))) {
        set_syscall_result(stack_base, -EFAULT);
        return;
    }
    
    int clone_flags = (int)flags;
    if (clone_flags == 0 || clone_flags == 5) {
        // 检查进程数限制
        if (check_process_limit()) {
            set_syscall_result(stack_base, -EAGAIN);
            return;
        }
        
        long result = syscall(SYS_clone, clone_flags, child_stack, ptid, ctid, newtls);
        if (result < 4097) {
            update_process_count();
        }
        set_syscall_result(stack_base, result);
    } else {
        long result = syscall(SYS_clone, clone_flags, child_stack, ptid, ctid, newtls);
        set_syscall_result(stack_base, result);
    }
}

// 系统调用：socket
void syscall_socket() {
    ulong stack_base = get_stack_base();
    long domain = get_syscall_arg(1);
    long type = get_syscall_arg(0);
    long protocol = get_syscall_arg(2);
    void* addr = get_syscall_arg(3);
    
    // 检查进程数限制
    if (check_process_limit()) {
        set_syscall_result(stack_base, -EAGAIN);
        return;
    }
    
    // 检查地址有效性
    if (addr != nullptr && !is_valid_user_address(addr, 64)) {
        set_syscall_result(stack_base, -EFAULT);
        return;
    }
    
    // 转换套接字类型和协议
    int socket_type, socket_protocol;
    convert_socket_params(type, protocol, &socket_type, &socket_protocol);
    
    long result = syscall(SYS_socket, domain, socket_type, protocol, addr);
    set_syscall_result(stack_base, result);
    
    if (result < 4097) {
        update_process_count();
        mark_socket_created();
    }
}

// 系统调用：exit
void syscall_exit() {
    ulong stack_base = get_stack_base();
    int exit_code = (int)get_syscall_arg(1);
    
    // 检查文件描述符范围
    if (exit_code >= 0 && exit_code >= MIN_RESERVED_FD && 
        exit_code < MIN_RESERVED_FD + 6) {
        set_syscall_result(stack_base, -EBADF);
        return;
    }
    
    long result = syscall(SYS_exit, exit_code);
    if (result < 4097) {
        update_process_count_on_exit();
    }
    
    set_syscall_result(stack_base, result);
}

// 系统调用：fork
void syscall_fork() {
    ulong stack_base = get_stack_base();
    long parent_pid = get_syscall_arg(1);
    
    if (parent_pid == 0) {
        set_syscall_result(stack_base, -EFAULT);
        return;
    }
    
    // 检查进程数限制
    if (check_process_limit()) {
        set_syscall_result(stack_base, -EAGAIN);
        return;
    }
    
    // 转换进程ID
    int pid;
    convert_process_id(parent_pid, &pid);
    
    long result = syscall(SYS_fork, parent_pid, pid);
    if (result < 4097) {
        if (result == 0) {
            // 子进程
            update_child_process_state();
        } else {
            // 父进程
            update_parent_process_state();
        }
    }
    
    set_syscall_result(stack_base, result);
}

// 系统调用：vfork  
void syscall_vfork() {
    ulong stack_base = get_stack_base();
    long parent_pid = get_syscall_arg(1);
    
    if (parent_pid == 0) {
        set_syscall_result(stack_base, -EFAULT);
        return;
    }
    
    // 检查进程数限制
    if (check_process_limit()) {
        set_syscall_result(stack_base, -EAGAIN);
        return;
    }
    
    // 转换进程ID
    int pid;
    convert_process_id(parent_pid, &pid);
    
    long result = syscall(SYS_vfork, parent_pid, pid);
    if (result < 4097) {
        if (result == 0) {
            // 子进程
            update_child_process_state();
        } else {
            // 父进程  
            update_parent_process_state();
        }
    }
    
    set_syscall_result(stack_base, result);
}

// 系统调用：kill
void syscall_kill() {
    ulong stack_base = get_stack_base();
    int pid = (int)get_syscall_arg(1);
    
    // 检查进程ID范围
    if (pid >= 0 && pid >= MIN_RESERVED_FD && pid < MIN_RESERVED_FD + 6) {
        set_syscall_result(stack_base, -EBADF);
        return;
    }
    
    // 检查进程数限制
    if (check_process_limit()) {
        set_syscall_result(stack_base, -EAGAIN);
        return;
    }
    
    long result = syscall(SYS_kill, pid);
    if (result < 4097) {
        update_process_count_on_kill();
    }
    
    set_syscall_result(stack_base, result);
}

// 系统调用：rt_sigaction
void syscall_rt_sigaction() {
    ulong stack_base = get_stack_base();
    ulong signum = get_syscall_arg(1);
    
    // 转换信号编号
    uint converted_signum = convert_signal_number((uint)signum);
    if (converted_signum == 0) {
        set_syscall_result(stack_base, -EINVAL);
        return;
    }
    
    // 检查进程数限制
    if (check_process_limit()) {
        set_syscall_result(stack_base, -EAGAIN);
        return;
    }
    
    long result = syscall(SYS_rt_sigaction, converted_signum);
    if (result < 4097) {
        update_process_count();
    }
    
    set_syscall_result(stack_base, result);
}

// 系统调用：rt_sigprocmask
void syscall_rt_sigprocmask() {
    ulong stack_base = get_stack_base();
    ulong signum = get_syscall_arg(1);
    
    // 转换信号编号
    uint converted_signum = convert_signal_number((uint)signum);
    if (converted_signum == 0) {
        set_syscall_result(stack_base, -EINVAL);
        return;
    }
    
    // 检查进程数限制
    if (check_process_limit()) {
        set_syscall_result(stack_base, -EAGAIN);
        return;
    }
    
    long result = syscall(SYS_rt_sigprocmask, converted_signum);
    if (result < 4097) {
        update_process_count();
    }
    
    set_syscall_result(stack_base, result);
}

// 转换信号编号的辅助函数
uint convert_signal_number(uint signum) {
    // 这里实现信号编号的转换逻辑
    // 根据原始代码中的复杂转换逻辑进行实现
    
    uint result = signum & 1;
    
    // 根据不同的位进行转换
    if ((signum & 1) == 0) {
        // 偶数信号的转换逻辑
        // ... 复杂的位操作转换
    } else {
        // 奇数信号的转换逻辑  
        // ... 复杂的位操作转换
    }
    
    // 处理特殊信号位
    if ((signum >> 1 & 1) != 0) {
        // 处理第2位
    }
    
    if ((signum >> 6 & 1) != 0) {
        // 处理第7位
    }
    
    // ... 继续处理其他位
    
    return result;
}

// 系统调用：brk (内存分配)
void syscall_brk() {
    ulong stack_base = get_stack_base();
    ulong new_brk = get_syscall_arg(1);
    
    acquire_memory_lock();
    acquire_brk_lock();
    
    ulong current_brk = get_current_brk();
    ulong brk_limit = get_brk_limit();
    
    if (new_brk != 0 && new_brk != current_brk && new_brk >= get_brk_start()) {
        ulong new_brk_aligned = (new_brk + 0xfff) & ~0xfff;
        ulong current_brk_aligned = (current_brk + 0xfff) & ~0xfff;
        
        if (new_brk_aligned != current_brk_aligned) {
            if (new_brk_aligned < current_brk_aligned) {
                // 缩小堆
                shrink_heap(new_brk_aligned, current_brk_aligned);
            } else {
                // 扩大堆
                if (expand_heap(current_brk_aligned, new_brk_aligned)) {
                    current_brk = new_brk;
                }
            }
        } else {
            current_brk = new_brk;
        }
    }
    
    set_current_brk(current_brk);
    release_brk_lock();
    release_memory_lock();
    
    set_syscall_result(stack_base, current_brk);
}

// 系统调用：mremap (重新映射内存)
void syscall_mremap() {
    ulong stack_base = get_stack_base();
    ulong old_addr = get_syscall_arg(1);
    ulong old_size = get_syscall_arg(0);
    ulong new_size = get_syscall_arg(2);
    ulong flags = get_syscall_arg(4);
    ulong new_addr = get_syscall_arg(3);
    
    // 参数验证
    if (((flags & ~3) != 0) || 
        ((~flags & 1 & flags >> 1) != 0) ||
        ((old_addr & 0xfff) != 0) ||
        ((new_size + 0xfff) & ~0xfff) == 0) {
        set_syscall_result(stack_base, -EINVAL);
        return;
    }
    
    // 地址范围检查
    if (!is_valid_memory_range(old_addr, old_size) ||
        !is_valid_memory_range(new_addr, new_size)) {
        set_syscall_result(stack_base, -EFAULT);
        return;
    }
    
    acquire_memory_lock();
    
    ulong result;
    if ((flags & 2) == 0) {
        // 就地重新映射
        result = mremap_in_place(old_addr, old_size, new_size);
    } else {
        // 移动重新映射
        result = mremap_with_move(old_addr, old_size, new_size, new_addr, flags);
    }
    
    release_memory_lock();
    set_syscall_result(stack_base, result);
}

// 辅助函数实现
bool check_process_limit() {
    // 检查进程数是否达到限制
    return get_current_process_count() >= get_max_process_limit();
}

void update_process_count() {
    // 更新进程计数
    atomic_increment(&process_count);
}

bool is_valid_user_address(void* addr, size_t size) {
    // 检查用户地址是否有效
    ulong start = (ulong)addr;
    ulong end = start + size;
    return (start >= USER_ADDR_MIN && end <= USER_ADDR_MAX);
}

void convert_socket_params(long type, long protocol, int* socket_type, int* socket_protocol) {
    // 转换套接字参数
    *socket_type = (int)type;
    *socket_protocol = (int)protocol;
}

ulong get_stack_base() {
    return (ulong)&stack_var & STACK_MASK;
}

long get_syscall_arg(int index) {
    ulong stack_base = get_stack_base();
    return *(long*)(stack_base + SYSCALL_ARG_OFFSET + index * 8);
}

void set_syscall_result(ulong stack_base, long result) {
    *(long*)(stack_base + SYSCALL_RESULT_OFFSET) = result;
}
