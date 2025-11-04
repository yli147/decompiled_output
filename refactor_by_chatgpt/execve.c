// execve.c
#include "execve.h"
#include "elf_loader.h"

int do_execve(const char *filename, char *const argv[], 
              char *const envp[], execve_mode_t mode) {
    
    // 解析文件路径
    char resolved_path[PATH_MAX];
    if (resolve_path(filename, resolved_path) != 0) {
        return -ENOENT;
    }
    
    // 打开文件
    int fd = open(resolved_path, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }
    
    // 检查文件类型
    char magic[4];
    if (read(fd, magic, 4) != 4) {
        close(fd);
        return -EIO;
    }
    
    lseek(fd, 0, SEEK_SET);
    
    // 根据文件类型选择执行方式
    if (magic[0] == 0x7f && magic[1] == 'E' && 
        magic[2] == 'L' && magic[3] == 'F') {
        // ELF文件
        return execute_elf(fd, resolved_path, argv, envp, mode);
    } else if (magic[0] == '#' && magic[1] == '!') {
        // 脚本文件
        return execute_script(fd, resolved_path, argv, envp, mode);
    } else {
        close(fd);
        return -ENOEXEC;
    }
}

static int execute_elf(int fd, const char *path, char *const argv[], 
                      char *const envp[], execve_mode_t mode) {
    elf_image_t elf = {0};
    
    int ret = load_elf_file(fd, &elf);
    if (ret != 0) {
        close(fd);
        return ret;
    }
    
    // 设置新的地址空间
    ret = setup_address_space(&elf);
    if (ret != 0) {
        close(fd);
        return ret;
    }
    
    // 设置栈和环境
    ret = setup_stack_and_env(argv, envp);
    if (ret != 0) {
        close(fd);
        return ret;
    }
    
    close(fd);
    
    // 跳转到程序入口点
    jump_to_entry(elf.header.e_entry);
    
    // 不应该到达这里
    return -ENOEXEC;
}
