// elf_loader.c
#include "elf_loader.h"
#include <sys/mman.h>

int load_elf_file(int fd, elf_image_t *elf) {
    // 读取ELF头
    ssize_t bytes_read = read(fd, &elf->header, sizeof(elf_header_t));
    if (bytes_read != sizeof(elf_header_t)) {
        return -EIO;
    }
    
    // 获取文件大小
    struct stat st;
    if (fstat(fd, &st) != 0) {
        return -errno;
    }
    
    // 验证ELF头
    int ret = validate_elf_header(&elf->header, st.st_size);
    if (ret != 0) {
        return ret;
    }
    
    // 读取程序头表
    if (elf->header.e_phnum > 0) {
        size_t phdrs_size = elf->header.e_phnum * sizeof(program_header_t);
        if (lseek(fd, elf->header.e_phoff, SEEK_SET) == -1) {
            return -errno;
        }
        
        bytes_read = read(fd, elf->phdrs, phdrs_size);
        if (bytes_read != phdrs_size) {
            return -EIO;
        }
    }
    
    // 加载程序段
    ret = load_program_segments(fd, elf);
    if (ret != 0) {
        return ret;
    }
    
    elf->loaded = true;
    return 0;
}

int validate_elf_header(const elf_header_t *header, size_t file_size) {
    // 检查ELF魔数
    if ((header->e_ident[0] != 0x7f) || 
        (header->e_ident[1] != 'E') ||
        (header->e_ident[2] != 'L') || 
        (header->e_ident[3] != 'F')) {
        return -ENOEXEC;
    }
    
    // 检查架构
    if (header->e_machine != EM_X86_64) {
        return -ENOEXEC;
    }
    
    // 检查文件类型
    if (header->e_type != ET_EXEC && header->e_type != ET_DYN) {
        return -ENOEXEC;
    }
    
    // 检查程序头表是否在文件范围内
    if (header->e_phoff >= file_size) {
        return -ENOEXEC;
    }
    
    size_t phdrs_end = header->e_phoff + 
                       header->e_phnum * sizeof(program_header_t);
    if (phdrs_end > file_size) {
        return -ENOEXEC;
    }
    
    return 0;
}

int load_program_segments(int fd, elf_image_t *elf) {
    for (int i = 0; i < elf->header.e_phnum; i++) {
        program_header_t *phdr = &elf->phdrs[i];
        
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        
        // 验证段的有效性
        if (phdr->p_filesz > phdr->p_memsz) {
            return -ENOEXEC;
        }
        
        // 检查地址对齐
        if ((phdr->p_vaddr & 0xfff) != (phdr->p_offset & 0xfff)) {
            return -ENOEXEC;
        }
        
        // 映射段到内存
        int prot = 0;
        if (phdr->p_flags & PF_R) prot |= PROT_READ;
        if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr->p_flags & PF_X) prot |= PROT_EXEC;
        
        void *addr = mmap((void*)(phdr->p_vaddr & ~0xfff),
                         (phdr->p_memsz + 0xfff) & ~0xfff,
                         prot,
                         MAP_PRIVATE | MAP_FIXED,
                         fd,
                         phdr->p_offset & ~0xfff);
        
        if (addr == MAP_FAILED) {
            return -errno;
        }
        
        // 处理BSS段（零填充）
        if (phdr->p_memsz > phdr->p_filesz) {
            zero_bss_pages((void*)phdr->p_vaddr + phdr->p_filesz,
                          (void*)phdr->p_vaddr + phdr->p_memsz);
        }
    }
    
    return 0;
}
