// elf_loader.h
#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t e_type;
    uint32_t e_machine;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint16_t e_phnum;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
    // ... 其他ELF头字段
} elf_header_t;

typedef struct {
    uint32_t p_type;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint32_t p_flags;
} program_header_t;

typedef struct {
    elf_header_t header;
    program_header_t phdrs[48]; // 最多48个程序头
    bool loaded;
} elf_image_t;

int load_elf_file(int fd, elf_image_t *elf);
int validate_elf_header(const elf_header_t *header, size_t file_size);
int load_program_segments(int fd, elf_image_t *elf);

#endif
