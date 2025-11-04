// execve.h
#ifndef EXECVE_H
#define EXECVE_H

typedef enum {
    EXECVE_MODE_NORMAL = 0,
    EXECVE_MODE_NATIVE = 1,
    EXECVE_MODE_EMULATED = 2,
    EXECVE_MODE_SCRIPT = 3
} execve_mode_t;

int do_execve(const char *filename, char *const argv[], 
              char *const envp[], execve_mode_t mode);
int resolve_interpreter(const char *filename, char *interpreter_path);
bool is_elf_file(const char *filename);
bool is_script_file(const char *filename);

#endif
