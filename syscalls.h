#include <sys/syscall.h>


struct syscall_entry {
    int syscall_no;
    char *syscall_name;
};

typedef struct syscall_entry SyscallEntry;


// list of syscalls that are not allowed
const SyscallEntry restricted_syscalls[] = {

};