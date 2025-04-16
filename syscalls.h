/***********************************************************************
     Copyright (c) 2025 GNU/Linux Users' Group (NIT Durgapur)
     Author: Dhruba Sinha
************************************************************************/


#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/sched.h>
#include <linux/prctl.h>
#include <unistd.h>


struct syscall_entry {
    long syscall_no;
    char *syscall_name;
};

typedef struct syscall_entry SyscallEntry;


// array of syscalls that are not allowed
const SyscallEntry disallowed_syscalls[] = {
    // {2, "open"},
    // {4, "stat"},
    // {5, "fstat"},
    // {6, "lstat"},
    // {7, "poll"},
    // {16, "ioctl"},
    // {}

    // {SYS_clone, "clone"},
    // {SYS_clone3, "clone3"},
    // {SYS_fork, "fork"},
    {SYS_execve, "execve"},
    // {SYS_reboot}
};


/*
    check wheather a syscall is allowed or not
    if allowed, return -1
    else return the index of that syscall in the array disallowed_syscalls
*/
long get_syscall_index(long syscall_no) {
    long n = sizeof(disallowed_syscalls) / sizeof(SyscallEntry);
    for (long i = 0; i < n; i++) {
        if (disallowed_syscalls[i].syscall_no == syscall_no) return i;
    }

    return -1;
}


// custom wrapper function SYS_clone3
pid_t clone3(struct clone_args *cl_args) {   
    return (pid_t)syscall(SYS_clone3, cl_args, sizeof(struct clone_args));  // use raw syscall interface
}