/***********************************************************************
     Copyright (c) 2024 GNU/Linux Users' Group (NIT Durgapur)
     Author: Dhruba Sinha
************************************************************************/


#include <sys/syscall.h>


struct syscall_entry {
    long syscallNo;
    char *syscallName;
};

typedef struct syscall_entry SyscallEntry;


// array of syscalls that are not allowed
const SyscallEntry disallowed_syscalls[] = {

};


/*
    check wheather a syscall is allowed or not
    if allowed, return -1
    else return the index of that syscall in the array disallowed_syscalls
*/
int isDisallowedSyscall(long syscallNo) {
    int n = sizeof(disallowed_syscalls) / sizeof(SyscallEntry);
    for (int i = 0; i < n; i++) {
        if (disallowed_syscalls[i].syscallNo == syscallNo) return i;
    }

    return -1;
}