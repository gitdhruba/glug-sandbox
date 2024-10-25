/***********************************************************************
     Copyright (c) 2024 GNU/Linux Users' Group (NIT Durgapur)
     Author: Dhruba Sinha
************************************************************************/

#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "./task.h"
#include "./syscalls.h"
#include "./signals.h"


#define ERR_SETSTDIN 11
#define ERR_SETSTDOUT 12
#define ERR_SETSTDERR 13
#define ERR_SETTIMELIMIT 14
#define ERR_SETMEMORYLIMIT 15
#define ERR_SETFSIZELIMIT 16
#define ERR_CHROOT 17
#define ERR_PTRACE 18
#define ERR_EXEC 19
  
  

void sandbox(const Task *task) {

    /********** prepare stdin, stdout, stderr **********/
    if (freopen(task->inputFile, "r", stdin) == NULL) exit(ERR_SETSTDIN);
    if (freopen(task->outputFile, "w", stdout) == NULL) exit(ERR_SETSTDOUT);
    if (freopen(task->errorFile, "w", stderr) == NULL) exit(ERR_SETSTDERR);

    /********** set resource limits **********/
    struct rlimit resourceLimit;
    // cpu limit
    resourceLimit.rlim_max = resourceLimit.rlim_cur = task->maxCpuTime;
    if (setrlimit(RLIMIT_CPU, &resourceLimit) < 0) exit(ERR_SETTIMELIMIT);
    // memory limit
    resourceLimit.rlim_max = resourceLimit.rlim_cur = task->maxMemory;
    if (setrlimit(RLIMIT_AS, &resourceLimit) < 0) exit(ERR_SETMEMORYLIMIT);
    // output file size limit
    resourceLimit.rlim_max = resourceLimit.rlim_cur = task->maxFileSize;
    if (setrlimit(RLIMIT_FSIZE, &resourceLimit) < 0) exit(ERR_SETFSIZELIMIT);

    /********** change root dir **********/
    if ((chdir(task->root) < 0) || (chroot(task->root) < 0)) exit(ERR_CHROOT);

    /********** start being traced by monitor ***********/
    if (ptrace(PTRACE_TRACEME, -1, NULL, NULL) < 0) exit(ERR_PTRACE);

    /********** execute task ***********/
    if (execv(task->execPath, task->args) < 0) exit(ERR_EXEC);

}


unsigned long getMemoryUsage(pid_t pid) {
    char filename[128];
    sprintf(filename, "/proc/%d/statm", pid);

    int pageSize = getpagesize() / 1024;

    FILE *memUsageFile = fopen(filename, "r");
    if (memUsageFile == NULL) return 0;

    // first value is total VM size (in no of pages)
    unsigned long memUsage = 0;
    fscanf(memUsageFile, "%lu", &memUsage);
    memUsage *= pageSize;

    return memUsage;
}


void monitor(const Task *task, pid_t sandboxPid, TaskResult *result) {

    int status;
    struct rusage resourceUsage;
    unsigned long currMemUsage = 0;

    // let the first exec call execute to start the user task
    wait4(sandboxPid, &status, 0, NULL);
    if (WIFEXITED(status)) {
        result->exitCode = WEXITSTATUS(status);
        result->errorMsg = "couldn't execute program";
        return;
    }


    // keep monitoring
    int isMLE = 0;
    int disallowedSyscallUsed = -1;
    while (1) {   
        // let the sandbox continue till next syscall
        ptrace(PTRACE_SYSCALL, sandboxPid, NULL, NULL); 

        // update memory usage
        currMemUsage = getMemoryUsage(sandboxPid);
        // check for MLE
        if (currMemUsage > task->maxMemory) {
            isMLE = 1;
            kill(sandboxPid, SIGTERM);
        }

        // wait for sandbox for a state change        
        wait4(sandboxPid, &status, 0, &resourceUsage);
        
        // check if exited
        if (WIFEXITED(status)) {
            result->status = 1;
            result->exitCode = WEXITSTATUS(status);
            result->execTime = ((resourceUsage.ru_utime.tv_sec + resourceUsage.ru_stime.tv_sec) * 1000) + ((resourceUsage.ru_utime.tv_usec + resourceUsage.ru_stime.tv_usec) / 1000);
            result->memoryUsed = currMemUsage;
            if (result->exitCode) result->errorMsg = "NZEC";
            break;
        }

        // check if signaled
        if (WIFSIGNALED(status)) {
            int signal = WTERMSIG(status);
            result->signal = signal;
            result->execTime = ((resourceUsage.ru_utime.tv_sec + resourceUsage.ru_stime.tv_sec) * 1000) + ((resourceUsage.ru_utime.tv_usec + resourceUsage.ru_stime.tv_usec) / 1000);
            result->memoryUsed = currMemUsage;

            // if terminated due to illegal syscall
            if ((disallowedSyscallUsed != -1) && (signal == SIGKILL)) sprintf(result->errorMsg, "illegal syscall used: %s", disallowed_syscalls[disallowedSyscallUsed]);
            // if terminated due to TLE
            else if ((signal == SIGXCPU) || (signal == SIGKILL)) result->errorMsg = "TLE";
            // if terminated due to MLE
            else if (isMLE && (signal == SIGTERM)) result->errorMsg = "MLE";
            // if terminated due to File size limit
            else if (signal == SIGXFSZ) result->errorMsg = "OLE";
            // other signals
            else sprintf(result->errorMsg, "program terminated with signal %s", signal_name[signal]);
            
            break;
        }

        // check for disallowed syscalls
        long offsetForOrigRax = sizeof(long) * ORIG_RAX;
        long syscallNumber = ptrace(PTRACE_PEEKUSER, sandboxPid, offsetForOrigRax, NULL);
        disallowedSyscallUsed = isDisallowedSyscall(syscallNumber);
        if (disallowedSyscallUsed != -1) kill(sandboxPid, SIGKILL);
        
    }

    return;
}



TaskResult secureExecute(const Task *task) {

    TaskResult result;
    result.status = 0;
    result.exitCode = -1;
    result.signal = -1;
    result.execTime = result.memoryUsed = 0;
    result.errorMsg = NULL;

    // create child process for executing task
    pid_t pid = fork();
    if (pid < 0) {
        result.errorMsg = "couldn't create child process";
    }
    else if (pid == 0) {            // child
        sandbox(task);
    }
    else {                          // parent
        monitor(task, pid, &result);

    }    

    return result;     
}