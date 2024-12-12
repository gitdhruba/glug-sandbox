/***********************************************************************
     Copyright (c) 2024 GNU/Linux Users' Group (NIT Durgapur)
     Author: Dhruba Sinha
************************************************************************/

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/resource.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "./task.h"
#include "./syscalls.h"
#include "./signals.h"


#define MAX_ALLOWED_MEMORY (2ll << 30)
#define CPULIMIT_CURR_MAX_PADDING 4
#define MEMORYLIMIT_PADDING (getpagesize() << 16)
#define COREDUMPLIMIT 0

#define SYSCALL_STOPSIG (SIGTRAP | 0x80)

#define ERR_SETSTDIN 11
#define ERR_SETSTDOUT 12
#define ERR_SETSTDERR 13
#define ERR_SETTIMELIMIT 14
#define ERR_SETMEMORYLIMIT 15
#define ERR_SETFSIZELIMIT 16
#define ERR_SETCORELIMIT 17
#define ERR_CHROOT 18
#define ERR_PTRACE 19
#define ERR_EXEC 20



unsigned long getMemoryUsage(pid_t pid) {
    long pageSize = getpagesize();
    char filename[128];
    sprintf(filename, "/proc/%d/statm", pid);

    FILE *memUsageFile = fopen(filename, "r");
    if (memUsageFile == NULL) return 0;

    // first value is total VM size (in no of pages)
    unsigned long memUsage = 0;
    fscanf(memUsageFile, "%lu", &memUsage);
    memUsage *= pageSize;

    fclose(memUsageFile);
    return memUsage;
}



void sandbox(const Task *task) {

    /********** prepare stdin, stdout, stderr **********/
    if (freopen(task->inputFile, "r", stdin) == NULL) exit(ERR_SETSTDIN);
    if (freopen(task->outputFile, "w", stdout) == NULL) exit(ERR_SETSTDOUT);
    if (freopen(task->errorFile, "w", stderr) == NULL) exit(ERR_SETSTDERR);

    /********** set resource limits **********/
    struct rlimit resourceLimit;
    // cpu limit
    resourceLimit.rlim_cur = task->maxCpuTime;
    resourceLimit.rlim_max = task->maxCpuTime + CPULIMIT_CURR_MAX_PADDING;
    if (setrlimit(RLIMIT_CPU, &resourceLimit) < 0) exit(ERR_SETTIMELIMIT);
    // //memory limit
    resourceLimit.rlim_max = resourceLimit.rlim_cur = MAX_ALLOWED_MEMORY;
    if (setrlimit(RLIMIT_AS, &resourceLimit) < 0) exit(ERR_SETMEMORYLIMIT);
    // output file size limit
    resourceLimit.rlim_max = resourceLimit.rlim_cur = task->maxFileSize;
    if (setrlimit(RLIMIT_FSIZE, &resourceLimit) < 0) exit(ERR_SETFSIZELIMIT);
    // core-dump limit (shouldn't generate core dump)
    resourceLimit.rlim_max = resourceLimit.rlim_cur = COREDUMPLIMIT;
    if (setrlimit(RLIMIT_CORE, &resourceLimit) < 0) exit(ERR_SETCORELIMIT);

    /********** change root dir **********/
    // if ((chdir(task->root) < 0) || (chroot(".") < 0)) exit(ERR_CHROOT);

    /********** start being traced by monitor ***********/
    if (ptrace(PTRACE_TRACEME, -1, NULL, NULL) < 0) exit(ERR_PTRACE);

    // now keep itself stopped until continued by parent
    kill(getpid(), SIGSTOP);            


    /********** execute task ***********/
    // (###)
    // ATTENTION: this is the very first exec() call which should be ignored in monitor, otherwise user program wouldn't be executed
    if (execv(task->execPath, task->args) < 0) exit(ERR_EXEC);

}



void monitor(const Task *task, pid_t sandboxPid, TaskResult *result) {

    struct rusage resourceUsage;
    const long offsetForOrigRax = sizeof(long) * ORIG_RAX;
    long currMemUsage = 0;
    long maxMemUsage = 0;
    long ptraceRes = 0;
    long syscallNo = -1;
    int status = 0;
    int signal = 0;

    // check whether all setup is done properly before being traced
    wait4(sandboxPid, &status, 0, NULL);
    if (WIFEXITED(status)) {
        result->exitCode = WEXITSTATUS(status);
        result->errorMsg = "couldn't execute program";
        return;
    }

    // PTRACE_O_EXITKILL for keeping sandbox under supervision
    // PTRACE_O_TRACESYSGOOD for sets bit 7 in the signal number (i.e., deliver SIGTRAP|0x80) when delivering syscall-traps
    errno = 0;
    ptraceRes = ptrace(PTRACE_SETOPTIONS, sandboxPid, 0, (PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD));
    if (ptraceRes == -1) {
        fprintf(stderr, "[X] ptrace error : %d\n", errno);
        kill(sandboxPid, SIGKILL);
        return;
    }


    // start monitoring
    int syscallFilterFlag = 0;
    while (1) {   
        // let the sandbox continue till next syscall-stop/signal-stop
        errno = 0;
        ptraceRes = ptrace(PTRACE_SYSCALL, sandboxPid, NULL, signal); 
        if (ptraceRes == -1) {
            fprintf(stderr, "[X] ptrace error : %d\n", errno);
            kill(sandboxPid, SIGKILL);
            break;
        }

        // wait for sandbox for a state change        
        wait4(sandboxPid, &status, 0, &resourceUsage);

        // check if exited
        if (WIFEXITED(status)) {
            result->status = 1;
            result->exitCode = WEXITSTATUS(status);
            result->errorMsg = (result->exitCode ? "NZEC" : "NONE") ;
            break;
        }

        // check if signaled
        else if (WIFSIGNALED(status)) {
            signal = WTERMSIG(status);
            result->signal = signal;
            printf("received signal: %s\n", signal_name[signal]);

            // if terminated due to MLE
            if ((maxMemUsage > task->maxMemory) && (signal == SIGSEGV)) result->errorMsg = "MLE";
            // if terminated due to TLE
            else if (signal == SIGXCPU) result->errorMsg = "TLE";
            // if terminated due to File size limit
            else if (signal == SIGXFSZ) result->errorMsg = "OLE";
            // other signals
            else sprintf(result->errorMsg, "signalled: %s", signal_name[signal]);

            break;
        }

        // stopped
        else {
            // signal that caused the stop
            signal = WSTOPSIG(status);

            // ignore first successfull exec()
            // check (###) marked code in sandbox()
            if ((!syscallFilterFlag) && (signal == SIGTRAP)) {
                syscallFilterFlag = 1;
                signal = 0;             // this SIGTRAP shouldn't be delivered
            }

            // check if it is a syscall-stop
            if (signal == SYSCALL_STOPSIG) {
                signal = 0;
                syscallNo = ptrace(PTRACE_PEEKUSER, sandboxPid, offsetForOrigRax, NULL);
                if (syscallNo == -1) {
                    fprintf(stderr, "[X] ptrace error : %d\n", errno);
                    kill(sandboxPid, SIGKILL);
                    break;
                }

                printf("[>>] syscall used: %ld\n", syscallNo);

                long idx = getSyscallIndex(syscallNo);
                if (syscallFilterFlag && (idx != -1)) {
                    // invoked a prohibited syscall
                    signal = SIGTERM;
                    sprintf(result->errorMsg, "prohibited syscall used: %s", disallowed_syscalls[idx].syscallName);
                }
            }

            // if it is signal-delivery-stop we don't need to do anything. Let the signal be delivered at next ptrace()

            // get the updated memory usage
            currMemUsage = getMemoryUsage(sandboxPid);
            maxMemUsage = (currMemUsage > maxMemUsage ? currMemUsage : maxMemUsage);

            // check for MLE, if yes then SIGSEGV will be delivered
            if (maxMemUsage > task->maxMemory) signal = SIGSEGV;
            
            // update resource usages
            result->execTime = ((resourceUsage.ru_utime.tv_sec + resourceUsage.ru_stime.tv_sec) * 1000) + ((resourceUsage.ru_utime.tv_usec + resourceUsage.ru_stime.tv_usec) / 1000);   // in miliseconds
            result->memoryUsed = maxMemUsage >> 10;                                                                                                                                     // in KB
        }
        
    }

    return;
}



TaskResult secureExecute(const Task *task) {

    TaskResult result;
    result.status = 0;
    result.exitCode = -1;
    result.signal = -1;
    result.execTime = result.memoryUsed = 0;
    result.errorMsg = (char *)malloc(256);
    memset(result.errorMsg, 0, sizeof(result.errorMsg));

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