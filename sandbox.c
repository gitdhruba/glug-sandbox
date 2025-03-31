/***********************************************************************
     Copyright (c) 2025 GNU/Linux Users' Group (NIT Durgapur)
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



unsigned long get_memory_usage(pid_t pid) {
    long page_size = getpagesize();
    char filename[128];
    sprintf(filename, "/proc/%d/statm", pid);

    FILE *mem_usage_file = fopen(filename, "r");
    if (mem_usage_file == NULL) return 0;

    // first value is total VM size (in no of pages)
    unsigned long mem_usage = 0;
    fscanf(mem_usage_file, "%lu", &mem_usage);
    mem_usage *= page_size;

    fclose(mem_usage_file);
    return mem_usage;
}

void sandbox(const Task *task) {

    /********** prepare stdin, stdout, stderr **********/
    if (freopen(task->input_file, "r", stdin) == NULL) exit(ERR_SETSTDIN);
    if (freopen(task->output_file, "w", stdout) == NULL) exit(ERR_SETSTDOUT);
    if (freopen(task->error_file, "w", stderr) == NULL) exit(ERR_SETSTDERR);

    /********** set resource limits **********/
    struct rlimit resource_limit;
    // cpu limit
    resource_limit.rlim_cur = task->max_cpu_time;
    resource_limit.rlim_max = task->max_cpu_time + CPULIMIT_CURR_MAX_PADDING;
    if (setrlimit(RLIMIT_CPU, &resource_limit) < 0) exit(ERR_SETTIMELIMIT);
    // memory limit
    resource_limit.rlim_max = resource_limit.rlim_cur = MAX_ALLOWED_MEMORY;
    if (setrlimit(RLIMIT_AS, &resource_limit) < 0) exit(ERR_SETMEMORYLIMIT);
    // output file size limit
    resource_limit.rlim_max = resource_limit.rlim_cur = task->max_file_size;
    if (setrlimit(RLIMIT_FSIZE, &resource_limit) < 0) exit(ERR_SETFSIZELIMIT);
    // core-dump limit (shouldn't generate core dump)
    resource_limit.rlim_max = resource_limit.rlim_cur = COREDUMPLIMIT;
    if (setrlimit(RLIMIT_CORE, &resource_limit) < 0) exit(ERR_SETCORELIMIT);

    /********** change root dir **********/
    // if ((chdir(task->root) < 0) || (chroot(".") < 0)) exit(ERR_CHROOT);

    /********** start being traced by monitor ***********/
    if (ptrace(PTRACE_TRACEME, -1, NULL, NULL) < 0) exit(ERR_PTRACE);

    // now keep itself stopped until continued by parent
    kill(getpid(), SIGSTOP);            

    /********** execute task ***********/
    // (###)
    // ATTENTION: this is the very first exec() call which should be ignored in monitor, otherwise user program wouldn't be executed
    if (execv(task->exec_path, task->args) < 0) exit(ERR_EXEC);
}

void monitor(const Task *task, pid_t sandbox_pid, TaskResult *result) {

    struct rusage resource_usage;
    const long offset_for_orig_rax = sizeof(long) * ORIG_RAX;
    long curr_mem_usage = 0;
    long max_mem_usage = 0;
    long ptrace_res = 0;
    long syscall_no = -1;
    int status = 0;
    int signal = 0;

    // check whether all setup is done properly before being traced
    wait4(sandbox_pid, &status, 0, NULL);
    if (WIFEXITED(status)) {
        result->exit_code = WEXITSTATUS(status);
        result->error_msg = "couldn't execute program";
        return;
    }

    // PTRACE_O_EXITKILL for keeping sandbox under supervision
    // PTRACE_O_TRACESYSGOOD for sets bit 7 in the signal number (i.e., deliver SIGTRAP|0x80) when delivering syscall-traps
    errno = 0;
    ptrace_res = ptrace(PTRACE_SETOPTIONS, sandbox_pid, 0, (PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD));
    if (ptrace_res == -1) {
        fprintf(stderr, "[X] ptrace error : %d\n", errno);
        kill(sandbox_pid, SIGKILL);
        return;
    }

    // start monitoring
    int syscall_filter_flag = 0;
    while (1) {   
        // let the sandbox continue till next syscall-stop/signal-stop
        errno = 0;
        ptrace_res = ptrace(PTRACE_SYSCALL, sandbox_pid, NULL, signal); 
        if (ptrace_res == -1) {
            fprintf(stderr, "[X] ptrace error : %d\n", errno);
            kill(sandbox_pid, SIGKILL);
            break;
        }

        // wait for sandbox for a state change        
        wait4(sandbox_pid, &status, 0, &resource_usage);

        // check if exited
        if (WIFEXITED(status)) {
            result->status = 1;
            result->exit_code = WEXITSTATUS(status);
            result->error_msg = (result->exit_code ? "NZEC" : "NONE") ;
            break;
        }

        // check if signaled
        else if (WIFSIGNALED(status)) {
            signal = WTERMSIG(status);
            result->signal = signal;
            printf("received signal: %s\n", signal_name[signal]);

            // if terminated due to MLE
            if ((max_mem_usage > task->max_memory) && (signal == SIGSEGV)) result->error_msg = "MLE";
            // if terminated due to TLE
            else if (signal == SIGXCPU) result->error_msg = "TLE";
            // if terminated due to File size limit
            else if (signal == SIGXFSZ) result->error_msg = "OLE";
            // other signals
            else sprintf(result->error_msg, "signalled: %s", signal_name[signal]);

            break;
        }

        // stopped
        else {
            // signal that caused the stop
            signal = WSTOPSIG(status);

            // ignore first successful exec()
            // check (###) marked code in sandbox()
            if ((!syscall_filter_flag) && (signal == SIGTRAP)) {
                syscall_filter_flag = 1;
                signal = 0;             // this SIGTRAP shouldn't be delivered
            }

            // check if it is a syscall-stop
            if (signal == SYSCALL_STOPSIG) {
                signal = 0;
                syscall_no = ptrace(PTRACE_PEEKUSER, sandbox_pid, offset_for_orig_rax, NULL);
                if (syscall_no == -1) {
                    fprintf(stderr, "[X] ptrace error : %d\n", errno);
                    kill(sandbox_pid, SIGKILL);
                    break;
                }

                printf("[>>] syscall used: %ld\n", syscall_no);

                long idx = get_syscall_index(syscall_no);
                if (syscall_filter_flag && (idx != -1)) {
                    // invoked a prohibited syscall
                    signal = SIGTERM;
                    sprintf(result->error_msg, "prohibited syscall used: %s", disallowed_syscalls[idx].syscall_name);
                }
            }

            // if it is signal-delivery-stop we don't need to do anything. Let the signal be delivered at next ptrace()

            // get the updated memory usage
            curr_mem_usage = get_memory_usage(sandbox_pid);
            max_mem_usage = (curr_mem_usage > max_mem_usage ? curr_mem_usage : max_mem_usage);

            // check for MLE, if yes then SIGSEGV will be delivered
            if (max_mem_usage > task->max_memory) signal = SIGSEGV;
            
            // update resource usages
            result->exec_time = ((resource_usage.ru_utime.tv_sec + resource_usage.ru_stime.tv_sec) * 1000) + ((resource_usage.ru_utime.tv_usec + resource_usage.ru_stime.tv_usec) / 1000);   // in milliseconds
            result->memory_used = max_mem_usage >> 10;                                                                                                                                     // in KB
        }
        
    }

    return;
}

TaskResult secure_execute(const Task *task) {

    TaskResult result;
    result.status = 0;
    result.exit_code = -1;
    result.signal = -1;
    result.exec_time = result.memory_used = 0;
    result.error_msg = (char *)malloc(256);
    memset(result.error_msg, 0, sizeof(result.error_msg));

    // create child process for executing task
    pid_t pid = fork();
    if (pid < 0) {
        result.error_msg = "couldn't create child process";
    }
    else if (pid == 0) {            // child
        sandbox(task);
    }
    else {                          // parent
        monitor(task, pid, &result);

    }    

    return result;     
}