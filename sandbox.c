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
#include <string.h>

#include "./task.h"
#include "./syscalls.h"
#include "./signals.h"

#define SANDBOX_UID (uid_t)65534
#define SANDBOX_GID (gid_t)65534

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
#define ERR_CHDIR 18
#define ERR_PTRACE 19
#define ERR_EXEC 20
#define ERR_SETUID 21
#define ERR_NULLFD 22



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

    /********** set resource limits **********/
    struct rlimit resource_limit;
    // cpu limit
    resource_limit.rlim_max = resource_limit.rlim_cur = task->max_cpu_time;
    if (setrlimit(RLIMIT_CPU, &resource_limit) < 0) exit(ERR_SETTIMELIMIT);
    // memory limit (already set in cgroup)
    // resource_limit.rlim_max = resource_limit.rlim_cur = MAX_ALLOWED_MEMORY;
    // if (setrlimit(RLIMIT_AS, &resource_limit) < 0) exit(ERR_SETMEMORYLIMIT);

    // output file size limit
    resource_limit.rlim_max = resource_limit.rlim_cur = task->max_file_size;
    if (setrlimit(RLIMIT_FSIZE, &resource_limit) < 0) exit(ERR_SETFSIZELIMIT);
    
    // core-dump limit (shouldn't generate core dump)
    resource_limit.rlim_max = resource_limit.rlim_cur = COREDUMPLIMIT;
    if (setrlimit(RLIMIT_CORE, &resource_limit) < 0) exit(ERR_SETCORELIMIT);

    /********** change root dir **********/
    if (chdir(task->work_dir) < 0) exit(ERR_CHDIR);

    /********** set user and group ids to unprivileged one ****************/
    if ((setgid(SANDBOX_GID) < 0) || (setuid(SANDBOX_UID) < 0)) exit(ERR_SETUID);
    if ((geteuid() != SANDBOX_UID) || (getegid() != SANDBOX_GID)) exit(ERR_SETUID);

    /********** set standard input/output/error files **********/
    if ((task->input_file == NULL) || (task->output_file == NULL) || (task->error_file == NULL)) exit(ERR_NULLFD);
    // set standard input
    if (freopen(task->input_file, "r", stdin) == NULL) exit(ERR_SETSTDIN);
    // set standard output
    if (freopen(task->output_file, "w", stdout) == NULL) exit(ERR_SETSTDOUT);
    // set standard error
    if (freopen(task->error_file, "w", stderr) == NULL) exit(ERR_SETSTDERR);

    /********** start being traced by monitor ***********/
    if (ptrace(PTRACE_TRACEME, -1, NULL, NULL) < 0) exit(ERR_PTRACE);

    // now keep itself stopped until continued by parent
    raise(SIGSTOP);            

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

    // setup sandbox cgroup
    int cgroup_fd = setup_sandbox_cgroup(task->max_memory);
    if (cgroup_fd == -1) {
        sprintf(result.error_msg, "couldn't setup cgroup");
        return result;
    }

    // create child process for executing task using clone3() syscall 
    struct clone_args cl_args;
    memset(&cl_args, 0, sizeof(cl_args));
    cl_args.flags = (     CLONE_NEWPID          // new pid namespace to prevent dangerous syscalls like kill(), reboot() etc from hampering the host
                        | CLONE_CLEAR_SIGHAND   // restore signal handlers to default
                        | CLONE_INTO_CGROUP     // attach to cgroup while creating the child, as doing it later will slower
                    );
    cl_args.cgroup = cgroup_fd;                 // cgroup fd to be used in clone3
    cl_args.exit_signal = SIGCHLD;              // child will send SIGCHLD to parent when it exits
    
    errno = 0;
    pid_t child = clone3(&cl_args);

    // before proceeding further we have to close the cgroup_fd, as we don't need it anymore
    close(cgroup_fd);

    if (child == -1) {
        fprintf(stderr, "[X] clone3 error, couldn't create child process : %d\n", errno);
        return result;
    }

    // child process, never returns
    if (child == 0) {
        sandbox(task);
        exit(0);
    }

    // parent process
    monitor(task, child, &result);

    return result;     
}