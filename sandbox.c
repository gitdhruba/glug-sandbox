/***********************************************************************
     Copyright (c) 2025 GNU/Linux Users' Group (NIT Durgapur)
     Author: Dhruba Sinha
************************************************************************/
#define _GNU_SOURCE
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
#include "./cgroup.h"

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
    resource_limit.rlim_max = resource_limit.rlim_cur = task->max_cpu_time + 1ull;
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

    /********** set user and group ids to unprivileged one ****************/
    if ((setgid(SANDBOX_GID) < 0) || (setuid(SANDBOX_UID) < 0)) exit(ERR_SETUID);
    if ((geteuid() != SANDBOX_UID) || (getegid() != SANDBOX_GID)) exit(ERR_SETUID);

    /********** change working directory **********/
    if (chdir(task->work_dir) < 0) exit(ERR_CHDIR);

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

    // // now keep itself stopped until continued by parent
    // raise(SIGSTOP);            

    /********** execute task ***********/
    // (###)
    // ATTENTION: this is the very first exec() call which should be ignored in monitor, otherwise user program wouldn't be executed
    if (execv(task->exec_path, task->args) < 0) exit(ERR_EXEC);
}



void monitor(pid_t sandbox_pid, const Task *task, TaskResult *result) {
    int status = 0;
    int signal = 0;
    unsigned long cpu_time_start = 0, cpu_time_curr = 0;
    unsigned long memory_used_max = 0, memory_used_curr = 0;;
    CgroupMemoryEvents memory_events_start, memory_events_curr;
    memset(&memory_events_start, 0, sizeof(memory_events_start));
    memset(&memory_events_curr, 0, sizeof(memory_events_curr));

    // wait for child to call first execv() to run user program
    waitpid(sandbox_pid, &status, 0);

    // check if child terminated before execv()
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        result->exec_time = 0;
        result->memory_used = 0;
        sprintf(result->error_msg, "child exited before execv()");
        result->exit_code = WEXITSTATUS(status);
        result->signal = WTERMSIG(status);
        return;
    }

    // here we are sure that WIFSTOPPED(status) == true
    // if the stop signal is not SIGTRAP, then some error has occured. kill child
    if (WSTOPSIG(status) != SIGTRAP) {
        kill(sandbox_pid, SIGKILL);

        result->exec_time = 0;
        result->memory_used = 0;
        sprintf(result->error_msg, "child terminated before execv()");
        result->exit_code = -1;
        result->signal = WSTOPSIG(status);
        
        return;
    }

    // at this point, we are sure that child has called execv() and will start running user program
    // but before continuing ...
    // set PTRACE_O_EXITKILL option such that sandbox can't rescue even after monitor dies accidentally
    ptrace(PTRACE_SETOPTIONS, sandbox_pid, NULL, PTRACE_O_EXITKILL);

    // get initial cpu time and memory events from cgroup
    get_memory_events(&memory_events_start);
    cpu_time_start = get_cpu_time();

    // continue the child process
    ptrace(PTRACE_CONT, sandbox_pid, NULL, 0);

    // track cpu time , memory usage and child's state changes in a loop until child exits or is killed
    do {
        // get child state update using waitpid
        pid_t res = waitpid(sandbox_pid, &status, WNOHANG);
        if (res == -1) break;

        // get current cpu time, memory usage and memory_events
        cpu_time_curr = get_cpu_time();
        memory_used_curr = get_current_memory_usage();          
        memory_used_max = ((memory_used_curr > memory_used_max) ? memory_used_curr : memory_used_max);
        get_memory_events(&memory_events_curr);

        // check if cpu time limit is exceeded or memory limit is exceeded
        if (((cpu_time_curr - cpu_time_start) > (task->max_cpu_time * 1000000))  // tle
            || (memory_events_curr.max > memory_events_start.max)                // mle
           ) kill(sandbox_pid, SIGKILL);

        // check for signal-delivery stop
        if ((res != 0) && WIFSTOPPED(status)) {
            // do nothing, let the signal be delivered to the child
            ptrace(PTRACE_CONT, sandbox_pid, NULL, WSTOPSIG(status));   // this call may not be successful in case of tle
        }
        
    } while ((!WIFEXITED(status)) && (!WIFSIGNALED(status)));
    
    // at this point, we are sure that child has exited or terminated
    // get cpu-time,  memory usage and memory_events for last time
    cpu_time_curr = get_cpu_time();
    memory_used_curr = get_current_memory_usage();
    memory_used_max = ((memory_used_curr > memory_used_max) ? memory_used_curr : memory_used_max);
    get_memory_events(&memory_events_curr);

    result->exec_time = (cpu_time_curr - cpu_time_start); 
    result->memory_used = memory_used_max;  
    result->status = 1;

    // if exited normally
    if (WIFEXITED(status)) {
        result->exit_code = WEXITSTATUS(status);
        result->signal = 0;
        sprintf(result->error_msg, "NONE");
    }
    // if terminated by signal
    else if (WIFSIGNALED(status)) {
        result->exit_code = -1;
        result->signal = WTERMSIG(status);
        
        // tle
        if (((result->signal == SIGXCPU) || (result->signal == SIGKILL)) && (result->exec_time > (task->max_cpu_time * 1000000))) sprintf(result->error_msg, "TLE");
        // mle
        else if ((memory_events_curr.max > memory_events_start.max) || (memory_events_curr.oom_kill > memory_events_start.oom_kill) || (memory_events_curr.oom > memory_events_start.oom)) {
            result->memory_used = memory_used_max;
            sprintf(result->error_msg, "MLE");
        }
        // other signals
        else sprintf(result->error_msg, "terminated by signal: %s", signal_name[result->signal]);
    }

    // convert cpu time from microseconds to milliseconds
    result->exec_time /= 1000;
    // convert memory usage from bytes to kilobytes 
    result->memory_used >>= 10;

    return;
}

TaskResult secure_execute(const Task *task) {
    TaskResult result;
    result.exec_time = result.memory_used = 0;
    result.status = 0;
    result.exit_code = -1;
    result.signal = -1;
    result.error_msg = (char *)malloc(256);
    memset(result.error_msg, 0, sizeof(result.error_msg));

    // setup sandbox cgroup
    int cgroup_fd = setup_sandbox_cgroup(task->max_memory, task->max_processes);
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
    pid_t pid = clone3(&cl_args);

    // before proceeding further we have to close the cgroup_fd, as we don't need it anymore
    close(cgroup_fd);

    if (pid == -1) {
        fprintf(stderr, "[X] clone3 error, couldn't create child process : %d\n", errno);
        return result;
    }

    // child process, never returns
    if (pid == 0) {
        sandbox(task);
        exit(0);
    }

    // parent process
    monitor(pid, task, &result);

    return result;     
}