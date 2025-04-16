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
#define ERR_PRCTL  23

#define ISFORKSTOP(status) ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8)))
#define ISVFORKSTOP(status) ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))
#define ISEXECSTOP(status) ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)))


// reap all zombies to make cgroup clean
void reap_all() {
    do {
        errno = 0;
    } while ((wait(NULL) > 0) || (errno == EINTR));

    return;
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

    /********** no new privileges should be given on execve (may it be accidental or intentional) *********/
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) < 0) exit(ERR_PRCTL);

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
       
    /********** execute task ***********/
    // (###)
    // ATTENTION: this is the very first exec() call which should be ignored in monitor, otherwise user program wouldn't be executed
    if (execv(task->exec_path, task->args) < 0) exit(ERR_EXEC);
}


// to monitor the sandbox
void monitor(pid_t sandbox_pid, const Task *task, TaskResult *result) {
    int status = 0;
    int signal = 0;                               
    unsigned long cpu_time_start = 0, cpu_time_curr = 0;
    unsigned long memory_used_max = 0, memory_used_curr = 0;

    CgroupMemoryEvents memory_events_start, memory_events_curr;
    memset(&memory_events_start, 0, sizeof(memory_events_start));
    memset(&memory_events_curr, 0, sizeof(memory_events_curr));

    // set monitor as nearest subreaper to give a proxy of an init process and clear cgroup properly
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) {
        kill_all(SIGKILL);
        sprintf(result->error_msg, "couldn't make monitor as subreaper");
        return;
    }

    // wait for child to call first execv() to run user program
    waitpid(sandbox_pid, &status, 0);

    // check if child terminated before execv()
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        sprintf(result->error_msg, "child exited before execv()");
        result->exit_code = WEXITSTATUS(status);
        result->signal = WTERMSIG(status);
        return;
    }

    // here we are sure that WIFSTOPPED(status) == true
    // if the stop signal is not SIGTRAP, then some error has occured. kill child
    if (WSTOPSIG(status) != SIGTRAP) {
        kill_all(SIGKILL);
        reap_all();
        sprintf(result->error_msg, "child terminated before execv() with signal %s", signal_name[WSTOPSIG(status)]);
        result->exit_code = WEXITSTATUS(status);;
        result->signal = WSTOPSIG(status);
        
        return;
    }

    // at this point sandbox is at exec() stop

    // get initial cpu time and memory events from cgroup
    get_memory_events(&memory_events_start);
    cpu_time_start = get_cpu_time();

    // continue the sandbox process
    ptrace(PTRACE_DETACH, sandbox_pid, 0, 0);

    // track cpu time , memory usage and child's state changes in a loop until child exits or is killed
    pid_t pid = 0;
    do {
        // get current cpu time, memory usage and memory_events
        cpu_time_curr = get_cpu_time();
        memory_used_curr = get_current_memory_usage();          
        memory_used_max = ((memory_used_curr > memory_used_max) ? memory_used_curr : memory_used_max);
        get_memory_events(&memory_events_curr);

        // check if cpu time limit is exceeded or memory limit is exceeded
        // we still have to check for cpu time limit even after setting RLIMIT_CPU because user process may create multiple processes
        if (((cpu_time_curr - cpu_time_start) > (task->max_cpu_time * 1000000))  // tle
            || (memory_events_curr.max > memory_events_start.max)                // mle
           ) kill_all(SIGKILL);

        // get child state update using waitpid
        status = 0;
        errno = 0;
        pid = waitpid(sandbox_pid, &status, WNOHANG);

    } while (
                (pid == 0)                          /* no state change */ 
            || ((pid == -1) && (errno == EINTR))    /* we are interrupted inside waitpid() syscall, so try again (this should not happen as we had set WNOHANG.. but still to be on safe side :)) */
        );
    
    // at this point, we are sure that sandbox has exited or terminated
    // ensure all child have been terminated in case of multiple processes created by user program
    kill_all(SIGKILL);

    // reap_all() to clear cgroup properly
    reap_all();

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
        sprintf(result->error_msg, "exited using exit()");
    }
    // if terminated by signal
    else if (WIFSIGNALED(status)) {
        result->exit_code = WEXITSTATUS(status);
        result->signal = WTERMSIG(status);
        
        // tle
        if ((result->signal == SIGXCPU) || ((result->signal == SIGKILL) && (result->exec_time > (task->max_cpu_time * 1000000)))) sprintf(result->error_msg, "TLE (%s)", signal_name[result->signal]);
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
    cl_args.flags = (     
                          CLONE_CLEAR_SIGHAND   // restore signal handlers to default
                        | CLONE_INTO_CGROUP     // attach to cgroup while creating the child, as doing it later will slower
                    );
    cl_args.cgroup = cgroup_fd;                 // cgroup fd to be used in clone3
    cl_args.exit_signal = SIGCHLD;              // child will send SIGCHLD to parent when it exits
    
    errno = 0;
    pid_t pid = clone3(&cl_args);

    // before proceeding further we have to close the cgroup_fd, as we don't need it anymore
    close(cgroup_fd);

    if (pid == -1) {
        sprintf(result.error_msg, "[X] clone3 error, couldn't create child process");
    }

    // child process, never returns
    else if (pid == 0) {
        sandbox(task);
        exit(EXIT_FAILURE);
    }

    // parent process
    else {
        monitor(pid, task, &result);
    }

    return result;     
}