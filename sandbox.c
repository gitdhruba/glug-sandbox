#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "./task.h"
#include "./syscalls.h"

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



void monitor(pid_t sandboxPid, TaskResult *result) {

}



TaskResult secureExecute(const Task *task) {

    TaskResult result;
    result.status = 0;

    // create child process for executing task
    pid_t pid = fork();
    if (pid < 0) {
        result.errorMsg = "couldn't create child process";
    }
    else if (pid == 0) {            // child
        sandbox(task);
    }
    else {                          // parent
        monitor(pid, &result);

    }    

    return result;     
}