/***********************************************************************
     Copyright (c) 2024 GNU/Linux Users' Group (NIT Durgapur)
     Author: Dhruba Sinha
************************************************************************/

#include "sandbox.c"


int main() {
    char *args[] = {"a.out", NULL};
    Task task;
    task.execPath = "./test/a.out";
    task.args = args;
    task.inputFile = "./test/in";
    task.outputFile = "./test/out";
    task.errorFile = "./test/error";
    task.maxCpuTime = 2;
    task.maxMemory = 256 * 1024 * 1024;
    task.maxFileSize = 32768;
    task.root = "./test";

    TaskResult res = secureExecute(&task);
    printf("status: %d\n", res.status);
    printf("exit-code: %d\n", res.exitCode);
    printf("signal: %d\n", res.signal);
    printf("time: %lu\n", res.execTime);
    printf("mem: %ld\n", res.memoryUsed);
    printf("errmsg: %s\n", res.errorMsg);

    return 0;
}