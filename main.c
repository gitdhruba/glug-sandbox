/***********************************************************************
     Copyright (c) 2025 GNU/Linux Users' Group (NIT Durgapur)
     Author: Dhruba Sinha
************************************************************************/

#include "sandbox.c"

int main() {
    char *args[] = {"a.out", NULL};
    Task task;
    task.exec_path = "./test/a.out";
    task.args = args;
    task.input_file = "./test/in";
    task.output_file = "./test/out";
    task.error_file = "./test/error";
    task.max_cpu_time = 2;
    task.max_memory = 256 * 1024 * 1024;
    task.max_file_size = 32768;
    task.root = "./test";

    TaskResult res = secure_execute(&task);
    printf("status: %d\n", res.status);
    printf("exit_code: %d\n", res.exit_code);
    printf("signal: %d\n", res.signal);
    printf("time: %lu\n", res.exec_time);
    printf("mem: %ld\n", res.memory_used);
    printf("errmsg: %s\n", res.error_msg);

    return 0;
}