/***********************************************************************
     Copyright (c) 2025 GNU/Linux Users' Group (NIT Durgapur)
     Author: Dhruba Sinha
************************************************************************/

#include "sandbox.c"

int main() {
    Task task;

    // char * const args[] = {"python3", "/home/sandbox/test.py", NULL};
    // task.exec_path = "/bin/python3";
    // task.args = args;
    // task.work_dir = "./test";
    // task.input_file = "/home/sandbox/in";
    // task.output_file = "/home/sandbox/out";
    // task.error_file = "/home/sandbox/err";
    // task.max_cpu_time = 2;
    // task.max_memory = 512 * 1024 * 1024;
    // task.max_file_size = 1048576;
    // task.max_processes = 1;
    
    char *args[] = {"main", NULL};
    task.exec_path = "./main";
    task.args = args;
    task.work_dir = "/home/sandbox/";
    task.input_file = "./in.txt";
    task.output_file = "./out.txt";
    task.error_file = "./err.txt";
    task.max_cpu_time = 2;
    task.max_memory = 512 * 1024 * 1024;
    task.max_file_size = 16 * 1024 * 1024;
    task.max_processes = 8;

    TaskResult res = secure_execute(&task);

    printf("status: %d\n", res.status);
    printf("exit_code: %d\n", res.exit_code);
    printf("signal: %d\n", res.signal);
    printf("time: %lu\n", res.exec_time);
    printf("mem: %ld\n", res.memory_used);
    printf("errmsg: %s\n", res.error_msg);

    return 0;
}