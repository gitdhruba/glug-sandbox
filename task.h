/***********************************************************************
     Copyright (c) 2025 GNU/Linux Users' Group (NIT Durgapur)
     Author: Dhruba Sinha
************************************************************************/


/* 
    Task structure definition
*/
struct task {

    // executable file path
    char *exec_path;

    // arguments to executable
    char **args;

    // working directory
    char *work_dir;

    // input file
    char *input_file;

    // output file
    char *output_file;

    // error file
    char *error_file;

    // resource limits
    // cpu (in seconds)
    unsigned long max_cpu_time;

    // memory (in bytes, it will be truncated to nearest multiple of page size)
    // better to keep in power of 2
    unsigned long max_memory;

    // output file size (int bytes)
    // better to keep in power of 2
    unsigned long max_file_size;

    // max number of processes
    unsigned long max_processes;

};



/* 
    Task-result structure definition
*/
struct task_result {
    unsigned long exec_time;       // in milliseconds
    unsigned long memory_used;     // in kilobytes
    char *error_msg;
    int status;
    int exit_code;
    int signal;
};



typedef struct task Task;
typedef struct task_result TaskResult;
