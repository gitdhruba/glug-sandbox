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
    // cpu
    unsigned long max_cpu_time;

    // memory
    unsigned long max_memory;

    // output file size
    unsigned long max_file_size;

};



/* 
    Task-result structure definition
*/
struct task_result {
    int status;
    int exit_code;
    int signal;
    unsigned long exec_time;       // in milliseconds
    unsigned long memory_used;     // in kilobytes
    char *error_msg;
};



typedef struct task Task;
typedef struct task_result TaskResult;
