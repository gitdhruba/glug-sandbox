/***********************************************************************
     Copyright (c) 2024 GNU/Linux Users' Group (NIT Durgapur)
     Author: Dhruba Sinha
************************************************************************/


/* 
    Task structure definition
*/
struct task {

    // executable file path
    char *execPath;

    // arguments to excutable
    char **args;

    // root for chroot
    char *root;

    // input file
    char *inputFile;

    // output file
    char *outputFile;

    // error file
    char *errorFile;

    // resource limits
    // cpu
    unsigned long maxCpuTime;

    // memory
    unsigned long maxMemory;

    // output file size
    unsigned long maxFileSize;

};



/* 
    Task-result structure definition
*/
struct task_result {
    int status;
    int exitCode;
    int signal;
    unsigned long execTime;       // in miliseconds
    unsigned long memoryUsed;     // in kilobytes
    char *errorMsg;
};



typedef struct task Task;
typedef struct task_result TaskResult;
