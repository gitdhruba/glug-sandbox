/***********************************************************************
     Copyright (c) 2025 GNU/Linux Users' Group (NIT Durgapur)
     Author: Dhruba Sinha
************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MAX_ALLOWED_MEMORY (1ull << 30)
#define MAX_PIDS_LIMIT 1

const char *root_cgroup = "/sys/fs/cgroup/user.slice";
const char *sandbox_cgroup = "/sys/fs/cgroup/user.slice/sandbox";
const char *cgroup_controllers = "+memory +pids";


// structure definition for memory.events
typedef struct memory_events {
    unsigned long low;
    unsigned long high;
    unsigned long max;
    unsigned long oom;
    unsigned long oom_kill;
    unsigned long oom_group_kill;
} CgroupMemoryEvents;


/*
    * This function writes the given data to the specified file.
    * It opens the file in write-only mode and truncates it if it already exists.
    * Returns 0 on success, -1 on failure.
*/
int write_to_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd == -1) return -1;

    ssize_t bytes_to_write = strlen(data);
    ssize_t bytes_written = write(fd, data, bytes_to_write);
    close(fd);
    if ((bytes_written < 0) || (bytes_written != bytes_to_write)) return -1;

    return 0;
}


/*
    * This function creates a cgroup for the sandbox environment.
    * It enables the necessary cgroup controllers and creates a new cgroup directory.
    * Returns 0 on success, -1 on failure.
*/
int create_cgroup() {
    // check if cgroup is mounted
    struct stat s;
    if (stat(root_cgroup, &s) == -1) {
        fprintf(stderr, "[X] cgroup not mounted\n");
        return -1;
    }

    // enable cgroup controllers for sandbox cgroup
    char subtree_control_path[256] = {0};
    sprintf(subtree_control_path, "%s/cgroup.subtree_control", root_cgroup);
    if (write_to_file(subtree_control_path, cgroup_controllers) == -1) {
        fprintf(stderr, "[X] couldn't write to cgroup.subtree_control\n");
        return -1;
    }

    // create cgroup directory
    if (mkdir(sandbox_cgroup, 0744) == -1) {
        fprintf(stderr, "[X] couldn't create cgroup directory\n");
        return -1;
    }

    return 0;
}

// set memory limit for the cgroup
int set_memory_limit(unsigned long high, unsigned long max = MAX_ALLOWED_MEMORY) {
    char memory_limit_path[256] = {0};
    char high_str[32], max_str[32];

    // set high
    sprintf(memory_limit_path, "%s/memory.high", sandbox_cgroup);
    sprintf(high_str, "%lu", high);
    if (write_to_file(memory_limit_path, high_str) == -1) {
        fprintf(stderr, "[X] couldn't write to memory.high\n");
        return -1;
    }

    // set max
    sprintf(memory_limit_path, "%s/memory.max", sandbox_cgroup);
    sprintf(max_str, "%lu", max);
    if (write_to_file(memory_limit_path, max_str) == -1) {
        fprintf(stderr, "[X] couldn't write to memory.max\n");
        return -1;
    }

    return 0;
}

// set pids limit for the cgroup
int set_pids_limit(long max) {
    char pids_limit_path[256] = {0};
    char max_str[32];

    // set pids.max
    sprintf(pids_limit_path, "%s/pids.max", sandbox_cgroup);
    sprintf(max_str, "%ld", max);
    if (write_to_file(pids_limit_path, max_str) == -1) {
        fprintf(stderr, "[X] couldn't write to pids.max\n");
        return -1;
    }

    return 0;
}

// setup sandbox cgroup for a given task 
// return cgroup fd to be used in clone3
// currently only applies limit on memory and pids controllers
int setup_sandbox_cgroup(unsigned long memory_limit, long pids_limit = MAX_PIDS_LIMIT) {
    // create cgroup
    // assume that it is already created for now
    // if (create_cgroup() == -1) return -1;

    // set memory limit
    if (set_memory_limit(memory_limit) == -1) return -1;

    // set pids limit
    if (set_pids_limit(pids_limit) == -1) return -1;

    // get cgroup fd
    int cgroup_fd = open(sandbox_cgroup, O_RDONLY);
    if (cgroup_fd == -1) {
        fprintf(stderr, "[X] couldn't open cgroup directory\n");
        return -1;
    }

    return cgroup_fd;
    // should be closed after use in clone3
}

// get cpu time from cpu.stat file
unsigned long get_cpu_time() {
    char cpu_stat_path[256] = {0};
    sprintf(cpu_stat_path, "%s/cpu.stat", sandbox_cgroup);

    FILE *cpu_stat_file = fopen(cpu_stat_path, "r");
    if (cpu_stat_file == NULL) return 0;

    unsigned long cpu_time = 0;
    fscanf(cpu_stat_file, "usage_usec %lu\n", &cpu_time);
    fclose(cpu_stat_file);

    return cpu_time;
}

// get memory usage from memory.peak file and reset it to 0 for next use
unsigned long get_peak_memory_usage() {
    char memory_usage_path[256] = {0};
    sprintf(memory_usage_path, "%s/memory.peak", sandbox_cgroup);

    FILE *memory_usage_file = fopen(memory_usage_path, "r");
    if (memory_usage_file == NULL) return 0;

    unsigned long memory_usage = 0;
    fscanf(memory_usage_file, "%lu\n", &memory_usage);
    fclose(memory_usage_file);

    // reset memory usage to 0
    write_to_file(memory_usage_path, "0");

    return memory_usage;
}