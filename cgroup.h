/***********************************************************************
     Copyright (c) 2025 GNU/Linux Users' Group (NIT Durgapur)
     Author: Dhruba Sinha
************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

const char *root_cgroup = "/sys/fs/cgroup";
const char *sandbox_cgroup = "/sys/fs/cgroup/sandbox";
const char *cgroup_controllers = "+cpu +memory +pids +cpuset";

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
    char subtree_control_path[256];
    sprintf(subtree_control_path, "%s/cgroup.subtree_control", root_cgroup);
    FILE *fp = fopen(subtree_control_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "[X] couldn't open cgroup.subtree_control\n");
        return -1;
    }

    int size = strlen(cgroup_controllers);
    int size_written = fwrite(cgroup_controllers, sizeof(char), size, fp);
    fclose(fp);
    if (size_written != size) {
        fprintf(stderr, "[X] couldn't write to cgroup.subtree_control\n");
        return -1;
    }

    // ceate cgroup directory
    if (mkdir(sandbox_cgroup, 0755) == -1) {
        fprintf(stderr, "[X] couldn't create cgroup directory\n");
        return -1;
    }

    return 0;
}