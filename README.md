# glug-sandbox

# Overview
This project implements a secure sandbox environment for executing user programs. The sandbox ensures isolation and security by monitoring the program’s CPU time, memory usage, and system calls. If the program exceeds predefined CPU or memory limits, the sandbox terminates the process and provides detailed logs of the event.


# Features

1) Resource Monitoring:

    CPU Time: Tracks the total CPU time consumed by the program.

    Memory Usage: Monitors memory allocation and usage.

    System Calls: Logs and analyzes all system calls made by the program. (using ptrace)


2) Limit Enforcement:

    Terminates the program if it exceeds the predefined CPU time or memory usage limits.


# Architecture

    This is divided into two parts: 

        1) Sandbox (child process): This executes the user program after imposing resource-limits on itself. Check sandbox() function in [sandbox.c](https://github.com/gitdhruba/glug-sandbox/blob/main/sandbox.c).

        2) Monitor (parent process): This is meant for constantly monitor the resource usage of Sandbox and intercept and analyze system calls invoked by Sandbox. Thus    provides a safe execution environment for untrusted code. Check monitor() function in [sandbox.c](https://github.com/gitdhruba/glug-sandbox/blob/main/sandbox.c).


# Prerequisites

    To run and test this project a GNU/Linux Operating system with gcc installed is needed.
    NOTE: this project may not work properly on other operating systems (like Windows NT, Mac OS) as it is fully based on Linux System call API
    
    To better understand this project please go through these docs:
        1) ptrace: https://man7.org/linux/man-pages/man2/ptrace.2.html
        2) rlimit: https://www.man7.org/linux/man-pages/man2/getrlimit.2.html
        3) signal: https://man7.org/linux/man-pages/man7/signal.7.html