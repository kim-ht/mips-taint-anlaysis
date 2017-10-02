/* tracer.c
 * by kimht
 */
#include "./tracer.h"

///////////////////////////////////////////////////////////////////////////////
/// function declarations
///////////////////////////////////////////////////////////////////////////////
static int RepeatSingleStep(pid_t traced_pid);
static int HandlerSingleStep(pid_t traced_pid);
static int GetDataFromPID(pid_t pid, unsigned int addr, size_t size,
    unsigned char *output);

///////////////////////////////////////////////////////////////////////////////
/// function definitions
///////////////////////////////////////////////////////////////////////////////
/*
 * StartTracingProgram  - Start tracing a program. child. 
 *
 * @path - The path of the program to be traced.
 * @argv - The argv which will be delivered to tracee program.
 * @envp - The envp which will be delivered to tracee program.
 * @return - 0 on success; -1 on failure.
 */
int TraceProgram(const char *path, char *const argv[], char *const envp[]) {
    pid_t pid;
    pid_t traced_pid;

    pid = fork();

    /* Negative PID means fork() has failed. */
    if ( pid < 0 ) {
        HANDLE_ERROR("StartTracingProgram() failure", -1);

    /*
     * Zero PID is child process. It starts tracing the child process with
     * ptrace.
     */
    } else if ( pid == 0 ) {
        if ( ptrace(PTRACE_TRACEME, 0, 0, 0) < 0 ) {
            HANDLE_ERROR("StartTracingProgram() failure", -1);
        }

        if ( execvpe(path, argv, envp) < 0 ) {
            HANDLE_ERROR("StartTracingProgram() failure", -1);
        }
    /*
     * Positive PID is parant process. it waits the child process and then
     * repeats single step.
     */
    } else {
        if ( wait(0) < 0 ) {
            HANDLE_ERROR("StartTracingProgram() failure", -1);
        }

        traced_pid = pid;

        if ( ptrace(PTRACE_SINGLESTEP, traced_pid, 0, 0) < 0 ) {
            HANDLE_ERROR("StartTracingProgram() failure", -1);
        }

        // Single step loop.
        RepeatSingleStep(traced_pid);
    }

    return 0;
}

/*
 * RepeatSingleStep - repeats single step and handles it.
 *
 * @return - 0 on success; -1 on failure.
*/
static int RepeatSingleStep(pid_t traced_pid) {
    int status;
    siginfo_t siginfo;
    int signo;

    if ( waitpid(traced_pid, &status, 0) < 0 ) {
        HANDLE_ERROR("RepeatSingleStep() failure", -1);
    }

    while ( WIFSTOPPED(status) ) {

        // Checks if the tracee is crashed.
        if ( ptrace(PTRACE_GETSIGINFO, traced_pid, 0, &siginfo) < 0 ) {
            HANDLE_ERROR("RepeatSingleStep() failure", -1);
        }

        signo = siginfo.si_signo;

        if ( signo == SIGILL || signo == SIGSEGV || signo == SIGFPE ||
            signo == SIGCHLD ) {
            return 0;
        }

        // Handles after single step like code hooking.
        if ( HandlerSingleStep(traced_pid) < 0 ) {
            HANDLE_ERROR("RepeatSingleStep() failure", -1);
        }

        if ( ptrace(PTRACE_SINGLESTEP, traced_pid, 0, 0) < 0 ) {
            HANDLE_ERROR("RepeatSingleStep() failure", -1);
        }

        if ( waitpid(traced_pid, &status, 0) < 0 ) {
            HANDLE_ERROR("RepeatSingleStep() failure", -1);
        }
    }

    return 0;
}

/*
 * HanderSingleStep - The hander that occurs just after single step.
 *
 * @return - 0 on success; 1 on failure.
 */
static int HandlerSingleStep(pid_t traced_pid) {
    struct user_regs_struct regs;
    unsigned int pc;
    unsigned int code;

    // Get current registers values.
    if ( ptrace(PTRACE_GETREGS, traced_pid, 0, &regs) < 0 ) {
        HANDLE_ERROR("HandlerSingleStep()", -1);
    }

    pc = regs.rip;

    // Gets code from child process and disassemble it.
    GetDataFromPID(traced_pid, pc, 4, (unsigned char *)&code);

    printf("pc: 0x%08x, machine code: 0x%08x\n", pc, code);

    return 0;
}

/*
 * GetDataFromPID - Gets data from a process specificed by PID.
 *
 * @pid - The PID to be read.
 * @addr - The address to be read from.
 * @size - The size to read.
 * @output - pointer to write read data.
 * @return - 0 on success; -1 on failure.
 */
static int GetDataFromPID(pid_t pid, unsigned int addr, size_t size,
    unsigned char *output) {
    char path[64];
    int fd;

    snprintf(path, 64, "/proc/%u/mem", pid);

    fd = open(path, O_RDONLY);
    if ( fd < 0 ) {
        HANDLE_ERROR("GetDataFromPID() failure", -1);
    }

    if ( pread(fd, output, size, addr) < 0 ) {
        HANDLE_ERROR("GetDataFromPID() failure", -1);
    }

    close(fd);

    return 0;
}

