/* tracer.c
 * by kimht
 */
#include "./tracer.h"

///////////////////////////////////////////////////////////////////////////////
/// macro functions
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// function declarations
///////////////////////////////////////////////////////////////////////////////
//static int RepeatSingleStep(pid_t traced_pid);
//static int GetDataFromPID(pid_t pid, unsigned int addr, size_t size,
//    unsigned char *output);
static int RunTargetWithTrace(const char *path, char *const argv[],
    char *const envp[]);
static int RunDebugger(pid_t traced_pid);
static int SingleStepHandler(pid_t traced_pid);
static int SingleStep(pid_t traced_pid);

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
        HANDLE_ERROR("TraceProgram()::fork()", -1);

    /*
     * Zero PID is child process. It starts tracing the child process with
     * ptrace.
     */
    } else if ( pid == 0 ) {
        if ( RunTargetWithTrace(path, argv, envp) < 0 ) {
            HANDLE_ERROR("TraceProgram()::RunTargetWithTrace()", -1);
        }

    /*
     * Positive PID is parant process. it waits the child process and then
     * repeats single step.
     */
    } else {
        traced_pid = pid;

        RunDebugger(traced_pid);
    }

    return 0;
}
/*
 * RunTargetWithTrace - Run program with attaching(ptrace traceme).
 *
 * @path - The path of the program to debug.
 * @argv - The argv will be passed to tracee.
 * @envp - The envp will be passed to tracee.
 * @return - 0 on success; -1 on failure.
 */
static int RunTargetWithTrace(const char *path, char *const argv[],
    char *const envp[]) {
    if ( ptrace(PTRACE_TRACEME, 0, 0, 0) < 0 ) {
        HANDLE_ERROR("RunTargetWithTrace()::ptrace()", -1);
    }

    if ( execvpe(path, argv, envp) < 0 ) {
        HANDLE_ERROR("RunTargetWithTrace()::execvpe()", -1);
    }

    return 0;
}

/*
 * RunDebugger - Starts debugging given pid.
 *
 * @traced_pid - The pid to trace.
 * @return - 0 on success; -1 on failure.
 */
static int RunDebugger(pid_t traced_pid) {
    int wait_status;

    printf("traced_pid:: %d\n", traced_pid);

    // Wait for tracee to stop on its first instruction.
    wait(&wait_status);

    while ( WIFSTOPPED(wait_status) ) {

        // Handler.
        SingleStepHandler(traced_pid);

        wait_status = SingleStep(traced_pid);
    }

    return 0;
}

/*
 * SingleStep - singlee step.
 *
 * @return 0 on success; -1 on failure.
 */
static int SingleStep(pid_t traced_pid) {
    struct pt_regs regs;
    int pc;
    int code;
    int mnem_id;
    int is_branch;
    int target;
    struct operands_t operands;
    int orig_code[2]; // [0] for when condition is true, [1] for when condition
                      // is false.
    int wait_status;
    int next_pc;
    int offset;

    is_branch = 0;

    // Get currency pc and machine code.
    ptrace(PTRACE_GETREGS, traced_pid, 0, &regs);
    pc = regs.cp0_epc;
    code = ptrace(PTRACE_PEEKTEXT, traced_pid, pc, 0);

    // Find mnemonic of the code to check if it's branch opcode and operands.
    mnem_id = FindCorrespondingMnemonic(code);
    GetOperandFromCode(code, mnem_id, &operands);

    switch ( mnem_id ) {
    case ID_JR:
    case ID_JALR:
        is_branch = 1;
        target = regs.regs[operands.rs & 0b11111];
        break;

    case ID_J:
    case ID_JAL:
        is_branch = 1;
        target = pc + 4;
        target >>= 28;
        target <<= 28;
        target |= (GetOffset(operands.offset) << 2);
        break;

    case ID_B:
    case ID_BAL:
    case ID_BGEZ:
    case ID_BGEZL:
    case ID_BGEZAL:
    case ID_BGEZALL:
    case ID_BLTZ:
    case ID_BLTZL:
    case ID_BLTZAL:
    case ID_BLTZALL:
    case ID_BEQ:
    case ID_BEQL:
    case ID_BNE:
    case ID_BNEL:
    case ID_BLEZ:
    case ID_BLEZL:
    case ID_BGTZ:
    case ID_BGTZL:
    case ID_BC1T:
    case ID_BC1F:
    case ID_BC1FL:
    case ID_BC1TL:
        is_branch = 1; //0x77fc57f0
        target = ((GetOffset(operands.offset) & 0b1000000000000000) ?
            GetOffset(operands.offset) | 0b11111111111111110000000000000000 : 
            GetOffset(operands.offset)) << 2;
        target += pc + 4;
        break;
    }

    if ( is_branch ) {

        // Set breakpoint.
        orig_code[0] = ptrace(PTRACE_PEEKTEXT, traced_pid, pc + 8, 0);
        orig_code[1] = ptrace(PTRACE_PEEKTEXT, traced_pid, target, 0);
        ptrace(PTRACE_POKETEXT, traced_pid, pc + 8, BREAK_POINT);
        ptrace(PTRACE_POKETEXT, traced_pid, target, BREAK_POINT);

        // Continue execution.
        ptrace(PTRACE_CONT, traced_pid, 0, 0);
        wait(&wait_status);

        // Restore original codes.
        ptrace(PTRACE_POKETEXT, traced_pid, pc + 8, orig_code[0]);
        ptrace(PTRACE_POKETEXT, traced_pid, target, orig_code[1]);

    } else {
        next_pc = pc + 4;

        // Set breakpoint.
        orig_code[0] = ptrace(PTRACE_PEEKTEXT, traced_pid, next_pc, 0);
        ptrace(PTRACE_POKETEXT, traced_pid, next_pc, BREAK_POINT);

        // Continue execution.
        ptrace(PTRACE_CONT, traced_pid, 0, 0);
        wait(&wait_status);

        // Restore original code.
        ptrace(PTRACE_POKETEXT, traced_pid, next_pc, orig_code[0]);
    }

    return wait_status;
}

/*
 * SingleStepHandler - This handler occurs before single step.
 *
 * @return - 0 on success; -1 on failure.
 */
static int SingleStepHandler(pid_t traced_pid) {
    unsigned int code = 0x12345678;
    struct pt_regs regs;
    char buf[128];
    uint32_t pc;

    ptrace(PTRACE_GETREGS, traced_pid, 0, &regs);
    pc = regs.cp0_epc;
    code = ptrace(PTRACE_PEEKTEXT, traced_pid, pc, 0);

    GetInstructionStringImmediately(buf, code, pc);
    printf("pc: 0x%08x, code: 0x%08x, %s\n", pc, code, buf);

    return 0;
}

/*
 * RepeatSingleStep - repeats single step and handles it.
 *
 * @return - 0 on success; -1 on failure.
*/
/*
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
*/

