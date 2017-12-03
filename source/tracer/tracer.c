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
static int RunTargetWithTrace(const char *path, char *const argv[],
        char *const envp[]);
static int RunDebugger(pid_t traced_pid, int start_addr, int end_addr);
static int PrintDisas(pid_t traced_pid);
static int SingleStepPreHandler(pid_t traced_pid);
static int SingleStepPostHandler(pid_t traced_pid);
static int SingleStep(pid_t traced_pid);
static int RunUntilStartAddress(pid_t traced_pid, int start_addr);
static int IsHitEndAddress(pid_t traced_pid, int start_addr);

///////////////////////////////////////////////////////////////////////////////
/// function definitions
///////////////////////////////////////////////////////////////////////////////
/*
 * StartTracingProgram  - Start tracing a program. child. 
 *
 * @path - The path of the program to be traced.
 * @argv - The argv which will be delivered to tracee program.
 * @envp - The envp which will be delivered to tracee program.
 * @start_addr - The address to start tracing.
 * @end_addr - The address to end up tracing.
 * @return - 0 on success; -1 on failure.
 */
int TraceProgram(const char *path, char *const argv[], char *const envp[],
        int start_addr, int end_addr) {
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

        RunDebugger(traced_pid, start_addr, end_addr);
    }

    return 0;
}
/*
 * RunTargetWithTrace - Run program with attaching(ptrace traceme).
 *
 * @path - The path of the program to debug.
 * @argv - The argv will be passed to tracee.
 * @envp - The envp will be passed to tracee.
 * @start_addr - The address to start tracing.
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
 * @traced_pid - The pid being traced.
 * @return - 0 on success; -1 on failure.
 */
static int RunDebugger(pid_t traced_pid, int start_addr, int end_addr) {
    int wait_status;

    dup2(123, 1);

    printf("traced_pid: %u\n", traced_pid);

    wait(&wait_status);

    // Run until start address.
    if ( start_addr != NO_START_ADDR ) {
        if ( RunUntilStartAddress(traced_pid, start_addr) < 0 ) {
            HANDLE_ERROR("RunDebugger()::RunUntilStartAddress()", -1);
        }
    }

    TaintCheckerInit();
    

    while ( WIFSTOPPED(wait_status) ) {

        SingleStepPreHandler(traced_pid);

        wait_status = SingleStep(traced_pid);

        SingleStepPostHandler(traced_pid);

        // End up debugging if pc hits end address.
        if ( end_addr != NO_END_ADDR &&
                IsHitEndAddress(traced_pid, end_addr) ) {
            break;
        }
    }
    ExitResultFile();
    return 0;
}

/*
 * RunUntilStartAddress - Run traced process until start address.
 *
 * @traced_pid - The traced process's id.
 * @start_addr - The address to start debugging.
 * @return - 0 on success; 1 on failure.
 */
static int RunUntilStartAddress(pid_t traced_pid, int start_addr) {
    int orig_code;
    int wait_status;

    orig_code = ptrace(PTRACE_PEEKTEXT, traced_pid, start_addr, 0);
    ptrace(PTRACE_POKETEXT, traced_pid, start_addr, BREAK_POINT);
    ptrace(PTRACE_CONT, traced_pid, 0, 0);

    wait(&wait_status);
    if ( WIFEXITED(wait_status) ) {
        return -1;
    }

    ptrace(PTRACE_POKETEXT, traced_pid, start_addr, orig_code);

    printf("pc hits start_addr(0x%08x).\n", start_addr);
    // printf("%d\n", wait_status);

    return 0;
}

/*
 * RunUntilStartAddress - Run traced process until start address.
 *
 * @traced_pid - 
 * @end_addr - 
 * @return - 1 on hit; 0 on no hit.
 */
static int IsHitEndAddress(pid_t traced_pid, int end_addr) {
    struct pt_regs regs;
    int pc;

    ptrace(PTRACE_GETREGS, traced_pid, 0, &regs);
    pc = regs.cp0_epc;

    if ( pc == end_addr ) {
        printf("pc hits end_addr(0x%08x).\n", end_addr);
        return 1;
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
    int orig_code[2];
    int wait_status;
    int next_pc;
    char buf[128];

    is_branch = 0;

    // Get currency pc and machine code.
    ptrace(PTRACE_GETREGS, traced_pid, 0, &regs);
    pc = regs.cp0_epc;
    code = ptrace(PTRACE_PEEKTEXT, traced_pid, pc, 0);

    // Find mnemonic of the code to check if it's branch opcode and operands.
    mnem_id = FindCorrespondingMnemonic(code);
    if ( mnem_id != -1 ) {
        GetOperandFromCode(code, mnem_id, &operands);
    }

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
        target |= GetIdx(operands.idx) << 2;
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
        is_branch = 1;
        target = ((GetOffset(operands.offset) & 0b1000000000000000) ?
            GetOffset(operands.offset) | 0b11111111111111110000000000000000 : 
            GetOffset(operands.offset)) << 2;
        target += pc + 4;
        break;

    /* to guarantee LL/SC sequence */
    case ID_LL:
        while ( FindCorrespondingMnemonic(code) != ID_SC ) {
            pc += 4;
            code = ptrace(PTRACE_PEEKTEXT, traced_pid, pc, 0);
            GetInstructionStringImmediately(buf, code, pc);
            printf("%s\n", buf);
        }
        break;
    }

    if ( is_branch ) {
        next_pc = pc + 8;

        // Set breakpoint.
        orig_code[0] = ptrace(PTRACE_PEEKTEXT, traced_pid, next_pc, 0);
        orig_code[1] = ptrace(PTRACE_PEEKTEXT, traced_pid, target, 0);
        ptrace(PTRACE_POKETEXT, traced_pid, next_pc, BREAK_POINT);
        ptrace(PTRACE_POKETEXT, traced_pid, target, BREAK_POINT);

        // Continue execution.
        ptrace(PTRACE_CONT, traced_pid, 0, 0);
        wait(&wait_status);

        // Restore original codes.
        ptrace(PTRACE_POKETEXT, traced_pid, next_pc, orig_code[0]);
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
 * PrintDisas - Prints disassembled instruction on current pc.
 *
 * @traced_pid - The process's id to disasemble.
 * @return - 0 on success; -1 on failure.
 */
static int PrintDisas(pid_t traced_pid) {
    unsigned int code;
    struct pt_regs regs;
    char buf[128];
    int pc;
    int mnem_id;
    struct operands_t op;

    ptrace(PTRACE_GETREGS, traced_pid, 0, &regs);
    pc = regs.cp0_epc;
    code = ptrace(PTRACE_PEEKTEXT, traced_pid, pc, 0);
    mnem_id = FindCorrespondingMnemonic(code);
    if ( mnem_id >= 0 ) {
        GetInstructionString(buf, mnem_id, &op, pc);
        GetOperandFromCode(code, mnem_id, &op);
    } else {
        strcpy(buf, "invalid mnem_id.");
    }
    //SaveTracerInfo(code, mnem_id, buf, &regs);
    printf(buf);
    return 0;
}

/*
 * SingleStepPreHandler - This handler occurs before single step.
 *
 * @return - 0 on success; -1 on failure.
 */
static int SingleStepPreHandler(pid_t traced_pid) {
    TaintCheckerPreHandler(traced_pid);

    return 0;
}

/*
 * SingleStepPostHandler - This handler occurs after single step.
 *
 * @return - 0 on success; -1 on failure.
 */
static int SingleStepPostHandler(pid_t traced_pid) {
    TaintCheckerPostHandler(traced_pid);

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

void PrintRegs(struct pt_regs *pt_regs) {
    int i;

    printf(" << regs >>\n");
    for ( i = 0; i < 32; ++i ) {
        printf("- %s: 0x%08x (%d)\n", gpr_str[i], GetRegsGPR(pt_regs, i), IsTaintedGPR(&tc_tstat, i));
    }
    printf("- lo: 0x%08x (%d)\n", GetRegsLO(pt_regs), IsTaintedLO(&tc_tstat));
    printf("- hi: 0x%08x (%d)\n", GetRegsLO(pt_regs), IsTaintedHI(&tc_tstat));
    printf("- pc: 0x%08x (%d)\n", GetRegsPC(pt_regs), IsTaintedPC(&tc_tstat));
    printf("- badvaddr: 0x%08x\n", (unsigned int)pt_regs->cp0_badvaddr);
    printf("- cause: 0x%08x\n", (unsigned int)pt_regs->cp0_cause);
    printf("- status: 0x%08x\n", (unsigned int)pt_regs->cp0_status);
}

