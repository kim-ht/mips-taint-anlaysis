/* tracer.h
 * by kimht
 */
#ifndef _TRACER_TRACER_H_
#define _TRACER_TRACER_H_

#include "../base/base.h"
#include "../disassembler_printer/disassembler_printer.h"

///////////////////////////////////////////////////////////////////////////////
/// defines
///////////////////////////////////////////////////////////////////////////////
#define BREAK_POINT 0x0000000d

///////////////////////////////////////////////////////////////////////////////
/// variables
///////////////////////////////////////////////////////////////////////////////

struct pt_regs {
    /* Saved main processor registers. */
    uint64_t regs[32];

    /* Saved special registers. */
    uint64_t lo;
    uint64_t hi;
    uint64_t cp0_epc;
    uint64_t cp0_badvaddr;
    uint64_t cp0_status;
    uint64_t cp0_cause;
};

///////////////////////////////////////////////////////////////////////////////
/// function prototypes
///////////////////////////////////////////////////////////////////////////////

/*
 * TraceProgram  - Start tracing a program. child. 
 *
 * @path - The path of the program to be traced.
 * @argv - The argv which will be delivered to tracee program.
 * @envp - The envp which will be delivered to tracee program.
 * @return - 0 on success; -1 on failure.
 */
int TraceProgram(const char *path, char *const argv[], char *const envp[]);

#endif

