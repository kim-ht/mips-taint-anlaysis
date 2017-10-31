/* tracer.h
 * by kimht
 */
#ifndef _TRACER_TRACER_H_
#define _TRACER_TRACER_H_

#include "../base/base.h"
#include "../disassembler_printer/disassembler_printer.h"
#include "../taint_checker/taint_checker.h"
#include "../result_saver/result_saver.h"

///////////////////////////////////////////////////////////////////////////////
/// defines
///////////////////////////////////////////////////////////////////////////////
#define BREAK_POINT     0x0000000d
#define NO_START_ADDR   -1
#define NO_END_ADDR     -1

///////////////////////////////////////////////////////////////////////////////
/// variables
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// function prototypes
///////////////////////////////////////////////////////////////////////////////

/*
 * TraceProgram  - Start tracing a program. child. 
 *
 * @path - The path of the program to be traced.
 * @argv - The argv which will be delivered to tracee program.
 * @envp - The envp which will be delivered to tracee program.
 * @start_addr - The address to start tracing.
 * @end_addr - The address to end up tracing.
 * @return - 0 on success; -1 on failure.
 */
int TraceProgram(const char *path, char *const argv[], char *const envp[],
    int start_addr, int end_addr);
void PrintRegs(struct pt_regs *pt_regs);

#endif

