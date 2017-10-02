/* tracer.h
 * by kimht
 */
#ifndef _TRACER_TRACER_H_
#define _TRACER_TRACER_H_

#include "../base/base.h"

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

