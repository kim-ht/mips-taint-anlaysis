/* result_saver.h
 * by kimht
 */
#ifndef _RESULT_SAVER_RESULT_SAVER_H_
#define _RESULT_SAVER_RESULT_SAVER_H_

///////////////////////////////////////////////////////////////////////////////
/// includes
///////////////////////////////////////////////////////////////////////////////
#include "../base/base.h"
#include "../taint_checker/taint_checker.h"

///////////////////////////////////////////////////////////////////////////////
/// externs
///////////////////////////////////////////////////////////////////////////////
extern unsigned int result_idx;
extern FILE *tracer_fd;
extern FILE *taint_checker_fd;

///////////////////////////////////////////////////////////////////////////////
/// function prototypes
///////////////////////////////////////////////////////////////////////////////

/*
 * InitResultFile - Creates/Recreates result files to store analysis result.
 *                  It uses extern variable tracer_fd and taint_checker_fd
 *                  implicilty.
 *
 * @return - 0 on success; -1 on failure.
 */
int InitResultFile();

/*
 * ExitResultFile - Closes result files. It uses extern variable tracer_fd and
 *                  taint_checker_fd implicitly.
 *
 * @return - 0 on success; -1 on failure.
 */
int ExitResultFile();

/*
 * SaveTracerInfo - Saves tracing information to tracer_result. It uses
 *                  tracer_fd implicitly.
 *
 * @code - The machine code.
 * @mnem_id - The mnemonic ID.
 * @disas - The pointer to disassembled string.
 * @regs - The pointer to registers.
 * @return - 0 on success; -1 on failure.
 */
int SaveTracerInfo(int code, int mnem_id, const char *disas,
                   struct pt_regs *regs);

/*
 * SaveTaintCheckerInfo - Saves taint checking information to
 *                        taint_checker_result. It uses tc_src, tc_dest,
 *                        tc_tstat, etc.
 *
 * @return - 0 on success; -1 on failure.
 */
int SaveTaintCheckerInfo();

#endif

