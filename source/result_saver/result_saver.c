/* result_saver.c
 * by kimht
 */

///////////////////////////////////////////////////////////////////////////////
/// includes
///////////////////////////////////////////////////////////////////////////////
#include "./result_saver.h"

///////////////////////////////////////////////////////////////////////////////
/// variables
///////////////////////////////////////////////////////////////////////////////
unsigned int result_idx;
FILE *tracer_fd;
FILE *taint_checker_fd;

///////////////////////////////////////////////////////////////////////////////
/// function declaration
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// function definition
///////////////////////////////////////////////////////////////////////////////

/*
 * InitResultFile - Creates/Recreates result files to store analysis result.
 *                  It uses extern variable tracer_fd and taint_checker_fd
 *                  implicilty.
 *
 * @return - 0 on success; -1 on failure.
 */
int InitResultFile() {
    result_idx = 0;

    tracer_fd = fopen("./tracer_result", "wb");
    if ( !tracer_fd ) {
        HANDLE_ERROR("InitResultFile()::fopen() error", -1);
    }
    taint_checker_fd = fopen("./taint_checker_result", "wb");
    if ( !taint_checker_fd ) {
        HANDLE_ERROR("InitResultFile()::fopen() error", -1);
    }
    return 0;
}

/*
 * ExitResultFile - Closes result files. It uses extern variable tracer_fd and
 *                  taint_checker_fd implicitly.
 *
 * @return - 0 on success; -1 on failure.
 */
int ExitResultFile() {
    if ( fclose(tracer_fd) == EOF ) {
        HANDLE_ERROR("ExitResultFile()::fclose() error", -1);
    }
    if ( fclose(taint_checker_fd) == EOF ) {
        HANDLE_ERROR("ExitResultFile()::fclose() error", -1);
    }
    return 0;
}

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
                   struct pt_regs *regs) {
    char buf[1024] = {0x00, };

    snprintf(buf, 1023, "%u|%u|%u|%s|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u\n",
            result_idx, code, mnem_id, disas,
            GetRegsGPR(regs, 0), GetRegsGPR(regs, 1), GetRegsGPR(regs, 2),
            GetRegsGPR(regs, 3), GetRegsGPR(regs, 4), GetRegsGPR(regs, 5),
            GetRegsGPR(regs, 6), GetRegsGPR(regs, 7), GetRegsGPR(regs, 8),
            GetRegsGPR(regs, 9), GetRegsGPR(regs, 10), GetRegsGPR(regs, 11),
            GetRegsGPR(regs, 12), GetRegsGPR(regs, 13), GetRegsGPR(regs, 14),
            GetRegsGPR(regs, 15), GetRegsGPR(regs, 16), GetRegsGPR(regs, 17),
            GetRegsGPR(regs, 18), GetRegsGPR(regs, 19), GetRegsGPR(regs, 20),
            GetRegsGPR(regs, 21), GetRegsGPR(regs, 22), GetRegsGPR(regs, 23),
            GetRegsGPR(regs, 24), GetRegsGPR(regs, 25), GetRegsGPR(regs, 26),
            GetRegsGPR(regs, 27), GetRegsGPR(regs, 28), GetRegsGPR(regs, 29),
            GetRegsGPR(regs, 30), GetRegsGPR(regs, 31), GetRegsPC(regs),
            GetRegsLO(regs), GetRegsHI(regs));
    if ( !fwrite(buf, sizeof(char), strlen(buf), tracer_fd) ) {
        HANDLE_ERROR("SaveTracerInfo()::fread() error", -1);
    }
    return 0;
}

/*
 * SaveTaintCheckerInfo - Saves taint checking information to
 *                        taint_checker_result. It uses tc_src, tc_dest,
 *                        tc_tstat, etc.
 *
 * @return - 0 on success; -1 on failure.
 */
int SaveTaintCheckerInfo() {
    char buf[1024] = {0x00, };

    snprintf(buf, 1023, "%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|%u|"  \
                        "%u|%u|",
            result_idx, 
            GetRegsGPR(&tc_regs_after, 0), GetRegsGPR(&tc_regs_after, 1), GetRegsGPR(&tc_regs_after, 2),
            GetRegsGPR(&tc_regs_after, 3), GetRegsGPR(&tc_regs_after, 4), GetRegsGPR(&tc_regs_after, 5),
            GetRegsGPR(&tc_regs_after, 6), GetRegsGPR(&tc_regs_after, 7), GetRegsGPR(&tc_regs_after, 8),
            GetRegsGPR(&tc_regs_after, 9), GetRegsGPR(&tc_regs_after, 10), GetRegsGPR(&tc_regs_after, 11),
            GetRegsGPR(&tc_regs_after, 12), GetRegsGPR(&tc_regs_after, 13), GetRegsGPR(&tc_regs_after, 14),
            GetRegsGPR(&tc_regs_after, 15), GetRegsGPR(&tc_regs_after, 16), GetRegsGPR(&tc_regs_after, 17),
            GetRegsGPR(&tc_regs_after, 18), GetRegsGPR(&tc_regs_after, 19), GetRegsGPR(&tc_regs_after, 20),
            GetRegsGPR(&tc_regs_after, 21), GetRegsGPR(&tc_regs_after, 22), GetRegsGPR(&tc_regs_after, 23),
            GetRegsGPR(&tc_regs_after, 24), GetRegsGPR(&tc_regs_after, 25), GetRegsGPR(&tc_regs_after, 26),
            GetRegsGPR(&tc_regs_after, 27), GetRegsGPR(&tc_regs_after, 28), GetRegsGPR(&tc_regs_after, 29),
            GetRegsGPR(&tc_regs_after, 30), GetRegsGPR(&tc_regs_after, 31), GetRegsPC(&tc_regs_after),
            GetRegsLO(&tc_regs_after), GetRegsHI(&tc_regs_after));

    if ( !fwrite(buf, sizeof(char), strlen(buf), taint_checker_fd) ) {
        HANDLE_ERROR("SaveTracerInfo()::fread() error", -1);
    }
    snprintf(buf, 1023, "%u|%u|%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u|%u|"  \
                        "%u\n",
            tc_src, tc_dest, tc_lr, tc_size,
            IsTaintedGPR(&tc_tstat, 0), IsTaintedGPR(&tc_tstat, 1),
            IsTaintedGPR(&tc_tstat, 2), IsTaintedGPR(&tc_tstat, 3),
            IsTaintedGPR(&tc_tstat, 4), IsTaintedGPR(&tc_tstat, 5),
            IsTaintedGPR(&tc_tstat, 6), IsTaintedGPR(&tc_tstat, 7),
            IsTaintedGPR(&tc_tstat, 8), IsTaintedGPR(&tc_tstat, 9),
            IsTaintedGPR(&tc_tstat, 10), IsTaintedGPR(&tc_tstat, 11),
            IsTaintedGPR(&tc_tstat, 12), IsTaintedGPR(&tc_tstat, 13),
            IsTaintedGPR(&tc_tstat, 14), IsTaintedGPR(&tc_tstat, 15),
            IsTaintedGPR(&tc_tstat, 16), IsTaintedGPR(&tc_tstat, 17),
            IsTaintedGPR(&tc_tstat, 18), IsTaintedGPR(&tc_tstat, 19),
            IsTaintedGPR(&tc_tstat, 20), IsTaintedGPR(&tc_tstat, 21),
            IsTaintedGPR(&tc_tstat, 22), IsTaintedGPR(&tc_tstat, 23),
            IsTaintedGPR(&tc_tstat, 24), IsTaintedGPR(&tc_tstat, 25),
            IsTaintedGPR(&tc_tstat, 26), IsTaintedGPR(&tc_tstat, 27),
            IsTaintedGPR(&tc_tstat, 28), IsTaintedGPR(&tc_tstat, 29),
            IsTaintedGPR(&tc_tstat, 30), IsTaintedGPR(&tc_tstat, 31),
            IsTaintedPC(&tc_tstat), IsTaintedLO(&tc_tstat),
            IsTaintedHI(&tc_tstat));
    if ( !fwrite(buf, sizeof(char), strlen(buf), taint_checker_fd) ) {
        HANDLE_ERROR("SaveTaintCheckerInfo()::fread() error", -1);
    }
    ++result_idx;
    return 0;
}

