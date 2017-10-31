/* base.h
 * by kimht
 */
#ifndef _BASE_BASE_H_
#define _BASE_BASE_H_

#define _GNU_SOURCE

////////////////////////////////////////////////////////////////////////////////
/// includes
////////////////////////////////////////////////////////////////////////////////
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <ucontext.h>


#include <sqlite3.h>

////////////////////////////////////////////////////////////////////////////////
/// macro functions
////////////////////////////////////////////////////////////////////////////////

/*
 * HANDLE_ERROR - Handles error. perror() and return a value.
 */
#define HANDLE_ERROR(msg, ret_val) {  \
    perror(msg);  \
    return ret_val;  \
}

#define GetOffset(o)  \
    (o & 0b1111111111111111)

#define GetImm(i)  \
    (i & 0b1111111111111111)

#define GetCode20(c)  \
    (c & 0b11111111111111111111)

#define GetIdx(i)  \
    (i & 0b11111111111111111111111111)

#define GetStype(s)  \
    (s & 0b11111)

#define GetGPR(r)  \
    (r & 0b11111)

#define GetGPRStr(r)  \
    gpr_str[GetGPR(r)]

#define GetRegsGPR(aregs, r)  \
    (unsigned int)((aregs)->regs[GetGPR(r)])

#define GetRegsHI(aregs)  \
    (unsigned int)((aregs)->hi)

#define GetRegsLO(aregs)  \
    (unsigned int)((aregs)->lo)

#define GetRegsPC(aregs)  \
    (unsigned int)((aregs)->cp0_epc)

#define IsTaintedGPR(atstat, r)  \
    (unsigned int)((atstat)->regs[GetGPR(r)])

#define IsTaintedPC(atstat)  \
    (unsigned int)((atstat)->cp0_epc)

#define IsTaintedLO(atstat)  \
    (unsigned int)((atstat)->lo)

#define IsTaintedHI(atstat)  \
    (unsigned int)((atstat)->hi)

#define SignExtend16(val)  \
    (val & 0b1000000000000000) ? val | 0b11111111111111110000000000000000 : val

#define SignExtend8(val)  \
    (val & 0b10000000) ? val | 0b11111111111111111111111100000000: val

///////////////////////////////////////////////////////////////////////////////
/// externs
///////////////////////////////////////////////////////////////////////////////
extern char *gpr_str[];

///////////////////////////////////////////////////////////////////////////////
/// struct
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

#endif

