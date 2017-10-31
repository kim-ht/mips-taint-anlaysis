/* sqlite_db.h
 * by kimht
 */

#ifndef _SQLITE_DB_SQLITE_DB_H_
#define _SQLITE_DB_SQLITE_DB_H_

///////////////////////////////////////////////////////////////////////////////
/// include
///////////////////////////////////////////////////////////////////////////////
#include "../base/base.h"
//#include "../tracer/tracer.h"
#include "../taint_checker/taint_checker.h"

struct db_pt_regs {
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
/// extern
///////////////////////////////////////////////////////////////////////////////
extern unsigned int db_idx;
extern int *result_fd;

int OpenResultFile(int *result_fd);
int InsertIntoTracerTable(sqlite3 **db_handle, int code, int mnem_id,
                          const char *disas, struct db_pt_regs *regs);

#endif

