/* result_.c
 * by kimht
 */

///////////////////////////////////////////////////////////////////////////////
/// include
///////////////////////////////////////////////////////////////////////////////
#include "./sqlite_db.h"

///////////////////////////////////////////////////////////////////////////////
/// varibles
///////////////////////////////////////////////////////////////////////////////
unsigned int db_idx;
int result_fd;

/*
 * OpenResultFile - Create/recreate result file.
 *
 * @result_fd - The result file's descriptor.
 * @return - 0 on success; -1 on failure.
 */
    unlink("./taint_result");

    open();
    return 0;
}


/*
 * InsertIntoTracerTable - Inserts data into Tracer table.
 *
 * @return - 0 on success; -1 on failure.
 */
int InsertIntoTracerTable(sqlite3 **db_handle, int code, int mnem_id,
                          const char *disas, struct db_pt_regs *regs) {
    char *err_msg = 0;
    char sql[1024];

    snprintf(sql, 1023,
            "%u, %u, %u, \"%s\","  \
            "%u, %u, %u,"  \
            "%u, %u, %u, %u,"  \
            "%u, %u, %u, %u,"  \
            "%u, %u, %u, %u,"  \
            "%u, %u, %u, %u,"  \
            "%u, %u, %u, %u,"  \
            "%u, %u, %u, %u,"  \
            "%u, %u, %u, %u,"  \
            "%u, %u, %u, %u\n",
            db_idx, code, mnem_id, disas,
            GetRegsGPR(regs, 0), GetRegsGPR(regs, 1), GetRegsGPR(regs, 2),
            GetRegsGPR(regs, 3), GetRegsGPR(regs, 4), GetRegsGPR(regs, 5), GetRegsGPR(regs, 6),
            GetRegsGPR(regs, 7), GetRegsGPR(regs, 8), GetRegsGPR(regs, 9), GetRegsGPR(regs, 10),
            GetRegsGPR(regs, 11), GetRegsGPR(regs, 12), GetRegsGPR(regs, 13), GetRegsGPR(regs, 14),
            GetRegsGPR(regs, 15), GetRegsGPR(regs, 16), GetRegsGPR(regs, 17), GetRegsGPR(regs, 18),
            GetRegsGPR(regs, 19), GetRegsGPR(regs, 20), GetRegsGPR(regs, 21), GetRegsGPR(regs, 22),
            GetRegsGPR(regs, 23), GetRegsGPR(regs, 24), GetRegsGPR(regs, 25), GetRegsGPR(regs, 26),
            GetRegsGPR(regs, 27), GetRegsGPR(regs, 28), GetRegsGPR(regs, 29), GetRegsGPR(regs, 30),
            GetRegsGPR(regs, 31), GetRegsHI(regs), GetRegsLO(regs), GetRegsPC(regs));

    if ( sqlite3_exec(*db_handle, sql, 0, 0, &err_msg) != SQLITE_OK ) {
        puts(sql);
        printf("err_msg: %s\n", err_msg);
        HANDLE_ERROR("sqlite3_exec() error", -1);
    }

    ++db_idx;

    return 0;
}


