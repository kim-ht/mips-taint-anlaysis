/* taint_checker.h
 * by kimht
 */
#ifndef _TAINT_CHECKER_TAINT_CHECKER_H_
#define _TAINT_CHECKER_TAINT_CHECKER_H_

///////////////////////////////////////////////////////////////////////////////
/// includes
///////////////////////////////////////////////////////////////////////////////
#include "../base/base.h"
#include "../disassembler/disassembler.h"
#include "../disassembler_printer/disassembler_printer.h"
#include "../tracer/tracer.h"

///////////////////////////////////////////////////////////////////////////////
/// defines
///////////////////////////////////////////////////////////////////////////////
#define SRC_NOP         0b00000000000000000000000000000000
#define SRC_RT          0b00000000000000000000000000000001
#define SRC_RS          0b00000000000000000000000000000010
#define SRC_IMM         0b00000000000000000000000000000100
#define SRC_OFFSET      0b00000000000000000000000000001000
#define SRC_PC          0b00000000000000000000000000010000
#define SRC_TARGET      0b00000000000000000000000000100000
#define SRC_BASE        0b00000000000000000000000001000000
#define SRC_HI          0b00000000000000000000000010000000
#define SRC_LO          0b00000000000000000000000100000000
#define SRC_SA          0b00000000000000000000001000000000
#define SRC_SYSCALL     0b00000000000000000000010000000000

#define DEST_NOP        0b00000000000000000000000000000000
#define DEST_RD         0b00000000000000000000000000000001
#define DEST_RT         0b00000000000000000000000000000010
#define DEST_PC         0b00000000000000000000000000000100
#define DEST_RA         0b00000000000000000000000000001000
#define DEST_OFFSET     0b00000000000000000000000000010000
#define DEST_BASE       0b00000000000000000000000000100000
#define DEST_HI         0b00000000000000000000000001000000
#define DEST_LO         0b00000000000000000000000010000000

#define NO_DIRECTION    0
#define LEFT            1
#define RIGHT           2

#define TSTAT_UNTAINTED     0
#define TSTAT_TAINTED       1

#define UNTAINTING      0
#define TAINTING        1
#define NOTHING         2
#define SYS_READ        3
#define MEM_TAINTING    4

///////////////////////////////////////////////////////////////////////////////
/// variables
///////////////////////////////////////////////////////////////////////////////
extern struct rbtree tree;
extern struct rbnode sentinel;

extern struct pt_regs tc_regs;
extern struct pt_regs tc_regs_after;
extern struct pt_regs tc_tstat;
extern int tc_code;
extern int tc_mnem_id;
extern struct operands_t tc_op;
extern int tc_src;
extern int tc_dest;
extern int tc_lr;
extern int tc_size;
extern int tc_is_tainting;

///////////////////////////////////////////////////////////////////////////////
/// function prototypes
///////////////////////////////////////////////////////////////////////////////
void TaintCheckerInit();
int TaintCheckerPreHandler(pid_t traced_pid);
int TaintCheckerPostHandler(pid_t traced_pid);

#endif

