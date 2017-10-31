/* taint_checker.c
 * by kimht
 */
#include "./taint_checker.h"
#include "../rbtree/rbtree.h"
///////////////////////////////////////////////////////////////////////////////
/// variables
///////////////////////////////////////////////////////////////////////////////

/* rbtree */
struct rbtree tree;
struct rbnode sentinel;

/* tainting status */
struct pt_regs tc_regs;
struct pt_regs tc_regs_after;
struct pt_regs tc_tstat;
int tc_code;
int tc_mnem_id;
struct operands_t tc_op;
int tc_src;
int tc_dest;
int tc_lr;
int tc_size;
int tc_is_tainting;

char *tainted_str[] = {
    "UNTAINTED",
    "TAINTED"
};

///////////////////////////////////////////////////////////////////////////////
/// function declarations
///////////////////////////////////////////////////////////////////////////////
static int GetFlowOfInstruction(pid_t traced_pid);
static int SavePreviousTaintInfo();
static int SavePostTaintInfo(pid_t traced_pid);

///////////////////////////////////////////////////////////////////////////////
/// function definitions
///////////////////////////////////////////////////////////////////////////////

void TaintCheckerInit() {
    rbtree_init(&tree, &sentinel);

    memset(&tc_regs, 0x00, sizeof(struct pt_regs));
    memset(&tc_regs_after, 0x00, sizeof(struct pt_regs));
    memset(&tc_tstat, 0x00, sizeof(struct pt_regs));
    tc_code = 0;
    tc_mnem_id = -1;
    memset(&tc_op, 0x00, sizeof(struct operands_t));
    tc_src = SRC_NOP;
    tc_dest = DEST_NOP;
    tc_lr = NO_DIRECTION;
    tc_size = 4;
    tc_is_tainting = UNTAINTING;
}

/*
 * GetFlowOfInstruction - Gets flow of given instruction mnemonic id.
 *
 * @return - 0 on success; -1 on failure.
 */
int GetFlowOfInstruction(pid_t traced_pid) {
    int i;
    unsigned int val;
    struct rbnode *node;
    unsigned int target;

    tc_is_tainting = UNTAINTING;
    tc_lr = NO_DIRECTION;
    tc_size = 4;
    tc_src = SRC_NOP;
    tc_dest = DEST_NOP;
    tc_is_tainting = NOTHING;

    switch ( tc_mnem_id ) {
    case ID_ADD:
    case ID_ADDU:
    case ID_AND:
    case ID_MUL:
    case ID_NOR:
    case ID_OR:
    case ID_SRAV:
    case ID_MOVN:
    case ID_MOVZ:
    case ID_SLLV:
    case ID_SLT:
    case ID_SLTU:
    case ID_SRLV:
    case ID_SUB:
    case ID_SUBU:
    case ID_XOR:
        tc_src = SRC_RT | SRC_RS;
        tc_dest = DEST_RD;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ||
                IsTaintedGPR(&tc_tstat, tc_op.rs) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.regs[GetGPR(tc_op.rd)] = TSTAT_TAINTED;
        } else {
            if ( IsTaintedGPR(&tc_tstat, tc_op.rd) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.regs[GetGPR(tc_op.rd)] = TSTAT_UNTAINTED;
        }
        break;

    case ID_ADDI:
    case ID_ADDIU:
    case ID_ANDI:
    case ID_ORI:
    case ID_SLTI:
    case ID_SLTIU:
    case ID_XORI:
        tc_src = SRC_RS | SRC_IMM;
        tc_dest = DEST_RT;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rs) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_TAINTED;
        } else {
            if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_UNTAINTED;
        }
        break;

    case ID_B:
    case ID_BC1T:
    case ID_BC1F:
    case ID_BC2F:
    case ID_BC1TL:
    case ID_BC1FL:
    case ID_BC2TL:
    case ID_BC2FL:
    case ID_BC2T:
        tc_src = SRC_OFFSET | SRC_PC;
        tc_dest = DEST_PC;

        if ( IsTaintedPC(&tc_tstat) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.cp0_epc = TSTAT_TAINTED;
        } else {
            if ( IsTaintedPC(&tc_tstat) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.cp0_epc = TSTAT_UNTAINTED;
        }
        break;

    case ID_BGEZ:
    case ID_BGTZ:
    case ID_BLEZ:
    case ID_BLTZ:
    case ID_BGEZL:
    case ID_BGTZL:
    case ID_BLEZL:
    case ID_BLTZL:
        tc_src = SRC_OFFSET | SRC_RS | SRC_PC;
        tc_dest = DEST_PC;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rs) || IsTaintedPC(&tc_tstat) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.cp0_epc = TSTAT_TAINTED;
        } else {
            if ( IsTaintedPC(&tc_tstat) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.cp0_epc = TSTAT_UNTAINTED;
        }
        break;

    case ID_BAL:
    case ID_BGEZAL:
    case ID_BGEZALL:
    case ID_BLTZAL:
    case ID_BLTZALL:
        tc_src = SRC_OFFSET | SRC_RS | SRC_PC;
        tc_dest = DEST_PC | DEST_RA;

        if ( IsTaintedPC(&tc_tstat) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.regs[31] = TSTAT_TAINTED;
        } else {
            if ( IsTaintedGPR(&tc_tstat, 31) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.regs[31] = TSTAT_UNTAINTED;
        }

        if ( IsTaintedGPR(&tc_tstat, tc_op.rs) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.cp0_epc = TSTAT_TAINTED;
        } else {
            if ( IsTaintedPC(&tc_tstat) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.cp0_epc = TSTAT_UNTAINTED;
        }
        break;

    case ID_BEQ:
    case ID_BEQL:
    case ID_BNE:
    case ID_BNEL:
        tc_src = SRC_OFFSET | SRC_RS | SRC_RT | SRC_PC;
        tc_dest = DEST_PC;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rs) ||
                IsTaintedGPR(&tc_tstat, tc_op.rt) ||
                IsTaintedPC(&tc_tstat) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.cp0_epc = TSTAT_TAINTED;
        } else {
            if ( IsTaintedPC(&tc_tstat) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.cp0_epc = TSTAT_UNTAINTED;
        }
        break;

    case ID_J:
        tc_src = SRC_TARGET;
        tc_dest = DEST_PC;

        tc_is_tainting = UNTAINTING;
        if ( IsTaintedPC(&tc_tstat) ) {
            tc_is_tainting = UNTAINTING;
        }
        tc_tstat.cp0_epc = TSTAT_UNTAINTED;
        break;

    case ID_JAL:
        tc_src = SRC_TARGET | SRC_PC;
        tc_dest = DEST_PC | DEST_RA;

        if ( IsTaintedPC(&tc_tstat) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.regs[31] = TSTAT_TAINTED;
        } else {
            if ( IsTaintedGPR(&tc_tstat, 31) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.regs[31] = TSTAT_UNTAINTED;
        }
        if ( IsTaintedPC(&tc_tstat) ) {
            tc_is_tainting = UNTAINTING;
        }
        tc_tstat.cp0_epc = TSTAT_UNTAINTED;
        break;

    case ID_JR:
        tc_src = SRC_RS;
        tc_dest = DEST_PC;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rs) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.cp0_epc = TSTAT_TAINTED;
        } else {
            if ( IsTaintedPC(&tc_tstat) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.cp0_epc = TSTAT_UNTAINTED;
        }
        break;

    case ID_JALR:
        tc_src = SRC_RS | SRC_PC;
        tc_dest = DEST_PC | DEST_RA;

        if ( IsTaintedPC(&tc_tstat) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.regs[31] = TSTAT_TAINTED;
        } else {
            if ( IsTaintedGPR(&tc_tstat, 31) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.regs[31] = TSTAT_UNTAINTED;
        }
        if ( IsTaintedGPR(&tc_tstat, tc_op.rs) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.cp0_epc = TSTAT_TAINTED;
        } else {
            if ( IsTaintedPC(&tc_tstat) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.cp0_epc = TSTAT_UNTAINTED;
        }
        break;

    case ID_LL:
        tc_src = SRC_OFFSET | SRC_BASE;
        tc_dest = DEST_RT;


        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
            tc_is_tainting = UNTAINTING;
        } else {
            tc_is_tainting = NOTHING;
        }
        tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_UNTAINTED;

        if ( IsTaintedGPR(&tc_tstat, tc_op.base) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_TAINTED;
        }
        target = SignExtend16(GetOffset(tc_op.offset)) +
                 GetRegsGPR(&tc_regs, tc_op.base);
        for ( i = 0; i < 4; ++i ) {
            if ( rbtree_search(&tree, target + i) ) {
                tc_is_tainting = MEM_TAINTING;
                tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_TAINTED;
                break;
            }
        }
        break;

    case ID_LB:
    case ID_LBU:
    case ID_LDC2:
    case ID_LH:
    case ID_LHU:
    case ID_LW:
    case ID_LWC2:
    case ID_SC:
        tc_src = SRC_OFFSET | SRC_BASE;
        tc_dest = DEST_RT;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
            tc_is_tainting = UNTAINTING;
        } else {
            tc_is_tainting = NOTHING;
        }
        tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_UNTAINTED;

        if ( IsTaintedGPR(&tc_tstat, tc_op.base) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_TAINTED;
        }
        target = SignExtend16(GetOffset(tc_op.offset)) +
                 GetRegsGPR(&tc_regs, tc_op.base);
        printf("load from 0x%08x\n", target);
        for ( i = 0; i < 4; ++i ) {
            if ( rbtree_search(&tree, target + i) ) {
                tc_is_tainting = MEM_TAINTING;
                tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_TAINTED;
                break;
            }
        }
        break;

    case ID_LWL:
        tc_lr = LEFT;
        tc_size = 2;
        tc_src = SRC_OFFSET |SRC_BASE;
        tc_dest = DEST_RT;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
            tc_is_tainting = UNTAINTING;
        } else {
            tc_is_tainting = NOTHING;
        }
        tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_UNTAINTED;

        if ( IsTaintedGPR(&tc_tstat, tc_op.base) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_TAINTED;
        }

        target = SignExtend16(GetOffset(tc_op.offset)) +
                 GetRegsGPR(&tc_regs, tc_op.base);
        for ( i = 0; i < 2; ++i ) {
            if ( rbtree_search(&tree, target + i) ) {
                tc_is_tainting = MEM_TAINTING;
                tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_TAINTED;
                break;
            }
        }
        break;

    case ID_LWR:
        tc_lr = RIGHT;
        tc_size = 2;
        tc_src = SRC_OFFSET | SRC_BASE;
        tc_dest = DEST_RT;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
            tc_is_tainting = UNTAINTING;
        } else {
            tc_is_tainting = NOTHING;
        }
        tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_UNTAINTED;

        if ( IsTaintedGPR(&tc_tstat, tc_op.base) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_TAINTED;
        }

        target = SignExtend16(GetOffset(tc_op.offset)) +
                 GetRegsGPR(&tc_regs, tc_op.base);
        for ( i = 0; i < 2; ++i ) {
            if ( rbtree_search(&tree, target - i) ) {
                tc_is_tainting = MEM_TAINTING;
                tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_TAINTED;
                break;
            }
        }
        break;

    case ID_LUI:
        tc_src = SRC_IMM;
        tc_dest = DEST_RT;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
            tc_is_tainting = UNTAINTING;
        }
        tc_tstat.regs[GetGPR(tc_op.rt)] = TSTAT_UNTAINTED;
        break;

    case ID_SW:
        tc_size = 4;
        tc_src = SRC_RT;
        tc_dest = DEST_OFFSET | DEST_BASE;

        target = SignExtend16(GetOffset(tc_op.offset)) +
                 GetRegsGPR(&tc_regs, tc_op.base);
        printf("store to 0x%08x\n", target);
        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
            tc_is_tainting = MEM_TAINTING;
            for ( i = 0; i < 4; ++i ) {
                node = rbtree_search(&tree,target + i);
                val = GetRegsGPR(&tc_regs, tc_op.rt);
                if ( node ) {
                    node->data = (val >> (3 - i)) & 0xff;
                } else {
                    node = (struct rbnode *)malloc(sizeof(struct rbnode));
                    node->key = target + i;
                    node->data = (val >> (3 - i)) & 0xff;
                    rbtree_insert(&tree, node);
                }
            }
        } else {
            for ( i = 0; i < 4; ++i ) {
                node = rbtree_search(&tree,target + i);
                if ( node ) {
                    rbtree_delete(&tree, node);
                }
            }
        }
        break;

    case ID_SH:
        tc_size = 4;
        tc_src = SRC_RT;
        tc_dest = DEST_OFFSET | DEST_BASE;

        target = SignExtend16(GetOffset(tc_op.offset)) +
                 GetRegsGPR(&tc_regs, tc_op.base);

        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
            tc_is_tainting = MEM_TAINTING;
            val = SignExtend16(GetRegsGPR(&tc_regs, tc_op.rt));
            for ( i = 0; i < 4; ++i ) {
                node = rbtree_search(&tree,target + i);
                if ( node ) {
                    node->data = (val >> (3 - i)) & 0xff;
                } else {
                    node = (struct rbnode *)malloc(sizeof(struct rbnode));
                    node->key = target + i;
                    node->data = (val >> (3 - i)) & 0xff;
                    rbtree_insert(&tree, node);
                }
            }
        } else {
            for ( i = 0; i < 4; ++i ) {
                node = rbtree_search(&tree,target + i);
                if ( node ) {
                    rbtree_delete(&tree, node);
                }
            }
        }
        break;

    case ID_SB:
        tc_size = 4;
        tc_src = SRC_RT;
        tc_dest = DEST_OFFSET | DEST_BASE;
        target = SignExtend16(GetOffset(tc_op.offset)) +
                 GetRegsGPR(&tc_regs, tc_op.base);
        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
            tc_is_tainting = MEM_TAINTING;
            val = SignExtend8(GetRegsGPR(&tc_regs, tc_op.rt));
            for ( i = 0; i < 4; ++i ) {
                node = rbtree_search(&tree,target + i);
                if ( node ) {
                    node->data = (val >> (3 - i)) & 0xff;
                } else {
                    node = (struct rbnode *)malloc(sizeof(struct rbnode));
                    node->key = target + i;
                    node->data = (val >> (3 - i)) & 0xff;
                    rbtree_insert(&tree, node);
                }
            }
        } else {
            for ( i = 0; i < 4; ++i ) {
                node = rbtree_search(&tree,target + i);
                if ( node ) {
                    rbtree_delete(&tree, node);
                }
            }
        }
        break;

    case ID_SDC1:
        tc_size = 8;
        tc_src = SRC_RT;
        tc_dest = DEST_OFFSET | DEST_BASE;
        target = SignExtend16(GetOffset(tc_op.offset)) +
                 GetRegsGPR(&tc_regs, tc_op.base);
        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
            tc_is_tainting = MEM_TAINTING;
            val = SignExtend8(GetRegsGPR(&tc_regs, tc_op.rt));
            for ( i = 0; i < 4; ++i ) {
                printf("searchgi:::::::::::::::::; 0x%x\n", target + i);
                node = rbtree_search(&tree,target + i);
                if ( node ) {
                    node->data = (val >> (3 - i)) & 0xff;
                } else {
                    node = (struct rbnode *)malloc(sizeof(struct rbnode));
                    node->key = target + i;
                    node->data = (val >> (3 - i)) & 0xff;
                    rbtree_insert(&tree, node);
                }
            }
        } else {
            for ( i = 0; i < 4; ++i ) {
                printf("searchgi:::::::::::::::::; 0x%x\n", target + i);
                node = rbtree_search(&tree,target + i);
                if ( node ) {
                    rbtree_delete(&tree, node);
                }
            }
        }
        break;

    case ID_SWC2:
        tc_size = 4;
        tc_src = SRC_RT;
        tc_dest = DEST_OFFSET | DEST_BASE;
        target = SignExtend16(GetOffset(tc_op.offset)) +
                 GetRegsGPR(&tc_regs, tc_op.base);
        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
            tc_is_tainting = TAINTING;
            val = SignExtend8(GetRegsGPR(&tc_regs, tc_op.rt));
            for ( i = 0; i < 4; ++i ) {
                node = rbtree_search(&tree,target + i);
                if ( node ) {
                    node->data = (val >> (3 - i)) & 0xff;
                } else {
                    node = (struct rbnode *)malloc(sizeof(struct rbnode));
                    node->key = target + i;
                    node->data = (val >> (3 - i)) & 0xff;
                    rbtree_insert(&tree, node);
                }
            }
        } else {
            for ( i = 0; i < 4; ++i ) {
                node = rbtree_search(&tree,target + i);
                if ( node ) {
                    rbtree_delete(&tree, node);
                }
            }
        }
        break;

    case ID_SWL:
        tc_lr = LEFT;
        tc_size = 2;
        tc_src = SRC_RT;
        tc_dest = DEST_OFFSET | DEST_BASE;

        target = SignExtend16(GetOffset(tc_op.offset)) +
                 GetRegsGPR(&tc_regs, tc_op.base);

        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
            tc_is_tainting = MEM_TAINTING;
            val = GetRegsGPR(&tc_regs, tc_op.rt);

            for ( i = 0; i < 2; ++i ) {
                printf("searchgi:::::::::::::::::; 0x%x\n", target + i);
                node = rbtree_search(&tree, target + i);
                if ( node ) {
                    node->data = (val >> (3 - i)) & 0xff;
                } else {
                    node = (struct rbnode *)malloc(sizeof(struct rbnode));
                    node->key = target + i;
                    node->data = (val >> (3 - i)) & 0xff;
                    rbtree_insert(&tree, node);
                }
            }
        } else {
            for ( i = 0; i < 2; ++i ) {
                printf("searchgi:::::::::::::::::; 0x%x\n", target + i);
                node = rbtree_search(&tree, target + i);
                if ( node ) {
                    rbtree_delete(&tree, node);
                }
            }
        }
        break;

    case ID_SWR:
        tc_lr = RIGHT;
        tc_size = 2;
        tc_src = SRC_RT;
        tc_dest = DEST_OFFSET | DEST_BASE;

        target = SignExtend16(GetOffset(tc_op.offset)) +
                 GetRegsGPR(&tc_regs, tc_op.base);

        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ) {
            tc_is_tainting = MEM_TAINTING;
            val = GetRegsGPR(&tc_regs, tc_op.rt);

            for ( i = 0; i < 2; ++i ) {
                printf("searchgi:::::::::::::::::; 0x%x\n", target - i);
                node = rbtree_search(&tree, target - i);
                if ( node ) {
                    node->data = (val >> i) & 0xff;
                } else {
                    node = (struct rbnode *)malloc(sizeof(struct rbnode));
                    node->key = target + i;
                    node->data = (val >> i) & 0xff;
                    rbtree_insert(&tree, node);
                }
            }
        } else {
            for ( i = 0; i < 2; ++i ) {
                printf("searchgi:::::::::::::::::; 0x%x\n", target - i);
                node = rbtree_search(&tree, target - i);
                if ( node ) {
                    rbtree_delete(&tree, node);
                }
            }
        }
        break;

    case ID_DIV:
    case ID_DIVU:
    case ID_MULT:
    case ID_MULTU:
        tc_src = SRC_RT | SRC_RS;
        tc_dest = DEST_HI | DEST_LO;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ||
                IsTaintedGPR(&tc_tstat, tc_op.rs) ) {
            tc_tstat.lo = TSTAT_TAINTED;
            tc_tstat.hi = TSTAT_TAINTED;
        } else {
            if ( IsTaintedLO(&tc_tstat) || IsTaintedHI(&tc_tstat) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.lo = TSTAT_UNTAINTED;
            tc_tstat.hi = TSTAT_UNTAINTED;
        }
        break;

    case ID_MSUB:
    case ID_MADD:
    case ID_MSUBU:
    case ID_MADDU:
        tc_src = SRC_RT | SRC_RS | SRC_HI | SRC_LO;
        tc_dest = DEST_HI | DEST_LO;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ||
                IsTaintedGPR(&tc_tstat, tc_op.rs) ||
                IsTaintedLO(&tc_tstat) || IsTaintedHI(&tc_tstat) ) {
            tc_tstat.lo = TSTAT_TAINTED;
            tc_tstat.hi = TSTAT_TAINTED;
        } else {
            if ( IsTaintedLO(&tc_tstat) || IsTaintedHI(&tc_tstat) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.lo = TSTAT_UNTAINTED;
            tc_tstat.hi = TSTAT_UNTAINTED;
        }
        break;

    case ID_MFLO:
        tc_src = SRC_LO;
        tc_dest = DEST_RD;

        if ( IsTaintedLO(&tc_tstat) ) {
            tc_tstat.regs[GetGPR(tc_op.rd)] = TSTAT_TAINTED;
        } else {
            if ( IsTaintedGPR(&tc_tstat, tc_op.rd) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.regs[GetGPR(tc_op.rd)] = TSTAT_UNTAINTED;
        }
        break;

    case ID_MFHI:
        tc_src = SRC_HI;
        tc_dest = DEST_RD;

        if ( IsTaintedHI(&tc_tstat) ) {
            tc_tstat.regs[GetGPR(tc_op.rd)] = TSTAT_TAINTED;
        } else {
            if ( IsTaintedGPR(&tc_tstat, tc_op.rd) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.regs[GetGPR(tc_op.rd)] = TSTAT_UNTAINTED;
        }
        break;

    case ID_MTHI:
        tc_src = SRC_RS;
        tc_dest = DEST_HI;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rs) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.hi = TSTAT_TAINTED;
        } else {
            if ( IsTaintedHI(&tc_tstat) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.hi = TSTAT_UNTAINTED;
        }
        break;

    case ID_MTLO:
        tc_src = SRC_RS;
        tc_dest = DEST_LO;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rs) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.lo = TSTAT_TAINTED;
        } else {
            if ( IsTaintedLO(&tc_tstat) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.lo = TSTAT_UNTAINTED;
        }
        break;

    case ID_SLL:
    case ID_SRA:
    case ID_SRL:
        tc_src = SRC_RT | SRC_SA;
        tc_dest = DEST_RD;

        if ( IsTaintedGPR(&tc_tstat, tc_op.rt) ||
                IsTaintedGPR(&tc_tstat, tc_op.sa) ) {
            tc_is_tainting = TAINTING;
            tc_tstat.regs[GetGPR(tc_op.rd)] = TSTAT_TAINTED;
        } else {
            if ( IsTaintedGPR(&tc_tstat, tc_op.rd) ) {
                tc_is_tainting = UNTAINTING;
            }
            tc_tstat.regs[GetGPR(tc_op.rd)] = TSTAT_UNTAINTED;
        }
        break;
    
    case ID_SYSCALL:
        tc_src = SRC_SYSCALL;
        if ( tc_src & SRC_SYSCALL && GetRegsGPR(&tc_regs, 2) == 4003 ) {
            tc_is_tainting = SYS_READ;
        }
        break;

    default:
        tc_src = SRC_NOP;
        tc_dest = DEST_NOP;
        break;
    }

    return 0;
}

/*
 * TaintCheckerPreHandler - It handles something for taint checker before
 *                          single step: getting flow of instruction; saving
 *                          status before single step.
 *
 * @code - The currenct code.
 * @return - 0 on success; -1 on failure.
 */
int TaintCheckerPreHandler(pid_t traced_pid) {
    char buf[128];
    int pc;

    ptrace(PTRACE_GETREGS, traced_pid, 0, &tc_regs);
    pc = GetRegsPC(&tc_regs);
    tc_code = ptrace(PTRACE_PEEKTEXT, traced_pid, pc, 0);
    tc_mnem_id = FindCorrespondingMnemonic(tc_code);
    if ( tc_mnem_id != -1 ) {
        GetOperandFromCode(tc_code, tc_mnem_id, &tc_op);
        GetInstructionString(buf, tc_mnem_id, &tc_op, pc);
    }
    GetFlowOfInstruction(traced_pid);

    if ( tc_is_tainting == TAINTING ) {
        printf("\x1B[32;47m\e[1m");
    } else if ( tc_is_tainting == UNTAINTING ) {
        printf("\x1B[31;47m\e[1m");
    /* tc_is_tainting == NOTHING */
    } else if ( tc_is_tainting == SYS_READ ) {
        printf("\x1B[34;47m\e[1m");
    }  else if ( tc_is_tainting == MEM_TAINTING ) {
        printf("\x1B[35;47m\e[1m");
    } else {
        printf("\x1B[0;0m\e[0m");
    }
    printf(buf);
    printf("\x1B[0;0m\e[0m\n");
    return 0;
}

/*
 * SavePreviousTaintInfo - It saves taint info before single stepping.
 *
 * @return - 0 on success; -1 on failure.
 */
static int SavePreviousTaintInfo() {
    int target;

    if ( tc_src == SRC_NOP && tc_dest == DEST_NOP ) {
        return 0;
    }
    if ( tc_src == SRC_SYSCALL ) {
        return 0;
    }
    /* These src/dest require special handling. */
    if ( tc_dest == (DEST_PC | DEST_RA) ) {
        /*
         * (rs, offset) try to taint (pc).
         * (pc) try to taint (ra).
         */
        if ( tc_src == (SRC_OFFSET | SRC_RS | SRC_PC) ) {
            target = ((GetOffset(tc_op.offset) & 0b1000000000000000) ?
                    GetOffset(tc_op.offset) | 0b11111111111111110000000000000000 :
                    GetOffset(tc_op.offset)) << 2;
            target += GetRegsPC(&tc_regs);

            printf("Flow %s(0x%08x) TARGET(0x%08x) --> pc(0x%08x)\n",
                    GetGPRStr(tc_op.rs), GetRegsGPR(&tc_regs, tc_op.rs),
                    target,
                    GetRegsPC(&tc_regs));

            printf("Flow pc(0x%08x) --> %s(0x%08x)\n",
                    GetRegsPC(&tc_regs),
                    GetGPRStr(31), GetRegsGPR(&tc_regs, 31));
        /*
         * (target) try to taint (pc)
         * (pc) try to taint (ra)
         */
        } else if ( tc_src == (SRC_TARGET | SRC_PC) ) {
            target = GetRegsPC(&tc_regs);
            target >>= 28;
            target <<= 28;
            target |= tc_op.idx << 2;

            printf("Flow TARGET(0x%08x) --> pc(0x%08x)\n",
                    target,
                    GetRegsPC(&tc_regs));
            printf("Flow pc(0x%08x) --> %s(0x%08x)\n",
                    GetRegsPC(&tc_regs),
                    GetGPRStr(31), GetRegsGPR(&tc_regs, 31));
        /*
         * (rs) try to taint (pc)
         * (pc) try to taint (ra)
         */
        } else if ( tc_src == (SRC_RS | SRC_PC) ) {
            printf("Flow %s(0x%08x) --> pc(0x%08x)\n",
                    GetGPRStr(tc_op.rs), GetRegsGPR(&tc_regs, tc_op.rs),
                    GetRegsPC(&tc_regs));
            printf("Flow pc(0x%08x) --> %s(0x%08x)\n",
                    GetRegsPC(&tc_regs),
                    GetGPRStr(31), GetRegsGPR(&tc_regs, tc_op.rs));
        }

    /* These src/dest also require special processing. */
    } else if ( tc_dest == (DEST_OFFSET | DEST_BASE) ) {

        /*
         * (rt) try to taint (*offset(base))
         */
        if ( tc_src == SRC_RT ) {

            // calculate target address(base + offset)
            target = GetRegsGPR(&tc_regs, tc_op.base) + GetOffset(tc_op.offset);

            printf("Flow %s(0x%08x) --> 0x%x(%s)(== *0x%08x)\n",
                    GetGPRStr(tc_op.rt), GetRegsGPR(&tc_regs, tc_op.rt),
                    GetOffset(tc_op.offset), GetGPRStr(tc_op.base),
                    target);
                    
            printf("SubInfo: tc_lr: %d, tc_size: %d\n" , tc_lr, tc_size);
        }

    /* These src/dest also require special processing. */
    } else if ( tc_dest == (DEST_HI | DEST_LO) ) {

        /*
         * (rt, rs) try to taint (hi, lo)
         */
        if ( tc_src == (SRC_RT | SRC_RS) ) {

            printf("Flow %s(0x%08x) %s(0x%08x) --> hi(0x%08x) lo(0x%08x)\n",
                    GetGPRStr(tc_op.rt), GetRegsGPR(&tc_regs, tc_op.rt),
                    GetGPRStr(tc_op.rs), GetRegsGPR(&tc_regs, tc_op.rs),
                    GetRegsHI(&tc_regs),
                    GetRegsLO(&tc_regs));

        /*
         * (rt, rs, hi, lo) try to taint (hi, lo)
         */
        } else if ( tc_src == (SRC_RT | SRC_RS | SRC_HI | SRC_LO) ) {

            printf("Flow %s(0x%08x) %s(0x%08x) hi(0x%08x) lo(0x%08x) --> hi(0x%08x) lo(0x%08x)",
                    GetGPRStr(tc_op.rt), GetRegsGPR(&tc_regs, tc_op.rt),
                    GetGPRStr(tc_op.rs), GetRegsGPR(&tc_regs, tc_op.rs),
                    GetRegsHI(&tc_regs),
                    GetRegsLO(&tc_regs),
                    GetRegsHI(&tc_regs),
                    GetRegsLO(&tc_regs));
        }
    }  else {

        printf("Flow");

        /* print sources */
        if ( tc_src & SRC_RT ) {
            printf(" %s(0x%08x)", GetGPRStr(tc_op.rt), GetRegsGPR(&tc_regs, tc_op.rt));
        }

        if ( tc_src & SRC_RS ) {
            printf(" %s(0x%08x)", GetGPRStr(tc_op.rs), GetRegsGPR(&tc_regs, tc_op.rs));
        }

        if ( tc_src & SRC_IMM ) {
            printf(" IMM(%hd)", GetImm(tc_op.imm));
        }

        if ( tc_src & SRC_OFFSET ) {
            printf(" OFFSET(0x%08x)", (int)GetOffset(tc_op.offset));
        }

        if ( tc_src & SRC_PC ) {
            printf(" pc(0x%08x)", GetRegsPC(&tc_regs));
        }

        if ( tc_src & SRC_TARGET ) {
            target = GetRegsPC(&tc_regs);
            target >>= 28;
            target <<= 28;
            target |= GetIdx(tc_op.idx) << 2;

            printf(" TARGET(0x%08x)", target);
        }

        if ( tc_src & SRC_BASE ) {
            printf(" %s(0x%08x)", GetGPRStr(tc_op.base), GetRegsGPR(&tc_regs, tc_op.base));
        }

        if ( tc_src & SRC_HI ) {
            printf(" hi(0x%08x)", GetRegsHI(&tc_regs));
        }

        if ( tc_src & SRC_LO ) {
            printf(" lo(0x%08x)", GetRegsLO(&tc_regs));
      }

        if ( tc_src & SRC_SA ) {
            printf(" %s(0x%08x)", GetGPRStr(tc_op.sa),
                    GetRegsGPR(&tc_regs, tc_op.sa));
        }

        printf(" -->");

        /* print destinations */
        if ( tc_dest & DEST_RD ) {
            printf(" %s(0x%08x)", GetGPRStr(tc_op.rd),
                    GetRegsGPR(&tc_regs, tc_op.rd));
            tc_tstat.regs[GetGPR(tc_op.rd)] = TSTAT_TAINTED;
        }
        if ( tc_dest & DEST_RT ) {
            printf(" %s(0x%08x)", GetGPRStr(tc_op.rt),
                    GetRegsGPR(&tc_regs, tc_op.rt));
        }
        if ( tc_dest & DEST_PC ) {
            printf(" pc(0x%08x)", GetRegsPC(&tc_regs));
            tc_tstat.cp0_epc = TSTAT_TAINTED;
        }

        if ( tc_dest & DEST_RA ) {
            printf(" %s(0x%08x)", GetGPRStr(31), GetRegsGPR(&tc_regs, 31));
            tc_tstat.regs[31] = TSTAT_TAINTED;
        }
        /*
         * If tc_dest is offset(base), tc_size bytes at offset(base) can be
         * tainted by tc_src.
         */
        if ( tc_dest == (DEST_OFFSET | DEST_BASE) ) {
            target = GetOffset(tc_op.offset) + GetRegsGPR(&tc_regs, tc_op.base);
            printf(" 0x%x(%s)(--> 0x%08x) is tainted.\n",
                    GetOffset(tc_op.offset), GetGPRStr(tc_op.base),
                    target);
        }

        if ( tc_dest & DEST_HI ) {
            printf(" hi(0x%08x)", GetRegsHI(&tc_regs));
        }

        if ( tc_dest & DEST_LO ) {
            printf(" lo(0x%08x)", GetRegsLO(&tc_regs));
        }
    }
    return 0;
}

/*
 * TaintCheckerPostHandler - It handles something for taint checker after
 *                           single step: getting flow of instruction; saving
 *                           status after single step.
 *
 * @code - The currenct code.
 * @return - 0 on success; -1 on failure.
 */
int TaintCheckerPostHandler(pid_t traced_pid) {
    int size;
    int i;
    unsigned int target;
    int val;
    struct rbnode *tmp_node;
    struct rbnode *new_node;

    ptrace(PTRACE_GETREGS, traced_pid, 0, &tc_regs_after);
    if ( tc_src & SRC_SYSCALL && GetRegsGPR(&tc_regs, 2) == 4003 ) {
        tc_tstat.regs[2] = TSTAT_TAINTED;
        tc_tstat.regs[4] = TSTAT_TAINTED;
        tc_tstat.regs[5] = TSTAT_TAINTED;
        tc_tstat.regs[6] = TSTAT_TAINTED;
        tc_tstat.regs[7] = TSTAT_TAINTED;
        size = GetRegsGPR(&tc_regs_after, 2);
        if ( size <= 0 ) {
            return 0;
        }
        printf("\x1B[34;47m\e[1m");
        printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
        printf("               read %d bytes              \n", size);
        printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
        printf("\x1B[0;0m");

        /* Iterates during size. */
        for ( i = 0; i < size; ++i ) {
            target = GetRegsGPR(&tc_regs, 5);
            val = (ptrace(PTRACE_PEEKTEXT, traced_pid, target + i, 0) >> 8 * 3);
            printf("0x%x, 0x%x, TAINTED\n", target + i, val);
            /*
             * If target byte doesn't exist, it creates new node and insert
             * to rbtree. Else, it just updates the value.
             */
            tmp_node = rbtree_search(&tree, target + i);
            if ( tmp_node == NULL ) {
                new_node = (struct rbnode *)malloc(sizeof(struct rbnode));
                if ( new_node == NULL ) {
                    HANDLE_ERROR("SavePostTaintInfo()::malloc() error", -1);
                }
                new_node->key = target + i;
                new_node->data = val;
                rbtree_insert(&tree, new_node);
            } else {
                tmp_node->data = val;
            }
        }
        rbtree_dump(&tree);
    }

    return 0;
}

/*
 * SavePreviousTaintInfo - It saves taint info before single stepping.
 *
 * @return - 0 on success; -1 on failure.
 */
static int SavePostTaintInfo(pid_t traced_pid) {
    int target;
    int size;
    int i;
    uint64_t data;
    unsigned char val;
    struct rbnode *tmp_node;
    struct rbnode *new_node;

    if ( tc_src & SRC_SYSCALL && GetRegsGPR(&tc_regs, 2) == 4003 ) {
        size = GetRegsGPR(&tc_regs_after, 2);
        if ( size <= 0 ) {
            return 0;
        }
        /* Iterates during size. */
        for ( i = 0; i < size; ++i ) {
            target = GetRegsGPR(&tc_regs, 5);
            val = (ptrace(PTRACE_PEEKTEXT, traced_pid, target + i, 0) >> 8 * 3);
            printf("0x%x, 0x%x, TAINTED\n", target + i, val);
            /*
             * If target byte doesn't exist, it creates new node and insert
             * to rbtree. Else, it just updates the value.
             */
            tmp_node = rbtree_search(&tree, target + i);
            if ( tmp_node == NULL ) {
                new_node = (struct rbnode *)malloc(sizeof(struct rbnode));
                if ( new_node == NULL ) {
                    HANDLE_ERROR("SavePostTaintInfo()::malloc() error", -1);
                }
                new_node->key = target + i;
                new_node->data = val;
                rbtree_insert(&tree, new_node);
            } else {
                tmp_node->data = val;
            }
        }
        return 0;
    }

     if ( tc_src == SRC_NOP && tc_dest == DEST_NOP ) {
        return 0;

    } else {
        printf("after singlestep: ");

        /* print destinations */
        if ( tc_dest & DEST_RD ) {
            printf(" %s(0x%08x)", GetGPRStr(tc_op.rd),
                    GetRegsGPR(&tc_regs_after, tc_op.rd));
        }
        if ( tc_dest & DEST_RT ) {
            printf(" %s(0x%08x)", GetGPRStr(tc_op.rt),
                    GetRegsGPR(&tc_regs_after, tc_op.rt));
        }
        if ( tc_dest & DEST_PC ) {
            printf(" pc(0x%08x)", GetRegsPC(&tc_regs_after));
        }
        if ( tc_dest & DEST_RA ) {
            printf(" %s(0x%08x)", GetGPRStr(31), GetRegsGPR(&tc_regs_after, 31));
        }
        if ( tc_dest == (DEST_OFFSET | DEST_BASE) ) {
            target = GetOffset(tc_op.offset) +
                     GetRegsGPR(&tc_regs_after, tc_op.base);
            data = ptrace(PTRACE_PEEKTEXT, traced_pid, GetRegsPC(&tc_regs_after), 0);

            printf(" 0x%x(%s)(== *0x%08x -> 0x%08x)",
                    GetOffset(tc_op.offset), GetGPRStr(tc_op.base),
                    target, (uint32_t)data);
        }

        if ( tc_dest & DEST_HI ) {
            printf(" hi(0x%08x)", GetRegsHI(&tc_regs_after));
        }

        if ( tc_dest & DEST_LO ) {
            printf(" lo(0x%08x)", GetRegsLO(&tc_regs_after));
        }

        printf(" could be changed.\n\n");
    }
    SaveTaintCheckerInfo();
    return 0;
}

