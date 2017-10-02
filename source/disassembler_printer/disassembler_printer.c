/* disassembler_printer.c
 * by kimht
 */

#include "./disassembler_printer.h"

///////////////////////////////////////////////////////////////////////////////
/// macro functions
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// function declarations
///////////////////////////////////////////////////////////////////////////////
static void GetInstructionStringRsRtRd(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRsRtImm(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRsRtOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringBaseOpOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringIdx(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringBaseRtOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringBaseFtOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringBaseHintOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRsOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRsImm(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRtRdSa(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRsRt(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringFmtFsFd(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRsRdHint(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRsCcRd(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringFmtFtFsFd(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRsHint(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringCode20(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringFmtRtFsFd(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRsRtCode10(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringCcOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRtFs(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRtRdSel(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringNoneOp(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringFmtFtFsCcCond(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRtImm(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringCofun(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRd(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringRs(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringStype(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);
static void GetInstructionStringImp(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr);

///////////////////////////////////////////////////////////////////////////////
/// variables
///////////////////////////////////////////////////////////////////////////////
static char *mnem_str[] = {
    "addu", "add", "and", "clo", "clz", 
    "movn", "movz", "mul", "nor", "or", 
    "sltu", "srlv", "sub", "subu", "xor", 
    "slt", "addi", "addiu", "andi", "beq", 
    "beql", "bne", "bnel", "cache", "j", 
    "jal", "lb", "lbu", "ldc1", "ldc2", 
    "lh", "lhu", "ll", "lw", "lwc1", 
    "lwc2", "lwl", "lwr", "ori", "pref", 
    "sb", "sc", "sdc1", "sdc2", "sh", 
    "slti", "sltiu", "sw", "swc1", "swc2", 
    "swl", "swr", "xori", "b", "bal", 
    "bgez", "bgezal", "bgezall", "bgezl", "bgtz", 
    "bgtzl", "blez", "blezl", "bltz", "bltzal", 
    "bltzall", "bltzl", "teqi", "tgei", "tgeiu", 
    "tlti", "tltiu", "tnei", "sll", "sra", 
    "srav", "srl", "div", "divu", "madd", 
    "maddu", "msub", "msubu", "mult", "multu", 
    "abs_fp", "ceil_fp", "cvtd_fp", "cvts_fp", "cvtw_fp", 
    "floor_fp", "jalr", "mov_fp", "neg_fp", "round_fp", 
    "sqrt_fp", "trunc_fp", "movf", "movf_fp", "movt", 
    "movt_fp", "jr", "add_fp", "break", "div_fp", 
    "movn_fp", "movz_fp", "mul_fp", "sdbbp", "sub_fp", 
    "syscall", "teq", "tge", "tgeu", "tlt", 
    "tltu", "tne", "bc1f", "bc1fl", "bc1t", 
    "bc1tl", "bc2f", "bc2fl", "bc2t", "bc2tl", 
    "cfc1", "cfc2", "ctc1", "ctc2", "mfc1", 
    "mtc1", "sllv", "mfc0", "mfc2", "mtc0", 
    "mtc2", "deret", "eret", "nop", "ssnop", 
    "tlbp", "tlbr", "tlbwi", "tlbwr", "cond", 
    "lui", "cop2", "mfhi", "mflo", "mthi", 
    "mtlo", "sync", "wait"
};

static char *gpr_str[] = {
    "zero", "at", "v0", "v1", "a0",
    "a1", "a2", "a3", "t0", "t1",
    "t2", "t3", "t4", "t5", "t6",
    "t7",  "s0", "s1", "s2", "s3",
    "s4", "s5", "s6", "s7", "t8",
    "t9", "k0", "k1", "gp", "sp",
    "fp", "ra"
};

static void (*GetInstructionStringCallTable[])(char *, int,
    struct operands_t *, unsigned int) = {
    &GetInstructionStringRsRtRd,  /* 0... */
    &GetInstructionStringRsRtRd,
    &GetInstructionStringRsRtRd,
    &GetInstructionStringRsRtRd,
    &GetInstructionStringRsRtRd,
    &GetInstructionStringRsRtRd,  /* 5... */
    &GetInstructionStringRsRtRd,
    &GetInstructionStringRsRtRd,
    &GetInstructionStringRsRtRd,
    &GetInstructionStringRsRtRd,
    &GetInstructionStringRsRtRd,  /* 10... */
    &GetInstructionStringRsRtRd,
    &GetInstructionStringRsRtRd,
    &GetInstructionStringRsRtRd,
    &GetInstructionStringRsRtRd,
    &GetInstructionStringRsRtRd,  /* 15... */
    &GetInstructionStringRsRtImm,
    &GetInstructionStringRsRtImm,
    &GetInstructionStringRsRtImm,
    &GetInstructionStringRsRtOffset,
    &GetInstructionStringRsRtOffset,  /* 20... */
    &GetInstructionStringRsRtOffset,
    &GetInstructionStringRsRtOffset,
    &GetInstructionStringBaseOpOffset,
    &GetInstructionStringIdx,
    &GetInstructionStringIdx,  /* 25... */
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringBaseFtOffset,
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringBaseRtOffset,  /* 30... */
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringBaseRtOffset,  /* 35... */
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringRsRtImm,
    &GetInstructionStringBaseHintOffset,
    &GetInstructionStringBaseFtOffset,  /* 40... */
    &GetInstructionStringBaseFtOffset,
    &GetInstructionStringBaseFtOffset,
    &GetInstructionStringBaseFtOffset,
    &GetInstructionStringBaseFtOffset,
    &GetInstructionStringRsRtImm,  /* 45... */
    &GetInstructionStringRsRtImm,
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringBaseRtOffset,  /* 50... */
    &GetInstructionStringBaseRtOffset,
    &GetInstructionStringRsRtImm,
    &GetInstructionStringOffset,
    &GetInstructionStringOffset,
    &GetInstructionStringRsOffset,  /* 55... */
    &GetInstructionStringRsOffset,
    &GetInstructionStringRsOffset,
    &GetInstructionStringRsOffset,
    &GetInstructionStringRsOffset,
    &GetInstructionStringRsOffset,  /* 60... */
    &GetInstructionStringRsOffset,
    &GetInstructionStringRsOffset,
    &GetInstructionStringRsOffset,
    &GetInstructionStringRsOffset,
    &GetInstructionStringRsOffset,  /* 65... */
    &GetInstructionStringRsOffset,
    &GetInstructionStringRsImm,
    &GetInstructionStringRsImm,
    &GetInstructionStringRsImm,
    &GetInstructionStringRsImm,  /* 70... */
    &GetInstructionStringRsImm,
    &GetInstructionStringRsImm,
    &GetInstructionStringRtRdSa,
    &GetInstructionStringRtRdSa,
    &GetInstructionStringRtRdSa,  /* 75... */
    &GetInstructionStringRtRdSa,
    &GetInstructionStringRsRt,
    &GetInstructionStringRsRt,
    &GetInstructionStringRsRt,
    &GetInstructionStringRsRt,  /* 80... */
    &GetInstructionStringRsRt,
    &GetInstructionStringRsRt,
    &GetInstructionStringRsRt,
    &GetInstructionStringRsRt,
    &GetInstructionStringFmtFsFd,  /* 85... */
    &GetInstructionStringFmtFsFd,
    &GetInstructionStringFmtFsFd,
    &GetInstructionStringFmtFsFd,
    &GetInstructionStringFmtFsFd,
    &GetInstructionStringFmtFsFd,  /* 90... */
    &GetInstructionStringRsRdHint,
    &GetInstructionStringFmtFsFd,
    &GetInstructionStringFmtFsFd,
    &GetInstructionStringFmtFsFd,
    &GetInstructionStringFmtFsFd,  /* 95... */
    &GetInstructionStringFmtFsFd,
    &GetInstructionStringRsCcRd,
    &GetInstructionStringRsCcRd,
    &GetInstructionStringRsCcRd,
    &GetInstructionStringRsCcRd,  /* 100... */
    &GetInstructionStringRsHint,
    &GetInstructionStringFmtFtFsFd,
    &GetInstructionStringCode20,
    &GetInstructionStringFmtFtFsFd,
    &GetInstructionStringFmtRtFsFd,  /* 105... */
    &GetInstructionStringFmtRtFsFd,
    &GetInstructionStringFmtFtFsFd,
    &GetInstructionStringCode20,
    &GetInstructionStringFmtFtFsFd,
    &GetInstructionStringCode20,  /* 110... */
    &GetInstructionStringRsRtCode10,
    &GetInstructionStringRsRtCode10,
    &GetInstructionStringRsRtCode10,
    &GetInstructionStringRsRtCode10,
    &GetInstructionStringRsRtCode10,  /* 115... */
    &GetInstructionStringRsRtCode10,
    &GetInstructionStringCcOffset,
    &GetInstructionStringCcOffset,
    &GetInstructionStringCcOffset,
    &GetInstructionStringCcOffset,  /* 120... */
    &GetInstructionStringCcOffset,
    &GetInstructionStringCcOffset,
    &GetInstructionStringCcOffset,
    &GetInstructionStringCcOffset,
    &GetInstructionStringRtFs,  /* 125... */
    &GetInstructionStringRtFs,
    &GetInstructionStringRtFs,
    &GetInstructionStringRtFs,
    &GetInstructionStringRtFs,
    &GetInstructionStringRtFs,  /* 130... */
    &GetInstructionStringRtRdSa,
    &GetInstructionStringRtRdSel,
    &GetInstructionStringRtRdSel,
    &GetInstructionStringRtRdSel,
    &GetInstructionStringRtRdSel,  /* 135... */
    &GetInstructionStringNoneOp,
    &GetInstructionStringNoneOp,
    &GetInstructionStringNoneOp,
    &GetInstructionStringNoneOp,
    &GetInstructionStringNoneOp,  /* 140... */
    &GetInstructionStringNoneOp,
    &GetInstructionStringNoneOp,
    &GetInstructionStringNoneOp,
    &GetInstructionStringFmtFtFsCcCond,
    &GetInstructionStringRtImm,  /* 145... */
    &GetInstructionStringCofun,
    &GetInstructionStringRd,
    &GetInstructionStringRd,
    &GetInstructionStringRs,
    &GetInstructionStringRs,  /* 150... */
    &GetInstructionStringStype,
    &GetInstructionStringImp
};

///////////////////////////////////////////////////////////////////////////////
/// function definitions
///////////////////////////////////////////////////////////////////////////////

/*
 * GetInstructionString - Gets string of instruction disassembled.
 *
 * @buf - Buffer to store the result string.
 * @mnem_id - The mnemonic id of the instrcution.
 * @operands - The operands of the instruction.
 * @addr - The address the instruction locating.
 * @return - 0 on success; -1 on failure.
 */
int GetInstructionString(char *buf, int mnem_id, struct operands_t *operands,
    unsigned int addr) {
    GetInstructionStringCallTable[mnem_id](buf, mnem_id, operands, addr);

    return 0;
}

static void GetInstructionStringRsRtRd(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s \t%s, %s, %s", addr, mnem_str[mnem_id],
        gpr_str[operands->rd], gpr_str[operands->rs], gpr_str[operands->rt]);
}

static void GetInstructionStringRsRtImm(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s \t%s, %s, 0x%x", addr, mnem_str[mnem_id],
        gpr_str[operands->rt], gpr_str[operands->rs], operands->imm);
}

static void GetInstructionStringRsRtOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s \t%s, %s, 0x%x", addr, mnem_str[mnem_id],
        gpr_str[operands->rs], gpr_str[operands->rt], operands->offset);
}

// required to be modified.
static void GetInstructionStringBaseOpOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

static void GetInstructionStringIdx(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s \t0x%x", addr, mnem_str[mnem_id],
        operands->idx*4);
}

static void GetInstructionStringBaseRtOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s \t%s, 0x%x(%s)", addr, mnem_str[mnem_id],
        gpr_str[operands->rt], operands->offset, gpr_str[operands->base]);
}

// required to be modified.
static void GetInstructionStringBaseFtOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringBaseHintOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

static void GetInstructionStringRsOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s \t0x%x", addr, mnem_str[mnem_id],
        addr + operands->offset);
}

static void GetInstructionStringRsImm(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s \t%s, 0x%x", addr, mnem_str[mnem_id],
        gpr_str[operands->rs], operands->imm);
}

static void GetInstructionStringRtRdSa(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s \t%s, %s, 0x%x", addr, mnem_str[mnem_id],
        gpr_str[operands->rd], gpr_str[operands->rt], operands->sa);
}

static void GetInstructionStringRsRt(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s \t%s, %s", addr, mnem_str[mnem_id],
        gpr_str[operands->rs], gpr_str[operands->rt]);
}

// required to be modified.
static void GetInstructionStringFmtFsFd(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringRsRdHint(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringRsCcRd(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringFmtFtFsFd(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringRsHint(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringCode20(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringFmtRtFsFd(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringRsRtCode10(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringCcOffset(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringRtFs(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringRtRdSel(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringNoneOp(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s", addr, mnem_str[mnem_id]);
}

// required to be modified.
static void GetInstructionStringFmtFtFsCcCond(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

static void GetInstructionStringRtImm(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s \t%s 0x%x", addr, mnem_str[mnem_id],
        gpr_str[operands->rt], operands->imm);
}

// required to be modified.
static void GetInstructionStringCofun(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

static void GetInstructionStringRd(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s \t%s", addr, mnem_str[mnem_id],
        gpr_str[operands->rd]);
}

static void GetInstructionStringRs(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "0x%08x    %s \t%s", addr, mnem_str[mnem_id],
        gpr_str[operands->rs]);
}

// required to be modified.
static void GetInstructionStringStype(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

// required to be modified.
static void GetInstructionStringImp(char *buf, int mnem_id,
    struct operands_t *operands, unsigned int addr) {
    sprintf(buf, "not implemented.\n");
}

