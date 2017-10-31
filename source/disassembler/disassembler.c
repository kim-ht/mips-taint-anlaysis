/* disassembler.c
 * by kimht
 */

///////////////////////////////////////////////////////////////////////////////
/// includes
///////////////////////////////////////////////////////////////////////////////
#include "./disassembler.h"

///////////////////////////////////////////////////////////////////////////////
/// macro functions
///////////////////////////////////////////////////////////////////////////////

/*
 * FindCorrespondingMnemonicInMask0 - Its find corresponding mnemonic from
 *                                    mask0.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask0(code) {  \
    switch ( code & 0b11111100000000000000011111111111 ) {  \
    case MASK_ADDU:  \
        return ID_ADDU;  \
    case MASK_ADD:  \
        return ID_ADD;  \
    case MASK_AND:  \
        return ID_AND;  \
    case MASK_CLO:  \
        return ID_CLO;  \
    case MASK_CLZ:  \
        return ID_CLZ;  \
    case MASK_MOVN:  \
        return ID_MOVN;  \
    case MASK_MOVZ:  \
        return ID_MOVZ;  \
    case MASK_MUL:  \
        return ID_MUL;  \
    case MASK_NOR:  \
        return ID_NOR;  \
    case MASK_OR:  \
        return ID_OR;  \
    case MASK_SLTU:  \
        return ID_SLTU;  \
    case MASK_SRLV:  \
        return ID_SRLV;  \
    case MASK_SUB:  \
        return ID_SUB;  \
    case MASK_SUBU:  \
        return ID_SUBU;  \
    case MASK_XOR:  \
        return ID_XOR;  \
    case MASK_SLT:  \
        return ID_SLT;  \
    case MASK_SLLV:  \
        return ID_SLLV;  \
    case MASK_SRAV:  \
        return ID_SRAV;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask1 - Its find corresponding mnemonic from
 *                                    mask1.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask1(code) {  \
    switch ( code & 0b11111100000000000000000000000000 ) {  \
    case MASK_ADDI:  \
        return ID_ADDI;  \
    case MASK_ADDIU:  \
        return ID_ADDIU;  \
    case MASK_ANDI:  \
        return ID_AND;  \
    case MASK_BEQ:  \
        return ID_BEQ;  \
    case MASK_BEQL:  \
        return ID_BEQL;  \
    case MASK_BNE:  \
        return ID_BNE;  \
    case MASK_BNEL:  \
        return ID_BNEL;  \
    case MASK_CACHE:  \
        return ID_CACHE;  \
    case MASK_J:  \
        return ID_J;  \
    case MASK_JAL:  \
        return ID_JAL;  \
    case MASK_LB:  \
        return ID_LB;  \
    case MASK_LBU:  \
        return ID_LBU;  \
    case MASK_LDC1:  \
        return ID_LDC1;  \
    case MASK_LDC2:  \
        return ID_LDC2;  \
    case MASK_LH:  \
        return ID_LH;  \
    case MASK_LHU:  \
        return ID_LHU;  \
    case MASK_LL:  \
        return ID_LL;  \
    case MASK_LW:  \
        return ID_LW;  \
    case MASK_LWC1:  \
        return ID_LWC1;  \
    case MASK_LWC2:  \
        return ID_LWC2;  \
    case MASK_LWL:  \
        return ID_LWL;  \
    case MASK_LWR:  \
        return ID_LWR;  \
    case MASK_ORI:  \
        return ID_ORI;  \
    case MASK_PREF:  \
        return ID_PREF;  \
    case MASK_SB:  \
        return ID_SB;  \
    case MASK_SC:  \
        return ID_SC;  \
    case MASK_SDC1:  \
        return ID_SDC1;  \
    case MASK_SDC2:  \
        return ID_SDC2;  \
    case MASK_SH:  \
        return ID_SH;  \
    case MASK_SLTI:  \
        return ID_SLTI;  \
    case MASK_SLTIU:  \
        return ID_SLTIU;  \
    case MASK_SW:  \
        return ID_SW;  \
    case MASK_SWC1:  \
        return ID_SWC1;  \
    case MASK_SWC2:  \
        return ID_SWC2;  \
    case MASK_SWL:  \
        return ID_SWL;  \
    case MASK_SWR:  \
        return ID_SWR;  \
    case MASK_XORI:  \
        return ID_XORI;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask2 - Its find corresponding mnemonic from
 *                                    mask2.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask2(code) {  \
    switch ( code & 0b11111111111111110000000000000000 ) {  \
    case MASK_B:  \
        return ID_B;  \
    case MASK_BAL:  \
        return ID_BAL;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask3 - Its find corresponding mnemonic from
 *                                    mask3.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask3(code) {  \
    switch ( code & 0b11111100000111110000000000000000 ) {  \
    case MASK_BGEZ:  \
        return ID_BGEZ;  \
    case MASK_BGEZAL:  \
        return ID_BGEZAL;  \
    case MASK_BGEZALL:  \
        return ID_BGEZALL;  \
    case MASK_BGEZL:  \
        return ID_BGEZL;  \
    case MASK_BGTZ:  \
        return ID_BGTZ;  \
    case MASK_BGTZL:  \
        return ID_BGTZL;  \
    case MASK_BLEZ:  \
        return ID_BLEZ;  \
    case MASK_BLEZL:  \
        return ID_BLEZL;  \
    case MASK_BLTZ:  \
        return ID_BLTZ;  \
    case MASK_BLTZAL:  \
        return ID_BLTZAL;  \
    case MASK_BLTZALL:  \
        return ID_BLTZALL;  \
    case MASK_BLTZL:  \
        return ID_BLTZL;  \
    case MASK_TEQI:  \
        return ID_TEQI;  \
    case MASK_TGEI:  \
        return ID_TGEI;  \
    case MASK_TGEIU:  \
        return ID_TGEIU;  \
    case MASK_TLTI:  \
        return ID_TLTI;  \
    case MASK_TLTIU:  \
        return ID_TLTIU;  \
    case MASK_TNEI:  \
        return ID_TNEI;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask4 - Its find corresponding mnemonic from
 *                                    mask4.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask4(code) {  \
    switch ( code & 0b11111111111000000000000000111111 ) {  \
    case MASK_SLL:  \
        return ID_SLL;  \
    case MASK_SRA:  \
        return ID_SRA;  \
    case MASK_SRL:  \
        return ID_SRL;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask5 - Its find corresponding mnemonic from
 *                                    mask5.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask5(code) {  \
    switch ( code & 0b11111100000000001111111111111111 ) {  \
    case MASK_DIV:  \
        return ID_DIV;  \
    case MASK_DIVU:  \
        return ID_DIVU;  \
    case MASK_MADD:  \
        return ID_MADD;  \
    case MASK_MADDU:  \
        return ID_MADDU;  \
    case MASK_MSUB:  \
        return ID_MSUB;  \
    case MASK_MSUBU:  \
        return ID_MSUBU;  \
    case MASK_MULT:  \
        return ID_MULT;  \
    case MASK_MULTU:  \
        return ID_MULTU;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask6 - Its find corresponding mnemonic from
 *                                     mask6.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask6(code) {  \
    switch ( code & 0b11111100000111110000000000111111 ) {  \
    case MASK_ABS_FP:  \
        return ID_ABS_FP;  \
    case MASK_CEIL_FP:  \
        return ID_CEIL_FP;  \
    case MASK_CVTD_FP:  \
        return ID_CVTD_FP;  \
    case MASK_CVTS_FP:  \
        return ID_CVTS_FP;  \
    case MASK_CVTW_FP:  \
        return ID_CVTW_FP;  \
    case MASK_FLOOR_FP:  \
        return ID_FLOOR_FP;  \
    case MASK_JALR:  \
        return ID_JALR;  \
    case MASK_MOV_FP:  \
        return ID_MOV_FP;  \
    case MASK_NEG_FP:  \
        return ID_NEG_FP;  \
    case MASK_ROUND_FP:  \
        return ID_ROUND_FP;  \
    case MASK_SQRT_FP:  \
        return ID_SQRT_FP;  \
    case MASK_TRUNC_FP:  \
        return ID_TRUNC_FP;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask7 - Its find corresponding mnemonic from
 *                                    mask7.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask7(code) {  \
    switch ( code & 0b11111100000000110000011111111111 ) {  \
    case MASK_MOVF:  \
        return ID_MOVF;  \
    case MASK_MOVF_FP:  \
        return ID_MOVF_FP;  \
    case MASK_MOVT:  \
        return ID_MOVT;  \
    case MASK_MOVT_FP:  \
        return ID_MOVT_FP;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask8 - Its find corresponding mnemonic from
 *                                    mask8.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask8(code) {  \
    switch ( code & 0b11111100000111111111100000111111 ) {  \
    case MASK_JR:  \
        return ID_JR;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask9 - Its find corresponding mnemonic from
 *                                    mask9.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask9(code) {  \
    switch ( code & 0b11111100000000000000000000111111 ) {  \
    case MASK_ADD_FP:  \
        return ID_ADD_FP;  \
    case MASK_BREAK:  \
        return ID_BREAK;  \
    case MASK_DIV_FP:  \
        return ID_DIV_FP;  \
    case MASK_MOVN_FP:  \
        return ID_MOVN_FP;  \
    case MASK_MOVZ_FP:  \
        return ID_MOVZ_FP;  \
    case MASK_MUL_FP:  \
        return ID_MUL_FP;  \
    case MASK_SDBBP:  \
        return ID_SDBBP;  \
    case MASK_SUB_FP:  \
        return ID_SUB_FP;  \
    case MASK_SYSCALL:  \
        return ID_SYSCALL;  \
    case MASK_TEQ:  \
        return ID_TEQ;  \
    case MASK_TGE:  \
        return ID_TGE;  \
    case MASK_TGEU:  \
        return ID_TGEU;  \
    case MASK_TLT:  \
        return ID_TLT;  \
    case MASK_TLTU:  \
        return ID_TLTU;  \
    case MASK_TNE:  \
        return ID_TNE;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask10 - Its find corresponding mnemonic from
 *                                     mask10.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask10(code) {  \
    switch ( code & 0b11111111111000110000000000000000 ) {  \
    case MASK_BC1F:  \
        return ID_BC1F;  \
    case MASK_BC1FL:  \
        return ID_BC1FL;  \
    case MASK_BC1T:  \
        return ID_BC1T;  \
    case MASK_BC1TL:  \
        return ID_BC1TL;  \
    case MASK_BC2F:  \
        return ID_BC2F;  \
    case MASK_BC2FL:  \
        return ID_BC2FL;  \
    case MASK_BC2T:  \
        return ID_BC2T;  \
    case MASK_BC2TL:  \
        return ID_BC2TL;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask11 - Its find corresponding mnemonic from
 *                                     mask11.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask11(code) {  \
    switch ( code & 0b11111111111000000000011111111111 ) {  \
    case MASK_CFC1:  \
        return ID_CFC1;  \
    case MASK_CFC2:  \
        return ID_CFC2;  \
    case MASK_CTC1:  \
        return ID_CTC1;  \
    case MASK_CTC2:  \
        return ID_CTC2;  \
    case MASK_MFC1:  \
        return ID_MFC1;  \
    case MASK_MTC1:  \
        return ID_MTC1;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask12 - Its find corresponding mnemonic from
 *                                     mask12.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask12(code) {  \
    switch ( code & 0b11111111111000000000011111111000 ) {  \
    case MASK_MFC0:  \
        return ID_MFC0;  \
    case MASK_MFC2:  \
        return ID_MFC2;  \
    case MASK_MTC0:  \
        return ID_MTC0;  \
    case MASK_MTC2:  \
        return ID_MTC2;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask13 - Its find corresponding mnemonic from
 *                                     mask13.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask13(code) {  \
    switch ( code & 0b11111111111111111111111111111111 ) {  \
    case MASK_DERET:  \
        return ID_DERET;  \
    case MASK_ERET:  \
        return ID_ERET;  \
    case MASK_NOP:  \
        return ID_NOP;  \
    case MASK_SSNOP:  \
        return ID_SSNOP;  \
    case MASK_TLBP:  \
        return ID_TLBP;  \
    case MASK_TLBR:  \
        return ID_TLBR;  \
    case MASK_TLBWI:  \
        return ID_TLBWI;  \
    case MASK_TLBWR:  \
        return ID_TLBWR;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask14 - Its find corresponding mnemonic from
 *                                     mask14.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask14(code) {  \
    switch ( code & 0b11111100000000000000000011110000 ) {  \
    case MASK_COND:  \
        return ID_COND;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask15 - Its find corresponding mnemonic from
 *                                     mask15.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask15(code) {  \
    switch ( code & 0b11111111111000000000000000000000 ) {  \
    case MASK_LUI:  \
        return ID_LUI;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask16 - Its find corresponding mnemonic from
 *                                     mask16.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask16(code) {  \
    switch ( code & 0b11111110000000000000000000000000 ) {  \
    case MASK_COP2:  \
        return ID_COP2;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask17 - Its find corresponding mnemonic from
 *                                     mask17.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask17(code) {  \
    switch ( code & 0b11111111111111110000011111111111 ) {  \
    case MASK_MFHI:  \
        return ID_MFHI;  \
    case MASK_MFLO:  \
        return ID_MFLO;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask18 - Its find corresponding mnemonic from
 *                                     mask18.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask18(code) {  \
    switch ( code & 0b11111100000111111111111111111111 ) {  \
    case MASK_MTHI:  \
        return ID_MTHI;  \
    case MASK_MTLO:  \
        return ID_MTLO;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask19 - Its find corresponding mnemonic from
 *                                     mask19.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask19(code) {  \
    switch ( code & 0b11111111111111111111100000111111 ) {  \
    case MASK_SYNC:  \
        return ID_SYNC;  \
    }  \
}

/*
 * FindCorrespondingMnemonicInMask20 - Its find corresponding mnemonic from
 *                                     mask20.
 *
 * @code - Machine code to find mnemonic.
 * @return - It returns mnemonic identifier.
 */
#define FindCorrespondingMnemonicInMask20(code) {  \
    switch ( code & 0b11111110000000000000000000111111 ) {  \
    case MASK_WAIT:  \
        return ID_WAIT;  \
    default:  \
        return -1;  \
    }  \
}

///////////////////////////////////////////////////////////////////////////////
/// function declarations
///////////////////////////////////////////////////////////////////////////////
static void ParseRsRtRd(int code, struct operands_t * operands);
static void ParseRsRtImm(int code, struct operands_t * operands);
static void ParseRsRtOffset(int code, struct operands_t * operands);
static void ParseBaseOpOffset(int code, struct operands_t * operands);
static void ParseIdx(int code, struct operands_t * operands);
static void ParseBaseRtOffset(int code, struct operands_t * operands);
static void ParseBaseFtOffset(int code, struct operands_t * operands);
static void ParseBaseHintOffset(int code, struct operands_t * operands);
static void ParseOffset(int code, struct operands_t * operands);
static void ParseRsOffset(int code, struct operands_t * operands);
static void ParseRsImm(int code, struct operands_t * operands);
static void ParseRtRdSa(int code, struct operands_t * operands);
static void ParseRsRt(int code, struct operands_t * operands);
static void ParseFmtFsFd(int code, struct operands_t * operands);
static void ParseRsRdHint(int code, struct operands_t * operands);
static void ParseRsCcRd(int code, struct operands_t * operands);
static void ParseRsHint(int code, struct operands_t * operands);
static void ParseFmtFtFsFd(int code, struct operands_t * operands);
static void ParseCode20(int code, struct operands_t * operands);
static void ParseFmtRtFsFd(int code, struct operands_t * operands);
static void ParseRsRtCode10(int code, struct operands_t * operands);
static void ParseCcOffset(int code, struct operands_t * operands);
static void ParseRtFs(int code, struct operands_t * operands);
static void ParseRtRdSel(int code, struct operands_t * operands);
static void ParseFmtFtFsCcCond(int code, struct operands_t * operands);
static void ParseRtImm(int code, struct operands_t * operands);
static void ParseCofun(int code, struct operands_t * operands);
static void ParseRd(int code, struct operands_t * operands);
static void ParseRs(int code, struct operands_t * operands);
static void ParseStype(int code, struct operands_t * operands);
static void ParseImp(int code, struct operands_t * operands);

///////////////////////////////////////////////////////////////////////////////
/// variables
///////////////////////////////////////////////////////////////////////////////

/*
 * Call table for parsing operands from machine code.
 */
static void (*GetOperandFromCodeTable[])(int, struct operands_t *) = {
    &ParseRsRtRd,  /* 0... */
    &ParseRsRtRd,
    &ParseRsRtRd,
    &ParseRsRtRd,
    &ParseRsRtRd,
    &ParseRsRtRd,  /* 5... */
    &ParseRsRtRd,
    &ParseRsRtRd,
    &ParseRsRtRd,
    &ParseRsRtRd,
    &ParseRsRtRd,  /* 10... */
    &ParseRsRtRd,
    &ParseRsRtRd,
    &ParseRsRtRd,
    &ParseRsRtRd,
    &ParseRsRtRd,  /* 15... */
    &ParseRsRtImm,
    &ParseRsRtImm,
    &ParseRsRtImm,
    &ParseRsRtOffset,
    &ParseRsRtOffset,  /* 20... */
    &ParseRsRtOffset,
    &ParseRsRtOffset,
    &ParseBaseOpOffset,
    &ParseIdx,
    &ParseIdx,  /* 25... */
    &ParseBaseRtOffset,
    &ParseBaseRtOffset,
    &ParseBaseFtOffset,
    &ParseBaseRtOffset,
    &ParseBaseRtOffset,  /* 30... */
    &ParseBaseRtOffset,
    &ParseBaseRtOffset,
    &ParseBaseRtOffset,
    &ParseBaseRtOffset,
    &ParseBaseRtOffset,  /* 35... */
    &ParseBaseRtOffset,
    &ParseBaseRtOffset,
    &ParseRsRtImm,
    &ParseBaseHintOffset,
    &ParseBaseRtOffset,  /* 40... */
    &ParseBaseRtOffset,
    &ParseBaseFtOffset,
    &ParseBaseFtOffset,
    &ParseBaseRtOffset,
    &ParseRsRtImm,  /* 45... */
    &ParseRsRtImm,
    &ParseBaseRtOffset,
    &ParseBaseRtOffset,
    &ParseBaseRtOffset,
    &ParseBaseRtOffset,  /* 50... */
    &ParseBaseRtOffset,
    &ParseRsRtImm,
    &ParseOffset,
    &ParseOffset,
    &ParseRsOffset,  /* 55... */
    &ParseRsOffset,
    &ParseRsOffset,
    &ParseRsOffset,
    &ParseRsOffset,
    &ParseRsOffset,  /* 60... */
    &ParseRsOffset,
    &ParseRsOffset,
    &ParseRsOffset,
    &ParseRsOffset,
    &ParseRsOffset,  /* 65... */
    &ParseRsOffset,
    &ParseRsImm,
    &ParseRsImm,
    &ParseRsImm,
    &ParseRsImm,  /* 70... */
    &ParseRsImm,
    &ParseRsImm,
    &ParseRtRdSa,
    &ParseRtRdSa,
    &ParseRtRdSa,  /* 75... */
    &ParseRtRdSa,
    &ParseRsRt,
    &ParseRsRt,
    &ParseRsRt,
    &ParseRsRt,  /* 80... */
    &ParseRsRt,
    &ParseRsRt,
    &ParseRsRt,
    &ParseRsRt,
    &ParseFmtFsFd,  /* 85... */
    &ParseFmtFsFd,
    &ParseFmtFsFd,
    &ParseFmtFsFd,
    &ParseFmtFsFd,
    &ParseFmtFsFd,  /* 90... */
    &ParseRsRdHint,
    &ParseFmtFsFd,
    &ParseFmtFsFd,
    &ParseFmtFsFd,
    &ParseFmtFsFd,  /* 95... */
    &ParseFmtFsFd,
    &ParseRsCcRd,
    &ParseRsCcRd,
    &ParseRsCcRd,
    &ParseRsCcRd,  /* 100... */
    &ParseRsHint,
    &ParseFmtFtFsFd,
    &ParseCode20,
    &ParseFmtFtFsFd,
    &ParseFmtRtFsFd,  /* 105... */
    &ParseFmtRtFsFd,
    &ParseFmtFtFsFd,
    &ParseCode20,
    &ParseFmtFtFsFd,
    &ParseCode20,  /* 110... */
    &ParseRsRtCode10,
    &ParseRsRtCode10,
    &ParseRsRtCode10,
    &ParseRsRtCode10,
    &ParseRsRtCode10,  /* 115... */
    &ParseRsRtCode10,
    &ParseCcOffset,
    &ParseCcOffset,
    &ParseCcOffset,
    &ParseCcOffset,  /* 120... */
    &ParseCcOffset,
    &ParseCcOffset,
    &ParseCcOffset,
    &ParseCcOffset,
    &ParseRtFs,  /* 125... */
    &ParseRtFs,
    &ParseRtFs,
    &ParseRtFs,
    &ParseRtFs,
    &ParseRtFs,  /* 130... */
    &ParseRsRtRd,
    &ParseRtRdSel,
    &ParseRtRdSel,
    &ParseRtRdSel,
    &ParseRtRdSel,  /* 135... */
    0,
    0,
    0,
    0,
    0,  /* 140... */
    0,
    0,
    0,
    &ParseFmtFtFsCcCond,
    &ParseRtImm,  /* 145... */
    &ParseCofun,
    &ParseRd,
    &ParseRd,
    &ParseRs,
    &ParseRs,  /* 150... */
    &ParseStype,
    &ParseImp
};

///////////////////////////////////////////////////////////////////////////////
/// function definitions
///////////////////////////////////////////////////////////////////////////////

/*
 * FindCorrespondingMnemonic - Finds mnemonic corresponding to given code.
 *
 * @code - Code to get mnemonic.
 * @return - ID_MNEMONIC value of the found mnemonic on success; -1 on failure.
 */
int FindCorrespondingMnemonic(int code) {
    FindCorrespondingMnemonicInMask0(code);
    FindCorrespondingMnemonicInMask1(code);
    FindCorrespondingMnemonicInMask2(code);
    FindCorrespondingMnemonicInMask3(code);
    FindCorrespondingMnemonicInMask4(code);
    FindCorrespondingMnemonicInMask5(code);
    FindCorrespondingMnemonicInMask6(code);
    FindCorrespondingMnemonicInMask7(code);
    FindCorrespondingMnemonicInMask8(code);
    FindCorrespondingMnemonicInMask9(code);
    FindCorrespondingMnemonicInMask10(code);
    FindCorrespondingMnemonicInMask11(code);
    FindCorrespondingMnemonicInMask12(code);
    FindCorrespondingMnemonicInMask13(code);
    FindCorrespondingMnemonicInMask14(code);
    FindCorrespondingMnemonicInMask15(code);
    FindCorrespondingMnemonicInMask16(code);
    FindCorrespondingMnemonicInMask17(code);
    FindCorrespondingMnemonicInMask18(code);
    FindCorrespondingMnemonicInMask19(code);
    FindCorrespondingMnemonicInMask20(code);
}

/*
 * GetOperandFromCode - Parses to get operands from code.
 *
 * @code - Code to get operands.
 * @mnem_id - Mnemonic id corresponding to given code.
 * @operands - Pointer to struct that takes operands.
 * @return - 0 on success; -1 on failure.
 */
int GetOperandFromCode(int code, int mnem_id, struct operands_t *operands) {

    if ( mnem_id < 136 || 143 < mnem_id ) {
        GetOperandFromCodeTable[mnem_id](code, operands);
        return 0;
    }

    return -1;
}

/*
 * ParseRsRtRd - Parses RS, RT, RD from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRsRtRd(int code, struct operands_t *operands) {
    operands->rs = (code & 0b00000011111000000000000000000000) >> 21;
    operands->rt = (code & 0b00000000000111110000000000000000) >> 16;
    operands->rd = (code & 0b00000000000000001111100000000000) >> 11;
}

/*
 * ParseRsRtImm - Parses RS, RT, Immediate from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRsRtImm(int code, struct operands_t *operands) {
    operands->rs = (code & 0b00000011111000000000000000000000) >> 21;
    operands->rt = (code & 0b00000000000111110000000000000000) >> 16;
    operands->imm = code & 0b00000000000000001111111111111111;
}

/*
 * ParseRsRtOffset - Parses RS, RT, Offset from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRsRtOffset(int code, struct operands_t *operands) {
    operands->rs = (code & 0b00000011111000000000000000000000) >> 21;
    operands->rt = (code & 0b00000000000111110000000000000000) >> 16;
    operands->offset = code & 0b00000000000000001111111111111111;
}

/*
 * ParseBaseOffset - Parses Base, Offset from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseBaseOpOffset(int code, struct operands_t *operands) {
    operands->base = (code & 0b00000011111000000000000000000000) >> 21;
    operands->op = (code & 0b00000000000111110000000000000000) >> 16;
    operands->offset = code & 0b00000000000000001111111111111111;
}

/*
 * ParseIdx - Parses Index from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseIdx(int code, struct operands_t *operands) {
    operands->idx = code & 0b00000011111111111111111111111111;
}

/*
 * ParseBaseRtOffset - Parses Base, RT, Offset from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseBaseRtOffset(int code, struct operands_t *operands) {
    operands->base = (code & 0b00000011111000000000000000000000) >> 21;
    operands->rt = (code & 0b00000000000111110000000000000000) >> 16;
    operands->offset = code & 0b00000000000000001111111111111111;
}

/*
 * ParseBaseFtOffset - Parses Base, FT, Offset from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseBaseFtOffset(int code, struct operands_t *operands) {
    operands->base = (code & 0b00000011111000000000000000000000) >> 21;
    operands->ft = (code & 0b00000011111000000000000000000000) >> 16;
    operands->offset = code & 0b00000000000000001111111111111111;
}

/*
 * ParseBaseHintOffset - Parses Base, Hint, Offset from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseBaseHintOffset(int code, struct operands_t *operands) {
    operands->base = (code & 0b00000011111000000000000000000000) >> 21;
    operands->hint = (code & 0b00000000000111110000000000000000) >> 16;
    operands->offset = code & 0b00000000000000001111111111111111;
}

/*
 * ParseOffset - Parses Offset from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseOffset(int code, struct operands_t *operands) {
    operands->offset = code & 0b00000000000000001111111111111111;
}

/*
 * ParseRsOffset - Parses RS, Offset from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRsOffset(int code, struct operands_t *operands) {
    operands->rs = (code & 0b00000011111000000000000000000000) >> 21;
    operands->offset = code & 0b00000000000000001111111111111111;
}

/*
 * ParseRsImm - Parses RS, Immediate from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRsImm(int code, struct operands_t *operands) {
    operands->rs = (code & 0b00000011111000000000000000000000) >> 21;
    operands->imm = code & 0b00000000000000001111111111111111;
}

/*
 * ParseRtRdSa - Parses RT, RD, SA from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRtRdSa(int code, struct operands_t *operands) {
    operands->rt = (code & 0b00000000000111110000000000000000) >> 16;
    operands->rd = (code & 0b00000000000000001111100000000000) >> 11;
    operands->sa = (code & 0b00000000000000000000011111000000) >> 6;
}

/*
 * ParseRsRt - Parses RS, RT from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRsRt(int code, struct operands_t *operands) {
    operands->rs = (code & 0b00000011111000000000000000000000) >> 21;
    operands->rt = (code & 0b00000000000111110000000000000000) >> 16;
}

/*
 * ParseFmtFsFd - Parses Format, FS, FD from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseFmtFsFd(int code, struct operands_t *operands) {
    operands->fmt = (code & 0b00000011111000000000000000000000) >> 21;
    operands->fs = (code & 0b00000000000000001111100000000000) >> 11;
    operands->fd = (code & 0b00000000000000000000011111000000) >> 6;
}

/*
 * ParseRsRdHint - Parses RS, RD, Hint from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRsRdHint(int code, struct operands_t *operands) {
    operands->rs = (code & 0b00000011111000000000000000000000) >> 21;
    operands->rd = (code & 0b00000000000000001111100000000000) >> 11;
    operands->hint = (code & 0b00000000000000000000011111000000) >> 6;
}

/*
 * ParseRsCcRd - Parses RS, CC, RD from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRsCcRd(int code, struct operands_t *operands) {
    operands->rs = (code & 0b00000011111000000000000000000000) >> 21;
    operands->cc = (code & 0b00000000000111000000000000000000) >> 18;
    operands->rd = (code & 0b00000000000000001111100000000000) >> 11;
}

/*
 * ParseRsHint - Parses Rs, Hint from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRsHint(int code, struct operands_t *operands) {
    operands->rs = (code & 0b00000011111000000000000000000000) >> 21;
    operands->hint = (code & 0b00000000000000000000011111000000) >> 6;
}

/*
 * ParseFmtFtFsFd - Parses Format, FT, FS, FD from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseFmtFtFsFd(int code, struct operands_t *operands) {
    operands->fmt = (code & 0b00000011111000000000000000000000) >> 21;
    operands->ft = (code & 0b00000000000111110000000000000000) >> 16;
    operands->fs = (code & 0b00000000000000001111100000000000) >> 11;
    operands->fd = (code & 0b00000000000000000000011111000000) >> 6;
}

/*
 * ParseCode20 - Parses code 20 bytes from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseCode20(int code, struct operands_t *operands) {
    operands->code20 = (code & 0b00000011111111111111111111000000) >> 6;
}

/*
 * ParseFmtRtFsFd - Parses Format, RT, FS, FD from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseFmtRtFsFd(int code, struct operands_t *operands) {
    operands->fmt = (code & 0b00000011111000000000000000000000) >> 21;
    operands->rt = (code & 0b00000000000111110000000000000000) >> 16;
    operands->fs = (code & 0b00000000000000001111100000000000) >> 11;
    operands->fd = (code & 0b00000000000000000000011111000000) >> 6;
}

/*
 * ParseRsRtCode10 - Parses RS, RT, Code 10bytes from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRsRtCode10(int code, struct operands_t *operands) {
    operands->rs = (code & 0b00000011111000000000000000000000) >> 21;
    operands->rt = (code & 0b00000000000111110000000000000000) >> 16;
    operands->code10 = (code & 0b00000000000000001111111111000000) >> 6;
}

/*
 * ParseCcOffset - Parses CC, Offset from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseCcOffset(int code, struct operands_t *operands) {
    operands->cc = (code & 0b00000000000111000000000000000000) >> 18;
    operands->offset = code & 0b00000000000000001111111111111111;
}

/*
 * ParseRtFs - Parses RT, FS from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRtFs(int code, struct operands_t *operands) {
    operands->rt = (code & 0b00000000000111110000000000000000) >> 16;
    operands->fs = (code & 0b00000000000000001111100000000000) >> 11;
}

/*
 * ParseRtRdSel - Parses RT, RD, Select from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRtRdSel(int code, struct operands_t *operands) {
    operands->rt = (code & 0b00000000000111110000000000000000) >> 16;
    operands->rd = (code & 0b00000000000000001111100000000000) >> 11;
    operands->sel = code & 0b00000000000000000000000000000111;
}

/*
 * ParseFmtFtFsCcCond - Parses Format, FT, FS, CC, Cond from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseFmtFtFsCcCond(int code, struct operands_t *operands) {
    operands->fmt = (code & 0b00000011111000000000000000000000) >> 21;
    operands->ft = (code & 0b00000000000111110000000000000000) >> 16;
    operands->fs = (code & 0b00000000000000001111100000000000) >> 11;
    operands->cc = (code & 0b00000000000000000000011100000000) >> 8;
    operands->cond = code & 0b00000000000000000000000000000111;
}

/*
 * ParseRtImm - Parses RT, Immediate from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRtImm(int code, struct operands_t *operands) {
    operands->rt = (code & 0b00000000000111110000000000000000) >> 16;
    operands->imm = code & 0b00000000000000001111111111111111;
}

/*
 * ParseCofun - Parses Cofun from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseCofun(int code, struct operands_t *operands) {
    operands->cofun = code & 0b00000001111111111111111111111111;
}

/*
 * ParseRd - Parses Rd from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRd(int code, struct operands_t *operands) {
    operands->rd = (code & 0b00000000000000001111100000000000) >> 11;
}

/*
 * ParseRs - Parses RS from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseRs(int code, struct operands_t *operands) {
    operands->rd = (code & 0b00000011111000000000000000000000) >> 21;
}

/*
 * ParseStype - Parses Stype from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseStype(int code, struct operands_t *operands) {
    operands->stype = (code & 0b00000000000000000000011111000000) >> 6;
}

/*
 * ParseImp - Parses Implement field from Code.
 *
 * @code - Code to be parsed.
 * @operands - a struct to store operands parsed.
 */
static void ParseImp(int code, struct operands_t *operands) {
    operands->imp = (code & 0b00000001111111111111111111000000) >> 6;
}

