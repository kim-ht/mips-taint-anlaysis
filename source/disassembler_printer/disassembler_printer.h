/* disassembler_printer.h
 * by kimht
 */
#ifndef _DISASSEMBLER_PRINTER_DISASSEMBLER_PRINTER_H_
#define _DISASSEMBLER_PRINTER_DISASSEMBLER_PRINTER_H_

///////////////////////////////////////////////////////////////////////////////
/// includes
///////////////////////////////////////////////////////////////////////////////
#include "../disassembler/disassembler.h"
#include "../base/base.h"

///////////////////////////////////////////////////////////////////////////////
/// function prototypes
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
    unsigned int addr);

#endif

