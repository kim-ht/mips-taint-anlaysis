/* main.c
 * by kimht
 */
#include "./base/base.h"
#include "./disassembler/disassembler.h"
#include "./disassembler_printer/disassembler_printer.h"
#include "./tracer/tracer.h"

int main(void) {
    //TraceProgram("../test_binary/test_elf0", NULL, NULL, 0x004006a0, 0x004007cc);
    TraceProgram("../test_binary/helloworld", NULL, NULL, 0x00400710, 0x00400890);

    return 0;
}



