/* main.c
 * by kimht
 */
#include "./base/base.h"
#include "./disassembler/disassembler.h"
#include "./disassembler_printer/disassembler_printer.h"
#include "./tracer/tracer.h"

int main(void) {
    TraceProgram("./test_binary/helloworld", NULL, NULL);

    return 0;
}

