/* main.c
 * by kimht
 */
#include "./base/base.h"
#include "./disassembler/disassembler.h"
#include "./disassembler_printer/disassembler_printer.h"
#include "./tracer/tracer.h"

int main(int argc, char *argv[]) {
    int start_addr;
    int end_addr;

    start_addr = strtol(argv[2], NULL, 16);
    end_addr = strtol(argv[3], NULL, 16);

    TraceProgram(argv[1], NULL, NULL, start_addr, end_addr);

    return 0;
}



