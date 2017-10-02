#Makefile
#by kimht

#macros
OBJECTS = base.o disassembler.o disassembler_printer.o tracer.o
CC = gcc
CFLAGS = -Wall -c

main: $(OBJECTS)
	$(CC) -Wall main.c $(OBJECTS) -o main

base.o: ./base/base.c ./base/base.h
	$(CC) $(CFLAGS) ./base/base.c

disassembler.o: ./disassembler/disassembler.c ./disassembler/disassembler.h
	$(CC) $(CFLAGS) ./disassembler/disassembler.c

disassembler_printer.o: ./disassembler_printer/disassembler_printer.c ./disassembler_printer/disassembler_printer.h
	$(CC) $(CFLAGS) ./disassembler_printer/disassembler_printer.c

tracer.o: ./tracer/tracer.c ./tracer/tracer.h
	$(CC) $(CFLAGS) ./tracer/tracer.c

clean:
	rm $(OBJECTS) main
