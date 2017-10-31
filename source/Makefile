#Makefile
#by kimht

#macros
OBJECTS = base.o disassembler.o disassembler_printer.o tracer.o taint_checker.o result_saver.o rbtree.o
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

taint_checker.o: ./taint_checker/taint_checker.c ./taint_checker/taint_checker.h
	$(CC) $(CFLAGS) ./taint_checker/taint_checker.c

result_saver.o: ./result_saver/result_saver.c ./result_saver/result_saver.h
	$(CC) $(CFLAGS) ./result_saver/result_saver.c

rbtree.o: ./rbtree/rbtree.c ./rbtree/rbtree.h
	$(CC) $(CFLAGS) ./rbtree/rbtree.c

clean:
	rm $(OBJECTS) main

