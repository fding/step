CFLAGS=-O2 -Wall -g
DIRFLAGS=-Llibelf/lib -I/usr/local/include/ 
LFLAGS=-lncurses -lelf

all: step test

step: main.o libdasm
	$(CC) $(CFLAGS) $(DIRFLAGS) -o step main.o libdasm/libdasm.o $(LFLAGS)

test: test.c
	$(CC) -o test test.c

main.o: main.c
	$(CC) $(CFLAGS) $(DIRFLAGS) -c main.c

libdasm:
	$(MAKE) -C libdasm

libelf:
	$(MAKE) -C libelf

clean:
	rm -f *.o test main
