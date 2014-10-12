CC=gcc

all: list.o easyptrace.o 
	$(CC) -o infectbin infectbin.c list.o easyptrace.o -I.
	rm *.o
