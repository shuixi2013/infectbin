CC=gcc

make: list.o easyptrace.o 
	$(CC) -o infectbin infectbin.c list.o easyptrace.o -I.

clean:
	rm -f *.o infectbin
