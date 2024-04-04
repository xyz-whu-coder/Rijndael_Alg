all: Rijndael

CFLAGS := -O2 -Wall

Rijndael: main.o Rijndael.o
	gcc $(CFLAGS) -o $@ main.o Rijndael.o

main.o: main.c
	gcc -c main.c

Rijndael.o: Rijndael.c
	gcc -c Rijndael.c

clean:
	rm -f Rijndael *.o

.PHONY: clean
