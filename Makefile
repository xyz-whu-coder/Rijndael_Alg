all: Rijndael

CFLAGS := -Ofast -Wall
SOURCE_DIR := ./src

Rijndael: $(SOURCE_DIR)/main.o $(SOURCE_DIR)/Rijndael.o
	gcc $(CFLAGS) -o $@ $(SOURCE_DIR)/main.o $(SOURCE_DIR)/Rijndael.o

main.o: $(SOURCE_DIR)/main.c
	gcc -c $(SOURCE_DIR)/main.c

Rijndael.o: Rijndael.c
	gcc -c $(SOURCE_DIR)/Rijndael.c

clean:
	rm -f Rijndael ./**/*.o

.PHONY: clean
