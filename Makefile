all: main

CC = gcc
CFLAGS = -g

SRC_DIR = src
LIB = $(SRC_DIR)/rsa_lib.o

main: $(SRC_DIR)/main.o $(LIB)
	$(CC) $(SRC_DIR)/main.o $(LIB) $(CFLAGS) -o main

$(SRC_DIR)/%.o: $(SRC_DIR)/%.s
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SRC_DIR)/*.o main
