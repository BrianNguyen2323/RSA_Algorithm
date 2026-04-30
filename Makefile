# 
# Makefile 
# =============================================================================

ifeq ($(shell command -v arm-linux-gnueabihf-gcc 2>/dev/null),)
    CC := gcc
else
    CC := arm-linux-gnueabihf-gcc
endif

# ---- Flags ----
# -g       debug symbols
# -no-pie  avoid PIE relocation issues with raw assembly symbols
CFLAGS := -g -no-pie

# ---- Files ----
SRC_DIR := src
TARGET  := main
OBJS    := $(SRC_DIR)/main.o $(SRC_DIR)/rsa_lib.o

# ---- Rules ----
.PHONY: all run clean info

all: info $(TARGET)

# Print which compiler we ended up using (helpful for debugging)
info:
	@echo "Using CC = $(CC)"

# Link main.o and rsa_lib.o into ./main
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Pattern rule: assemble any src/*.s into src/*.o
$(SRC_DIR)/%.o: $(SRC_DIR)/%.s
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(SRC_DIR)/*.o $(TARGET) encrypted.txt plaintext.txt