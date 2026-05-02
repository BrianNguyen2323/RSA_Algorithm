#
# File:         Makefile
# Author:       Brian Nguyen and Ryan Rossman
# Purpose:      Builds the RSA Algorithm project by assembling src/main.s and
#               src/rsa_lib.s into object files and linking them into a single
#               executable called 'program'. Automatically strips UTF-8 BOM and
#               Windows carriage returns from .s files before assembling so the
#               project builds cleanly on Linux after editing on Windows.
# Targets:
#               all   - default target; assembles, links, and produces ./program
#               run   - builds then immediately runs ./program
#               clean - removes object files, the executable, and output txt files
#               info  - prints the compiler being used
# Usage:
#               make          (build)
#               make run      (build and run)
#               make clean    (remove build artifacts)
#

## Try different compilers for different machines

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
TARGET  := program
OBJS    := $(SRC_DIR)/main.o $(SRC_DIR)/rsa_lib.o

.PHONY: all run clean info

all: info $(TARGET)

info:
	@echo "Using CC = $(CC)"

# Link main.o and rsa_lib.o into ./main
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Pattern rule: assemble any src/*.s into src/*.o
# sed strips UTF-8 BOM (line 1) and Windows carriage returns before assembling
$(SRC_DIR)/%.o: $(SRC_DIR)/%.s
	sed -i '1s/^\xEF\xBB\xBF//; s/\r$$//' $<
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(SRC_DIR)/*.o $(TARGET) encrypted.txt plaintext.txt