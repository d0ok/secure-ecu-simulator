CC = gcc

CPPFLAGS = -Iinclude
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -O2 -g

BUILD_DIR = build
TARGET = $(BUILD_DIR)/can_receiver

.PHONY: all clean

all: $(TARGET)

$(TARGET): src/can_receiver.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
