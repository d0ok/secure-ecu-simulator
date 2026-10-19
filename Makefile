.RECIPEPREFIX = >
CC := gcc
CPPFLAGS := -Iinclude
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS := $(shell pkg-config --libs openssl)
BUILD_DIR := build
HDRS := include/secoc.h include/freshness.h

.PHONY: all test clean

all: $(BUILD_DIR)/can_receiver $(BUILD_DIR)/secoc_sender $(BUILD_DIR)/test_secoc $(BUILD_DIR)/test_freshness

$(BUILD_DIR):
> mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/can_receiver: src/can_receiver.c src/secoc.c src/freshness.c $(HDRS) | $(BUILD_DIR)
> $(CC) $(CPPFLAGS) $(CFLAGS) $(OPENSSL_CFLAGS) src/can_receiver.c src/secoc.c src/freshness.c -o $@ $(OPENSSL_LIBS)

$(BUILD_DIR)/secoc_sender: src/secoc_sender.c src/secoc.c $(HDRS) | $(BUILD_DIR)
> $(CC) $(CPPFLAGS) $(CFLAGS) $(OPENSSL_CFLAGS) src/secoc_sender.c src/secoc.c -o $@ $(OPENSSL_LIBS)

$(BUILD_DIR)/test_secoc: tests/test_secoc.c src/secoc.c $(HDRS) | $(BUILD_DIR)
> $(CC) $(CPPFLAGS) $(CFLAGS) $(OPENSSL_CFLAGS) tests/test_secoc.c src/secoc.c -o $@ $(OPENSSL_LIBS)

$(BUILD_DIR)/test_freshness: tests/test_freshness.c src/freshness.c $(HDRS) | $(BUILD_DIR)
> $(CC) $(CPPFLAGS) $(CFLAGS) tests/test_freshness.c src/freshness.c -o $@

test: $(BUILD_DIR)/test_secoc $(BUILD_DIR)/test_freshness
> ./$(BUILD_DIR)/test_secoc
> ./$(BUILD_DIR)/test_freshness

clean:
> rm -rf $(BUILD_DIR)
