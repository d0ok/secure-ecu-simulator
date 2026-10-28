.RECIPEPREFIX = >
CC := gcc
CPPFLAGS := -Iinclude
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS := $(shell pkg-config --libs openssl)
BUILD_DIR := build
HDRS := $(wildcard include/*.h)
COMPILE = $(CC) $(CPPFLAGS) $(CFLAGS) $(OPENSSL_CFLAGS)
SEC_SRCS := src/secoc.c src/freshness.c src/sec_layer.c

# Fuzzing: AddressSanitizer + UndefinedBehaviorSanitizer, any UB aborts the run.
FUZZ_FLAGS := -std=c11 -Wall -Wextra -Wpedantic -O1 -g \
              -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
FUZZ_ITERS ?= 100000
FUZZ_SEED ?= 1

BINS := $(BUILD_DIR)/can_receiver $(BUILD_DIR)/secoc_sender \
        $(BUILD_DIR)/test_secoc $(BUILD_DIR)/test_freshness \
        $(BUILD_DIR)/test_sec_layer $(BUILD_DIR)/test_ecu_app \
        $(BUILD_DIR)/test_counter_store

.PHONY: all test integration fuzz clean

all: $(BINS)

$(BUILD_DIR):
> mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/can_receiver: src/can_receiver.c src/can_if.c src/ecu_app.c src/counter_store.c $(SEC_SRCS) $(HDRS) | $(BUILD_DIR)
> $(COMPILE) $(filter %.c,$^) -o $@ $(OPENSSL_LIBS)

$(BUILD_DIR)/secoc_sender: src/secoc_sender.c src/secoc.c $(HDRS) | $(BUILD_DIR)
> $(COMPILE) $(filter %.c,$^) -o $@ $(OPENSSL_LIBS)

$(BUILD_DIR)/test_secoc: tests/test_secoc.c src/secoc.c $(HDRS) | $(BUILD_DIR)
> $(COMPILE) $(filter %.c,$^) -o $@ $(OPENSSL_LIBS)

$(BUILD_DIR)/test_freshness: tests/test_freshness.c src/freshness.c $(HDRS) | $(BUILD_DIR)
> $(COMPILE) $(filter %.c,$^) -o $@ $(OPENSSL_LIBS)

$(BUILD_DIR)/test_sec_layer: tests/test_sec_layer.c $(SEC_SRCS) $(HDRS) | $(BUILD_DIR)
> $(COMPILE) $(filter %.c,$^) -o $@ $(OPENSSL_LIBS)

$(BUILD_DIR)/test_ecu_app: tests/test_ecu_app.c src/ecu_app.c $(HDRS) | $(BUILD_DIR)
> $(COMPILE) $(filter %.c,$^) -o $@ $(OPENSSL_LIBS)

$(BUILD_DIR)/test_counter_store: tests/test_counter_store.c src/counter_store.c $(HDRS) | $(BUILD_DIR)
> $(COMPILE) $(filter %.c,$^) -o $@ $(OPENSSL_LIBS)

$(BUILD_DIR)/fuzz_ecu: tests/fuzz_ecu.c $(SEC_SRCS) src/ecu_app.c src/counter_store.c $(HDRS) | $(BUILD_DIR)
> $(CC) $(CPPFLAGS) $(FUZZ_FLAGS) $(OPENSSL_CFLAGS) $(filter %.c,$^) -o $@ $(OPENSSL_LIBS)

test: $(BUILD_DIR)/test_secoc $(BUILD_DIR)/test_freshness $(BUILD_DIR)/test_sec_layer $(BUILD_DIR)/test_ecu_app $(BUILD_DIR)/test_counter_store
> ./$(BUILD_DIR)/test_secoc
> ./$(BUILD_DIR)/test_freshness
> ./$(BUILD_DIR)/test_sec_layer
> ./$(BUILD_DIR)/test_ecu_app
> ./$(BUILD_DIR)/test_counter_store

integration: all
> bash tests/live_test.sh

fuzz: $(BUILD_DIR)/fuzz_ecu
> ./$(BUILD_DIR)/fuzz_ecu $(FUZZ_ITERS) $(FUZZ_SEED)

clean:
> rm -rf $(BUILD_DIR)
