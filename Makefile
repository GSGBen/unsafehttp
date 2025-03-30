# based on https://makefiletutorial.com/#makefile-cookbook and
# https://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/

TARGET_EXEC := unsafehttp

BUILD_DIR := ./build
SRC_DIRS := ./src

CC := gcc
CFLAGS := -std=gnu17 -Wall -Werror -I $(SRC_DIRS)
CFLAGS_DEV := -g -fsanitize=address -fsanitize=leak -fsanitize=undefined

SRC_FILES := $(shell find $(SRC_DIRS) -name '*.c')

default: build-dev

.PHONY: build-dev
build-dev:
	$(CC) $(CFLAGS) $(CFLAGS_DEV) -o $(BUILD_DIR)/$(TARGET_EXEC) $(SRC_FILES)

.PHONY: build-rel
build-rel:
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$(TARGET_EXEC) $(SRC_FILES)

.PHONY: run
run: build-dev
	$(BUILD_DIR)/$(TARGET_EXEC) $(ARGS)
