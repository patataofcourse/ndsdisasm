CAPSTONE_DIR := capstone

DEBUG               ?= 0
USE_SYSTEM_CAPSTONE ?= 1

CFLAGS := -Wall -Wextra -Wpedantic
ifeq ($(DEBUG),1)
CFLAGS += -O0 -g
else
CFLAGS += -O2 -g
endif
CFLAGS += -fsanitize=address

PROGRAM := ndsdisasm
SOURCES := main.c disasm.c
HEADERS := ndsdisasm.h

.PHONY: all capstone

all: $(PROGRAM)

# Compile the program
ifneq ($(USE_SYSTEM_CAPSTONE),1)
$(PROGRAM): $(CAPSTONE_DIR)/libcapstone.a
$(CAPSTONE_DIR)/libcapstone.a: capstone
export PKG_CONFIG_PATH := $(CAPSTONE_DIR)
endif

$(PROGRAM): CFLAGS += $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" pkg-config --cflags capstone)
$(PROGRAM): LDFLAGS += $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" pkg-config --libs capstone)
$(PROGRAM): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

# Build libcapstone
capstone:
	@$(MAKE) -C $(CAPSTONE_DIR) CAPSTONE_STATIC=yes CAPSTONE_SHARED=no CAPSTONE_ARCHS="arm" CAPSTONE_BUILD_CORE_ONLY=yes PREFIX=$(CAPSTONE_DIR)

clean:
	$(RM) $(PROGRAM) $(PROGRAM).exe
	@$(MAKE) -C $(CAPSTONE_DIR) clean
