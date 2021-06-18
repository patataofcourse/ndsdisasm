CAPSTONE_DIR := capstone
CAPSTONE_LIB := -L$(CAPSTONE_DIR) -lcapstone

include $(CAPSTONE_DIR)/pkgconfig.mk

CAPSTONE_VERSION := $(PKG_MAJOR).$(PKG_MINOR).$(PKG_EXTRA)
ifneq (,$(CAPSTONE_VERTAG))
	CAPSTONE_VERSION += -$(CAPSTONE_VERTAG)
endif

DEBUG ?= 0

CC := gcc
CFLAGS := -isystem $(CAPSTONE_DIR)/include -Wall -Wextra -Wpedantic -DCAPSTONE_VERSION="$(CAPSTONE_VERSION)" -DCAPSTONE_VERMAJ=$(PKG_MAJOR) -DCAPSTONE_VERMIN=$(PKG_MINOR) -DCAPSTONE_REVISN=$(PKG_EXTRA)
ifeq ($(DEBUG),1)
CFLAGS += -O0 -g
else
CFLAGS += -O2 -g
endif
#CFLAGS += -fsanitize=address

LDFLAGS := -L$(CAPSTONE_DIR) -lcapstone
PROGRAM := ndsdisasm
SOURCES := main.c disasm.c
LIBS := $(CAPSTONE_LIB)

.PHONY: all capstone

all: capstone $(PROGRAM)

# Compile the program
$(PROGRAM): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

# Build libcapstone
capstone:
	@$(MAKE) -C $(CAPSTONE_DIR) CAPSTONE_STATIC=yes CAPSTONE_SHARED=no CAPSTONE_ARCHS="arm" CAPSTONE_BUILD_CORE_ONLY=yes

clean:
	$(RM) $(PROGRAM) $(PROGRAM).exe
	@$(MAKE) -C $(CAPSTONE_DIR) clean

$(PROGRAM): $(CAPSTONE_DIR)/libcapstone.a
$(CAPSTONE_DIR)/libcapstone.a: ;
