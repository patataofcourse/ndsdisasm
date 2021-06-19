CAPSTONE_DIR := capstone

DEBUG ?= 0

CFLAGS := -Wall -Wextra -Wpedantic
ifeq ($(DEBUG),1)
CFLAGS += -O0 -g
else
CFLAGS += -O2 -g
endif

PROGRAM := ndsdisasm
SOURCES := main.c disasm.c

.PHONY: all capstone

all: capstone $(PROGRAM)

# Compile the program
$(PROGRAM): CFLAGS += $(shell PKG_CONFIG_PATH=$(CAPSTONE_DIR) pkg-config --cflags capstone)
$(PROGRAM): LDFLAGS += $(shell PKG_CONFIG_PATH=$(CAPSTONE_DIR) pkg-config --libs capstone)
$(PROGRAM): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

# Build libcapstone
capstone:
	@$(MAKE) -C $(CAPSTONE_DIR) CAPSTONE_STATIC=yes CAPSTONE_SHARED=no CAPSTONE_ARCHS="arm" CAPSTONE_BUILD_CORE_ONLY=yes PREFIX=$(CAPSTONE_DIR)

clean:
	$(RM) $(PROGRAM) $(PROGRAM).exe
	@$(MAKE) -C $(CAPSTONE_DIR) clean

$(PROGRAM): $(CAPSTONE_DIR)/libcapstone.a
$(CAPSTONE_DIR)/libcapstone.a: ;
