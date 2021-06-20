#include <stdnoreturn.h>

#define NDSDISASM_VERMAJ    1
#define NDSDISASM_VERMIN    0
#define NDSDISASM_VERSTP    5

static inline noreturn __attribute__((format(printf, 1, 2))) void fatal_error(const char *fmt, ...)
{
    va_list args;

    fputs("error: ", stderr);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputs("\n", stderr);
    exit(1);
}

enum LabelType
{
    LABEL_ARM_CODE,
    LABEL_THUMB_CODE,
    LABEL_DATA,
    LABEL_POOL,
    LABEL_JUMP_TABLE,
    LABEL_JUMP_TABLE_THUMB,
    LABEL_JUMP_TABLE_THUMB_BX,
    LABEL_ASCII,
};

extern uint8_t *gInputFileBuffer;
extern size_t gInputFileBufferSize;
extern uint32_t ROM_LOAD_ADDR;
extern uint32_t gRomStart;
extern uint32_t gRamStart;
extern bool isFullRom;
extern bool isArm7;
extern bool dumpUnDisassembled;
extern const char *functionPrefix;
extern const char *dataPrefix;
extern bool functionPrefixOverridden;
extern bool dataPrefixOverridden;

// disasm.c
int disasm_add_label(uint32_t addr, enum LabelType type, char *name, bool is_config);
void disasm_disassemble(void);
