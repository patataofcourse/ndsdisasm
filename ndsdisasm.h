
enum LabelType
{
    LABEL_ARM_CODE,
    LABEL_THUMB_CODE,
    LABEL_DATA,
    LABEL_POOL,
    LABEL_JUMP_TABLE,
    LABEL_JUMP_TABLE_THUMB,
    LABEL_JUMP_TABLE_THUMB_BX,
};

extern uint8_t *gInputFileBuffer;
extern size_t gInputFileBufferSize;
extern uint32_t ROM_LOAD_ADDR;
extern uint32_t gRomStart;
extern uint32_t gRamStart;
extern bool isFullRom;
extern bool isArm7;

// disasm.c
int disasm_add_label(uint32_t addr, enum LabelType type, char *name);
void disasm_disassemble(void);
