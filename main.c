#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if CAPSTONE_VERMAJ < 4
#include <capstone.h>
#else
#include <capstone/capstone.h>
#endif //CAPSTONE_VERMAJ

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#include "ndsdisasm.h"

struct ConfigLabel
{
    uint32_t addr;
    uint8_t type;
    const char *label;
};

uint8_t *gInputFileBuffer;
size_t gInputFileBufferSize;
uint32_t gRomStart;
uint32_t gRamStart;
bool isFullRom = true;
bool isArm7 = false;
int ModuleNum = -1;

static void read_input_file(const char *fname)
{
    FILE *file = fopen(fname, "rb");

    if (file == NULL)
        fatal_error("could not open input file '%s'", fname);
    if (isFullRom) {
        fseek(file, 0x2C + 0x10 * isArm7, SEEK_SET);
        fread(&gInputFileBufferSize, 4, 1, file);
        fseek(file, 0x28 + 0x10 * isArm7, SEEK_SET);
        fread(&gRamStart, 4, 1, file);
        fseek(file, 0x20 + 0x10 * isArm7, SEEK_SET);
        fread(&gRomStart, 4, 1, file);
    } else {
        uint32_t fat_offset, fat_size, ovy_offset, ovy_size;
        fseek(file, 0x48, SEEK_SET);
        fread(&fat_offset, 4, 1, file);
        fread(&fat_size, 4, 1, file);
        fseek(file, 0x50 + 8 * isArm7, SEEK_SET);
        fread(&ovy_offset, 4, 1, file);
        fread(&ovy_size, 4, 1, file);
        if (ModuleNum * 32u > ovy_size)
            fatal_error("Argument to -m is out of range");
        fseek(file, ovy_offset + ModuleNum * 32 + 4, SEEK_SET);
        fread(&gRamStart, 4, 1, file);
        fread(&gInputFileBufferSize, 4, 1, file);
        fseek(file, fat_offset + ModuleNum * 8, SEEK_SET);
        fread(&gRomStart, 4, 1, file);
    }
    fseek(file, gRomStart, SEEK_SET);
    gInputFileBuffer = malloc(gInputFileBufferSize);
    if (gInputFileBuffer == NULL)
        fatal_error("failed to alloc file buffer for '%s'", fname);
    if (fread(gInputFileBuffer, 1, gInputFileBufferSize, file) != gInputFileBufferSize)
        fatal_error("failed to read from file '%s'", fname);
    fclose(file);
}

static char *split_word(char *s)
{
    while (!isspace(*s))
    {
        if (*s == '\0')
            return s;
        s++;
    }
    *s++ = '\0';
    while (isspace(*s))
        s++;
    return s;
}

static char *split_line(char *s)
{
    while (*s != '\n' && *s != '\r')
    {
        if (*s == '\0')
            return s;
        s++;
    }
    *s++ = '\0';
    while (*s == '\n' || *s == '\r')
        s++;
    return s;
}

static char *skip_whitespace(char *s)
{
    while (isspace(*s))
        s++;
    return s;
}

static char *dup_string(const char *s)
{
    char *new = malloc(strlen(s) + 1);

    if (new == NULL)
        fatal_error("could not alloc space for string '%s'", s);
    strcpy(new, s);
    return new;
}

static void read_config(const char *fname)
{
    FILE *file = fopen(fname, "rb");
    char *buffer;
    size_t size;
    char *line;
    char *next;
    int lineNum = 1;

    if (file == NULL)
        fatal_error("could not open config file '%s'", fname);
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fseek(file, 0, SEEK_SET);
    buffer = malloc(size + 1);
    if (buffer == NULL)
        fatal_error("could not alloc buffer for '%s'", fname);
    if (fread(buffer, 1, size, file) != size)
        fatal_error("failed to read from file '%s'", fname);
    buffer[size] = '\0';
    fclose(file);

    for (line = next = buffer; *line != '\0'; line = next, lineNum++)
    {
        char *tokens[3];
        char *name = NULL;
        int i;

        next = split_line(line);

        tokens[0] = line = skip_whitespace(line);
        for (i = 1; i < 3; i++)
            tokens[i] = line = split_word(line);

        if (tokens[0][0] == '#')
            continue;
        if (strcmp(tokens[0], "arm_func") == 0)
        {
            int addr;

            if (sscanf(tokens[1], "%i", &addr) == 1)
            {
                if (strlen(tokens[2]) != 0)
                    name = dup_string(tokens[2]);
                disasm_add_label(addr, LABEL_ARM_CODE, name);
            }
            else
            {
                fatal_error("%s: syntax error on line %i", fname, lineNum);
            }
        }
        else if (strcmp(tokens[0], "thumb_func") == 0)
        {
            int addr;

            if (sscanf(tokens[1], "%i", &addr) == 1)
            {
                if (strlen(tokens[2]) != 0)
                    name = dup_string(tokens[2]);
                disasm_add_label(addr, LABEL_THUMB_CODE, name);
            }
            else
            {
                fatal_error("%s: syntax error on line %i", fname, lineNum);
            }
        }
        else
        {
            fprintf(stderr, "%s: warning: unrecognized command '%s' on line %i\n", fname, tokens[0], lineNum);
        }
    }

    free(buffer);
}

int main(int argc, char **argv)
{
    int i;
    const char *romFileName = NULL;
    const char *configFileName = NULL;
    //ROM_LOAD_ADDR = 0x08000000;

#ifdef _WIN32
    // Work around MinGW bug that prevents us from seeing the assert message
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-c") == 0)
        {
            if (i + 1 >= argc)
                fatal_error("expected filename for option -c");
            i++;
            configFileName = argv[i];
        }
        else if (strcmp(argv[i], "-l") == 0)
        {
            fprintf(stderr, "warning: option -l is deprecated and will be removed in a future version\n");
            char * end;
            if (i + 1 >= argc)
                fatal_error("expected integer for option -l");
            i++;
            ROM_LOAD_ADDR = strtoul(argv[i], &end, 0);
            if (*end != 0)
                fatal_error("invalid integer value for option -l");
        }
        else if (strcmp(argv[i], "-m") == 0)
        {
            char * endptr;
            i++;
            if (i + 1 >= argc)
                fatal_error("expected integer for option -m");
            ModuleNum = strtol(argv[i], &endptr, 0);
            if (ModuleNum == 0 && endptr == argv[i])
                fatal_error("Invalid integer value for option -m");
            isFullRom = false;
        }
        else if (strcmp(argv[i], "-7") == 0)
        {
            isArm7 = true;
        }
        else
        {
            romFileName = argv[i];
        }
    }

    if (romFileName == NULL)
        fatal_error("no ROM file specified");
    read_input_file(romFileName);
    ROM_LOAD_ADDR=gRamStart;
    if (configFileName != NULL)
        read_config(configFileName);
    else
        fatal_error("config file required");
    disasm_disassemble();
    free(gInputFileBuffer);
    return 0;
}
