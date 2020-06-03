# NDSDISASM

This is a simple disassembler for Nintendo DS games, based on a disassembler for Game Boy Advance games by camthesaxman.

## Usage

`ndsdisasm rom_file -c config_file [-m ovly_id] [-7]`
where `rom_file` is the NDS rom to disassemble, and `config_file` is a **REQUIRED** config file that gives hints to the disassembler.

To disassemble an overlay, pass its integer ID to the `-m` switch.

To disassemble the ARM7 binary, pass `-7`.

## Config File

The config file consists of a list of statements, one per line. Lines beginning with `#` are treated as comments. An config file `pokediamond.cfg` for Pokemon Diamond is provided as an example.
