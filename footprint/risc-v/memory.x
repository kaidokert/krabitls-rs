/* QEMU `virt` only has one DRAM region (at 0x80000000), but the linker
 * still wants distinct FLASH / RAM regions: `paint_stack` uses
 * `_ram_length` as the bound for the 0xAA fill, so if code and stack share
 * one region, paint runs across `.text` and corrupts the program.
 *
 * Split the DRAM logically: FLASH holds `.text` + `.rodata`, RAM holds
 * `.data` + `.bss` + `.heap` + `.stack`. Sizes are picked so the krabitls
 * RSA-2048 build (~60 KiB of code) fits in FLASH, with room for the 16 KiB
 * scratch buffers and ~30 KiB of stack in RAM.
 */
MEMORY
{
    FLASH : ORIGIN = 0x80000000, LENGTH = 128K
    RAM   : ORIGIN = 0x80020000, LENGTH = 128K
}

REGION_ALIAS("REGION_TEXT", FLASH);
REGION_ALIAS("REGION_RODATA", FLASH);
REGION_ALIAS("REGION_DATA", RAM);
REGION_ALIAS("REGION_BSS", RAM);
REGION_ALIAS("REGION_HEAP", RAM);
REGION_ALIAS("REGION_STACK", RAM);

_ram_length = LENGTH(RAM);
