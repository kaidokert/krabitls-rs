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

/* riscv-rt's link.x places `.eh_frame` / `.eh_frame_hdr` as `(INFO)` sections
 * with no anchor region; lld defaults them to address 0, so PCREL32 fixups
 * from `.text` at 0x80000000 overflow as soon as the binary grows past a few
 * KiB. We ship with `panic = "abort"` and don't unwind, so discard the input
 * sections outright. `-T memory.x` is parsed before `-T link.x`, so this
 * `/DISCARD/` claims the `.eh_frame*` inputs first. */
SECTIONS {
    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame.*)
        *(.eh_frame_hdr)
    }
}
