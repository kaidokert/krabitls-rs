/* QEMU mps2-an385 (Cortex-M3) memory map — matches the krabipqc_cortex_m3
   harness so the post-quantum rows measure on the same board the PQC crate
   already uses. ML-DSA-44 verify peaks around ~50 KB of stack, and the
   64 KB lm3s6965evb part was already nearly full at the RSA row (≈27 KB
   stack + ≈37 KB wire scratch), so 256 KB gives headroom without overflow.
   Stack high-water is RAM-size-independent, so the classical rows measure
   identically here. */
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 4M
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
_ram_length = LENGTH(RAM);
