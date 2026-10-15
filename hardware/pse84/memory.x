/* PSoC Edge E84 all-Secure SRAM qualification image. */
MEMORY
{
  FLASH : ORIGIN = 0x34008000, LENGTH = 128K
  RAM   : ORIGIN = 0x34028000, LENGTH = 192K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
