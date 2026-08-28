# KrabiTLS STM32 hardware backends

This crate is the common home for STM32-family adapters. Select an exact
device feature; family-specific register drivers remain isolated so similarly
named peripherals are not assumed to be interchangeable.

The initial `stm32h533` implementation provides:

- `aes`: native STM32H5 AES-128-GCM through KrabiTLS `AeadBackend`;
- `kx`: PKA-backed X25519 and P-256 ECDH through `KxBackend`.

The application must enable the AES and PKA clocks and guarantee exclusive
access for each blocking operation. This crate does not configure RCC, steal
clock ownership, or initialize the board. PKA operand RAM is outside the PAC
model and is accessed and cleared with volatile operations.

These paths were ported from the STM32H533RE bring-up suite, where AES-GCM,
RFC 7748 X25519, and P-256 ECDH were checked on silicon. The fixed-command
X25519 ladder and secret clearing do not claim resistance to power or EM
analysis.
