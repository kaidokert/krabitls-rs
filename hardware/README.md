# Hardware backends

These crates adapt selected MCU cryptography peripherals to KrabiTLS's public
backend traits. They are libraries, not board-support packages: applications
remain responsible for clocks, interrupt policy, peripheral ownership, entropy
seeding, linker configuration, and networking.

- `nrf52833` exposes the nRF52833 ECB engine as an AES-128 block primitive and
  TLS AES-GCM backend. The chip has no public-key accelerator, so key exchange
  remains software.
- `nrf5340` provides native CryptoCell-312 AES-128-GCM and a bare-metal
  qualification image for the nRF5340 application core.
- `pse84` provides PSoC Edge E84 register-level AES-128-GCM and true entropy,
  with no vendor C or binary dependency.
- `pg26` drives the EFM32PG26 Secure Engine mailbox directly for AES-128-GCM,
  entropy, SHA-256/HMAC/HKDF, and PUF-wrapped P-256 ECDHE, with no vendor C or
  PSA dependency.
- `ra6m5` compiles the pinned Renesas FSP SCE9 protected-mode sources for
  entropy, SHA-256/HMAC/HKDF, wrapped AES-GCM, wrapped P-256 ECDHE/KDF, and
  ECDSA. Its README documents why opaque SCE9 ECDHE and AES keys cannot form a
  native TLS 1.3 backend and the supported software-KX/AEAD composition.
- `sam` groups Microchip SAM hardware by silicon family. Its first backend is
  SAM D5x/E5x AES plus the ROM-resident PUKCL/PUKCC P-256 key-exchange path.
  SAM4 and SAM E/S/V7x parts do not share that PUKCL facility; future support
  belongs behind separate family features rather than the SAME5x implementation.
- `stm32` groups STM32 adapters behind exact device features. Its initial H533
  backend provides native AES-GCM and PKA-backed X25519/P-256 key exchange.

The crates are initially unpublished and independently addressable with
`--manifest-path`; the repository deliberately has no root Cargo workspace.
