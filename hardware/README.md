# Hardware backends

These crates adapt selected MCU cryptography peripherals to KrabiTLS's public
backend traits. They are libraries, not board-support packages: applications
remain responsible for clocks, interrupt policy, peripheral ownership, entropy
seeding, linker configuration, and networking.

- `nrf52833` exposes the nRF52833 ECB engine as an AES-128 block primitive and
  TLS AES-GCM backend. The chip has no public-key accelerator, so key exchange
  remains software.
- `sam` groups Microchip SAM hardware by silicon family. Its first backend is
  SAM D5x/E5x AES plus the ROM-resident PUKCL/PUKCC P-256 key-exchange path.
  SAM4 and SAM E/S/V7x parts do not share that PUKCL facility; future support
  belongs behind separate family features rather than the SAME5x implementation.

The crates are initially unpublished and independently addressable with
`--manifest-path`; the repository deliberately has no root Cargo workspace.
