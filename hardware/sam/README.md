# KrabiTLS Microchip SAM hardware backends

This crate groups hardware adapters by SAM silicon family while keeping their
different accelerator generations explicit. Select exactly one device-family
feature.

The initial implementation supports SAM D5x/E5x:

- `aes`: peripheral AES-128 with software GHASH for TLS AES-GCM;
- `p256-kx`: ROM PUKCL/PUKCC P-256 ECDH.

PUKCL is not a shared facility across SAM4 and SAM E/S/V7x. Those families may
gain AES, SHA, or TRNG modules under separate features, but they must not expose
the SAME5x PUKCL backend without device-specific ABI qualification.

Applications own clocks, interrupt policy, exclusive peripheral access, TRNG
seeding, and board initialization.
