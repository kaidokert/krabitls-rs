### KrabiTLS

[![crate](https://img.shields.io/crates/v/krabitls.svg)](https://crates.io/crates/krabitls)
[![documentation](https://docs.rs/krabitls/badge.svg)](https://docs.rs/krabitls/)
[![Rust](https://github.com/kaidokert/krabitls-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/krabitls-rs/actions/workflows/rust.yml)
[![Footprint](https://github.com/kaidokert/krabitls-rs/actions/workflows/footprint.yml/badge.svg)](https://github.com/kaidokert/krabitls-rs/actions/workflows/footprint.yml)
[![Coverage Status](https://coveralls.io/repos/github/kaidokert/krabitls-rs/badge.svg?branch=main)](https://coveralls.io/github/kaidokert/krabitls-rs?branch=main)

A hobby `no_std` TLS 1.3 client for microcontrollers. Don't use it for anything you care about.

- X25519 and TLS 1.3 only, and verifies only Ed25519 / RSA-PSS server keys — won't connect to many real-world servers
- Trust model is "pin a pubkey or trust SAN" — no CA bundle, no chain walking
- Hand-rolled, unaudited, not constant-time, no scalar blinding

No heap allocations, and prefer reduced flash + stack size over speed.

#### Resource usage (as of version 0.1.0)

Cortex-M3 and RV32IMAC footprint. Values are real-minus-baseline deltas from
the Footprint workflow's step summary. Wire-data scratch buffers live in
`.bss` (via `footprint_handshakes::with_buffers`), so the stack column
reflects only the crypto + protocol cost.

| Target   | Suite             | Sig          | .text (KiB) | Stack (B) |
|----------|-------------------|--------------|------------:|----------:|
| M3       | ChaCha20-Poly1305 | Ed25519      |        35.4 |     10692 |
| M3       | AES-128-GCM       | Ed25519      |        40.1 |     15844 |
| M3       | AES-128-GCM       | RSA-2048-PSS |        53.8 |     27280 |
| RV32IMAC | ChaCha20-Poly1305 | Ed25519      |        53.8 |     10436 |
| RV32IMAC | AES-128-GCM       | Ed25519      |        63.3 |     15604 |
| RV32IMAC | AES-128-GCM       | RSA-2048-PSS |        86.4 |     30484 |

## License

Apache 2.0; see [`LICENSE`](LICENSE) for details.
