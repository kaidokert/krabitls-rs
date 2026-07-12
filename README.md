### KrabiTLS

[![crate](https://img.shields.io/crates/v/krabitls.svg)](https://crates.io/crates/krabitls)
[![documentation](https://docs.rs/krabitls/badge.svg)](https://docs.rs/krabitls/)
[![Rust](https://github.com/kaidokert/krabitls-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/krabitls-rs/actions/workflows/rust.yml)
[![Footprint](https://github.com/kaidokert/krabitls-rs/actions/workflows/footprint.yml/badge.svg)](https://github.com/kaidokert/krabitls-rs/actions/workflows/footprint.yml)
[![Coverage Status](https://coveralls.io/repos/github/kaidokert/krabitls-rs/badge.svg?branch=main)](https://coveralls.io/github/kaidokert/krabitls-rs?branch=main)

A hobby `no_std` TLS 1.3 client for microcontrollers. Don't use it for anything you care about.

- TLS 1.3; X25519 or X25519MLKEM768 key exchange
- Verifies Ed25519, RSA, ECDSA (P-256/P-384), or ML-DSA server certificates
- Bundled trust is pin-a-pubkey or trust-SAN — no CA bundle or chain walking; verification is a pluggable `VerifyStrategy`
- Hand-rolled, unaudited, not constant-time, no scalar blinding

No heap allocations, and prefer reduced flash + stack size over speed.

#### Resource usage

Cortex-M3 and RV32IMAC footprint — real-minus-baseline `.text` and peak stack.

| Target   | Suite             | KEX / Sig                  | .text (KiB) | Stack (B) |
|----------|-------------------|----------------------------|------------:|----------:|
| M3       | ChaCha20-Poly1305 | X25519 / Ed25519           |        37.3 |     10916 |
| M3       | AES-128-GCM       | X25519 / Ed25519           |        41.8 |     16444 |
| M3       | AES-128-GCM       | X25519 / RSA-2048-PSS      |        55.5 |     31292 |
| M3       | AES-128-GCM       | X25519 / ECDSA-P256        |        58.4 |     20668 |
| M3       | AES-128-GCM       | X25519MLKEM768 / ML-DSA-44 |        60.6 |    117252 |
| RV32IMAC | ChaCha20-Poly1305 | X25519 / Ed25519           |        55.9 |     10692 |
| RV32IMAC | AES-128-GCM       | X25519 / Ed25519           |        65.2 |     16212 |
| RV32IMAC | AES-128-GCM       | X25519 / RSA-2048-PSS      |        88.2 |     31012 |
| RV32IMAC | AES-128-GCM       | X25519 / ECDSA-P256        |        90.4 |     20300 |
| RV32IMAC | AES-128-GCM       | X25519MLKEM768 / ML-DSA-44 |        93.0 |    117112 |

## License

Apache 2.0; see [`LICENSE`](LICENSE) for details.
