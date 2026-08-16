### KrabiTLS

[![crate](https://img.shields.io/crates/v/krabitls.svg)](https://crates.io/crates/krabitls)
[![documentation](https://docs.rs/krabitls/badge.svg)](https://docs.rs/krabitls/)
[![Rust](https://github.com/kaidokert/krabitls-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/krabitls-rs/actions/workflows/rust.yml)
[![Footprint](https://github.com/kaidokert/krabitls-rs/actions/workflows/footprint.yml/badge.svg)](https://github.com/kaidokert/krabitls-rs/actions/workflows/footprint.yml)
[![Coverage Status](https://coveralls.io/repos/github/kaidokert/krabitls-rs/badge.svg?branch=main)](https://coveralls.io/github/kaidokert/krabitls-rs?branch=main)

A hobby `no_std` TLS 1.3 client for microcontrollers. Don't use it for anything you care about.

- TLS 1.3; X25519 or X25519MLKEM768 key exchange
- Verifies Ed25519, RSA, ECDSA (P-256/P-384), or ML-DSA server certificates
- RSA is 2048-bit; 1024/3072/4096 are opt-in cargo features
- Optional mutual-TLS client certificates (Ed25519 or RSA-PSS)
- Bundled trust is pin-a-pubkey or trust-SAN — no CA bundle or chain walking; verification is a pluggable `VerifyStrategy`
- Hand-rolled and unaudited; constant-time primitives, with opt-in power/EM-DPA blinding (key exchange + signing) behind the `blinding` feature

No heap allocations, and prefer reduced flash + stack size over speed. On builds
that use several signature algorithms, the `bigint-heapless` feature cuts code
size at the cost of some wasted stack.

#### Resource usage

Peak stack and `.text` for a full TLS 1.3 handshake (real − baseline, QEMU).
A few corners of the range on Cortex-M3; the `+ client cert` column is mutual
TLS. Full grid for both M3 and RV32IMAC, all key-exchange / cipher / signature
combinations: [`FOOTPRINT.md`](FOOTPRINT.md).

| KEX            | AEAD              | Server cert  | .text (KiB) | Stack (B) | + client cert |
|----------------|-------------------|--------------|------------:|----------:|--------------:|
| X25519         | ChaCha20-Poly1305 | Ed25519      |        37.5 |    10 660 |             — |
| X25519         | AES-128-GCM       | ECDSA-P256   |        58.5 |     9 716 |        12 844 |
| P-256 ECDHE    | AES-128-GCM       | Ed25519      |        50.1 |    12 884 |             — |
| X25519         | AES-128-GCM       | RSA-2048-PSS |        47.8 |    29 492 |        47 268 |
| X25519MLKEM768 | AES-128-GCM       | ML-DSA-44    |        62.1 |   107 668 |             — |

Smallest flash is ChaCha20/Ed25519; smallest stack is ECDSA-P256 (its verify is
shallow, though its `.text` is among the largest); the post-quantum
X25519MLKEM768 / ML-DSA-44 corner is ~10× the stack. RV32IMAC spans the same
range at ≈1.5× the `.text`: ChaCha20/Ed25519 ~56.7 KiB / 10 524 B, the PQC corner
~96.2 KiB / 111 640 B.

## License

Apache 2.0; see [`LICENSE`](LICENSE) for details.
