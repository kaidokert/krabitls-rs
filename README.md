### KrabiTLS

[![crate](https://img.shields.io/crates/v/krabitls.svg)](https://crates.io/crates/krabitls)
[![documentation](https://docs.rs/krabitls/badge.svg)](https://docs.rs/krabitls/)
[![Rust](https://github.com/kaidokert/krabitls-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/krabitls-rs/actions/workflows/rust.yml)
[![Footprint](https://github.com/kaidokert/krabitls-rs/actions/workflows/footprint.yml/badge.svg)](https://github.com/kaidokert/krabitls-rs/actions/workflows/footprint.yml)
[![Coverage Status](https://coveralls.io/repos/github/kaidokert/krabitls-rs/badge.svg?branch=main)](https://coveralls.io/github/kaidokert/krabitls-rs?branch=main)

A hobby `no_std` TLS 1.3 client for microcontrollers. Don't use it for anything you care about.

- TLS 1.3; X25519, P-256 ECDHE, or X25519MLKEM768 key exchange
- Verifies Ed25519, RSA, ECDSA (P-256/P-384), or ML-DSA server certificates
- RSA is 2048-bit; 1024/3072/4096 are opt-in cargo features
- Optional mutual-TLS client certificates (Ed25519 or RSA-PSS)
- Bundled trust is pin-a-pubkey or trust-SAN — no CA bundle or chain walking; verification is a pluggable `VerifyStrategy`
- Hand-rolled and unaudited; constant-time primitives, with opt-in power/EM-DPA blinding (key exchange + signing) behind the `blinding` feature

No heap allocations, and prefer reduced flash + stack size over speed. On builds
that use several signature algorithms, the `bigint-heapless` feature cuts code
size at the cost of some wasted stack.

#### Resource usage

Example peak stack and `.text` for a full TLS 1.3 handshake (representative
measurement, real − baseline, on QEMU). `+ client cert` is the same handshake
with mutual TLS (a same-algorithm client certificate). The `.text` and `Stack`
columns are the server-auth build. Full grid — P-256 ECDHE and X25519MLKEM768
key exchange, ML-DSA server certs, both targets — in
[`FOOTPRINT.md`](FOOTPRINT.md).

| Target   | Server cert  | AEAD              | KEX            | .text (KiB) | Stack (B) | + client cert |
|----------|--------------|-------------------|----------------|------------:|----------:|--------------:|
| M3       | Ed25519      | ChaCha20-Poly1305 | X25519         |        37.5 |    10 660 |        12 668 |
| M3       | Ed25519      | AES-128-GCM       | X25519         |        41.0 |    10 604 |        12 484 |
| M3       | ECDSA-P256   | AES-128-GCM       | X25519         |        58.5 |     9 716 |        12 844 |
| M3       | RSA-2048-PSS | AES-128-GCM       | X25519         |        47.8 |    29 492 |        47 276 |
| M3       | ML-DSA-44    | AES-128-GCM       | X25519MLKEM768 |        62.1 |   107 668 |             — |
| RV32IMAC | Ed25519      | AES-128-GCM       | X25519         |        63.9 |    10 476 |        12 396 |
| RV32IMAC | ML-DSA-44    | AES-128-GCM       | X25519MLKEM768 |        96.2 |   111 640 |             — |

RV32IMAC shows the most-common and post-quantum configs (same as their M3 rows)
to demonstrate the cross-architecture delta — stack within a few percent, `.text`
≈1.5×. P-256 ECDHE key exchange (~12.9 KB stack) and the full grid are in
[`FOOTPRINT.md`](FOOTPRINT.md).

## License

Apache 2.0; see [`LICENSE`](LICENSE) for details.
