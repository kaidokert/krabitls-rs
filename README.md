### KrabiTLS

[![Rust](https://github.com/kaidokert/krabitls-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/krabitls-rs/actions/workflows/rust.yml)
[![Cortex-M](https://github.com/kaidokert/krabitls-rs/actions/workflows/cortex_m.yml/badge.svg)](https://github.com/kaidokert/krabitls-rs/actions/workflows/cortex_m.yml)

A hobby `no_std` TLS 1.3 client for microcontrollers. Don't use it for anything you care about.

- Locked to one cipher / curve / sig combo per build — won't negotiate with most servers
- Trust model is "pin a pubkey or trust SAN" — no CA bundle, no chain walking
- Hand-rolled, unaudited, not constant-time, no scalar blinding

No heap allocations, and prefer reduced flash + stack size over speed.

#### Resource usage (as of version 0.1.0)

Cortex-M3 footprint. Values are real-minus-baseline deltas from the Cortex-M
workflow's step summary. Wire-data scratch buffers live in `.bss` (via
`with_buffers`), so the stack column reflects only the crypto + protocol cost.

| Target | Suite             | Sig          | .text (KiB) | Stack (B) |
|--------|-------------------|--------------|------------:|----------:|
| M3     | AES-128-GCM       | Ed25519      |        32.8 |      5764 |
| M3     | ChaCha20-Poly1305 | Ed25519      |        28.3 |      5716 |
| M3     | AES-128-GCM       | RSA-2048-PSS |        42.5 |     15572 |

## License

Apache 2.0; see [`LICENSE`](LICENSE) for details.
