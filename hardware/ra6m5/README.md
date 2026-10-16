# Renesas RA6M5 SCE9 backend

This crate adapts the RA6M5 SCE9 protected-mode API to KrabiTLS. It provides
hardware entropy, incremental SHA-256, HMAC/HKDF, generated wrapped AES-128-GCM
keys, generated wrapped P-256 keys, ECDSA client authentication, and the SCE9
authenticated ECDHE → SP800-56C KDF → wrapped AES path. Private scalars, ECDH
shared secrets, and derived AES keys stay device-bound and have no byte-export
API.

Board code owns clocks, TrustZone attribution, and exclusive SCE9 access. It
must also provide an independent reset deadline to
`Sce9Crypto::claim_after_board_init`. Renesas control procedures contain
hardware wait loops with no cancellation path; returning while an operation
still references stack buffers would be unsound. The adapter therefore arms
the board deadline around every protected call, serializes all access, wipes
wrapped material on drop, and clears unauthenticated plaintext on failure.

The adapter compiles the official protected SCE9 sources from Renesas FSP
v6.6.0, commit `6e2675336b37fbd805f0c01d5134adfdab4bf294`. Set
`RENESAS_FSP_PATH` to that checkout when building for ARM. No generated board
project, prebuilt library, or Renesas source is copied into this repository.

## TLS 1.3 boundary

SCE9 protected mode cannot implement KrabiTLS's complete TLS 1.3 P-256/AES
backend without exposing secrets:

- `PublicKeyReadWithoutSignature` accepts a TLS-shaped peer point, but on the
  qualified RA6M5 its resulting public wrapper is rejected by
  `SharedSecretCalculate`. The SCE-authenticated peer-import path succeeds, but
  TLS 1.3 authenticates the server only after deriving handshake traffic keys.
- A successful protected ECDH operation returns an opaque wrapped secret.
  SCE9 can feed it only to its SP800-56C one-step KDF, not TLS 1.3 HKDF.
- Protected mode cannot import an arbitrary runtime TLS traffic key into AES;
  its key-import API requires an offline encrypted provisioning package.

Consequently this crate does not pretend to implement `KxGroup` or
`AeadBackend`. The supported complete TLS 1.3 composition uses KrabiTLS's
software P-256 and AES implementations with `Sce9Hkdf` and `Sce9Rng`; long-term
ECDSA client keys can still remain wrapped in SCE9 through `Sce9P256Signer`.
The qualification image exercises that complete KrabiTLS flow separately from
the fully protected SCE9 ECDHE/KDF/AES chain.

SCE9's dedicated TLS functions are TLS 1.2-specific and are intentionally not
used. RSA, AES-256, CCM, CMAC, persistent provisioned keys, and HMAC-wrapped
SP800-56C salt keys are also outside this first backend.

## Qualification

From this directory:

```console
RENESAS_FSP_PATH=/path/to/fsp cargo test
RENESAS_FSP_PATH=/path/to/fsp cargo clippy --all-targets -- -D warnings
RENESAS_FSP_PATH=/path/to/fsp \
  cargo build --target thumbv8m.main-none-eabihf \
  --release --features qualification --example qualify
probe-rs run --probe 1366:0101:000831389070 --chip R7FA6M5BH \
  --no-catch-hardfault \
  target/thumbv8m.main-none-eabihf/release/examples/qualify
```

The bare-metal image selects the conservative 20 MHz HOCO clock and checks
positive SHA-256/HMAC/HKDF vectors, transcript cloning, entropy, generated
wrapped AES-GCM, tag rejection and recovery, wrapped-secret zeroization,
authenticated wrapped P-256
ECDHE, wrapped SP800-56C derivation into AES, invalid-peer rejection, raw and
KrabiTLS ECDSA signing, invalid signatures, and the complete KrabiTLS software
P-256 → SCE9 key schedule → authenticated record fallback.

On 2026-10-15 the attached EK-RA6M5 completed with:

```text
PASS wrapped P-256 ECDH/KDF/AES and invalid peer
PASS ECDSA raw and KrabiTLS ClientAuth flow
PASS KrabiTLS P-256 + SCE9 key schedule + record flow
RA6M5 SCE9 QUALIFICATION PASS
```
