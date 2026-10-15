# EFM32PG26 Secure Engine backend

This crate provides direct-register KrabiTLS backends for the EFM32PG26B500
Secure Engine: AES-128-GCM, TRNG, SHA-256/HMAC/HKDF, and P-256 ECDHE. It uses
the documented SEMAILBOX command and DMA-descriptor interface and links no
Silicon Labs C, PSA, or binary library.

Board code owns SEMAILBOX clocking, TrustZone attribution, interrupts, linker
placement, and exclusive ownership outside this crate. After establishing
those conditions it may call `Pg26Crypto::claim_after_board_init`. Operations
are synchronous, globally serialized, and allocation-free. Every mailbox wait
is bounded. Decoded command failures release ownership for the next operation.
A timeout before submission poisons the adapter until board code establishes a
reset boundary; after submission, the SE may still own stack-backed DMA
descriptors and exposes no cancellation command, so timeout or mailbox protocol
loss immediately requests a system reset rather than returning dangling DMA
pointers.

AES keys live in zeroizing Rust storage and are exposed to the SE only during a
serialized DMA operation. Generated P-256 private scalars are returned directly
as 60-byte authenticated PUF-wrapped blobs; public-key export and ECDH consume
that blob in the SE, so plaintext scalar material never enters application
memory. ECDH output and TLS traffic keys necessarily enter software memory for
KrabiTLS's key schedule and record layer. Authentication failures wipe record
output, and wrapped secrets and intermediate key material wipe on drop.

The command values, key specifications, descriptor layout, and wrapped-key
overhead were checked against Silicon Labs' EFM32PG26 DFP 2025.12.1 and
Simplicity SDK `sisdk-2025.6` at commit
`b41bec3ff2485199c1a5a9995b3e649e118c1b8d`. Wider SE support such as signing,
verification, persistent keys, and additional curves is deliberately deferred.

## Qualification

The bare-metal example owns only the minimal PG26 board setup and has no Astrum
dependency. It checks standard SHA-256, HMAC, HKDF, and AES-GCM vectors; entropy
and continuous-health rejection; bad-tag wiping; two wrapped P-256 key
agreements; invalid-peer rejection; command-error recovery; and secret wiping.
It then cross-checks hardware P-256 against software and runs the result through
KrabiTLS's hardware HKDF key schedule and authenticated record path.

On 2026-10-15 it passed on the attached EFM32PG26B500F3200IM68 using probe
`1366:0105:000440339259`:

```console
cd hardware/pg26
cargo run --release --features qualification --example qualify
# ...
PASS: wrapped P-256 agreement
PASS: wrapped P-256 + hardware key schedule + authenticated record
PG26 QUALIFICATION COMPLETE
```

The runner carries a local probe-rs target description because upstream
probe-rs does not yet identify this exact PG26 part.
