# KrabiTLS nRF5340 hardware backend

This crate implements AES-128-GCM, entropy, and P-256 ECDH with the nRF5340
application core's CryptoCell-312. `Nrf5340Aead`, `Nrf5340Rng`, and
`Nrf5340Kx` select them through KrabiTLS's existing AEAD, fallible RNG, and key
exchange interfaces. It is intended for Secure code and accesses the Secure
CryptoCell aliases.

The implementation is synchronous and allocation-free. AES-GCM drives the raw
PAC, giving the adapter bounded waits and explicit cleanup. Entropy and ECC use
Nordic's supported binary CryptoCell libraries: the PAC exposes only the PKA's
modular-arithmetic machinery, so a direct driver would also need the complete
constant-time curve algorithm. The exact nRF Connect SDK 3.4.1 archives,
license, checksums, and PSA ABI source revision are recorded under
`vendor/nrfxlib`.

A process-global lock serializes raw and Nordic-library calls. Authentication
and hardware failures erase caller output, Rust key storage uses `Zeroizing`,
and terminal shutdown deinitializes Nordic's platform state before the raw
peripheral power-down.

## Integration contract

The application must ensure no code outside this adapter uses CryptoCell while
an operation is active. The adapter's lock cannot coordinate with another
driver, debugger, or Non-secure user of the peripheral. The application also
owns interrupt policy and the security attribution that makes CryptoCell a
Secure peripheral.

The adapter leaves the subsystem enabled after first use while gating the raw
AES, GHASH, and DMA clocks between calls. Full power-down is terminal for a
period of ownership; the backend traits provide no peripheral-lifetime hook.
The application must call `shutdown()` only when no later backend call can
occur. Cleanup failure force-disables and permanently poisons the adapter, and
apparently successful output is rejected if cleanup cannot establish that
sensitive state was cleared.

CryptoCell DMA reads 16-byte RAM blocks. The raw adapter bounces every AES and
GHASH input block through aligned stack storage. Callers may supply unaligned
records and AAD in flash, but mutable record output must be writable.

The current interfaces impose a few compromises:

- `KeyInit` is infallible, so startup and contention errors surface on the first
  record operation.
- `AeadInOut` reduces failures to `aead::Error`; `last_error()` retains a
  detailed global diagnostic for bring-up and telemetry.
- Backend traits carry no peripheral token or driver context, requiring a
  process-global peripheral and lock.
- `KxGroup` fits ephemeral ECDH without changes: generation owns a fallible RNG,
  the scalar moves in a zeroize-on-drop holder, and derivation consumes it.
- The TLS stack receives the raw ECDH result for HKDF, so this backend does not
  provide managed-key or fully hardware-confined custody.
- Nordic's binary PKA implementation exposes neither its polling loop nor a
  cancellation hook. Qualification can inject an adapter-boundary timeout and
  verify recovery, but cannot bound an actual hang inside that opaque call.
  Raw-PKA ownership would be required to close that limitation.

## Hardware qualification

The `qualify` example borrows linker, startup, RTT, and probe conventions from
Astrum's nRF5340 bring-up but has no Astrum dependency. Alongside NIST AES-GCM
vectors and failure cleanup, it exercises CryptoCell entropy, the RFC 5903
P-256 vector, hardware/software cross-agreement, eight generated-key
agreements, invalid-peer rejection, injected error recovery, and secret-buffer
wiping. It feeds a hardware ECDH result through KrabiTLS's TLS 1.3 handshake
key schedule and a hardware AES record round trip. Finally it deinitializes the
Nordic library, powers down CryptoCell, and verifies later calls fail.

On 2026-10-14 it passed on the attached nRF5340 DK application core (probe
`1366:1060:001050013763`):

```console
cd hardware/nrf5340
cargo run --release --features qualification --example qualify
# ...
PASS: RFC 5903 shared secret
PASS: KrabiTLS P-256, TLS 1.3 key schedule, and record round trip
PASS: KrabiTLS TLS record encrypt/decrypt and bad-tag rejection
PASS: terminal power-down handshake
CRYPTOCELL QUALIFICATION PASS
```

The included runner selects an attached nRF5340 probe. A multi-probe rig can
override `target.thumbv8m.main-none-eabihf.runner` with Cargo's `--config`
option to add a probe selector, or flash the ELF by another method.
