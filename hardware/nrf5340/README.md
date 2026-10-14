# KrabiTLS nRF5340 hardware backend

This crate implements AES-128-GCM with the nRF5340 application core's
CryptoCell-312 AES and GHASH engines. `Nrf5340Aead` selects it through
KrabiTLS's existing `AeadBackend` interface. It is intended for Secure code;
the adapter accesses the Secure CryptoCell register aliases.

The implementation is synchronous and allocation-free. A process-global lock
serializes calls made through this adapter, every hardware wait is bounded,
and an operation gates the engine clocks and clears its AES key, GHASH subkey,
and accumulator registers on both success and failure. Authentication failures
and hardware failures erase the caller's output buffer. Rust key storage uses
`Zeroizing` and is wiped by `Drop`.

## Integration contract

The application must ensure no code outside this adapter uses CryptoCell while
an operation is active. The adapter's lock cannot coordinate with another
driver, debugger, or Non-secure user of the peripheral. The application also
owns interrupt policy and the security attribution that makes CryptoCell a
Secure peripheral.

The adapter leaves the CryptoCell subsystem enabled after first use while
gating the AES, GHASH, and DMA clocks between calls. Nordic's full power-down
handshake is terminal for a period of ownership; `AeadBackend` provides no
peripheral-lifetime hook in which to perform it. The application must call
`shutdown()` when it knows no later backend call can occur. A successful
shutdown follows the documented idle, interrupt-clear, power-down-request, and
disable sequence and makes later adapter calls fail without touching hardware.
A cleanup that remains non-idle even after DMA reset also force-disables and
permanently poisons the adapter; apparently successful record output is rejected
when cleanup cannot establish that sensitive state was cleared.

CryptoCell DMA reads 16-byte RAM blocks. The adapter therefore bounces every
AES/GHASH input block through aligned stack storage. Callers may supply
unaligned records and AAD in flash, but this constraint forces a copy for every
block. Mutable record output must reside in writable memory as required by
`AeadInOut`.

The current traits impose a few additional compromises:

- `KeyInit` is infallible, so peripheral contention and hardware startup errors
  can only surface when the first record operation runs.
- `AeadInOut` reduces all failures to `aead::Error`; `last_error()` retains the
  most recent global `Busy`, `PoweredDown`, `Timeout`, `Hardware`, or
  `Authentication` diagnostic for bring-up and telemetry.
- `AeadBackend` names types but carries no peripheral token or driver context,
  requiring a process-global peripheral and lock.
- The synchronous AEAD contract requires bounded polling rather than an
  interrupt-driven or asynchronous completion path.
- KrabiTLS stores raw traffic-key bytes and constructs a cipher for each
  record, so this interface cannot provide managed-key custody.

## Hardware qualification

The `qualify` example borrows only linker, startup, RTT, and probe conventions
from Astrum's nRF5340 bring-up; it has no Astrum dependency. It covers the NIST
empty-message, single-block, and partial-block/AAD vectors, encryption and
decryption, bad-tag rejection, injected timeout and recovery, output erasure,
key wiping, and a KrabiTLS TLS 1.3 record encrypt/decrypt/bad-tag cycle. The
image also reads back the GHASH accumulator and CryptoCell host-idle state
after cleanup; the AES key and GHASH subkey registers themselves are
write-only. Its final step exercises terminal power-down and verifies that a
later operation is rejected.

On 2026-10-14 it passed on the attached nRF5340 DK application core (probe
`1366:1060:001050013763`):

```console
cd hardware/nrf5340
cargo run --release --features qualification --example qualify
# ...
PASS: KrabiTLS TLS record encrypt/decrypt and bad-tag rejection
PASS: terminal power-down handshake
PASS: post-shutdown operation rejected
CRYPTOCELL QUALIFICATION PASS
```

The included runner selects an attached nRF5340 probe. A multi-probe rig can
override `target.thumbv8m.main-none-eabihf.runner` with Cargo's `--config`
option to add a probe selector, or flash the ELF by another method.
