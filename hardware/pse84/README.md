# PSoC Edge E84 backend

This crate provides an AES-128-GCM `AeadBackend` and a fallible cryptographic
RNG using the E84 MXCRYPTO v2 register/instruction interface. AES blocks run in
hardware; a constant-time Rust GHASH layer supplies the GCM composition. It
links no Infineon C code or binary library.

Board code must enable the CRYPTO peripheral clock, assign the peripheral and
DMA-visible SRAM to the caller's security domain, and ensure no ROM service,
interrupt handler, second core, or other firmware accesses CRYPTO. Once those
conditions hold, it may call `Pse84Crypto::claim_after_board_init`. The token is
the ownership boundary; its RNG borrows it and AEAD operations fail when no
token is live.

Operations are synchronous and globally serialized. All FIFO, AES, and TRNG
waits are bounded. A timeout or hardware/health error resets the peripheral;
successful operations clear the CRYPTO register file before power-down. Keys
remain in zeroizing Rust storage for the lifetime of an AEAD value and are
reloaded only for a serialized operation. The adapter does not provide key
slots or protection from code executing in the same security domain.

AES transfers use dedicated 32-byte-aligned staging lines. The adapter cleans
inputs before DMA and invalidates output afterward when D-cache is enabled, so
the same code is valid on the E84 M33 and M55. Dropping the ownership token
either resets an idle engine or leaves reset to the active operation's cleanup;
it never resets CRYPTO underneath an operation.

Entropy is not released until the hardware repetition-count and adaptive-
proportion monitors have observed a complete 512-bit startup window. The token
also retains the previous accepted word and rejects identical consecutive
words across separate RNG calls. These are online failure tests, not a claim of
entropy-source certification.

The included E84 SRAM qualification image is board harness only. It is not an
Astrum dependency and does not move clock/security initialization into this
crate.

Run it with `cargo run --release --features qualification --example qualify`.
The runner defaults to the repository test rig's KitProg3 serial and accepts
`PSE84_PROBE` and `PSE84_CHIP` overrides.
