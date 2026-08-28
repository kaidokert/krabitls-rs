# KrabiTLS nRF52833 hardware backend

This crate exposes the nRF52833 ECB peripheral as a RustCrypto-compatible
AES-128 primitive and `NrfAead` KrabiTLS backend. GHASH remains software.

The application must ensure ECB does not overlap CCM or AAR use. Clocks,
interrupt policy, peripheral ownership, and failure recovery remain
application responsibilities.
