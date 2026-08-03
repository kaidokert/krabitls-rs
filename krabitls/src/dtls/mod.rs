//! DTLS 1.3 (RFC 9147) datagram client.
//!
//! The cryptography — key schedule ([`crate::hkdf`]), cipher suites and AEAD
//! ([`crate::aead`]), the certificate/verify path, and the `bigint` carriers —
//! is shared unchanged with the TLS 1.3 client; DTLS differs only in the record
//! framing and the handshake reliability layer, which live here.
//!
//! This module is built up in phases. Landed so far: the record layer
//! ([`record`]) — the unified header codec, record-number encryption, and
//! per-epoch key state — and the anti-replay window ([`replay`]).

// The record, framing, and replay primitives are consumed by tests and by the
// DTLS handshake engine; where the engine is not yet present, a non-test build
// sees them as unused.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod framing;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod record;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod replay;
