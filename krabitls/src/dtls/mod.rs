//! DTLS 1.3 (RFC 9147) datagram client.
//!
//! The cryptography — key schedule ([`crate::hkdf`]), cipher suites and AEAD
//! ([`crate::aead`]), the certificate/verify path, and the `bigint` carriers —
//! is shared unchanged with the TLS 1.3 client; DTLS differs only in the record
//! framing and the handshake reliability layer, which live here.
//!
//! The public surface is [`DatagramTransport`] (the caller's UDP adapter) and
//! [`DtlsStream`] (the blocking client façade over it); the record/handshake
//! internals stay crate-private.
//!
//! Explicit-panic constructs are compile-forbidden in this module's non-test
//! code: `unwrap`, `expect`, and `panic!` are denied, so every failure path is a
//! typed error instead. (Slice indexing is *not* denied — the parsers use an
//! up-front length guard then index, which `clippy::indexing_slicing` flags even
//! when provably safe; converting the whole codec to `.get()?` costs readability
//! for no real gain, so bounds rest on those guards, verified by review.)

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

// The record, framing, and replay primitives are consumed by tests and by the
// DTLS handshake driver; parts of the surface a given build doesn't reach are
// allowed to be unused.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod ack;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod client;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod framing;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod handshake;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod keys;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod reassembly;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod record;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod replay;
#[cfg(any(feature = "cipher-aes", feature = "chacha20"))]
pub(crate) mod stream;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod transport;

pub use client::DtlsClientError;
#[cfg(any(feature = "cipher-aes", feature = "chacha20"))]
pub use stream::DtlsStream;
pub use transport::DatagramTransport;
