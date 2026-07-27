//! krabitls TLS 1.3 client over the [`embedded-nal`](embedded_nal) network
//! abstraction — the reusable core shared by the `nal_connect` host binary and
//! any target demo.
//!
//! Layers, each independently reusable:
//! - [`transport`] — [`NalTransport`](transport::NalTransport) bridges any
//!   [`embedded_nal::TcpClientStack`] socket to an [`embedded_io`] stream;
//!   [`connect`](transport::connect) drives the TLS 1.3 handshake over it.
//! - [`http`] / [`mqtt`] — application probes over any `embedded_io` stream, so
//!   they run over a plaintext socket or a
//!   [`TlsStream`](krabitls::client::TlsStream) (→ HTTPS / MQTT-over-TLS)
//!   unchanged.
//!
//! `no_std`, no allocation: the host binary supplies `std` (arg parsing,
//! `std-embedded-nal`, mTLS key loading); a target supplies its own NAL stack.

#![no_std]

pub mod http;
pub mod mqtt;
pub mod transport;

pub use transport::{NalError, NalStream, NalTransport, connect, resolve};
