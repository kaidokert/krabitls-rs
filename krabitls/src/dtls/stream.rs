//! Public blocking DTLS 1.3 client over a [`DatagramTransport`].
//!
//! [`DtlsStream`] is the outward-facing façade over the internal driver: it fixes
//! the crypto backend to `RustCrypto`, the certificate parser to DER, and the
//! cipher suite at compile time — AES-128-GCM-SHA256 when `cipher-aes` is built,
//! otherwise ChaCha20-Poly1305-SHA256 — leaving the trust decision to a caller
//! [`VerifyStrategy`]. This is the DTLS analogue of
//! [`TlsStream`](crate::client::TlsStream).

use crate::backends::{DerCert, RustCrypto};
use crate::dtls::client::{DtlsClient, DtlsClientError};
use crate::dtls::transport::DatagramTransport;
use crate::traits::verify_strategy::VerifyStrategy;

/// The suite the façade speaks. A `no_std` client is built for one suite, so it
/// is selected at compile time — AES when present, else ChaCha20-Poly1305.
#[cfg(feature = "cipher-aes")]
type FacadeSuite = crate::aead::Aes128GcmSha256;
#[cfg(all(not(feature = "cipher-aes"), feature = "chacha20"))]
type FacadeSuite = crate::aead::ChaCha20Poly1305Sha256;

/// A connected DTLS 1.3 client: owns the datagram transport and the negotiated
/// epoch-3 application keys.
pub struct DtlsStream<T: DatagramTransport> {
    client: DtlsClient<FacadeSuite>,
    transport: T,
}

impl<T: DatagramTransport> DtlsStream<T> {
    /// Drive a full DTLS 1.3 handshake over `transport` and return a ready
    /// stream. `strategy` decides trust in the server certificate chain;
    /// `hostname`, when `Some`, is matched against the leaf SAN (`None` skips the
    /// check — sound only when the strategy pins the key). `rng` supplies the
    /// ephemeral X25519 key entropy; `client_random` is caller-supplied entropy;
    /// `flight_buf` receives the reassembled server flight and must fit it (a few
    /// KiB).
    ///
    /// `MAX_CHAIN` bounds the accepted certificate-chain length. `flight_buf`
    /// receives the reassembled server flight and `reasm_buf` is scratch for
    /// fragment reassembly; both must fit the whole flight.
    /// `client_cid` (RFC 9146), when `Some`, is the connection id the client
    /// advertises; if the server agrees, records carry connection ids afterward.
    #[allow(clippy::too_many_arguments)]
    pub fn connect<V, Rng, const MAX_CHAIN: usize>(
        mut transport: T,
        strategy: &V,
        hostname: Option<&str>,
        client_cid: Option<&[u8]>,
        rng: &mut Rng,
        client_random: &[u8; 32],
        flight_buf: &mut [u8],
        reasm_buf: &mut [u8],
    ) -> Result<Self, DtlsClientError<T::Error>>
    where
        V: VerifyStrategy<RustCrypto>,
        Rng: rand_core::TryCryptoRng + ?Sized,
    {
        let client = DtlsClient::<FacadeSuite>::connect::<
            T,
            RustCrypto,
            V,
            RustCrypto,
            Rng,
            DerCert,
            MAX_CHAIN,
        >(
            &mut transport,
            strategy,
            hostname,
            client_cid,
            rng,
            client_random,
            flight_buf,
            reasm_buf,
        )?;
        Ok(Self { client, transport })
    }

    /// Seal `payload` as an application_data record and send it. `out` is scratch
    /// for the sealed record and must exceed `payload.len()` by the record
    /// overhead (header + tag).
    pub fn send(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<(), DtlsClientError<T::Error>> {
        self.client.send(&mut self.transport, payload, out)
    }

    /// Receive and decrypt the next application_data record into `buf`, returning
    /// its length. Post-handshake control records are handled internally;
    /// `Ok(None)` means the transport timed out.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, DtlsClientError<T::Error>> {
        self.client.recv(&mut self.transport, buf)
    }

    /// The underlying transport, e.g. to close it.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}
