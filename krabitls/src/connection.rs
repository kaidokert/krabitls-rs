//! Typestate TLS 1.3 client handshake.
//!
//! Wraps the sans-io functions (`write_client_hello`,
//! `parse_server_hello`, `verify_server_flight`,
//! `RecordKeys::<S>::*`, …) behind a `TlsConnection<State, H, C>`
//! carrier whose only legal next move is named by `State`. The
//! sans-io functions stay `pub` for low-level callers; this module
//! is the high-level API.
//!
//! Design notes live in `TYPESTATE_DESIGN.md` at the repo root.

use core::marker::PhantomData;

use embedded_io::Write;

#[cfg(feature = "chacha20")]
use crate::aead::ChaCha20Poly1305Sha256;
use crate::aead::{Aes128GcmSha256, CipherSuite, RecordKeys};
use crate::backends::RustCrypto;
#[cfg(feature = "chacha20")]
use crate::consts::CIPHER_CHACHA20_POLY1305_SHA256;
use crate::consts::{CIPHER_AES_128_GCM_SHA256, CT_APPLICATION_DATA, CT_HANDSHAKE};
use crate::hkdf::{
    HkdfLabelError, TranscriptError, TranscriptHash, handshake_secret, handshake_traffic_secrets,
};
use crate::newtype::{Secret, ZeroBuf};
use crate::reassembler::{ReassemblyError, ServerFlightReassembler};
use crate::server_flight::ServerPubkey;
#[cfg(feature = "chacha20")]
use crate::traits::ChaCha20Poly1305Aead;
use crate::traits::{Aes128GcmAead, CertParser, Ed25519Verify, HkdfSha256};
use crate::{
    ClientHelloError, DecryptError, EncryptError, FlightError, ParseError, parse_server_hello,
    split_inner_plaintext, verify_server_flight, write_client_hello,
};

/// Middlebox-compat ChangeCipherSpec content type; skipped without bumping
/// the read sequence per RFC 8446 §5.1.
const CT_CHANGE_CIPHER_SPEC: u8 = 0x14;

/// Fixed-width bigint used by `ed25519_heapless::x25519` for the X25519
/// DH inside [`TlsConnection::read_server_hello`]. 512 bits = comfortable
/// for the 256-bit X25519 field; matches what the rest of the crate uses.
type Bn = fixed_bigint::FixedUInt<u32, 16, fixed_bigint::Ct>;

/// Stack buffer for the outgoing ClientHello before it's forwarded to
/// the caller's `Write` and fed into the transcript hash. Sized to fit
/// the locked-profile CH plus a generous SNI hostname (255 chars + RFC
/// overhead).
const CH_SCRATCH: usize = 512;

/// Errors a [`TlsConnection`] transition may return.
///
/// `E` is the underlying `embedded_io::Write::Error` for transitions
/// that produce records into a caller writer. Methods that don't write
/// produce `ConnectionError<core::convert::Infallible>`, which is `From`-
/// convertible to any `ConnectionError<E>`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConnectionError<E = core::convert::Infallible> {
    ClientHello(ClientHelloError<E>),
    Parse(ParseError),
    Hkdf(HkdfLabelError),
    Flight(FlightError),
    Decrypt(DecryptError),
    Encrypt(EncryptError),
    Transcript(TranscriptError),
    Reassembly(ReassemblyError),
    /// ServerHello picked a suite that we didn't advertise or that
    /// doesn't match the `assume_*` shortcut the caller used.
    WrongSuite {
        expected: u16,
        got: u16,
    },
    /// `finalize_server_flight` was called before the reassembler had
    /// reassembled a complete `Finished` message.
    IncompleteFlight,
}

impl<E> From<ClientHelloError<E>> for ConnectionError<E> {
    fn from(e: ClientHelloError<E>) -> Self {
        Self::ClientHello(e)
    }
}

impl<E> From<ParseError> for ConnectionError<E> {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl<E> From<HkdfLabelError> for ConnectionError<E> {
    fn from(e: HkdfLabelError) -> Self {
        Self::Hkdf(e)
    }
}

impl<E> From<FlightError> for ConnectionError<E> {
    fn from(e: FlightError) -> Self {
        Self::Flight(e)
    }
}

impl<E> From<DecryptError> for ConnectionError<E> {
    fn from(e: DecryptError) -> Self {
        Self::Decrypt(e)
    }
}

impl<E> From<EncryptError> for ConnectionError<E> {
    fn from(e: EncryptError) -> Self {
        Self::Encrypt(e)
    }
}

impl<E> From<TranscriptError> for ConnectionError<E> {
    fn from(e: TranscriptError) -> Self {
        Self::Transcript(e)
    }
}

impl<E> From<ReassemblyError> for ConnectionError<E> {
    fn from(e: ReassemblyError) -> Self {
        Self::Reassembly(e)
    }
}

// ============================================================================
// State markers
// ============================================================================

/// Initial state: the connection holds the caller's client random and
/// the ephemeral X25519 private key, but no ClientHello has gone out
/// yet. Only transition: [`TlsConnection::write_client_hello`].
pub struct Init {
    pub(crate) client_random: [u8; 32],
    pub(crate) x25519_priv: ZeroBuf<32>,
}

/// Post-ClientHello: waiting for the server's first record. The state
/// keeps the same DH priv (we'll need it once we know the server's
/// share) and a pre-positioned transcript over `CH`.
pub struct WaitServerHello {
    pub(crate) x25519_priv: ZeroBuf<32>,
}

/// ServerHello parsed, DH complete, handshake key schedule derived,
/// `s_hs` AEAD keys live. The connection knows the cipher suite `S` at
/// this point. Transitions: feed records into a caller-supplied
/// [`crate::reassembler::ServerFlightReassembler`], then finalize.
#[allow(dead_code)] // fields wired in follow-up commits on this branch
pub struct WaitServerFlight<S: CipherSuite> {
    pub(crate) hs: Secret,
    pub(crate) c_hs_ts: Secret,
    pub(crate) s_hs_ts: Secret,
    pub(crate) s_hs_keys: RecordKeys<S>,
    pub(crate) seq_in: u64,
}

/// Server flight verified (cert + CertificateVerify + Finished). The
/// transcript is positioned through `CH ‖ SH ‖ EE ‖ Cert ‖ CV ‖ sFin`,
/// ready to bind both the client Finished MAC and the application
/// traffic secrets in a single transition.
#[allow(dead_code)] // fields wired in follow-up commits on this branch
pub struct ServerFlightDone<S: CipherSuite> {
    pub(crate) hs: Secret,
    pub(crate) c_hs_ts: Secret,
    pub(crate) s_hs_ts: Secret,
    pub(crate) server_pubkey: ServerPubkeyOwned,
    pub(crate) _suite: PhantomData<S>,
}

/// Owned counterpart to [`ServerPubkey`]. `verify_server_flight` hands back
/// a borrow into the reassembler buffer; we copy it into an owned form so
/// the transition can outlive the borrow. RSA modulus is sized for the
/// largest supported key (RSA-2048 = 256 bytes).
#[derive(Debug, Clone)]
// no-alloc: can't box the RSA modulus, so the variants are unavoidably
// asymmetric (32B Ed25519 vs ~268B RSA-2048). Living with the size delta
// is the price of carrying both inline.
#[allow(clippy::large_enum_variant)]
pub enum ServerPubkeyOwned {
    Ed25519([u8; 32]),
    #[cfg(feature = "rsa")]
    Rsa {
        modulus: heapless::Vec<u8, 256>,
        exponent: u32,
    },
}

impl ServerPubkeyOwned {
    fn from_view(view: &ServerPubkey<'_>) -> Self {
        match view {
            ServerPubkey::Ed25519(pk, _) => Self::Ed25519(*pk),
            #[cfg(feature = "rsa")]
            ServerPubkey::Rsa { modulus, exponent } => {
                let mut v = heapless::Vec::new();
                // Cert parser already rejected anything beyond RSA-2048,
                // so the modulus is guaranteed to fit in the 256-byte cap.
                v.extend_from_slice(modulus).expect("modulus fits in 256B");
                Self::Rsa {
                    modulus: v,
                    exponent: *exponent,
                }
            }
        }
    }

    /// Borrow as a [`ServerPubkey`] view for callers that want to plug the
    /// pubkey back into the sans-io layer (e.g., RSA app-data verify in a
    /// post-handshake protocol).
    pub fn as_view(&self) -> ServerPubkey<'_> {
        match self {
            Self::Ed25519(pk) => ServerPubkey::ed25519(*pk),
            #[cfg(feature = "rsa")]
            Self::Rsa { modulus, exponent } => ServerPubkey::Rsa {
                modulus: &modulus[..],
                exponent: *exponent,
            },
        }
    }
}

/// Outcome of feeding one server-flight record into the reassembler.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FlightStep {
    /// More records expected before the flight is complete.
    Pending,
    /// Reassembler holds a complete `Finished` — caller should next call
    /// `finalize_server_flight`.
    Ready,
}

/// Steady state: handshake done, application traffic secrets live.
/// Both `c_ap_keys` (for outbound records) and `s_ap_keys` (inbound)
/// are RecordKeys-typed under the negotiated suite `S`. Per-direction
/// record-layer sequence numbers tick under the AEAD nonce derivation.
#[allow(dead_code)] // fields wired in follow-up commits on this branch
pub struct AppData<S: CipherSuite> {
    pub(crate) c_ap_keys: RecordKeys<S>,
    pub(crate) s_ap_keys: RecordKeys<S>,
    pub(crate) seq_out: u64,
    pub(crate) seq_in: u64,
}

// ============================================================================
// Carrier
// ============================================================================

/// Typestate TLS 1.3 client connection. The `State` parameter is the
/// only thing the compiler cares about between transitions; methods
/// are defined on `impl TlsConnection<SpecificState, …>` blocks so
/// "calling the wrong method for this state" is a compile error.
///
/// `H` is the HKDF / SHA-256 backend (also drives the transcript hash);
/// `C` is the AEAD backend. Both default to `RustCrypto` to keep
/// embedded call sites short. Neither changes mid-connection.
pub struct TlsConnection<State, H = RustCrypto, C = RustCrypto>
where
    H: HkdfSha256,
{
    transcript: TranscriptHash<H>,
    state: State,
    _crypto: PhantomData<C>,
}

// ============================================================================
// Init -> WaitServerHello
// ============================================================================

impl<H, C> TlsConnection<Init, H, C>
where
    H: HkdfSha256,
{
    /// Construct a fresh connection with caller-supplied randomness +
    /// X25519 ephemeral private key. Both come from the caller because
    /// krabitls is sans-randomness — embedded targets typically have
    /// hardware RNGs we don't want to plumb through here.
    pub fn new(client_random: [u8; 32], x25519_priv: ZeroBuf<32>) -> Self {
        Self {
            transcript: TranscriptHash::<H>::new(),
            state: Init {
                client_random,
                x25519_priv,
            },
            _crypto: PhantomData,
        }
    }

    /// Serialize the ClientHello into `out`, feed the same bytes into
    /// the transcript hash, and advance to [`WaitServerHello`].
    pub fn write_client_hello<W: Write>(
        mut self,
        out: &mut W,
        x25519_pub: &[u8; 32],
        hostname: Option<&[u8]>,
    ) -> Result<TlsConnection<WaitServerHello, H, C>, ConnectionError<W::Error>> {
        // Write into an internal scratch buffer so we can feed the
        // exact wire bytes into the transcript hash before forwarding
        // them to the caller's Writer. Sized to fit the locked-profile
        // CH plus a generous SNI hostname.
        let mut scratch = [0u8; CH_SCRATCH];
        let mut cursor: &mut [u8] = &mut scratch[..];
        // Re-route the slice-cursor's own error to the user-facing IO
        // error space: a `Full` here means our internal CH scratch
        // wasn't big enough for the requested hostname, which is the
        // user's `MessageTooLong` from their perspective.
        let n = write_client_hello(&mut cursor, &self.state.client_random, x25519_pub, hostname)
            .map_err(|e| match e {
                ClientHelloError::HostnameTooLong => {
                    ConnectionError::ClientHello(ClientHelloError::HostnameTooLong)
                }
                ClientHelloError::MessageTooLong | ClientHelloError::Write(_) => {
                    ConnectionError::ClientHello(ClientHelloError::MessageTooLong)
                }
                ClientHelloError::IntegerOverflow => {
                    ConnectionError::ClientHello(ClientHelloError::IntegerOverflow)
                }
            })?;
        let ch_bytes = &scratch[..n];

        out.write_all(ch_bytes)
            .map_err(|e| ConnectionError::ClientHello(ClientHelloError::Write(e)))?;
        self.transcript
            .update_record(ch_bytes)
            .map_err(ConnectionError::Transcript)?;

        Ok(TlsConnection {
            transcript: self.transcript,
            state: WaitServerHello {
                x25519_priv: self.state.x25519_priv,
            },
            _crypto: PhantomData,
        })
    }
}

// ============================================================================
// WaitServerHello -> NegotiatedSuite
// ============================================================================

/// Runtime-dispatch hop the [`TlsConnection::read_server_hello`]
/// transition produces. The suite isn't known until SH is parsed; this
/// enum lets the type-system pick up the resolved suite at one
/// well-defined point. CLI callers match on it; embedded callers who
/// pre-know their suite use one of the `assume_*` methods to skip the
/// match and monomorphize directly.
pub enum NegotiatedSuite<H = RustCrypto, C = RustCrypto>
where
    H: HkdfSha256,
{
    Aes128Gcm(TlsConnection<WaitServerFlight<Aes128GcmSha256>, H, C>),
    #[cfg(feature = "chacha20")]
    ChaCha20Poly1305(TlsConnection<WaitServerFlight<ChaCha20Poly1305Sha256>, H, C>),
}

impl<H, C> NegotiatedSuite<H, C>
where
    H: HkdfSha256,
{
    /// Coerce to the AES-128-GCM-SHA256 variant. Returns
    /// `Err(ConnectionError::WrongSuite)` if the server actually
    /// negotiated something else.
    ///
    /// Use this on embedded targets that physically only carry AES code
    /// so the chacha branch of the enum match never monomorphizes.
    pub fn assume_aes_128_gcm(
        self,
    ) -> Result<TlsConnection<WaitServerFlight<Aes128GcmSha256>, H, C>, ConnectionError> {
        match self {
            Self::Aes128Gcm(c) => Ok(c),
            #[cfg(feature = "chacha20")]
            Self::ChaCha20Poly1305(_) => Err(ConnectionError::WrongSuite {
                expected: CIPHER_AES_128_GCM_SHA256,
                got: CIPHER_CHACHA20_POLY1305_SHA256,
            }),
        }
    }

    /// Coerce to the ChaCha20-Poly1305-SHA256 variant.
    #[cfg(feature = "chacha20")]
    pub fn assume_chacha20_poly1305(
        self,
    ) -> Result<TlsConnection<WaitServerFlight<ChaCha20Poly1305Sha256>, H, C>, ConnectionError>
    {
        match self {
            Self::ChaCha20Poly1305(c) => Ok(c),
            Self::Aes128Gcm(_) => Err(ConnectionError::WrongSuite {
                expected: CIPHER_CHACHA20_POLY1305_SHA256,
                got: CIPHER_AES_128_GCM_SHA256,
            }),
        }
    }
}

impl<H, C> TlsConnection<WaitServerHello, H, C>
where
    H: HkdfSha256,
{
    /// Parse the ServerHello record, run X25519 against the server's
    /// `key_share`, derive the handshake secret and the
    /// `(c_hs_ts, s_hs_ts)` traffic-secret pair, materialize the
    /// `s_hs` AEAD keys, and advance to [`NegotiatedSuite`].
    pub fn read_server_hello(
        mut self,
        sh_record: &[u8],
    ) -> Result<NegotiatedSuite<H, C>, ConnectionError> {
        let sh = parse_server_hello(sh_record)?;

        // X25519 DH against the server's share — the connection holds
        // the priv from Init; the server's share is in sh.
        let dhe = ed25519_heapless::x25519::<Bn>(&self.state.x25519_priv, sh.x25519_share);

        // Feed the SH record into the transcript before deriving any
        // secrets — handshake_traffic_secrets needs H(CH ‖ SH).
        self.transcript.update_record(sh_record)?;
        let th_ch_sh = self.transcript.snapshot();

        let hs = handshake_secret::<H>(&dhe)?;
        let (c_hs_ts, s_hs_ts) = handshake_traffic_secrets::<H>(&hs, &th_ch_sh)?;

        match sh.cipher_suite {
            CIPHER_AES_128_GCM_SHA256 => {
                let s_hs_keys = RecordKeys::<Aes128GcmSha256>::derive::<H>(&s_hs_ts)?;
                Ok(NegotiatedSuite::Aes128Gcm(TlsConnection {
                    transcript: self.transcript,
                    state: WaitServerFlight {
                        hs,
                        c_hs_ts,
                        s_hs_ts,
                        s_hs_keys,
                        seq_in: 0,
                    },
                    _crypto: PhantomData,
                }))
            }
            #[cfg(feature = "chacha20")]
            CIPHER_CHACHA20_POLY1305_SHA256 => {
                let s_hs_keys = RecordKeys::<ChaCha20Poly1305Sha256>::derive::<H>(&s_hs_ts)?;
                Ok(NegotiatedSuite::ChaCha20Poly1305(TlsConnection {
                    transcript: self.transcript,
                    state: WaitServerFlight {
                        hs,
                        c_hs_ts,
                        s_hs_ts,
                        s_hs_keys,
                        seq_in: 0,
                    },
                    _crypto: PhantomData,
                }))
            }
            other => Err(ConnectionError::Parse(ParseError::UnsupportedCipherSuite(
                other,
            ))),
        }
    }
}

// ============================================================================
// WaitServerFlight -> ServerFlightDone
// ============================================================================

/// Shared body for `feed_server_record` across cipher suites. Generic over
/// the decrypt closure so each suite's impl can call its own
/// `RecordKeys::<S>::decrypt_record::<C>` without going through a trait
/// object.
fn feed_server_record_inner<const N: usize, F>(
    record: &[u8],
    seq_in: &mut u64,
    reassembler: &mut ServerFlightReassembler<N>,
    scratch: &mut [u8],
    decrypt: F,
) -> Result<FlightStep, ConnectionError>
where
    F: for<'a> FnOnce(&[u8], u64, &'a mut [u8]) -> Result<&'a [u8], DecryptError>,
{
    if record.is_empty() {
        return Err(ConnectionError::Decrypt(DecryptError::Truncated));
    }
    match record[0] {
        // Middlebox-compat CCS: drop without bumping seq_in. RFC 8446 §5.
        CT_CHANGE_CIPHER_SPEC => Ok(if reassembler.is_complete() {
            FlightStep::Ready
        } else {
            FlightStep::Pending
        }),
        CT_APPLICATION_DATA => {
            let inner = decrypt(record, *seq_in, scratch)?;
            let (content, inner_ct) = split_inner_plaintext(inner)?;
            if inner_ct != CT_HANDSHAKE {
                return Err(ConnectionError::Decrypt(
                    DecryptError::UnexpectedContentType(inner_ct),
                ));
            }
            reassembler.push_content(content)?;
            *seq_in += 1;
            Ok(if reassembler.is_complete() {
                FlightStep::Ready
            } else {
                FlightStep::Pending
            })
        }
        other => Err(ConnectionError::Decrypt(
            DecryptError::UnexpectedContentType(other),
        )),
    }
}

impl<H, C> TlsConnection<WaitServerFlight<Aes128GcmSha256>, H, C>
where
    H: HkdfSha256,
    C: Aes128GcmAead,
{
    /// Decrypt one server-flight record into `scratch`, push its inner
    /// handshake content into `reassembler`, and report whether the
    /// reassembled flight is complete. `scratch` only needs to hold the
    /// inner plaintext of one record (≤ 2^14 + 256 bytes by RFC).
    ///
    /// CCS records (sent by the server for middlebox compat) are dropped
    /// without bumping the read sequence.
    pub fn feed_server_record<const N: usize>(
        &mut self,
        record: &[u8],
        reassembler: &mut ServerFlightReassembler<N>,
        scratch: &mut [u8],
    ) -> Result<FlightStep, ConnectionError> {
        feed_server_record_inner(
            record,
            &mut self.state.seq_in,
            reassembler,
            scratch,
            |r, s, b| self.state.s_hs_keys.decrypt_record::<C>(r, s, b),
        )
    }

    /// Verify the reassembled server flight (cert + CertificateVerify +
    /// server Finished) and advance to [`ServerFlightDone`]. The transcript
    /// is positioned through sFin on success.
    pub fn finalize_server_flight<const N: usize, P: CertParser, E: Ed25519Verify>(
        mut self,
        reassembler: &ServerFlightReassembler<N>,
    ) -> Result<TlsConnection<ServerFlightDone<Aes128GcmSha256>, H, C>, ConnectionError> {
        let plaintext = reassembler
            .flight_bytes()
            .ok_or(ConnectionError::IncompleteFlight)?;
        let verified =
            verify_server_flight::<H, P, E>(&mut self.transcript, plaintext, &self.state.s_hs_ts)?;
        let server_pubkey = ServerPubkeyOwned::from_view(&verified.server_pubkey);
        Ok(TlsConnection {
            transcript: self.transcript,
            state: ServerFlightDone {
                hs: self.state.hs,
                c_hs_ts: self.state.c_hs_ts,
                s_hs_ts: self.state.s_hs_ts,
                server_pubkey,
                _suite: PhantomData,
            },
            _crypto: PhantomData,
        })
    }
}

#[cfg(feature = "chacha20")]
impl<H, C> TlsConnection<WaitServerFlight<ChaCha20Poly1305Sha256>, H, C>
where
    H: HkdfSha256,
    C: ChaCha20Poly1305Aead,
{
    pub fn feed_server_record<const N: usize>(
        &mut self,
        record: &[u8],
        reassembler: &mut ServerFlightReassembler<N>,
        scratch: &mut [u8],
    ) -> Result<FlightStep, ConnectionError> {
        feed_server_record_inner(
            record,
            &mut self.state.seq_in,
            reassembler,
            scratch,
            |r, s, b| self.state.s_hs_keys.decrypt_record::<C>(r, s, b),
        )
    }

    pub fn finalize_server_flight<const N: usize, P: CertParser, E: Ed25519Verify>(
        mut self,
        reassembler: &ServerFlightReassembler<N>,
    ) -> Result<TlsConnection<ServerFlightDone<ChaCha20Poly1305Sha256>, H, C>, ConnectionError>
    {
        let plaintext = reassembler
            .flight_bytes()
            .ok_or(ConnectionError::IncompleteFlight)?;
        let verified =
            verify_server_flight::<H, P, E>(&mut self.transcript, plaintext, &self.state.s_hs_ts)?;
        let server_pubkey = ServerPubkeyOwned::from_view(&verified.server_pubkey);
        Ok(TlsConnection {
            transcript: self.transcript,
            state: ServerFlightDone {
                hs: self.state.hs,
                c_hs_ts: self.state.c_hs_ts,
                s_hs_ts: self.state.s_hs_ts,
                server_pubkey,
                _suite: PhantomData,
            },
            _crypto: PhantomData,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(dead_code, unused_imports)] // fixtures only used under the no-chacha20 cfg-gated tests
mod tests {
    use super::*;
    use crate::backends::RustCrypto;

    // The seed-0 fixtures from `lib.rs` — duplicated locally so the
    // connection tests can run independently of the larger tests module.
    // Same bytes; if the upstream fixtures ever change, these need to
    // move with them.
    const FIXTURE_RANDOM: [u8; 32] = [
        0xed, 0xe5, 0x7b, 0xa2, 0x43, 0x3a, 0xd5, 0xa3, 0x4d, 0x05, 0x50, 0x3a, 0xfe, 0x4f, 0xc2,
        0x89, 0xdf, 0xd9, 0xe9, 0x53, 0x57, 0xd8, 0x16, 0x36, 0x80, 0x24, 0xe7, 0x3f, 0xbf, 0xa6,
        0xfa, 0xf5,
    ];
    const FIXTURE_X25519_PUB: [u8; 32] = [
        0x82, 0x46, 0xe7, 0x35, 0x8f, 0x0a, 0xf7, 0xf3, 0x31, 0x7d, 0xca, 0xf6, 0x88, 0xd0, 0x34,
        0xc9, 0x5d, 0x5a, 0x2b, 0x54, 0xbf, 0x66, 0xc8, 0x95, 0x0e, 0xb8, 0x7a, 0x5f, 0x47, 0x93,
        0x96, 0x0d,
    ];
    const FIXTURE_CLIENT_X25519_PRIV: [u8; 32] = [
        0xac, 0xe1, 0xc2, 0x3b, 0x24, 0xdf, 0xad, 0x58, 0xc5, 0x4c, 0xcf, 0x4c, 0x1f, 0xe8, 0xdf,
        0xe8, 0x5e, 0x76, 0x0e, 0x02, 0x3b, 0x6c, 0xb6, 0x02, 0x2f, 0x70, 0x0f, 0x34, 0xde, 0x4c,
        0x28, 0x28,
    ];
    const FIXTURE_CLIENT_HELLO: [u8; 117] = [
        0x16, 0x03, 0x03, 0x00, 0x70, 0x01, 0x00, 0x00, 0x6c, 0x03, 0x03, 0xed, 0xe5, 0x7b, 0xa2,
        0x43, 0x3a, 0xd5, 0xa3, 0x4d, 0x05, 0x50, 0x3a, 0xfe, 0x4f, 0xc2, 0x89, 0xdf, 0xd9, 0xe9,
        0x53, 0x57, 0xd8, 0x16, 0x36, 0x80, 0x24, 0xe7, 0x3f, 0xbf, 0xa6, 0xfa, 0xf5, 0x00, 0x00,
        0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x41, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
        0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07,
        0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x82, 0x46, 0xe7, 0x35, 0x8f,
        0x0a, 0xf7, 0xf3, 0x31, 0x7d, 0xca, 0xf6, 0x88, 0xd0, 0x34, 0xc9, 0x5d, 0x5a, 0x2b, 0x54,
        0xbf, 0x66, 0xc8, 0x95, 0x0e, 0xb8, 0x7a, 0x5f, 0x47, 0x93, 0x96, 0x0d,
    ];
    const FIXTURE_SERVER_HELLO: [u8; 95] = [
        0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0x64, 0x1c, 0x5b, 0xd9,
        0x34, 0xab, 0xe1, 0xc5, 0x98, 0xa9, 0xc9, 0x61, 0xf7, 0xcb, 0x1e, 0x06, 0x28, 0x0b, 0x4a,
        0x5e, 0x88, 0x0c, 0x1c, 0x19, 0xd2, 0xfe, 0x9e, 0xef, 0x33, 0x48, 0x0c, 0xae, 0x00, 0x13,
        0x01, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00,
        0x1d, 0x00, 0x20, 0x60, 0x4d, 0x7a, 0x17, 0x18, 0x38, 0xbd, 0xa2, 0x15, 0xd2, 0xb5, 0x4a,
        0x24, 0xfb, 0x7d, 0x3a, 0x88, 0x8d, 0xa5, 0xac, 0x36, 0x72, 0x72, 0x6d, 0x20, 0x06, 0x44,
        0x04, 0xf7, 0x06, 0xdb, 0x7e,
    ];

    /// Round-trip the seed-0 fixture through `Init -> WaitServerHello`
    /// and assert byte-identity against `FIXTURE_CLIENT_HELLO`.
    #[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
    #[test]
    fn init_writes_byte_identical_client_hello() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto, RustCrypto> =
            TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        const BUF_LEN: usize = 256;
        let mut out = [0u8; BUF_LEN];
        let written = {
            let mut cursor: &mut [u8] = &mut out[..];
            let _conn = conn
                .write_client_hello(&mut cursor, &FIXTURE_X25519_PUB, None)
                .expect("write_client_hello");
            BUF_LEN - cursor.len()
        };
        assert_eq!(written, FIXTURE_CLIENT_HELLO.len());
        assert_eq!(&out[..written], &FIXTURE_CLIENT_HELLO);
    }

    /// Drive the connection through `Init -> WaitServerHello ->
    /// NegotiatedSuite` and verify we land on the AES variant under the
    /// default-features build (where the SH negotiates AES-128-GCM).
    #[cfg(not(feature = "chacha20"))]
    #[test]
    fn read_server_hello_lands_on_aes_variant() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto, RustCrypto> =
            TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello(&mut cursor, &FIXTURE_X25519_PUB, None)
            .unwrap();

        let negotiated = conn.read_server_hello(&FIXTURE_SERVER_HELLO).unwrap();
        match negotiated {
            NegotiatedSuite::Aes128Gcm(_) => {}
            #[allow(unreachable_patterns)]
            _ => panic!("expected AES-128-GCM variant"),
        }
    }

    /// packets/003 is one 380-byte AEAD record carrying the entire seed-0
    /// server flight (EE / Cert / CertVerify / Finished). Loading it the
    /// same way the lib.rs fixture-decrypt tests do.
    const FIXTURE_PACKET_3: [u8; 380] = crate::hex_decode(include_str!(
        "../../testdata/packets/003_s2c_ServerFlight_encrypted.hex"
    ));

    /// Ed25519 pubkey embedded in the seed-0 self-signed cert; this is the
    /// value `ServerFlightDone::server_pubkey` should carry on success.
    const EXPECTED_SERVER_ID_PUB: [u8; 32] = [
        0x9d, 0xfe, 0x2a, 0xb0, 0x3e, 0x35, 0x70, 0x4b, 0x9c, 0xfb, 0x93, 0xb6, 0x03, 0xa6, 0x61,
        0x18, 0x82, 0x17, 0xa6, 0xb5, 0xfd, 0x6a, 0x1f, 0x75, 0xe6, 0x16, 0x1a, 0x39, 0xe0, 0x53,
        0x4c, 0x3f,
    ];

    /// End-to-end smoke test through `WaitServerFlight`: feed the captured
    /// packet 003 into the reassembler, finalize, and check that the
    /// extracted server pubkey matches the cert in the fixture.
    #[cfg(not(feature = "chacha20"))]
    #[test]
    fn feed_server_record_and_finalize_smoke() {
        use crate::backends::DerCert;
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto, RustCrypto> =
            TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello(&mut cursor, &FIXTURE_X25519_PUB, None)
            .unwrap();
        let mut conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();

        let mut reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut scratch = [0u8; 400];
        let step = conn
            .feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .expect("feed_server_record");
        assert_eq!(step, FlightStep::Ready);

        let done = conn
            .finalize_server_flight::<512, DerCert, RustCrypto>(&reassembler)
            .expect("finalize_server_flight");
        match &done.state.server_pubkey {
            ServerPubkeyOwned::Ed25519(pk) => assert_eq!(pk, &EXPECTED_SERVER_ID_PUB),
            #[cfg(feature = "rsa")]
            ServerPubkeyOwned::Rsa { .. } => panic!("expected Ed25519 pubkey"),
        }
    }

    /// `finalize_server_flight` must reject an empty reassembler with the
    /// `IncompleteFlight` sentinel rather than wandering into the verifier.
    #[cfg(not(feature = "chacha20"))]
    #[test]
    fn finalize_without_flight_is_incomplete() {
        use crate::backends::DerCert;
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto, RustCrypto> =
            TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello(&mut cursor, &FIXTURE_X25519_PUB, None)
            .unwrap();
        let conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();

        let reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let err = match conn.finalize_server_flight::<512, DerCert, RustCrypto>(&reassembler) {
            Ok(_) => panic!("expected IncompleteFlight"),
            Err(e) => e,
        };
        assert_eq!(err, ConnectionError::IncompleteFlight);
    }

    /// CCS records must be dropped without bumping `seq_in` so the next
    /// real AEAD record decrypts under sequence 0.
    #[cfg(not(feature = "chacha20"))]
    #[test]
    fn feed_server_record_skips_ccs_without_bumping_seq() {
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto, RustCrypto> =
            TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello(&mut cursor, &FIXTURE_X25519_PUB, None)
            .unwrap();
        let mut conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();

        let mut reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut scratch = [0u8; 400];

        // Middlebox-compat CCS: type=0x14, body = 0x01.
        let ccs_record = [0x14u8, 0x03, 0x03, 0x00, 0x01, 0x01];
        let step = conn
            .feed_server_record(&ccs_record, &mut reassembler, &mut scratch)
            .unwrap();
        assert_eq!(step, FlightStep::Pending);
        assert_eq!(conn.state.seq_in, 0);

        // And the real flight record still decrypts under seq=0.
        let step = conn
            .feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .unwrap();
        assert_eq!(step, FlightStep::Ready);
        assert_eq!(conn.state.seq_in, 1);
    }

    /// Verify that `assume_aes_128_gcm` succeeds when the suite really
    /// is AES — embedded callers use this to skip the runtime enum.
    #[cfg(not(feature = "chacha20"))]
    #[test]
    fn assume_aes_succeeds_for_aes_handshake() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto, RustCrypto> =
            TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello(&mut cursor, &FIXTURE_X25519_PUB, None)
            .unwrap();

        let negotiated = conn.read_server_hello(&FIXTURE_SERVER_HELLO).unwrap();
        let _conn = negotiated
            .assume_aes_128_gcm()
            .expect("assume_aes_128_gcm should accept an AES handshake");
    }
}
