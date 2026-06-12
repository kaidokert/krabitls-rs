//! Typestate TLS 1.3 client. `TlsConnection<State, H, C>`'s only legal
//! next move is the one named by `State` — wrong-method-for-state is a
//! compile error. Design notes in `TYPESTATE_DESIGN.md`.

use core::marker::PhantomData;

use embedded_io::Write;

#[cfg(feature = "chacha20")]
use crate::aead::ChaCha20Poly1305Sha256;
use crate::aead::split_inner_plaintext;
use crate::aead::{Aes128GcmSha256, CipherSuite, RecordKeys};
use crate::backends::RustCrypto;
use crate::client_flight::ClientFinishedError;
#[cfg(feature = "chacha20")]
use crate::consts::CIPHER_CHACHA20_POLY1305_SHA256;
use crate::consts::{CIPHER_AES_128_GCM_SHA256, CT_APPLICATION_DATA, CT_HANDSHAKE};
use crate::hkdf::{
    HkdfLabelError, TranscriptError, TranscriptHash, application_traffic_secrets, handshake_secret,
    handshake_traffic_secrets, master_secret,
};
use crate::newtype::{Secret, ZeroBuf};
use crate::reassembler::{ReassemblyError, ServerFlightReassembler};
use crate::server_flight::ServerPubkey;
use crate::server_flight::verify_server_flight;
#[cfg(feature = "chacha20")]
use crate::traits::ChaCha20Poly1305Aead;
use crate::traits::{Aes128GcmAead, CertParser, Ed25519Verify, HkdfSha256};
use crate::{
    ClientHelloError, DecryptError, EncryptError, FlightError, ParseError, parse_server_hello,
    write_client_hello,
};

const CT_ALERT: u8 = 0x15;
const CLOSE_NOTIFY_ALERT: [u8; 2] = [0x01, 0x00];
/// Middlebox-compat ChangeCipherSpec — dropped without bumping seq_in.
const CT_CHANGE_CIPHER_SPEC: u8 = 0x14;

type Bn = fixed_bigint::FixedUInt<u32, 16, fixed_bigint::Ct>;

/// Internal scratch for the outgoing ClientHello before it's forwarded
/// to the caller's `Write`. Sized for the locked profile + a 255-char SNI.
const CH_SCRATCH: usize = 512;

/// `E` is the caller `Write::Error` for transitions that write records;
/// non-write transitions yield `ConnectionError<Infallible>`.
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
    ClientFinished(ClientFinishedError),
    WrongSuite { expected: u16, got: u16 },
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

impl<E> From<ClientFinishedError> for ConnectionError<E> {
    fn from(e: ClientFinishedError) -> Self {
        Self::ClientFinished(e)
    }
}

impl<E: core::fmt::Display> core::fmt::Display for ConnectionError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ClientHello(e) => write!(f, "ClientHello: {e}"),
            Self::Parse(e) => write!(f, "parse: {e}"),
            Self::Hkdf(e) => write!(f, "HKDF: {e}"),
            Self::Flight(e) => write!(f, "server flight: {e}"),
            Self::Decrypt(e) => write!(f, "decrypt: {e}"),
            Self::Encrypt(e) => write!(f, "encrypt: {e}"),
            Self::Transcript(e) => write!(f, "transcript: {e}"),
            Self::Reassembly(e) => write!(f, "reassembly: {e}"),
            Self::ClientFinished(e) => write!(f, "ClientFinished: {e}"),
            Self::WrongSuite { expected, got } => write!(
                f,
                "cipher suite mismatch: expected 0x{expected:04x}, got 0x{got:04x}"
            ),
            Self::IncompleteFlight => f.write_str("server flight reassembly incomplete"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for ConnectionError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::ClientHello(e) => Some(e),
            Self::Parse(e) => Some(e),
            Self::Hkdf(e) => Some(e),
            Self::Flight(e) => Some(e),
            Self::Decrypt(e) => Some(e),
            Self::Encrypt(e) => Some(e),
            Self::Transcript(e) => Some(e),
            Self::Reassembly(e) => Some(e),
            Self::ClientFinished(e) => Some(e),
            Self::WrongSuite { .. } | Self::IncompleteFlight => None,
        }
    }
}

// ============================================================================
// State markers
// ============================================================================

/// Initial state. Next: [`TlsConnection::write_client_hello`].
pub struct Init {
    pub(crate) client_random: [u8; 32],
    pub(crate) x25519_priv: ZeroBuf<32>,
}

/// Post-CH, waiting for ServerHello.
pub struct WaitServerHello {
    pub(crate) x25519_priv: ZeroBuf<32>,
}

mod sealed {
    pub trait Sealed {}
}

/// Sealed marker discriminating live-handshake vs replay-derived `WaitServerFlight`
/// / `ServerFlightDone`. Replay-derived states have a zeroed `hs`, so the
/// post-handshake `finish_handshake` / `derive_app_secrets` transitions only impl
/// for [`Live`].
pub trait HandshakeMode: sealed::Sealed {}

/// Live handshake: `hs` is the real DH-derived handshake secret.
pub struct Live;
/// Replay-derived: `hs` is zeroed; only `finalize_server_flight` +
/// `build_client_finished` produce meaningful output.
pub struct Replay;
impl sealed::Sealed for Live {}
impl sealed::Sealed for Replay {}
impl HandshakeMode for Live {}
impl HandshakeMode for Replay {}

/// SH parsed, x25519 done, s_hs keys live, suite `S` now known.
pub struct WaitServerFlight<S: CipherSuite, M: HandshakeMode = Live> {
    pub(crate) hs: Secret,
    pub(crate) c_hs_ts: Secret,
    pub(crate) s_hs_ts: Secret,
    pub(crate) s_hs_keys: RecordKeys<S>,
    pub(crate) seq_in: u64,
    pub(crate) _mode: PhantomData<M>,
}

/// Server flight verified; transcript through sFin.
pub struct ServerFlightDone<S: CipherSuite, M: HandshakeMode = Live> {
    pub(crate) hs: Secret,
    pub(crate) c_hs_ts: Secret,
    #[allow(dead_code)] // client doesn't re-derive s_hs keys; kept for symmetry
    pub(crate) s_hs_ts: Secret,
    pub(crate) server_pubkey: ServerPubkeyOwned,
    pub(crate) _suite: PhantomData<S>,
    pub(crate) _mode: PhantomData<M>,
}

/// Owned [`ServerPubkey`]. No-alloc forces the RSA variant inline (RSA-2048
/// is 256B), so the size delta vs Ed25519's 32B is unavoidable.
#[derive(Debug, Clone)]
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
    fn from_view(view: &ServerPubkey<'_>) -> Result<Self, FlightError> {
        match view {
            ServerPubkey::Ed25519(pk, _) => Ok(Self::Ed25519(*pk)),
            #[cfg(feature = "rsa")]
            ServerPubkey::Rsa { modulus, exponent } => {
                let mut v = heapless::Vec::new();
                v.extend_from_slice(modulus)
                    .map_err(|_| FlightError::InternalEncoding)?;
                Ok(Self::Rsa {
                    modulus: v,
                    exponent: *exponent,
                })
            }
        }
    }

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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FlightStep {
    Pending,
    Ready,
}

/// Cert outer-sig policy for [`TlsConnection::finalize_server_flight`].
/// Placeholder until a richer `VerifyStrategy` trait lands chain walking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// Self-signed cert: verify outer sig with its own pubkey.
    SelfSigned,
    /// CA-issued cert: skip outer sig (caller trusts via pin / SAN / OOB).
    /// CV + server Finished still verified.
    TrustOnPin,
}

/// Steady state: app-traffic keys live for both directions.
pub struct AppData<S: CipherSuite> {
    pub(crate) c_ap_keys: RecordKeys<S>,
    pub(crate) s_ap_keys: RecordKeys<S>,
    pub(crate) seq_out: u64,
    pub(crate) seq_in: u64,
}

// ============================================================================
// Carrier
// ============================================================================

/// `H` = HKDF/SHA-256 + transcript backend; `C` = AEAD backend.
/// Both default to `RustCrypto` and don't change mid-connection.
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

/// Successful return of [`TlsConnection::write_client_hello_to_slice`].
pub type WriteClientHelloToSliceResult<'a, H, C> = Result<
    (&'a [u8], TlsConnection<WaitServerHello, H, C>),
    ConnectionError<embedded_io::SliceWriteError>,
>;

impl<H, C> TlsConnection<Init, H, C>
where
    H: HkdfSha256,
{
    /// Both arguments are caller-supplied — krabitls is sans-randomness.
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

    /// Convenience for the common in-memory case: serialize CH into `buf`,
    /// return the written prefix and the next state.
    ///
    /// Equivalent to driving [`Self::write_client_hello`] against the
    /// `embedded_io::Write` impl for `&mut [u8]`, with the cursor
    /// arithmetic and slice re-borrow encapsulated. A too-small `buf`
    /// surfaces as
    /// `ConnectionError::ClientHello(ClientHelloError::Write(SliceWriteError::Full))`.
    /// Use [`crate::client_hello_len`] to size `buf` exactly.
    pub fn write_client_hello_to_slice<'a>(
        self,
        buf: &'a mut [u8],
        x25519_pub: &[u8; 32],
        hostname: Option<&[u8]>,
    ) -> WriteClientHelloToSliceResult<'a, H, C> {
        let total = buf.len();
        let mut cursor = &mut *buf;
        let next = self.write_client_hello(&mut cursor, x25519_pub, hostname)?;
        let written = total - cursor.len();
        Ok((&buf[..written], next))
    }

    /// Serialize CH into `out`, feed bytes into transcript, advance.
    pub fn write_client_hello<W: Write>(
        mut self,
        out: &mut W,
        x25519_pub: &[u8; 32],
        hostname: Option<&[u8]>,
    ) -> Result<TlsConnection<WaitServerHello, H, C>, ConnectionError<W::Error>> {
        // Internal scratch so we feed the exact wire bytes into the
        // transcript before forwarding to the caller's Writer.
        let mut scratch = [0u8; CH_SCRATCH];
        let mut cursor: &mut [u8] = &mut scratch[..];
        // Cursor-Full means scratch wasn't big enough; surface as MessageTooLong.
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

#[cfg(feature = "replay")]
impl<H, C> TlsConnection<WaitServerHello, H, C>
where
    H: HkdfSha256,
{
    /// Replay entry: feed a captured ClientHello *record* into a fresh
    /// transcript and hand back `WaitServerHello`. Avoids reconstructing CH
    /// via `write_client_hello` (which may not be byte-identical to what was
    /// actually sent — extension ordering, future CH-shape drift). Caller
    /// passes the same `x25519_priv` whose pub appeared in that CH.
    pub fn from_client_hello_record(
        ch_record: &[u8],
        x25519_priv: ZeroBuf<32>,
    ) -> Result<Self, ConnectionError> {
        let mut transcript = TranscriptHash::<H>::new();
        transcript.update_record(ch_record)?;
        Ok(Self {
            transcript,
            state: WaitServerHello { x25519_priv },
            _crypto: PhantomData,
        })
    }
}

// ============================================================================
// WaitServerHello -> NegotiatedSuite
// ============================================================================

/// Runtime suite dispatch from [`TlsConnection::read_server_hello`].
/// Embedded callers who pre-know the suite use `assume_*` to skip the match.
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
    /// Skip the runtime suite match on AES-only embedded builds.
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
    /// Parse SH, run x25519, derive handshake secrets, materialize s_hs keys.
    pub fn read_server_hello(
        mut self,
        sh_record: &[u8],
    ) -> Result<NegotiatedSuite<H, C>, ConnectionError> {
        use subtle::ConstantTimeEq;

        let sh = parse_server_hello(sh_record)?;
        let dhe = zeroize::Zeroizing::new(ed25519_heapless::x25519::<Bn>(
            &self.state.x25519_priv,
            sh.x25519_share,
        ));
        // RFC 8446 §7.4.2.1: all-zero DH output (low-order server share)
        // MUST abort with `illegal_parameter`.
        if bool::from(dhe.ct_eq(&[0u8; 32])) {
            return Err(ConnectionError::Parse(ParseError::DhAllZero));
        }

        // SH into transcript first — handshake_traffic_secrets needs H(CH‖SH).
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
                        _mode: PhantomData,
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
                        _mode: PhantomData,
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

/// Shared body for per-suite `feed_server_record`.
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

impl<H, C, M> TlsConnection<WaitServerFlight<Aes128GcmSha256, M>, H, C>
where
    H: HkdfSha256,
    C: Aes128GcmAead,
    M: HandshakeMode,
{
    /// Decrypt one record, push into `reassembler`. Returns `Ready` when
    /// the flight is complete. CCS records skipped without bumping seq_in.
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

    /// Verify the flight (CV + Finished, plus self-sig if [`VerifyMode::SelfSigned`])
    /// and advance to [`ServerFlightDone`].
    pub fn finalize_server_flight<const N: usize, P: CertParser, E: Ed25519Verify>(
        mut self,
        reassembler: &ServerFlightReassembler<N>,
        mode: VerifyMode,
    ) -> Result<TlsConnection<ServerFlightDone<Aes128GcmSha256, M>, H, C>, ConnectionError> {
        let plaintext = reassembler
            .flight_bytes()
            .ok_or(ConnectionError::IncompleteFlight)?;
        let verify_self_sig = matches!(mode, VerifyMode::SelfSigned);
        let verified = verify_server_flight::<H, P, E>(
            &mut self.transcript,
            plaintext,
            &self.state.s_hs_ts,
            verify_self_sig,
        )?;
        let server_pubkey = ServerPubkeyOwned::from_view(&verified.server_pubkey)?;
        Ok(TlsConnection {
            transcript: self.transcript,
            state: ServerFlightDone {
                hs: self.state.hs,
                c_hs_ts: self.state.c_hs_ts,
                s_hs_ts: self.state.s_hs_ts,
                server_pubkey,
                _suite: PhantomData,
                _mode: PhantomData,
            },
            _crypto: PhantomData,
        })
    }
}

#[cfg(feature = "chacha20")]
impl<H, C, M> TlsConnection<WaitServerFlight<ChaCha20Poly1305Sha256, M>, H, C>
where
    H: HkdfSha256,
    C: ChaCha20Poly1305Aead,
    M: HandshakeMode,
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
        mode: VerifyMode,
    ) -> Result<TlsConnection<ServerFlightDone<ChaCha20Poly1305Sha256, M>, H, C>, ConnectionError>
    {
        let plaintext = reassembler
            .flight_bytes()
            .ok_or(ConnectionError::IncompleteFlight)?;
        let verify_self_sig = matches!(mode, VerifyMode::SelfSigned);
        let verified = verify_server_flight::<H, P, E>(
            &mut self.transcript,
            plaintext,
            &self.state.s_hs_ts,
            verify_self_sig,
        )?;
        let server_pubkey = ServerPubkeyOwned::from_view(&verified.server_pubkey)?;
        Ok(TlsConnection {
            transcript: self.transcript,
            state: ServerFlightDone {
                hs: self.state.hs,
                c_hs_ts: self.state.c_hs_ts,
                s_hs_ts: self.state.s_hs_ts,
                server_pubkey,
                _suite: PhantomData,
                _mode: PhantomData,
            },
            _crypto: PhantomData,
        })
    }
}

// ============================================================================
// ServerFlightDone -> AppData
// ============================================================================

/// `(cf_record_bytes, c_ap_keys, s_ap_keys)` produced by `finish_handshake_inner`.
type FinishHandshakeOut<'a, S> = (&'a [u8], RecordKeys<S>, RecordKeys<S>);

/// Successful return of [`TlsConnection::finish_handshake`].
type FinishHandshakeOk<'a, S, H, C> = (&'a [u8], TlsConnection<AppData<S>, H, C>);

/// Shared body for per-suite `finish_handshake`.
fn finish_handshake_inner<'a, S, H, BuildFn, DeriveFn>(
    hs: &Secret,
    c_hs_ts: &Secret,
    th_through_sfin: &crate::newtype::TranscriptDigest,
    out_buf: &'a mut [u8],
    build_client_finished: BuildFn,
    derive_record_keys: DeriveFn,
) -> Result<FinishHandshakeOut<'a, S>, ConnectionError>
where
    S: CipherSuite,
    H: HkdfSha256,
    BuildFn: FnOnce(
        &Secret,
        &crate::newtype::TranscriptDigest,
        u64,
        &'a mut [u8],
    ) -> Result<&'a [u8], ClientFinishedError>,
    DeriveFn: Fn(&Secret) -> Result<RecordKeys<S>, HkdfLabelError>,
{
    // Seq 0 — first c->s record under c_hs AEAD keys.
    let record = build_client_finished(c_hs_ts, th_through_sfin, 0, out_buf)?;

    let ms = master_secret::<H>(hs)?;
    let (c_ap_ts, s_ap_ts) = application_traffic_secrets::<H>(&ms, th_through_sfin)?;
    let c_ap_keys = derive_record_keys(&c_ap_ts)?;
    let s_ap_keys = derive_record_keys(&s_ap_ts)?;
    Ok((record, c_ap_keys, s_ap_keys))
}

impl<S, H, C, M> TlsConnection<ServerFlightDone<S, M>, H, C>
where
    S: CipherSuite,
    H: HkdfSha256,
    M: HandshakeMode,
{
    pub fn server_pubkey(&self) -> ServerPubkey<'_> {
        self.state.server_pubkey.as_view()
    }

    /// Server handshake-traffic secret. Exposed for replay-fixture capture.
    pub fn s_hs_traffic_secret(&self) -> &Secret {
        &self.state.s_hs_ts
    }

    /// Client handshake-traffic secret. Same capture use case.
    pub fn c_hs_traffic_secret(&self) -> &Secret {
        &self.state.c_hs_ts
    }
}

impl<S, H, C> TlsConnection<ServerFlightDone<S, Live>, H, C>
where
    S: CipherSuite,
    H: HkdfSha256,
{
    /// Derive the `(c_ap, s_ap)` traffic secrets without transitioning into
    /// AppData. For replay tools that persist secrets across invocations and
    /// re-enter AppData via [`TlsConnection::from_app_secrets`]. `Live`-only
    /// because the replay path's `hs` is zeroed.
    #[cfg(feature = "replay")]
    pub fn derive_app_secrets(&self) -> Result<(Secret, Secret), ConnectionError> {
        let th = self.transcript.snapshot();
        let ms = master_secret::<H>(&self.state.hs)?;
        Ok(application_traffic_secrets::<H>(&ms, &th)?)
    }
}

impl<H, C, M> TlsConnection<ServerFlightDone<Aes128GcmSha256, M>, H, C>
where
    H: HkdfSha256,
    C: Aes128GcmAead,
    M: HandshakeMode,
{
    /// Build the client Finished record into `out_buf` without transitioning.
    /// Skips the `ms` + app-traffic derivation; replay-harness use. Production
    /// callers want [`Self::finish_handshake`] instead.
    pub fn build_client_finished<'a>(
        &self,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], ConnectionError> {
        let th = self.transcript.snapshot();
        let record = RecordKeys::<Aes128GcmSha256>::build_client_finished::<H, C>(
            &self.state.c_hs_ts,
            &th,
            0,
            out_buf,
        )?;
        Ok(record)
    }
}

#[cfg(feature = "chacha20")]
impl<H, C, M> TlsConnection<ServerFlightDone<ChaCha20Poly1305Sha256, M>, H, C>
where
    H: HkdfSha256,
    C: ChaCha20Poly1305Aead,
    M: HandshakeMode,
{
    pub fn build_client_finished<'a>(
        &self,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], ConnectionError> {
        let th = self.transcript.snapshot();
        let record = RecordKeys::<ChaCha20Poly1305Sha256>::build_client_finished::<H, C>(
            &self.state.c_hs_ts,
            &th,
            0,
            out_buf,
        )?;
        Ok(record)
    }
}

// ============================================================================
// Replay entry points (feature = "replay")
// ============================================================================
//
// Captured-fixture harnesses enter at `WaitServerFlight<S>` with pre-derived
// secrets, skipping x25519 + early HKDF. Gated so production binaries don't
// see the constructor.

#[cfg(feature = "replay")]
impl<H, C> TlsConnection<WaitServerFlight<Aes128GcmSha256, Replay>, H, C>
where
    H: HkdfSha256,
{
    /// Enter `WaitServerFlight<S, Replay>` with pre-derived secrets + transcript
    /// at `H(CH‖SH)`. `hs` is zeroed; lands on `ServerFlightDone<S, Replay>` after
    /// `finalize_server_flight`, where only `build_client_finished` is in scope —
    /// `finish_handshake` / `derive_app_secrets` are typestate-unreachable.
    pub fn from_handshake_secrets(
        transcript: TranscriptHash<H>,
        c_hs_ts: Secret,
        s_hs_ts: Secret,
    ) -> Result<Self, ConnectionError> {
        let s_hs_keys = RecordKeys::<Aes128GcmSha256>::derive::<H>(&s_hs_ts)?;
        Ok(Self {
            transcript,
            state: WaitServerFlight {
                hs: Secret::from([0u8; 32]),
                c_hs_ts,
                s_hs_ts,
                s_hs_keys,
                seq_in: 0,
                _mode: PhantomData,
            },
            _crypto: PhantomData,
        })
    }
}

#[cfg(all(feature = "replay", feature = "chacha20"))]
impl<H, C> TlsConnection<WaitServerFlight<ChaCha20Poly1305Sha256, Replay>, H, C>
where
    H: HkdfSha256,
{
    pub fn from_handshake_secrets(
        transcript: TranscriptHash<H>,
        c_hs_ts: Secret,
        s_hs_ts: Secret,
    ) -> Result<Self, ConnectionError> {
        let s_hs_keys = RecordKeys::<ChaCha20Poly1305Sha256>::derive::<H>(&s_hs_ts)?;
        Ok(Self {
            transcript,
            state: WaitServerFlight {
                hs: Secret::from([0u8; 32]),
                c_hs_ts,
                s_hs_ts,
                s_hs_keys,
                seq_in: 0,
                _mode: PhantomData,
            },
            _crypto: PhantomData,
        })
    }
}

#[cfg(feature = "replay")]
impl<H, C> TlsConnection<AppData<Aes128GcmSha256>, H, C>
where
    H: HkdfSha256,
{
    /// Enter `AppData` from persisted app-traffic secrets + per-direction
    /// sequence numbers. Replay/fixture-CLI use; bypasses the handshake.
    pub fn from_app_secrets(
        c_ap_ts: Secret,
        s_ap_ts: Secret,
        seq_out: u64,
        seq_in: u64,
    ) -> Result<Self, ConnectionError> {
        let c_ap_keys = RecordKeys::<Aes128GcmSha256>::derive::<H>(&c_ap_ts)?;
        let s_ap_keys = RecordKeys::<Aes128GcmSha256>::derive::<H>(&s_ap_ts)?;
        Ok(Self {
            transcript: TranscriptHash::<H>::new(),
            state: AppData {
                c_ap_keys,
                s_ap_keys,
                seq_out,
                seq_in,
            },
            _crypto: PhantomData,
        })
    }
}

#[cfg(all(feature = "replay", feature = "chacha20"))]
impl<H, C> TlsConnection<AppData<ChaCha20Poly1305Sha256>, H, C>
where
    H: HkdfSha256,
{
    pub fn from_app_secrets(
        c_ap_ts: Secret,
        s_ap_ts: Secret,
        seq_out: u64,
        seq_in: u64,
    ) -> Result<Self, ConnectionError> {
        let c_ap_keys = RecordKeys::<ChaCha20Poly1305Sha256>::derive::<H>(&c_ap_ts)?;
        let s_ap_keys = RecordKeys::<ChaCha20Poly1305Sha256>::derive::<H>(&s_ap_ts)?;
        Ok(Self {
            transcript: TranscriptHash::<H>::new(),
            state: AppData {
                c_ap_keys,
                s_ap_keys,
                seq_out,
                seq_in,
            },
            _crypto: PhantomData,
        })
    }
}

impl<H, C> TlsConnection<ServerFlightDone<Aes128GcmSha256, Live>, H, C>
where
    H: HkdfSha256,
    C: Aes128GcmAead,
{
    /// Build CF into `out_buf` (≥ 58 B), derive `ms` + app-traffic keys,
    /// advance to [`AppData`]. Caller writes the returned record bytes.
    /// `Live`-only — replay-derived `ServerFlightDone` has a zeroed `hs` and
    /// would produce meaningless app keys.
    pub fn finish_handshake<'a>(
        self,
        out_buf: &'a mut [u8],
    ) -> Result<FinishHandshakeOk<'a, Aes128GcmSha256, H, C>, ConnectionError> {
        let th = self.transcript.snapshot();
        let (record, c_ap_keys, s_ap_keys) = finish_handshake_inner::<Aes128GcmSha256, H, _, _>(
            &self.state.hs,
            &self.state.c_hs_ts,
            &th,
            out_buf,
            |secret, th, seq, buf| {
                RecordKeys::<Aes128GcmSha256>::build_client_finished::<H, C>(secret, th, seq, buf)
            },
            RecordKeys::<Aes128GcmSha256>::derive::<H>,
        )?;
        Ok((
            record,
            TlsConnection {
                transcript: self.transcript,
                state: AppData {
                    c_ap_keys,
                    s_ap_keys,
                    seq_out: 0,
                    seq_in: 0,
                },
                _crypto: PhantomData,
            },
        ))
    }
}

#[cfg(feature = "chacha20")]
impl<H, C> TlsConnection<ServerFlightDone<ChaCha20Poly1305Sha256, Live>, H, C>
where
    H: HkdfSha256,
    C: ChaCha20Poly1305Aead,
{
    pub fn finish_handshake<'a>(
        self,
        out_buf: &'a mut [u8],
    ) -> Result<FinishHandshakeOk<'a, ChaCha20Poly1305Sha256, H, C>, ConnectionError> {
        let th = self.transcript.snapshot();
        let (record, c_ap_keys, s_ap_keys) =
            finish_handshake_inner::<ChaCha20Poly1305Sha256, H, _, _>(
                &self.state.hs,
                &self.state.c_hs_ts,
                &th,
                out_buf,
                |secret, th, seq, buf| {
                    RecordKeys::<ChaCha20Poly1305Sha256>::build_client_finished::<H, C>(
                        secret, th, seq, buf,
                    )
                },
                RecordKeys::<ChaCha20Poly1305Sha256>::derive::<H>,
            )?;
        Ok((
            record,
            TlsConnection {
                transcript: self.transcript,
                state: AppData {
                    c_ap_keys,
                    s_ap_keys,
                    seq_out: 0,
                    seq_in: 0,
                },
                _crypto: PhantomData,
            },
        ))
    }
}

// ============================================================================
// AppData: encrypt_record / decrypt_record / close_notify
// ============================================================================

impl<H, C> TlsConnection<AppData<Aes128GcmSha256>, H, C>
where
    H: HkdfSha256,
    C: Aes128GcmAead,
{
    /// Encrypt one record under `c_ap_keys` and bump seq_out. `content_type`
    /// is the inner TLS 1.3 content type (`CT_APPLICATION_DATA` / `CT_ALERT`).
    pub fn encrypt_record<'a>(
        &mut self,
        content: &[u8],
        content_type: u8,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], ConnectionError> {
        let record = self.state.c_ap_keys.encrypt_record::<C>(
            content,
            content_type,
            self.state.seq_out,
            out_buf,
        )?;
        self.state.seq_out += 1;
        Ok(record)
    }

    /// Decrypt one record under `s_ap_keys`, return `(content, inner_ct)`,
    /// bump seq_in.
    pub fn decrypt_record<'a>(
        &mut self,
        record: &[u8],
        scratch: &'a mut [u8],
    ) -> Result<(&'a [u8], u8), ConnectionError> {
        let inner = self
            .state
            .s_ap_keys
            .decrypt_record::<C>(record, self.state.seq_in, scratch)?;
        // Borrow split: end split_inner_plaintext's borrow before reborrowing scratch.
        let (content_len, ct) = {
            let (content, ct) = split_inner_plaintext(inner)?;
            (content.len(), ct)
        };
        self.state.seq_in += 1;
        Ok((&scratch[..content_len], ct))
    }

    /// Emit a close_notify alert record. Consumes the connection.
    pub fn close_notify(mut self, out_buf: &mut [u8]) -> Result<&[u8], ConnectionError> {
        self.encrypt_record(&CLOSE_NOTIFY_ALERT, CT_ALERT, out_buf)
    }
}

#[cfg(feature = "chacha20")]
impl<H, C> TlsConnection<AppData<ChaCha20Poly1305Sha256>, H, C>
where
    H: HkdfSha256,
    C: ChaCha20Poly1305Aead,
{
    pub fn encrypt_record<'a>(
        &mut self,
        content: &[u8],
        content_type: u8,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], ConnectionError> {
        let record = self.state.c_ap_keys.encrypt_record::<C>(
            content,
            content_type,
            self.state.seq_out,
            out_buf,
        )?;
        self.state.seq_out += 1;
        Ok(record)
    }

    pub fn decrypt_record<'a>(
        &mut self,
        record: &[u8],
        scratch: &'a mut [u8],
    ) -> Result<(&'a [u8], u8), ConnectionError> {
        let inner = self
            .state
            .s_ap_keys
            .decrypt_record::<C>(record, self.state.seq_in, scratch)?;
        let (content_len, ct) = {
            let (content, ct) = split_inner_plaintext(inner)?;
            (content.len(), ct)
        };
        self.state.seq_in += 1;
        Ok((&scratch[..content_len], ct))
    }

    pub fn close_notify(mut self, out_buf: &mut [u8]) -> Result<&[u8], ConnectionError> {
        self.encrypt_record(&CLOSE_NOTIFY_ALERT, CT_ALERT, out_buf)
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
    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
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
    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
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
            .finalize_server_flight::<512, DerCert, RustCrypto>(
                &reassembler,
                VerifyMode::SelfSigned,
            )
            .expect("finalize_server_flight");
        match &done.state.server_pubkey {
            ServerPubkeyOwned::Ed25519(pk) => assert_eq!(pk, &EXPECTED_SERVER_ID_PUB),
            #[cfg(feature = "rsa")]
            ServerPubkeyOwned::Rsa { .. } => panic!("expected Ed25519 pubkey"),
        }
    }

    /// `finalize_server_flight` must reject an empty reassembler with the
    /// `IncompleteFlight` sentinel rather than wandering into the verifier.
    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
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
        let err = match conn.finalize_server_flight::<512, DerCert, RustCrypto>(
            &reassembler,
            VerifyMode::SelfSigned,
        ) {
            Ok(_) => panic!("expected IncompleteFlight"),
            Err(e) => e,
        };
        assert_eq!(err, ConnectionError::IncompleteFlight);
    }

    /// CCS records must be dropped without bumping `seq_in` so the next
    /// real AEAD record decrypts under sequence 0.
    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
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

    /// packets/004 — the byte-attested client Finished record under the
    /// seed-0 keys. 58 bytes (= [`CLIENT_FINISHED_LEN`]).
    const FIXTURE_PACKET_4: [u8; 58] = crate::hex_decode(include_str!(
        "../../testdata/packets/004_c2s_ClientFinished_encrypted.hex"
    ));
    /// packets/005 — first client app-data record under the seed-0 c_ap key.
    const FIXTURE_PACKET_5: [u8; 52] = crate::hex_decode(include_str!(
        "../../testdata/packets/005_c2s_AppData_send_0.hex"
    ));
    /// packets/006 — first server app-data record under the seed-0 s_ap key.
    const FIXTURE_PACKET_6: [u8; 48] = crate::hex_decode(include_str!(
        "../../testdata/packets/006_s2c_AppData_reply_0.hex"
    ));
    /// Plaintext the seed-0 client sent in packet 5.
    const PACKET_5_PLAINTEXT: &[u8] = b"hello from the embedded client";
    /// Plaintext the seed-0 server sent in packet 6 (includes a UTF-8 em-dash).
    const PACKET_6_PLAINTEXT: &[u8] = b"hello back \xe2\x80\x94 server here";

    /// Drive the typestate through `Init → AppData` and assert that
    /// `finish_handshake` lays down the exact byte sequence the
    /// Python fixture captured in `packets/004_c2s_ClientFinished_encrypted.hex`.
    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn finish_handshake_byte_identical_client_finished() {
        use crate::backends::DerCert;
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto, RustCrypto> =
            TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out[..];
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
        conn.feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .unwrap();
        let conn = conn
            .finalize_server_flight::<512, DerCert, RustCrypto>(
                &reassembler,
                VerifyMode::SelfSigned,
            )
            .unwrap();

        let mut fin_buf = [0u8; 64];
        let (fin_record, _conn) = conn.finish_handshake(&mut fin_buf).unwrap();
        assert_eq!(fin_record, &FIXTURE_PACKET_4[..]);
    }

    /// Full pipeline through `AppData::encrypt_record`: the same plaintext
    /// the Python seed-0 cli.py sent encrypts to the same bytes captured
    /// in `packets/005`.
    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn app_data_encrypt_record_byte_identical_packet_5() {
        use crate::backends::DerCert;
        use crate::consts::CT_APPLICATION_DATA;
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto, RustCrypto> =
            TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut ch_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut ch_buf[..];
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
        conn.feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .unwrap();
        let conn = conn
            .finalize_server_flight::<512, DerCert, RustCrypto>(
                &reassembler,
                VerifyMode::SelfSigned,
            )
            .unwrap();

        let mut fin_buf = [0u8; 64];
        let (_fin, mut conn) = conn.finish_handshake(&mut fin_buf).unwrap();

        // First c->s app-data record uses seq_out = 0.
        let mut rec_buf = [0u8; 80];
        let rec = conn
            .encrypt_record(PACKET_5_PLAINTEXT, CT_APPLICATION_DATA, &mut rec_buf)
            .unwrap();
        assert_eq!(rec, &FIXTURE_PACKET_5[..]);
        assert_eq!(conn.state.seq_out, 1);
    }

    /// Full pipeline through `AppData::decrypt_record`: the captured
    /// server reply in `packets/006` round-trips back to the original
    /// plaintext.
    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn app_data_decrypt_record_round_trips_packet_6() {
        use crate::backends::DerCert;
        use crate::consts::CT_APPLICATION_DATA;
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto, RustCrypto> =
            TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut ch_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut ch_buf[..];
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
        conn.feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .unwrap();
        let conn = conn
            .finalize_server_flight::<512, DerCert, RustCrypto>(
                &reassembler,
                VerifyMode::SelfSigned,
            )
            .unwrap();

        // Pull the server pubkey *before* burning the borrow in finish_handshake.
        assert!(matches!(conn.server_pubkey(), ServerPubkey::Ed25519(_, _)));

        let mut fin_buf = [0u8; 64];
        let (_fin, mut conn) = conn.finish_handshake(&mut fin_buf).unwrap();

        let mut pt = [0u8; 64];
        let (content, ct) = conn.decrypt_record(&FIXTURE_PACKET_6, &mut pt).unwrap();
        assert_eq!(ct, CT_APPLICATION_DATA);
        assert_eq!(content, PACKET_6_PLAINTEXT);
        assert_eq!(conn.state.seq_in, 1);
    }

    /// `close_notify` encrypts the standard `[0x01, 0x00]` alert under
    /// the next outbound sequence and consumes the connection.
    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn close_notify_emits_encrypted_alert_record() {
        use crate::backends::DerCert;
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto, RustCrypto> =
            TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut ch_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut ch_buf[..];
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
        conn.feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .unwrap();
        let conn = conn
            .finalize_server_flight::<512, DerCert, RustCrypto>(
                &reassembler,
                VerifyMode::SelfSigned,
            )
            .unwrap();
        let mut fin_buf = [0u8; 64];
        let (_fin, conn) = conn.finish_handshake(&mut fin_buf).unwrap();

        let mut alert_buf = [0u8; 64];
        let alert = conn.close_notify(&mut alert_buf).unwrap();
        // Outer record framing: application_data, TLS 1.2 record version,
        // body = AEAD(plaintext = 2B alert + 1B inner_ct + tag).
        assert_eq!(alert[0], CT_APPLICATION_DATA);
        assert_eq!(&alert[1..3], &[0x03, 0x03]);
        let body_len = u16::from_be_bytes([alert[3], alert[4]]) as usize;
        // 2-byte alert content + 1-byte inner content_type + 16-byte tag.
        assert_eq!(body_len, 2 + 1 + 16);
        assert_eq!(alert.len(), 5 + body_len);
    }

    /// Verify that `assume_aes_128_gcm` succeeds when the suite really
    /// is AES — embedded callers use this to skip the runtime enum.
    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
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
