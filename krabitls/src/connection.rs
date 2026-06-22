//! Typestate TLS 1.3 client. `TlsConnection<State, H>`'s only legal
//! next move is the one named by `State` — wrong-method-for-state is a
//! compile error. Design notes in `TYPESTATE_DESIGN.md`.

use core::marker::PhantomData;

use embedded_io::Write;

#[cfg(feature = "cipher-aes")]
use crate::aead::Aes128GcmSha256;
#[cfg(feature = "chacha20")]
use crate::aead::ChaCha20Poly1305Sha256;
use crate::aead::split_inner_plaintext;
use crate::aead::{CipherSuite, RecordKeys};
use crate::aead::{DecryptError, EncryptError};
use crate::backends::RustCrypto;
use crate::client_flight::ClientFinishedError;
#[cfg(feature = "cipher-aes")]
use crate::consts::CIPHER_AES_128_GCM_SHA256;
#[cfg(feature = "chacha20")]
use crate::consts::CIPHER_CHACHA20_POLY1305_SHA256;
use crate::consts::{CT_APPLICATION_DATA, CT_HANDSHAKE};
use crate::errors::{ClientHelloError, ParseError};
use crate::hkdf::{
    HkdfLabelError, TranscriptError, TranscriptHash, application_traffic_secrets, handshake_secret,
    handshake_traffic_secrets, master_secret,
};
use crate::newtype::{Secret, ZeroBuf};
use crate::parse_server_hello;
use crate::reassembler::{ReassemblyError, ServerFlightReassembler};
use crate::server_flight::FlightError;
use crate::server_flight::ServerPubkey;
use crate::server_flight::verify_server_flight;
use crate::traits::verify_strategy::PreparedVerifier;
use crate::traits::{CertView, Ed25519VerifierProvider, HkdfSha256, RsaVerifierProvider};

// Only consumer is `close_notify` on Live, whose gate is matched here.
#[cfg(all(test, not(feature = "chacha20"), not(feature = "rsa")))]
const CT_ALERT: u8 = 0x15;
#[cfg(all(test, not(feature = "chacha20"), not(feature = "rsa")))]
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
    WrongSuite {
        expected: u16,
        got: u16,
    },
    IncompleteFlight,
    UnexpectedSuite {
        selected_id: u16,
    },
    /// RFC 8446 §6: `level` 1=warning, 2=fatal; `description` is AlertDescription.
    Alert {
        level: u8,
        description: u8,
    },
    UnknownContentType(u8),
}

impl<E> ConnectionError<E> {
    pub fn map_writer<F, U>(self, f: F) -> ConnectionError<U>
    where
        F: FnOnce(E) -> U,
    {
        use ConnectionError::*;
        match self {
            ClientHello(ch) => ClientHello(ch.map_writer(f)),
            Parse(p) => Parse(p),
            Hkdf(h) => Hkdf(h),
            Flight(fl) => Flight(fl),
            Decrypt(d) => Decrypt(d),
            Encrypt(en) => Encrypt(en),
            Transcript(t) => Transcript(t),
            Reassembly(r) => Reassembly(r),
            ClientFinished(cf) => ClientFinished(cf),
            WrongSuite { expected, got } => WrongSuite { expected, got },
            IncompleteFlight => IncompleteFlight,
            UnexpectedSuite { selected_id } => UnexpectedSuite { selected_id },
            Alert { level, description } => Alert { level, description },
            UnknownContentType(c) => UnknownContentType(c),
        }
    }
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
            Self::UnexpectedSuite { selected_id } => write!(
                f,
                "server selected unadvertised cipher suite 0x{selected_id:04x}"
            ),
            Self::Alert { level, description } => {
                write!(f, "peer alert: level {level}, description {description}")
            }
            Self::UnknownContentType(ct) => {
                write!(f, "unknown TLS record content_type 0x{ct:02x}")
            }
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
            Self::WrongSuite { .. }
            | Self::IncompleteFlight
            | Self::UnexpectedSuite { .. }
            | Self::Alert { .. }
            | Self::UnknownContentType(_) => None,
        }
    }
}

// ============================================================================
// State markers
// ============================================================================

pub struct Init {
    pub(crate) client_random: [u8; 32],
    pub(crate) x25519_priv: ZeroBuf<32>,
}

pub struct WaitServerHello {
    pub(crate) x25519_priv: ZeroBuf<32>,
    /// Cipher suites we advertised in the ClientHello. `read_server_hello`
    /// rejects a selected suite that wasn't on this list. Only consulted
    /// under `feature = "chacha20"` — without it, AES is the only suite.
    #[cfg_attr(not(feature = "chacha20"), allow(dead_code))]
    pub(crate) advertised: crate::SuiteList,
}

mod sealed {
    pub trait Sealed {}
}

/// Replay-derived states have a zeroed `hs`; `finish_handshake` /
/// `derive_app_secrets` impl only for [`Live`].
pub trait HandshakeMode: sealed::Sealed {}

pub struct Live;
// Replay-mode marker. All `Replay`-typed code paths sit behind
// `feature = "replay"`; mirror that gate on the marker itself so the
// non-replay build never compiles the type at all.
#[cfg(feature = "replay")]
pub struct Replay;
impl sealed::Sealed for Live {}
#[cfg(feature = "replay")]
impl sealed::Sealed for Replay {}
impl HandshakeMode for Live {}
#[cfg(feature = "replay")]
impl HandshakeMode for Replay {}

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
    // `s_hs_ts` and `server_pubkey` are stored by `verify_server_flight`'s
    // construction site but never read in production (finish_handshake
    // only consumes `hs` and `c_hs_ts`). They're load-bearing for the
    // cfg(test) `server_pubkey()` accessor + a direct field-read in this
    // file's tests. Carried in the typestate rather than dropped so the
    // test surface still has something to inspect.
    #[allow(dead_code)]
    pub(crate) s_hs_ts: Secret,
    #[allow(dead_code)]
    pub(crate) server_pubkey: ServerPubkeyOwned,
    pub(crate) _suite: PhantomData<S>,
    pub(crate) _mode: PhantomData<M>,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
// Fields are only read by `from_view`/`as_view` below — both of which
// are themselves part of the replay-fixture surface (no facade-engine
// caller). Kept so the typestate's ServerFlightDone can carry a
// concrete pubkey for replay tooling.
#[allow(dead_code)]
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

    // Only caller is the cfg(test) `server_pubkey()` accessor on
    // ServerFlightDone — same gate.
    #[cfg(all(test, not(feature = "chacha20"), not(feature = "rsa")))]
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
pub struct TlsConnection<State, H = RustCrypto>
where
    H: HkdfSha256,
{
    transcript: TranscriptHash<H>,
    state: State,
}

// ============================================================================
// Init -> WaitServerHello
// ============================================================================

/// Carries `written_len` rather than `&buf[..n]` so the borrow ends before the next state.
pub type WriteClientHelloToSliceWithResult<H> = Result<
    (usize, TlsConnection<WaitServerHello, H>),
    ConnectionError<embedded_io::SliceWriteError>,
>;

impl<H> TlsConnection<Init, H>
where
    H: HkdfSha256,
{
    pub fn new(client_random: [u8; 32], x25519_priv: ZeroBuf<32>) -> Self {
        Self {
            transcript: TranscriptHash::<H>::new(),
            state: Init {
                client_random,
                x25519_priv,
            },
        }
    }

    pub fn write_client_hello_with<W: Write>(
        mut self,
        out: &mut W,
        x25519_pub: &[u8; 32],
        opts: &crate::ClientHelloOptions<'_>,
    ) -> Result<TlsConnection<WaitServerHello, H>, ConnectionError<W::Error>> {
        // Scratch first so the transcript sees the exact wire bytes.
        let mut scratch = [0u8; CH_SCRATCH];
        let mut cursor: &mut [u8] = &mut scratch[..];
        let n = crate::write_client_hello_with(
            &mut cursor,
            &self.state.client_random,
            x25519_pub,
            opts,
        )
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
            ClientHelloError::RecordSizeLimitOutOfRange => {
                ConnectionError::ClientHello(ClientHelloError::RecordSizeLimitOutOfRange)
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
                advertised: opts.suites,
            },
        })
    }

    pub fn write_client_hello_to_slice_with(
        self,
        buf: &mut [u8],
        x25519_pub: &[u8; 32],
        opts: &crate::ClientHelloOptions<'_>,
    ) -> WriteClientHelloToSliceWithResult<H> {
        let total = buf.len();
        let mut cursor = &mut *buf;
        let next = self.write_client_hello_with(&mut cursor, x25519_pub, opts)?;
        let written = total - cursor.len();
        Ok((written, next))
    }
}

#[cfg(feature = "replay")]
impl<H> TlsConnection<WaitServerHello, H>
where
    H: HkdfSha256,
{
    /// Replay entry from a captured CH record. `x25519_priv` must match
    /// the pub in that CH. `advertised` must match the CH's
    /// `cipher_suites` list; pass [`crate::SuiteList::Default`] when the
    /// captured CH advertised both AES and ChaCha.
    pub fn from_client_hello_record(
        ch_record: &[u8],
        x25519_priv: ZeroBuf<32>,
        advertised: crate::SuiteList,
    ) -> Result<Self, ConnectionError> {
        let mut transcript = TranscriptHash::<H>::new();
        transcript.update_record(ch_record)?;
        Ok(Self {
            transcript,
            state: WaitServerHello {
                x25519_priv,
                advertised,
            },
        })
    }
}

// ============================================================================
// WaitServerHello -> NegotiatedSuite
// ============================================================================

/// Pre-known suite? Use `assume_*` to skip the runtime match.
#[allow(clippy::large_enum_variant)] // AES Aes128Gcm key schedule dominates
pub enum NegotiatedSuite<H = RustCrypto>
where
    H: HkdfSha256,
{
    #[cfg(feature = "cipher-aes")]
    Aes128Gcm(TlsConnection<WaitServerFlight<Aes128GcmSha256>, H>),
    #[cfg(feature = "chacha20")]
    ChaCha20Poly1305(TlsConnection<WaitServerFlight<ChaCha20Poly1305Sha256>, H>),
}

impl<H> NegotiatedSuite<H>
where
    H: HkdfSha256,
{
    // Test-only typestate accessor; the facade engine matches on the
    // NegotiatedSuite enum directly. Only kept for tests that drive the
    // typestate through a known cipher choice. Test gating mirrors the
    // test functions that use it (e.g. `feed_server_record_and_finalize_smoke`).
    #[cfg(all(
        test,
        feature = "cipher-aes",
        not(feature = "chacha20"),
        not(feature = "rsa")
    ))]
    pub fn assume_aes_128_gcm(
        self,
    ) -> Result<TlsConnection<WaitServerFlight<Aes128GcmSha256>, H>, ConnectionError> {
        match self {
            Self::Aes128Gcm(c) => Ok(c),
            #[cfg(feature = "chacha20")]
            Self::ChaCha20Poly1305(_) => Err(ConnectionError::WrongSuite {
                expected: CIPHER_AES_128_GCM_SHA256,
                got: CIPHER_CHACHA20_POLY1305_SHA256,
            }),
        }
    }
}

impl<H> TlsConnection<WaitServerHello, H>
where
    H: HkdfSha256,
{
    pub fn read_server_hello(
        mut self,
        sh_record: &[u8],
    ) -> Result<NegotiatedSuite<H>, ConnectionError> {
        use subtle::ConstantTimeEq;

        let sh = parse_server_hello(sh_record)?;
        // Selected suite must have been in the advertised cipher_suites list.
        let advertised_ok = match sh.cipher_suite {
            #[cfg(feature = "cipher-aes")]
            CIPHER_AES_128_GCM_SHA256 => {
                #[cfg(feature = "chacha20")]
                {
                    !matches!(self.state.advertised, crate::SuiteList::ChaChaOnly)
                }
                #[cfg(not(feature = "chacha20"))]
                {
                    true
                }
            }
            #[cfg(feature = "chacha20")]
            CIPHER_CHACHA20_POLY1305_SHA256 => matches!(
                self.state.advertised,
                crate::SuiteList::Default | crate::SuiteList::ChaChaOnly,
            ),
            _ => false,
        };
        if !advertised_ok {
            return Err(ConnectionError::UnexpectedSuite {
                selected_id: sh.cipher_suite,
            });
        }

        let dhe = zeroize::Zeroizing::new(ed25519_heapless::x25519::<Bn>(
            &self.state.x25519_priv,
            sh.x25519_share,
        ));
        // RFC 8446 §7.4.2.1: all-zero DH output (low-order server share)
        // MUST abort with `illegal_parameter`.
        if bool::from(dhe.ct_eq(&[0u8; 32])) {
            return Err(ConnectionError::Parse(ParseError::DhAllZero));
        }

        // handshake_traffic_secrets needs H(CH‖SH).
        self.transcript.update_record(sh_record)?;
        let th_ch_sh = self.transcript.snapshot();

        let hs = handshake_secret::<H>(&dhe)?;
        let (c_hs_ts, s_hs_ts) = handshake_traffic_secrets::<H>(&hs, &th_ch_sh)?;

        match sh.cipher_suite {
            #[cfg(feature = "cipher-aes")]
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

// Only caller is `feed_server_record` below — same gate.
#[cfg(all(test, not(feature = "chacha20"), not(feature = "rsa")))]
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

/// `record` must be the full TLS record. On error the buffer is
/// undefined — MUST NOT inspect.
fn feed_server_record_inplace_inner<const N: usize, F>(
    record: &mut [u8],
    seq_in: &mut u64,
    reassembler: &mut ServerFlightReassembler<N>,
    decrypt: F,
) -> Result<FlightStep, ConnectionError>
where
    F: FnOnce(&mut [u8], u64) -> Result<usize, DecryptError>,
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
            let inner_len = decrypt(record, *seq_in)?;
            let inner = &record[5..5 + inner_len];
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

impl<S, H, M> TlsConnection<WaitServerFlight<S, M>, H>
where
    S: CipherSuite,
    H: HkdfSha256,
    M: HandshakeMode,
{
    /// CCS records skipped without bumping seq_in.
    // The facade engine has its own record-feed path (decrypt_record_inplace
    // + manual reassembly). Only callers of this typestate-style method
    // are this file's tests, gated `not(chacha20)+not(rsa)`.
    #[cfg(all(test, not(feature = "chacha20"), not(feature = "rsa")))]
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
            |r, s, b| self.state.s_hs_keys.decrypt_record(r, s, b),
        )
    }

    pub fn feed_server_record_inplace<const N: usize>(
        &mut self,
        record: &mut [u8],
        reassembler: &mut ServerFlightReassembler<N>,
    ) -> Result<FlightStep, ConnectionError> {
        feed_server_record_inplace_inner(record, &mut self.state.seq_in, reassembler, |r, s| {
            self.state.s_hs_keys.decrypt_record_inplace(r, s)
        })
    }

    /// Verify CV + Finished against the caller-supplied prepared verifier
    /// and advance to [`ServerFlightDone`]. The typestate boundary
    /// defensively re-checks `prepared.matches_cert(leaf_view)` so a
    /// non-engine caller can't sneak in a verifier built from one cert
    /// while the stored `server_pubkey` comes from another.
    pub fn finalize_server_flight<
        const N: usize,
        E: Ed25519VerifierProvider,
        R: RsaVerifierProvider,
    >(
        mut self,
        reassembler: &ServerFlightReassembler<N>,
        prepared: &PreparedVerifier<E, R>,
        leaf_view: &CertView<'_>,
    ) -> Result<TlsConnection<ServerFlightDone<S, M>, H>, ConnectionError> {
        if !bool::from(prepared.matches_cert(leaf_view)) {
            return Err(ConnectionError::Flight(FlightError::CertVerifyInvalid));
        }
        let plaintext = reassembler
            .flight_bytes()
            .ok_or(ConnectionError::IncompleteFlight)?;
        let verified = verify_server_flight::<H, E, R>(
            &mut self.transcript,
            plaintext,
            &self.state.s_hs_ts,
            prepared,
            leaf_view,
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
        })
    }
}

// ============================================================================
// ServerFlightDone -> AppData
// ============================================================================

type FinishHandshakeOut<'a, S> = (&'a [u8], RecordKeys<S>, RecordKeys<S>);

type FinishHandshakeOk<'a, S, H> = (&'a [u8], TlsConnection<AppData<S>, H>);

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

impl<S, H, M> TlsConnection<ServerFlightDone<S, M>, H>
where
    S: CipherSuite,
    H: HkdfSha256,
    M: HandshakeMode,
{
    // Test-only accessor — used by this file's `replay_state_matches`
    // test. s_hs_traffic_secret / c_hs_traffic_secret / build_client_finished
    // had zero callers and were removed entirely. Gate matches the
    // caller test's cfg.
    #[cfg(all(test, not(feature = "chacha20"), not(feature = "rsa")))]
    pub fn server_pubkey(&self) -> ServerPubkey<'_> {
        self.state.server_pubkey.as_view()
    }
}

impl<S, H> TlsConnection<ServerFlightDone<S, Live>, H>
where
    S: CipherSuite,
    H: HkdfSha256,
{
    /// `Live`-only: replay path's `hs` is zeroed. Pairs with [`TlsConnection::from_app_secrets`].
    #[cfg(feature = "replay")]
    pub fn derive_app_secrets(&self) -> Result<(Secret, Secret), ConnectionError> {
        let th = self.transcript.snapshot();
        let ms = master_secret::<H>(&self.state.hs)?;
        Ok(application_traffic_secrets::<H>(&ms, &th)?)
    }
}

// ============================================================================
// Replay entry points (feature = "replay")
// ============================================================================

#[cfg(feature = "replay")]
impl<S, H> TlsConnection<WaitServerFlight<S, Replay>, H>
where
    S: CipherSuite,
    H: HkdfSha256,
{
    /// `transcript` at `H(CH‖SH)`; `hs` zeroed.
    pub fn from_handshake_secrets(
        transcript: TranscriptHash<H>,
        c_hs_ts: Secret,
        s_hs_ts: Secret,
    ) -> Result<Self, ConnectionError> {
        let s_hs_keys = RecordKeys::<S>::derive::<H>(&s_hs_ts)?;
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
        })
    }
}

#[cfg(feature = "replay")]
impl<S, H> TlsConnection<AppData<S>, H>
where
    S: CipherSuite,
    H: HkdfSha256,
{
    /// Replay/fixture-CLI entry; bypasses the handshake.
    pub fn from_app_secrets(
        c_ap_ts: Secret,
        s_ap_ts: Secret,
        seq_out: u64,
        seq_in: u64,
    ) -> Result<Self, ConnectionError> {
        let c_ap_keys = RecordKeys::<S>::derive::<H>(&c_ap_ts)?;
        let s_ap_keys = RecordKeys::<S>::derive::<H>(&s_ap_ts)?;
        Ok(Self {
            transcript: TranscriptHash::<H>::new(),
            state: AppData {
                c_ap_keys,
                s_ap_keys,
                seq_out,
                seq_in,
            },
        })
    }
}

impl<S, H> TlsConnection<ServerFlightDone<S, Live>, H>
where
    S: CipherSuite,
    H: HkdfSha256,
{
    /// `out_buf` ≥ 58 B. `Live`-only.
    pub fn finish_handshake<'a>(
        self,
        out_buf: &'a mut [u8],
    ) -> Result<FinishHandshakeOk<'a, S, H>, ConnectionError> {
        let th = self.transcript.snapshot();
        let (record, c_ap_keys, s_ap_keys) = finish_handshake_inner::<S, H, _, _>(
            &self.state.hs,
            &self.state.c_hs_ts,
            &th,
            out_buf,
            |secret, th, seq, buf| {
                RecordKeys::<S>::build_client_finished::<H>(secret, th, seq, buf)
            },
            RecordKeys::<S>::derive::<H>,
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
            },
        ))
    }
}

// ============================================================================
// AppData: encrypt_record / decrypt_record / close_notify
// ============================================================================

impl<S, H> TlsConnection<AppData<S>, H>
where
    S: CipherSuite,
    H: HkdfSha256,
{
    /// `content_type` is the inner TLS 1.3 type (`CT_APPLICATION_DATA` / `CT_ALERT`).
    pub fn encrypt_record<'a>(
        &mut self,
        content: &[u8],
        content_type: u8,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], ConnectionError> {
        let record = self.state.c_ap_keys.encrypt_record(
            content,
            content_type,
            self.state.seq_out,
            out_buf,
        )?;
        self.state.seq_out += 1;
        Ok(record)
    }

    // Test-only path; the facade engine uses `decrypt_record_inplace`.
    // Gate matches the cfg on the test function that calls it.
    #[cfg(all(test, not(feature = "chacha20"), not(feature = "rsa")))]
    pub fn decrypt_record<'a>(
        &mut self,
        record: &[u8],
        scratch: &'a mut [u8],
    ) -> Result<(&'a [u8], u8), ConnectionError> {
        let inner = self
            .state
            .s_ap_keys
            .decrypt_record(record, self.state.seq_in, scratch)?;
        // Borrow split: end split_inner_plaintext's borrow before reborrowing scratch.
        let (content_len, ct) = {
            let (content, ct) = split_inner_plaintext(inner)?;
            (content.len(), ct)
        };
        self.state.seq_in += 1;
        Ok((&scratch[..content_len], ct))
    }

    /// Plaintext lands at `record[5..5 + content_len]`; `record` must
    /// be the full record (5-byte header used as AAD). On error
    /// `record` is undefined — MUST NOT inspect.
    pub fn decrypt_record_inplace(
        &mut self,
        record: &mut [u8],
    ) -> Result<(usize, u8), ConnectionError> {
        let inner_len = self
            .state
            .s_ap_keys
            .decrypt_record_inplace(record, self.state.seq_in)?;
        let (content_len, ct) = {
            let inner = &record[5..5 + inner_len];
            let (content, ct) = split_inner_plaintext(inner)?;
            (content.len(), ct)
        };
        self.state.seq_in += 1;
        Ok((content_len, ct))
    }

    // Test-only path; the facade engine handles close_notify in its own
    // event loop. Gate matches the cfg on the test function that calls it.
    #[cfg(all(test, not(feature = "chacha20"), not(feature = "rsa")))]
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

    // Seed-0 fixtures duplicated from `lib.rs` — keep in sync.
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
    /// Matches `testdata/packets/001_c2s_ClientHello.hex` (RFC 8449 RSL=16385).
    const FIXTURE_CLIENT_HELLO: [u8; 149] = [
        0x16, 0x03, 0x03, 0x00, 0x90, 0x01, 0x00, 0x00, 0x8c, 0x03, 0x03, 0xed, 0xe5, 0x7b, 0xa2,
        0x43, 0x3a, 0xd5, 0xa3, 0x4d, 0x05, 0x50, 0x3a, 0xfe, 0x4f, 0xc2, 0x89, 0xdf, 0xd9, 0xe9,
        0x53, 0x57, 0xd8, 0x16, 0x36, 0x80, 0x24, 0xe7, 0x3f, 0xbf, 0xa6, 0xfa, 0xf5, 0x00, 0x00,
        0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x61, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
        0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07,
        0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x00, 0x00, 0x11, 0x74, 0x6c, 0x73, 0x2d, 0x66, 0x69,
        0x78, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x1c, 0x00, 0x02,
        0x40, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x82, 0x46, 0xe7,
        0x35, 0x8f, 0x0a, 0xf7, 0xf3, 0x31, 0x7d, 0xca, 0xf6, 0x88, 0xd0, 0x34, 0xc9, 0x5d, 0x5a,
        0x2b, 0x54, 0xbf, 0x66, 0xc8, 0x95, 0x0e, 0xb8, 0x7a, 0x5f, 0x47, 0x93, 0x96, 0x0d,
    ];
    /// Matches `FIXTURE_CLIENT_HELLO`: RSL=16385, SNI=`tls-fixture.local`.
    fn fixture_opts() -> crate::ClientHelloOptions<'static> {
        crate::ClientHelloOptions {
            hostname: Some(b"tls-fixture.local"),
            record_size_limit: Some(16385),
            suites: crate::SuiteList::Default,
        }
    }
    const FIXTURE_SERVER_HELLO: [u8; 95] = [
        0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0x64, 0x1c, 0x5b, 0xd9,
        0x34, 0xab, 0xe1, 0xc5, 0x98, 0xa9, 0xc9, 0x61, 0xf7, 0xcb, 0x1e, 0x06, 0x28, 0x0b, 0x4a,
        0x5e, 0x88, 0x0c, 0x1c, 0x19, 0xd2, 0xfe, 0x9e, 0xef, 0x33, 0x48, 0x0c, 0xae, 0x00, 0x13,
        0x01, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00,
        0x1d, 0x00, 0x20, 0x60, 0x4d, 0x7a, 0x17, 0x18, 0x38, 0xbd, 0xa2, 0x15, 0xd2, 0xb5, 0x4a,
        0x24, 0xfb, 0x7d, 0x3a, 0x88, 0x8d, 0xa5, 0xac, 0x36, 0x72, 0x72, 0x6d, 0x20, 0x06, 0x44,
        0x04, 0xf7, 0x06, 0xdb, 0x7e,
    ];

    #[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
    #[test]
    fn write_client_hello_with_legacy_opts_emits_no_rsl_extension() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out = [0u8; 256];
        let (written, _next) = conn
            .write_client_hello_to_slice_with(
                &mut out[..],
                &FIXTURE_X25519_PUB,
                &crate::ClientHelloOptions::legacy(),
            )
            .expect("write_client_hello_to_slice_with");
        assert_eq!(written, crate::CLIENT_HELLO_LEN);
        // RSL extension type bytes (0x00 0x1c) must be absent.
        let needle = [0x00u8, 0x1c];
        let haystack = &out[..written];
        assert!(
            !haystack.windows(2).any(|w| w == needle),
            "legacy opts unexpectedly emitted the RSL extension type bytes",
        );
    }

    #[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
    #[test]
    fn write_client_hello_with_record_size_limit_extension_present() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out = [0u8; 256];
        let opts = crate::ClientHelloOptions {
            hostname: None,
            record_size_limit: Some(8192),
            suites: crate::SuiteList::Default,
        };
        let (written, _next) = conn
            .write_client_hello_to_slice_with(&mut out[..], &FIXTURE_X25519_PUB, &opts)
            .expect("write_client_hello_to_slice_with");
        // +6 vs legacy = 4-byte ext header + 2-byte u16 value.
        assert_eq!(written, crate::CLIENT_HELLO_LEN + 6);
        // 8192 = 0x2000.
        let needle = [0x00, 0x1c, 0x00, 0x02, 0x20, 0x00];
        let haystack = &out[..written];
        assert!(
            haystack.windows(needle.len()).any(|w| w == needle),
            "record_size_limit extension bytes not found",
        );
    }

    #[cfg(all(feature = "cipher-aes", feature = "chacha20"))]
    #[test]
    fn write_client_hello_with_aes_only_narrows_cipher_suites() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn_default: TlsConnection<Init, RustCrypto> =
            TlsConnection::new(FIXTURE_RANDOM, priv_zb.clone());
        let mut out_default = [0u8; 256];
        let (written_default, _) = conn_default
            .write_client_hello_to_slice_with(
                &mut out_default[..],
                &FIXTURE_X25519_PUB,
                &crate::ClientHelloOptions::legacy(),
            )
            .expect("default");

        let conn_aes: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_aes = [0u8; 256];
        let aes_opts = crate::ClientHelloOptions {
            hostname: None,
            record_size_limit: None,
            suites: crate::SuiteList::AesOnly,
        };
        let (written_aes, _) = conn_aes
            .write_client_hello_to_slice_with(&mut out_aes[..], &FIXTURE_X25519_PUB, &aes_opts)
            .expect("aes-only");

        assert_eq!(written_aes + 2, written_default);
        let aes_bytes = &out_aes[..written_aes];
        assert!(
            !aes_bytes.windows(2).any(|w| w == [0x13, 0x03]),
            "AES-only CH still advertises ChaCha suite",
        );
        assert!(
            aes_bytes.windows(2).any(|w| w == [0x13, 0x01]),
            "AES-only CH missing AES suite",
        );
    }

    #[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
    #[test]
    fn init_writes_byte_identical_client_hello() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        const BUF_LEN: usize = 256;
        let mut out = [0u8; BUF_LEN];
        let written = {
            let mut cursor: &mut [u8] = &mut out[..];
            let _conn = conn
                .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
                .expect("write_client_hello_with");
            BUF_LEN - cursor.len()
        };
        assert_eq!(written, FIXTURE_CLIENT_HELLO.len());
        assert_eq!(&out[..written], &FIXTURE_CLIENT_HELLO);
    }

    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn read_server_hello_lands_on_aes_variant() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();

        let negotiated = conn.read_server_hello(&FIXTURE_SERVER_HELLO).unwrap();
        match negotiated {
            #[cfg(feature = "cipher-aes")]
            NegotiatedSuite::Aes128Gcm(_) => {}
            #[allow(unreachable_patterns)]
            _ => panic!("expected AES-128-GCM variant"),
        }
    }

    /// One 415-byte AEAD record carrying the full seed-0 server flight.
    const FIXTURE_PACKET_3: [u8; 415] = crate::hex_decode(include_str!(
        "../../testdata/packets/003_s2c_ServerFlight_encrypted.hex"
    ));

    /// Ed25519 pubkey in the seed-0 self-signed cert.
    const EXPECTED_SERVER_ID_PUB: [u8; 32] = [
        0x9d, 0xfe, 0x2a, 0xb0, 0x3e, 0x35, 0x70, 0x4b, 0x9c, 0xfb, 0x93, 0xb6, 0x03, 0xa6, 0x61,
        0x18, 0x82, 0x17, 0xa6, 0xb5, 0xfd, 0x6a, 0x1f, 0x75, 0xe6, 0x16, 0x1a, 0x39, 0xe0, 0x53,
        0x4c, 0x3f,
    ];

    fn fixture_prepared() -> PreparedVerifier<RustCrypto, RustCrypto> {
        PreparedVerifier::ed25519(<RustCrypto as Ed25519VerifierProvider>::prepare_ed25519(
            &EXPECTED_SERVER_ID_PUB,
        ))
    }

    fn fixture_leaf_view() -> CertView<'static> {
        CertView::Ed25519 {
            tbs: &[],
            signature: &[0u8; 64],
            pubkey: &EXPECTED_SERVER_ID_PUB,
            san: None,
            validity_der: &[],
        }
    }

    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn feed_server_record_and_finalize_smoke() {
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
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
            .finalize_server_flight::<512, RustCrypto, RustCrypto>(
                &reassembler,
                &fixture_prepared(),
                &fixture_leaf_view(),
            )
            .expect("finalize_server_flight");
        match &done.state.server_pubkey {
            ServerPubkeyOwned::Ed25519(pk) => assert_eq!(pk, &EXPECTED_SERVER_ID_PUB),
            #[cfg(feature = "rsa")]
            ServerPubkeyOwned::Rsa { .. } => panic!("expected Ed25519 pubkey"),
        }
    }

    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn finalize_without_flight_is_incomplete() {
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();

        let reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let err = match conn.finalize_server_flight::<512, RustCrypto, RustCrypto>(
            &reassembler,
            &fixture_prepared(),
            &fixture_leaf_view(),
        ) {
            Ok(_) => panic!("expected IncompleteFlight"),
            Err(e) => e,
        };
        assert_eq!(err, ConnectionError::IncompleteFlight);
    }

    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn feed_server_record_skips_ccs_without_bumping_seq() {
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
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

        let step = conn
            .feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .unwrap();
        assert_eq!(step, FlightStep::Ready);
        assert_eq!(conn.state.seq_in, 1);
    }

    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn feed_server_record_inplace_matches_copying() {
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let mut conn_copy = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();
        let mut copy_reasm: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut scratch = [0u8; 400];
        let step_copy = conn_copy
            .feed_server_record(&FIXTURE_PACKET_3, &mut copy_reasm, &mut scratch)
            .unwrap();
        let seq_copy = conn_copy.state.seq_in;

        // Separate TlsConnection so we can compare seq_in.
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let mut conn_inplace = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();
        let mut inplace_reasm: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut record_buf = FIXTURE_PACKET_3;
        let step_inplace = conn_inplace
            .feed_server_record_inplace(&mut record_buf[..], &mut inplace_reasm)
            .unwrap();

        assert_eq!(step_copy, step_inplace);
        assert_eq!(seq_copy, conn_inplace.state.seq_in);
        assert_eq!(copy_reasm.flight_bytes(), inplace_reasm.flight_bytes());
    }

    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn feed_server_record_inplace_skips_ccs_without_bumping_seq() {
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let mut conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();

        let mut reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut ccs_record = [0x14u8, 0x03, 0x03, 0x00, 0x01, 0x01];
        let step = conn
            .feed_server_record_inplace(&mut ccs_record, &mut reassembler)
            .unwrap();
        assert_eq!(step, FlightStep::Pending);
        assert_eq!(conn.state.seq_in, 0);

        let mut flight = FIXTURE_PACKET_3;
        let step = conn
            .feed_server_record_inplace(&mut flight[..], &mut reassembler)
            .unwrap();
        assert_eq!(step, FlightStep::Ready);
        assert_eq!(conn.state.seq_in, 1);
    }

    /// Seed-0 client Finished, 58 B (= [`CLIENT_FINISHED_LEN`]).
    const FIXTURE_PACKET_4: [u8; 58] = crate::hex_decode(include_str!(
        "../../testdata/packets/004_c2s_ClientFinished_encrypted.hex"
    ));
    /// First c->s app-data record under seed-0 c_ap.
    const FIXTURE_PACKET_5: [u8; 52] = crate::hex_decode(include_str!(
        "../../testdata/packets/005_c2s_AppData_send_0.hex"
    ));
    /// First s->c app-data record under seed-0 s_ap.
    const FIXTURE_PACKET_6: [u8; 48] = crate::hex_decode(include_str!(
        "../../testdata/packets/006_s2c_AppData_reply_0.hex"
    ));
    const PACKET_5_PLAINTEXT: &[u8] = b"hello from the embedded client";
    const PACKET_6_PLAINTEXT: &[u8] = b"hello back \xe2\x80\x94 server here";

    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn finish_handshake_byte_identical_client_finished() {
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
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
            .finalize_server_flight::<512, RustCrypto, RustCrypto>(
                &reassembler,
                &fixture_prepared(),
                &fixture_leaf_view(),
            )
            .unwrap();

        let mut fin_buf = [0u8; 64];
        let (fin_record, _conn) = conn.finish_handshake(&mut fin_buf).unwrap();
        assert_eq!(fin_record, &FIXTURE_PACKET_4[..]);
    }

    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn app_data_encrypt_record_byte_identical_packet_5() {
        use crate::consts::CT_APPLICATION_DATA;
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut ch_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut ch_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
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
            .finalize_server_flight::<512, RustCrypto, RustCrypto>(
                &reassembler,
                &fixture_prepared(),
                &fixture_leaf_view(),
            )
            .unwrap();

        let mut fin_buf = [0u8; 64];
        let (_fin, mut conn) = conn.finish_handshake(&mut fin_buf).unwrap();

        let mut rec_buf = [0u8; 80];
        let rec = conn
            .encrypt_record(PACKET_5_PLAINTEXT, CT_APPLICATION_DATA, &mut rec_buf)
            .unwrap();
        assert_eq!(rec, &FIXTURE_PACKET_5[..]);
        assert_eq!(conn.state.seq_out, 1);
    }

    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn app_data_decrypt_record_round_trips_packet_6() {
        use crate::consts::CT_APPLICATION_DATA;
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut ch_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut ch_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
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
            .finalize_server_flight::<512, RustCrypto, RustCrypto>(
                &reassembler,
                &fixture_prepared(),
                &fixture_leaf_view(),
            )
            .unwrap();

        // Pull pubkey before finish_handshake burns the borrow.
        assert!(matches!(conn.server_pubkey(), ServerPubkey::Ed25519(_, _)));

        let mut fin_buf = [0u8; 64];
        let (_fin, mut conn) = conn.finish_handshake(&mut fin_buf).unwrap();

        let mut pt = [0u8; 64];
        let (content, ct) = conn.decrypt_record(&FIXTURE_PACKET_6, &mut pt).unwrap();
        assert_eq!(ct, CT_APPLICATION_DATA);
        assert_eq!(content, PACKET_6_PLAINTEXT);
        assert_eq!(conn.state.seq_in, 1);
    }

    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn close_notify_emits_encrypted_alert_record() {
        use crate::reassembler::ServerFlightReassembler;

        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut ch_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut ch_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
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
            .finalize_server_flight::<512, RustCrypto, RustCrypto>(
                &reassembler,
                &fixture_prepared(),
                &fixture_leaf_view(),
            )
            .unwrap();
        let mut fin_buf = [0u8; 64];
        let (_fin, conn) = conn.finish_handshake(&mut fin_buf).unwrap();

        let mut alert_buf = [0u8; 64];
        let alert = conn.close_notify(&mut alert_buf).unwrap();
        assert_eq!(alert[0], CT_APPLICATION_DATA);
        assert_eq!(&alert[1..3], &[0x03, 0x03]);
        let body_len = u16::from_be_bytes([alert[3], alert[4]]) as usize;
        // 2B alert + 1B inner_ct + 16B tag.
        assert_eq!(body_len, 2 + 1 + 16);
        assert_eq!(alert.len(), 5 + body_len);
    }

    #[cfg(all(not(feature = "chacha20"), not(feature = "rsa")))]
    #[test]
    fn assume_aes_succeeds_for_aes_handshake() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();

        let negotiated = conn.read_server_hello(&FIXTURE_SERVER_HELLO).unwrap();
        let _conn = negotiated
            .assume_aes_128_gcm()
            .expect("assume_aes_128_gcm should accept an AES handshake");
    }
}
