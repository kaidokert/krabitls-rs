//! Typestate TLS 1.3 client. `TlsConnection<State, H>`'s only legal
//! next move is the one named by `State` — wrong-method-for-state is a
//! compile error.

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
// Test-only: `close_notify` on `Live` is the sole consumer; gate matches it.
#[cfg(all(test, not(feature = "chacha20"), not(feature = "rsa")))]
use crate::consts::{CLOSE_NOTIFY_ALERT, CT_ALERT};
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
use subtle::ConstantTimeEq;

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
        match self {
            ConnectionError::ClientHello(ch) => ConnectionError::ClientHello(ch.map_writer(f)),
            ConnectionError::Parse(p) => ConnectionError::Parse(p),
            ConnectionError::Hkdf(h) => ConnectionError::Hkdf(h),
            ConnectionError::Flight(fl) => ConnectionError::Flight(fl),
            ConnectionError::Decrypt(d) => ConnectionError::Decrypt(d),
            ConnectionError::Encrypt(en) => ConnectionError::Encrypt(en),
            ConnectionError::Transcript(t) => ConnectionError::Transcript(t),
            ConnectionError::Reassembly(r) => ConnectionError::Reassembly(r),
            ConnectionError::ClientFinished(cf) => ConnectionError::ClientFinished(cf),
            ConnectionError::WrongSuite { expected, got } => {
                ConnectionError::WrongSuite { expected, got }
            }
            ConnectionError::IncompleteFlight => ConnectionError::IncompleteFlight,
            ConnectionError::UnexpectedSuite { selected_id } => {
                ConnectionError::UnexpectedSuite { selected_id }
            }
            ConnectionError::Alert { level, description } => {
                ConnectionError::Alert { level, description }
            }
            ConnectionError::UnknownContentType(c) => ConnectionError::UnknownContentType(c),
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

/// Typestate marker on `WaitServerFlight`. Only [`Live`] exists — the param
/// is retained so the handshake states stay generic over it.
pub trait HandshakeMode: sealed::Sealed {}

pub struct Live;
impl sealed::Sealed for Live {}
impl HandshakeMode for Live {}

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
    // Read only by the `cfg(all(test, not(chacha20), not(rsa)))` accessor
    // `server_pubkey()`; carrying the value uniformly costs an
    // \`#[allow(dead_code)]\` rather than feature-gating the field.
    #[allow(dead_code)]
    pub(crate) server_pubkey: ServerPubkeyOwned,
    pub(crate) _suite: PhantomData<S>,
    pub(crate) _mode: PhantomData<M>,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
// Carries a concrete pubkey for replay tooling.
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
    // Test-only; production matches on `NegotiatedSuite`.
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
    // Test-only; the facade engine has its own record-feed path.
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
    // test. Gate matches the caller test's cfg.
    #[cfg(all(test, not(feature = "chacha20"), not(feature = "rsa")))]
    pub fn server_pubkey(&self) -> ServerPubkey<'_> {
        self.state.server_pubkey.as_view()
    }
}

// ============================================================================
// Replay entry point (test-only, `feature = "replay"`)
// ============================================================================

#[cfg(all(test, feature = "replay", feature = "cipher-aes"))]
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

    // Test-only; the facade engine uses `decrypt_record_inplace`.
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

    // Test-only; the facade engine handles close_notify in its own event loop.
    #[cfg(all(test, not(feature = "chacha20"), not(feature = "rsa")))]
    pub fn close_notify(mut self, out_buf: &mut [u8]) -> Result<&[u8], ConnectionError> {
        self.encrypt_record(&CLOSE_NOTIFY_ALERT, CT_ALERT, out_buf)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;
