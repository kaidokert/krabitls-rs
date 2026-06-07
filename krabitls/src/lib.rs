//! `krabitls` — a sans-io, `no_std` TLS 1.3 client for a fixed embedded profile.
//!
//! The crate emits a minimal ClientHello and parses the matching ServerHello.
//! Callers provide the 32-byte random and X25519 public key; output goes
//! through any [`embedded_io::Write`].

#![cfg_attr(not(test), no_std)]

pub mod aead;
pub mod backends;
pub mod client_flight;
pub mod hkdf;
pub mod identity;
pub mod newtype;
pub mod reassembler;
pub mod server_flight;
pub mod traits;

#[cfg(feature = "chacha20")]
pub use aead::ChaCha20Poly1305Sha256;
pub use aead::{
    Aes128GcmSha256, CipherSuite, DecryptError, EncryptError, RecordKeys, aead_nonce,
    split_inner_plaintext,
};
#[cfg(feature = "jedisct")]
pub use backends::JedisctCrypto;
pub use backends::{DerCert, RustCrypto};
#[cfg(feature = "rsa")]
pub use backends::{RsaVerifierKey, RsaVerifyError};
pub use client_flight::{CLIENT_FINISHED_LEN, ClientFinishedError};
pub use hkdf::{
    EMPTY_TRANSCRIPT_HASH, HkdfLabelError, TranscriptError, TranscriptHash,
    application_traffic_secrets, derive_secret, early_secret, finished_mac, handshake_secret,
    handshake_traffic_secrets, hkdf_expand_label, master_secret,
};
#[cfg(feature = "validity")]
pub use identity::{ValidityError, verify_validity};
pub use newtype::{AeadIv, AeadKey, Secret, TranscriptDigest, ZeroBuf};
pub use server_flight::{
    FlightError, ServerFlightVerified, ServerFlightView, ServerPubkey, extract_cert_der,
    parse_server_flight, verify_certificate_verify, verify_self_signed_cert,
    verify_server_finished, verify_server_flight,
};
#[cfg(feature = "chacha20")]
pub use traits::ChaCha20Poly1305Aead;
pub use traits::{
    AeadError, Aes128GcmAead, CertParseError, CertParser, CertView, Ed25519Verify, HkdfExpandError,
    HkdfSha256, Sha256Hasher,
};
#[cfg(feature = "validity")]
pub use traits::{FixedTime, TimeSource};

use embedded_io::Write;

/// Compile-time hex decoder for `testdata/*.hex` fixtures.
#[cfg(any(test, feature = "dev-utils"))]
pub const fn hex_decode<const N: usize>(s: &str) -> [u8; N] {
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0; // input cursor
    let mut o = 0; // output cursor
    while i < bytes.len() {
        let c = bytes[i];
        // Skip whitespace.
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
            i += 1;
            continue;
        }
        // Skip `#`-to-EOL comments.
        if c == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let hi = hex_nibble(bytes[i]);
        if i + 1 >= bytes.len() {
            panic!("hex_decode: dangling nibble at end of input");
        }
        let lo = hex_nibble(bytes[i + 1]);
        if o >= N {
            panic!("hex_decode: more bytes in input than the declared N");
        }
        out[o] = (hi << 4) | lo;
        i += 2;
        o += 1;
    }
    if o != N {
        panic!("hex_decode: fewer bytes in input than the declared N");
    }
    out
}

#[cfg(any(test, feature = "dev-utils"))]
const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("hex_decode: non-hex byte in input"),
    }
}

pub mod consts {
    pub const CT_HANDSHAKE: u8 = 22;
    pub const CT_APPLICATION_DATA: u8 = 23;

    /// RFC 8446 mandates 0x0303 in the record header and in
    /// `ClientHello.legacy_version`, even when negotiating TLS 1.3.
    pub const LEGACY_VERSION: u16 = 0x0303;
    pub const TLS_1_3: u16 = 0x0304;

    pub const HS_CLIENT_HELLO: u8 = 1;
    pub const HS_SERVER_HELLO: u8 = 2;

    pub const CIPHER_AES_128_GCM_SHA256: u16 = 0x1301;
    pub const CIPHER_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
    pub const NAMED_GROUP_X25519: u16 = 0x001D;
    pub const SIG_SCHEME_ED25519: u16 = 0x0807;
    /// `rsa_pss_rsae_sha256` — RSASSA-PSS with the leaf's RSAE key encoding,
    /// MGF1-SHA-256, salt_len = hash output (32 B). RFC 8446 §4.2.3.
    pub const SIG_SCHEME_RSA_PSS_RSAE_SHA256: u16 = 0x0804;

    pub const EXT_SERVER_NAME: u16 = 0;
    pub const EXT_SUPPORTED_GROUPS: u16 = 10;
    pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
    pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
    pub const EXT_KEY_SHARE: u16 = 51;
    /// `name_type` value inside the SNI extension (RFC 6066 §3). Krabitls
    /// only ever writes `host_name`; we don't carry other NameType values.
    pub const SNI_NAME_TYPE_HOST_NAME: u8 = 0;

    /// Magic value a TLS-1.3-capable server places in `ServerHello.random`
    /// when the message is actually a HelloRetryRequest. From RFC 8446
    /// §4.1.3: `SHA-256("HelloRetryRequest")`.
    pub const HRR_RANDOM: [u8; 32] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8,
        0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8,
        0x33, 0x9C,
    ];

    /// Last 8 bytes of `ServerHello.random` when a TLS-1.3-capable server
    /// has been downgraded to TLS 1.2. RFC 8446 §4.1.3.
    pub const DOWNGRADE_TLS12: [u8; 8] = *b"DOWNGRD\x01";
    /// Same as `DOWNGRADE_TLS12` but for downgrade to TLS 1.1 or earlier.
    pub const DOWNGRADE_TLS11_OR_BELOW: [u8; 8] = *b"DOWNGRD\x00";
}

use consts::*;

// Each extension we emit, sized exactly. Type+length header is 4 bytes
// (`u16 ext_type` + `u16 ext_data_len`), plus the inner data length.
//
// supported_versions: u8(list_len=2) + u16(TLS_1_3)            = 3 inner -> 7 total
// supported_groups:   u16(list_len=2) + u16(x25519)            = 4 inner -> 8 total
// signature_algorithms (no rsa): u16(list_len=2) + u16(ed25519) = 4 inner -> 8 total
// signature_algorithms (+rsa):   u16(list_len=4) + ed25519 + rsa_pss = 6 inner -> 10 total
// key_share: u16(list_len=36) + u16(group) + u16(32) + 32B pub = 38 inner -> 42 total
// server_name (when present): u16(list_len) + u8(name_type=0) + u16(hostname_len) + N
//                            = 5 + N inner -> 9 + N total
const EXT_SUPPORTED_VERSIONS_TOTAL: u16 = 4 + 3;
const EXT_SUPPORTED_GROUPS_TOTAL: u16 = 4 + 4;
#[cfg(not(feature = "rsa"))]
const EXT_SIGNATURE_ALGORITHMS_TOTAL: u16 = 4 + 4;
#[cfg(feature = "rsa")]
const EXT_SIGNATURE_ALGORITHMS_TOTAL: u16 = 4 + 6;
const EXT_KEY_SHARE_TOTAL: u16 = 4 + 38;

#[cfg(not(feature = "chacha20"))]
const CH_CIPHER_SUITES_COUNT: usize = 1;
#[cfg(feature = "chacha20")]
const CH_CIPHER_SUITES_COUNT: usize = 2;

/// Wire size of `cipher_suites`: 2-byte length prefix + 2 bytes per suite.
const CH_CIPHER_SUITES_FIELD_LEN: usize = 2 + 2 * CH_CIPHER_SUITES_COUNT;

/// Fixed-extension total when the caller supplies no SNI.
const CH_EXTENSIONS_FIXED_TOTAL: u16 = EXT_SUPPORTED_VERSIONS_TOTAL
    + EXT_SUPPORTED_GROUPS_TOTAL
    + EXT_SIGNATURE_ALGORITHMS_TOTAL
    + EXT_KEY_SHARE_TOTAL;

/// Total wire size of the server_name extension for a given hostname length.
const fn sni_ext_total(hostname_len: usize) -> usize {
    // 4 (ext type+len header) + 2 (list_len) + 1 (name_type) + 2 (hostname_len) + N
    9 + hostname_len
}

/// Compute the exact serialized size of a ClientHello with the given
/// hostname option. Useful for the connect binary that needs to size its
/// buffer at runtime.
pub const fn client_hello_len(hostname_len: Option<usize>) -> usize {
    let sni = match hostname_len {
        None => 0,
        Some(n) => sni_ext_total(n),
    };
    // 5 (record header) + 4 (handshake header) + body
    // body = legacy_version(2) + random(32) + session_id(1+0)
    //      + cipher_suites(2 + 2*N) + compression(1+1)
    //      + extensions_len(2) + fixed_extensions + sni_ext
    5 + 4
        + 2
        + 32
        + 1
        + CH_CIPHER_SUITES_FIELD_LEN
        + (1 + 1)
        + 2
        + CH_EXTENSIONS_FIXED_TOTAL as usize
        + sni
}

/// Serialized size of the ClientHello [`write_client_hello`] produces when
/// no SNI is supplied. 117 bytes by default, 119 with `feature = "rsa"` (the
/// signature_algorithms extension carries one extra scheme entry).
///
/// Composed from per-field lengths above — adding or dropping an extension
/// flows through `CH_EXTENSIONS_FIXED_TOTAL` automatically.
pub const CLIENT_HELLO_LEN: usize = client_hello_len(None);

// Sanity pin on CLIENT_HELLO_LEN under each feature combo.
#[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
const _: () = assert!(CLIENT_HELLO_LEN == 117);
#[cfg(all(feature = "rsa", not(feature = "chacha20")))]
const _: () = assert!(CLIENT_HELLO_LEN == 119);
#[cfg(all(not(feature = "rsa"), feature = "chacha20"))]
const _: () = assert!(CLIENT_HELLO_LEN == 119);
#[cfg(all(feature = "rsa", feature = "chacha20"))]
const _: () = assert!(CLIENT_HELLO_LEN == 121);

/// Big-endian byte-emission helpers layered on top of [`embedded_io::Write`].
///
/// Kept internal for now — the only public entry point is
/// [`write_client_hello`]. Promoted to `pub` later if/when callers need to
/// assemble their own TLS messages.
trait WriteExt: Write {
    fn write_u8(&mut self, n: u8) -> Result<(), Self::Error> {
        self.write_all(&[n])
    }

    fn write_u16(&mut self, n: u16) -> Result<(), Self::Error> {
        self.write_all(&n.to_be_bytes())
    }

    /// Writes the low 3 bytes of `n` big-endian. Returns
    /// [`Write24Error::Overflow`] if `n > 0xFF_FFFF`. Checked in both
    /// debug and release — a silently truncated handshake length would
    /// corrupt the TLS framing.
    fn write_u24(&mut self, n: u32) -> Result<(), Write24Error<Self::Error>> {
        if n > 0xFF_FFFF {
            return Err(Write24Error::Overflow);
        }
        let bytes = n.to_be_bytes();
        self.write_all(&bytes[1..])?;
        Ok(())
    }
}

impl<W: Write + ?Sized> WriteExt for W {}

/// Error returned by [`WriteExt::write_u24`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Write24Error<E> {
    /// `n > 0xFF_FFFF` — cannot be encoded as a 24-bit big-endian field.
    Overflow,
    /// The underlying writer returned an error.
    Write(E),
}

impl<E> From<E> for Write24Error<E> {
    fn from(e: E) -> Self {
        Self::Write(e)
    }
}

impl<E: core::fmt::Display> core::fmt::Display for Write24Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Overflow => f.write_str("value does not fit in 24 bits"),
            Self::Write(e) => write!(f, "writer error: {e}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Write24Error<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Overflow => None,
            Self::Write(e) => Some(e),
        }
    }
}

/// TLS 1.3 plaintext fragment maximum (RFC 8446 §5.1). The record body of
/// a ClientHello must not exceed this; `write_client_hello` enforces it.
const TLS_PLAINTEXT_MAX: usize = 1 << 14;

/// Reasons [`write_client_hello`] may fail before any bytes hit the writer.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ClientHelloError<E> {
    /// `hostname.len()` exceeds the u16 cap of the SNI `HostName` field
    /// (RFC 6066 §3). Real hostnames are far shorter (DNS caps at 255
    /// bytes), but the wire format permits up to 65535.
    HostnameTooLong,
    /// Computed ClientHello record body exceeds TLS 1.3's `2^14` plaintext
    /// fragment limit (RFC 8446 §5.1). In practice this can only fire from
    /// a very long hostname; the rest of the message is fixed-size.
    MessageTooLong,
    /// A length field overflowed its wire-format encoding (currently only
    /// `u24` for the handshake body length). Not reachable from
    /// [`write_client_hello`] given the existing `u16`-typed
    /// `body_len` and `MessageTooLong` precheck — kept as a real error
    /// rather than a silent debug-only assert so a future refactor can't
    /// regress to truncated framing.
    IntegerOverflow,
    /// The underlying writer returned an error.
    Write(E),
}

impl<E> From<E> for ClientHelloError<E> {
    fn from(e: E) -> Self {
        Self::Write(e)
    }
}

impl<E> From<Write24Error<E>> for ClientHelloError<E> {
    fn from(e: Write24Error<E>) -> Self {
        match e {
            Write24Error::Overflow => Self::IntegerOverflow,
            Write24Error::Write(e) => Self::Write(e),
        }
    }
}

impl<E: core::fmt::Display> core::fmt::Display for ClientHelloError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HostnameTooLong => f.write_str("hostname exceeds the u16 SNI length cap"),
            Self::MessageTooLong => {
                f.write_str("ClientHello body exceeds the 2^14 plaintext fragment cap")
            }
            Self::IntegerOverflow => {
                f.write_str("a length field overflowed its wire-format encoding")
            }
            Self::Write(e) => write!(f, "writer error: {e}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for ClientHelloError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Write(e) => Some(e),
            _ => None,
        }
    }
}

/// Serialize a TLS 1.3 ClientHello into `out`.
///
/// `random` is the 32-byte `ClientHello.random` field; `x25519_pub` is the
/// raw 32-byte ephemeral X25519 public key for the `key_share` extension.
/// `hostname`, if `Some`, becomes a `server_name` extension (RFC 6066 §3) —
/// required to talk to virtually any modern public-internet server (CDN
/// fronts pick the cert from the SNI). Pass `None` for the historical
/// no-SNI ClientHello shape used by the fixture tests.
///
/// `random`, `x25519_pub`, and `hostname` are supplied by the caller — this
/// function never touches crypto or randomness.
///
/// Returns [`ClientHelloError::HostnameTooLong`] if `hostname` overflows the
/// u16 SNI length field, [`ClientHelloError::MessageTooLong`] if the
/// resulting record exceeds the TLS 1.3 plaintext fragment cap, or
/// [`ClientHelloError::Write`] wrapping `W`'s error type for any I/O
/// failure on the writer.
///
/// Returns the number of bytes written on success, equal to
/// [`client_hello_len`]`(hostname.map(|h| h.len()))`. When `hostname` is
/// `None`, that's [`CLIENT_HELLO_LEN`] (117 by default, 119 with
/// `feature = "rsa"` or `feature = "chacha20"`, 121 with both).
///
/// With `feature = "chacha20"`, the CH advertises
/// `TLS_CHACHA20_POLY1305_SHA256` first. Callers MUST dispatch their
/// record-layer code on the suite returned in `ServerHelloView::cipher_suite` —
/// using AES-typed `traffic_keys` / `decrypt_record` / `encrypt_record` /
/// `build_client_finished` on a ChaCha-negotiated connection will fail at the
/// first encrypted record.
pub fn write_client_hello<W: Write>(
    out: &mut W,
    random: &[u8; 32],
    x25519_pub: &[u8; 32],
    hostname: Option<&[u8]>,
) -> Result<usize, ClientHelloError<W::Error>> {
    // Upfront bounds checks. After these, every `as u16` / `as u32` cast
    // below is provably non-truncating.
    let host_len = hostname.map(|h| h.len()).unwrap_or(0);
    if host_len > u16::MAX as usize {
        return Err(ClientHelloError::HostnameTooLong);
    }
    let total_len = client_hello_len(hostname.map(|h| h.len()));
    if total_len > 5 + TLS_PLAINTEXT_MAX {
        return Err(ClientHelloError::MessageTooLong);
    }

    let sni_total = hostname.map(|h| sni_ext_total(h.len())).unwrap_or(0);
    let extensions_total = (CH_EXTENSIONS_FIXED_TOTAL as usize + sni_total) as u16;
    let body_len =
        (2 + 32 + 1 + CH_CIPHER_SUITES_FIELD_LEN + (1 + 1) + 2 + extensions_total as usize) as u16;
    let hs_len = 4 + body_len;

    out.write_u8(CT_HANDSHAKE)?; // 0x16
    out.write_u16(LEGACY_VERSION)?; // 0x0303
    out.write_u16(hs_len)?; // length of handshake message that follows

    out.write_u8(HS_CLIENT_HELLO)?; // 0x01
    out.write_u24(body_len as u32)?; // length of ClientHello body

    out.write_u16(LEGACY_VERSION)?; // legacy_version = 0x0303
    out.write_all(random)?; // random (32)
    out.write_u8(0)?; // legacy_session_id length = 0
    // ChaCha first so servers that honor client preference pick it.
    out.write_u16((2 * CH_CIPHER_SUITES_COUNT) as u16)?;
    #[cfg(feature = "chacha20")]
    out.write_u16(CIPHER_CHACHA20_POLY1305_SHA256)?;
    out.write_u16(CIPHER_AES_128_GCM_SHA256)?;
    out.write_u8(1)?; // legacy_compression_methods length
    out.write_u8(0)?; // null compression
    out.write_u16(extensions_total)?; // total extensions length

    // -- supported_versions --
    out.write_u16(EXT_SUPPORTED_VERSIONS)?;
    out.write_u16(3)?; // extension data length
    out.write_u8(2)?; // versions list length (in bytes)
    out.write_u16(TLS_1_3)?; // 0x0304

    // -- supported_groups --
    out.write_u16(EXT_SUPPORTED_GROUPS)?;
    out.write_u16(4)?;
    out.write_u16(2)?; // groups list length
    out.write_u16(NAMED_GROUP_X25519)?;

    // -- signature_algorithms --
    out.write_u16(EXT_SIGNATURE_ALGORITHMS)?;
    #[cfg(not(feature = "rsa"))]
    {
        out.write_u16(4)?; // ext_data_len = list_len(2) + scheme(2)
        out.write_u16(2)?; // sig schemes list length
        out.write_u16(SIG_SCHEME_ED25519)?;
    }
    #[cfg(feature = "rsa")]
    {
        out.write_u16(6)?; // ext_data_len = list_len(2) + scheme(2) + scheme(2)
        out.write_u16(4)?; // sig schemes list length = 2 schemes * 2 bytes
        out.write_u16(SIG_SCHEME_ED25519)?;
        out.write_u16(SIG_SCHEME_RSA_PSS_RSAE_SHA256)?;
    }

    // -- server_name (SNI), if supplied --
    if let Some(h) = hostname {
        let host_len = h.len() as u16;
        let list_len: u16 = 1 + 2 + host_len; // name_type(1) + hostname_len(2) + hostname(N)
        let ext_data_len: u16 = 2 + list_len; // list_len(2) + list_contents
        out.write_u16(EXT_SERVER_NAME)?;
        out.write_u16(ext_data_len)?;
        out.write_u16(list_len)?; // server_name_list_len
        out.write_u8(SNI_NAME_TYPE_HOST_NAME)?; // 0
        out.write_u16(host_len)?;
        out.write_all(h)?;
    }

    // -- key_share (kept last so x25519_pub sits at the end of the record) --
    out.write_u16(EXT_KEY_SHARE)?;
    out.write_u16(38)?; // extension data length
    out.write_u16(36)?; // client_shares list length
    out.write_u16(NAMED_GROUP_X25519)?; // KeyShareEntry.group
    out.write_u16(32)?; // KeyShareEntry.key_exchange length
    out.write_all(x25519_pub)?;

    Ok(total_len)
}

// ServerHello — parse the inverse of write_client_hello.

/// Parsed view of a ServerHello, with borrows into the caller's input.
///
/// Returned by [`parse_server_hello`]. Lifetime is tied to the input slice
/// so the random and X25519 share don't need to be copied out unless the
/// caller chooses to.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ServerHelloView<'a> {
    /// `ServerHello.random` (32 bytes).
    pub random: &'a [u8; 32],
    /// Echoed `legacy_session_id` — empty in our profile.
    pub session_id_echo: &'a [u8],
    /// Selected cipher suite. `TLS_AES_128_GCM_SHA256` (`0x1301`), or
    /// `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`) when `feature = "chacha20"`
    /// is enabled. Callers must dispatch their record-layer code on this value.
    pub cipher_suite: u16,
    /// Selected TLS version (from `supported_versions`). Validated to be `0x0304`.
    pub selected_version: u16,
    /// Server's ephemeral X25519 public key (32 bytes).
    pub x25519_share: &'a [u8; 32],
}

/// Reasons a `parse_*` call may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ParseError {
    /// Buffer ended mid-field, or a length prefix declared more bytes than remained.
    Truncated,
    /// TLS record content type wasn't `handshake` (22).
    UnexpectedContentType(u8),
    /// Handshake message type wasn't `server_hello` (2).
    UnexpectedHandshakeType(u8),
    /// Record-layer or `ClientHello.legacy_version` wasn't 0x0303.
    UnexpectedLegacyVersion(u16),
    /// Selected cipher suite isn't part of our locked profile.
    UnsupportedCipherSuite(u16),
    /// `legacy_compression_method` wasn't 0.
    UnexpectedCompressionMethod(u8),
    /// `supported_versions` extension missing, malformed, or didn't pick TLS 1.3.
    BadSupportedVersions,
    /// `key_share` extension missing, wrong group, or wrong key length.
    BadKeyShare,
    /// Bytes left over after the structure said it was done.
    TrailingBytes,
    /// Outer length didn't match the body it framed.
    LengthMismatch,

    /// ServerHello carried an extension type we did not offer in the ClientHello.
    /// Per RFC 8446 §4.1.4 the client MUST abort the handshake.
    UnknownExtension(u16),
    /// Same extension type appeared twice in the same extension block.
    /// RFC 8446 §4.2 forbids this.
    DuplicateExtension(u16),
    /// Server echoed back a non-empty `legacy_session_id_echo`, but the client
    /// sent an empty `legacy_session_id`. RFC 8446 §4.1.3 requires the echo to
    /// match what was sent.
    UnexpectedSessionIdEcho,
    /// `ServerHello.random` carries the magic value indicating this message is
    /// really a HelloRetryRequest. Our profile never expects HRR, so this is
    /// either a misconfigured server or a downgrade attempt.
    HelloRetryRequested,
    /// Last 8 bytes of `ServerHello.random` match the RFC 8446 §4.1.3 sentinel
    /// that a TLS-1.3-capable server uses when it has been forced to negotiate
    /// TLS 1.2 or below. A real TLS 1.3 server speaking only TLS 1.3 will never
    /// emit this; if we see it, the connection is being downgraded.
    DowngradeDetected,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("buffer ended mid-field or length prefix overran"),
            Self::UnexpectedContentType(b) => {
                write!(
                    f,
                    "record content_type was 0x{b:02x}, expected handshake (22)"
                )
            }
            Self::UnexpectedHandshakeType(b) => {
                write!(f, "handshake type was 0x{b:02x}, expected server_hello (2)")
            }
            Self::UnexpectedLegacyVersion(v) => {
                write!(f, "legacy_version was 0x{v:04x}, expected 0x0303")
            }
            Self::UnsupportedCipherSuite(v) => {
                write!(f, "cipher suite 0x{v:04x} is outside the locked profile")
            }
            Self::UnexpectedCompressionMethod(b) => {
                write!(f, "legacy_compression_method was 0x{b:02x}, expected 0")
            }
            Self::BadSupportedVersions => f.write_str(
                "supported_versions extension missing, malformed, or did not pick TLS 1.3",
            ),
            Self::BadKeyShare => {
                f.write_str("key_share extension missing, wrong group, or wrong key length")
            }
            Self::TrailingBytes => {
                f.write_str("bytes left over after the structure said it was done")
            }
            Self::LengthMismatch => f.write_str("outer length did not match the body it framed"),
            Self::UnknownExtension(v) => {
                write!(
                    f,
                    "ServerHello carried an extension type 0x{v:04x} not offered in the ClientHello"
                )
            }
            Self::DuplicateExtension(v) => {
                write!(
                    f,
                    "extension type 0x{v:04x} appeared twice in the same extension block"
                )
            }
            Self::UnexpectedSessionIdEcho => {
                f.write_str("server echoed a non-empty legacy_session_id_echo")
            }
            Self::HelloRetryRequested => f.write_str("server requested HelloRetryRequest"),
            Self::DowngradeDetected => {
                f.write_str("ServerHello.random sentinel indicates a TLS-1.2-or-below downgrade")
            }
        }
    }
}

impl core::error::Error for ParseError {}

/// Parse a complete TLS record carrying a `server_hello` handshake message.
///
/// Validates the locked profile (TLS 1.3, x25519, AES-128-GCM-SHA256 or
/// `TLS_CHACHA20_POLY1305_SHA256` under `feature = "chacha20"`) and returns
/// a [`ServerHelloView`] borrowing into `input`.
pub fn parse_server_hello(input: &[u8]) -> Result<ServerHelloView<'_>, ParseError> {
    let mut r = Reader::new(input);

    let content_type = r.u8()?;
    if content_type != CT_HANDSHAKE {
        return Err(ParseError::UnexpectedContentType(content_type));
    }
    let record_version = r.u16()?;
    if record_version != LEGACY_VERSION {
        return Err(ParseError::UnexpectedLegacyVersion(record_version));
    }
    let record_body = r.vec_u16()?;
    if !r.at_end() {
        return Err(ParseError::TrailingBytes);
    }

    let mut hr = Reader::new(record_body);
    let hs_type = hr.u8()?;
    if hs_type != HS_SERVER_HELLO {
        return Err(ParseError::UnexpectedHandshakeType(hs_type));
    }
    let hs_body = hr.vec_u24()?;
    if !hr.at_end() {
        return Err(ParseError::LengthMismatch);
    }

    let mut b = Reader::new(hs_body);
    let legacy_version = b.u16()?;
    if legacy_version != LEGACY_VERSION {
        return Err(ParseError::UnexpectedLegacyVersion(legacy_version));
    }
    let random: &[u8; 32] = b.take_array()?;
    // HelloRetryRequest is signalled by a magic ServerHello.random value (RFC 8446
    // §4.1.3). Our locked profile already advertises the only group the server can
    // pick, so HRR can only mean misconfiguration or an attack — refuse it.
    if random == &HRR_RANDOM {
        return Err(ParseError::HelloRetryRequested);
    }
    // Downgrade sentinels live in the last 8 bytes of random. A real TLS 1.3-only
    // server would never emit these; an MITM forcing TLS 1.2 would.
    // Slice equality avoids the `try_into().expect(...)` path (the
    // sentinels are `&[u8; 8]`, comparing them against `&[u8]` works
    // via `PartialEq<[u8; 8]> for [u8]`).
    let suffix = &random[24..];
    if suffix == DOWNGRADE_TLS12 || suffix == DOWNGRADE_TLS11_OR_BELOW {
        return Err(ParseError::DowngradeDetected);
    }

    let session_id_echo = b.vec_u8()?;
    // We always send an empty legacy_session_id; the server MUST echo it back
    // unchanged (RFC 8446 §4.1.3).
    if !session_id_echo.is_empty() {
        return Err(ParseError::UnexpectedSessionIdEcho);
    }
    let cipher_suite = b.u16()?;
    let suite_accepted = cipher_suite == CIPHER_AES_128_GCM_SHA256
        || (cfg!(feature = "chacha20") && cipher_suite == CIPHER_CHACHA20_POLY1305_SHA256);
    if !suite_accepted {
        return Err(ParseError::UnsupportedCipherSuite(cipher_suite));
    }
    let compression = b.u8()?;
    if compression != 0 {
        return Err(ParseError::UnexpectedCompressionMethod(compression));
    }
    let ext_body = b.vec_u16()?;
    if !b.at_end() {
        return Err(ParseError::TrailingBytes);
    }

    let mut selected_version: Option<u16> = None;
    let mut x25519_share: Option<&[u8; 32]> = None;

    let mut e = Reader::new(ext_body);
    while !e.at_end() {
        let ext_type = e.u16()?;
        let ext_data = e.vec_u16()?;
        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                if selected_version.is_some() {
                    return Err(ParseError::DuplicateExtension(ext_type));
                }
                // In ServerHello, the body is exactly one ProtocolVersion (u16).
                if ext_data.len() != 2 {
                    return Err(ParseError::BadSupportedVersions);
                }
                let v = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                if v != TLS_1_3 {
                    return Err(ParseError::BadSupportedVersions);
                }
                selected_version = Some(v);
            }
            EXT_KEY_SHARE => {
                if x25519_share.is_some() {
                    return Err(ParseError::DuplicateExtension(ext_type));
                }
                // ServerHello key_share: single KeyShareEntry = group(u16) + key(u16-len-prefixed).
                let mut kr = Reader::new(ext_data);
                let group = kr.u16()?;
                if group != NAMED_GROUP_X25519 {
                    return Err(ParseError::BadKeyShare);
                }
                let key = kr.vec_u16()?;
                if !kr.at_end() {
                    return Err(ParseError::BadKeyShare);
                }
                let key_array: &[u8; 32] = key.try_into().map_err(|_| ParseError::BadKeyShare)?;
                x25519_share = Some(key_array);
            }
            // RFC 8446 §4.1.4: a client that receives an unrecognized extension
            // in ServerHello MUST abort with `illegal_parameter`. We didn't ask
            // for it, so it shouldn't be here.
            _ => return Err(ParseError::UnknownExtension(ext_type)),
        }
    }

    Ok(ServerHelloView {
        random,
        session_id_echo,
        cipher_suite,
        selected_version: selected_version.ok_or(ParseError::BadSupportedVersions)?,
        x25519_share: x25519_share.ok_or(ParseError::BadKeyShare)?,
    })
}

// Internal byte reader. Mirrors the Writer/WriteExt pair; returns ParseError
// on truncation / length-prefix overruns.

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.remaining() < n {
            return Err(ParseError::Truncated);
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<&'a [u8; N], ParseError> {
        let slice = self.take(N)?;
        // `take(N)` guarantees `slice.len() == N`, so the `try_from` here
        // is statically infallible — but we map the error rather than
        // `expect(...)`-ing to keep the panic-machinery path out of the
        // binary. The dead `Err` arm is dropped by codegen.
        <&[u8; N]>::try_from(slice).map_err(|_| ParseError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Result<u32, ParseError> {
        let bytes = self.take(3)?;
        Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }

    fn vec_u8(&mut self) -> Result<&'a [u8], ParseError> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    fn vec_u16(&mut self) -> Result<&'a [u8], ParseError> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    fn vec_u24(&mut self) -> Result<&'a [u8], ParseError> {
        // 24-bit lengths exceed `u16::MAX` and so don't fit a 16-bit `usize`.
        // Use `try_into` instead of `as usize` so the truncation surfaces
        // as a clean parse error rather than a silent slice underflow.
        let n: usize = self.u24()?.try_into().map_err(|_| ParseError::Truncated)?;
        self.take(n)
    }
}

// Tests — cross-check against the Python fixture's seed-0 ClientHello.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{decrypt_record, encrypt_record};
    #[cfg(feature = "chacha20")]
    use crate::aead::{decrypt_record_chacha, encrypt_record_chacha};
    use crate::hkdf::traffic_keys;
    #[cfg(feature = "chacha20")]
    use crate::newtype::AeadKey32;
    use crate::newtype::{AeadIv, AeadKey, Secret, TranscriptDigest};
    use embedded_io::SliceWriteError;

    // Captured from tls_fixture/packets/001_c2s_ClientHello.bin (seed 0).
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
    /// Seed-0 ed25519-mode ClientHello from the Python fixture
    /// (`packets/001_c2s_ClientHello.bin`), 117 bytes.
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

    /// Helper: write into a fresh buffer through `&mut &mut [u8]`. Returns the
    /// borrowed slice as it stands after writing so we can confirm how many
    /// bytes were consumed.
    fn write_into(buf: &mut [u8]) -> Result<&mut [u8], ClientHelloError<SliceWriteError>> {
        let mut cursor: &mut [u8] = buf;
        write_client_hello(&mut cursor, &FIXTURE_RANDOM, &FIXTURE_X25519_PUB, None)?;
        // `cursor` now points at the *unused* tail.
        Ok(cursor)
    }

    // Byte-identity against the seed-0 Python fixture only holds when our CH
    // advertises ed25519 alone with AES-128-GCM only. With `feature = "rsa"`
    // we also advertise rsa_pss_rsae_sha256; with `feature = "chacha20"` we
    // also advertise CHACHA20_POLY1305_SHA256 — either changes the CH bytes.
    #[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
    #[test]
    fn matches_python_fixture() {
        let mut buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut buf;
        let n =
            write_client_hello(&mut cursor, &FIXTURE_RANDOM, &FIXTURE_X25519_PUB, None).unwrap();
        assert_eq!(n, CLIENT_HELLO_LEN);
        assert_eq!(&buf[..CLIENT_HELLO_LEN], &FIXTURE_CLIENT_HELLO);
    }

    #[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
    #[test]
    fn exact_sized_buffer_works() {
        let mut buf = [0u8; CLIENT_HELLO_LEN];
        let leftover = write_into(&mut buf).unwrap();
        assert!(
            leftover.is_empty(),
            "should fully consume a tightly-sized buffer"
        );
        assert_eq!(buf, FIXTURE_CLIENT_HELLO);
    }

    #[test]
    fn rejects_small_buffer() {
        let mut buf = [0u8; CLIENT_HELLO_LEN - 1];
        let err = write_into(&mut buf).unwrap_err();
        assert_eq!(err, ClientHelloError::Write(SliceWriteError::Full));
    }

    #[test]
    fn rejects_oversize_hostname() {
        // hostname.len() > u16::MAX → HostnameTooLong.
        let huge = vec![b'a'; (u16::MAX as usize) + 1];
        let mut buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut buf;
        let err = write_client_hello(
            &mut cursor,
            &FIXTURE_RANDOM,
            &FIXTURE_X25519_PUB,
            Some(&huge),
        )
        .unwrap_err();
        assert_eq!(err, ClientHelloError::HostnameTooLong);
    }

    #[test]
    fn rejects_oversize_record() {
        // hostname fits in u16 but pushes total record past 2^14 → MessageTooLong.
        let big = vec![b'a'; 16500];
        let mut buf = [0u8; 128];
        let mut cursor: &mut [u8] = &mut buf;
        let err = write_client_hello(
            &mut cursor,
            &FIXTURE_RANDOM,
            &FIXTURE_X25519_PUB,
            Some(&big),
        )
        .unwrap_err();
        assert_eq!(err, ClientHelloError::MessageTooLong);
    }

    #[test]
    fn error_types_display() {
        // Round-trip Display through `format!` to catch any breakage in the
        // trait impls. `std` is available under cfg(test) so `format!` works.
        let e: Write24Error<SliceWriteError> = Write24Error::Overflow;
        assert!(format!("{e}").contains("24"));
        let e: ClientHelloError<SliceWriteError> = ClientHelloError::HostnameTooLong;
        assert!(format!("{e}").contains("hostname"));
        let e: ClientHelloError<SliceWriteError> = ClientHelloError::IntegerOverflow;
        assert!(format!("{e}").to_lowercase().contains("overflow"));
    }

    #[test]
    fn write_u24_rejects_overflow() {
        // Not reachable from `write_client_hello` (body_len is u16-typed), but
        // the trait method needs to be safe against future callers passing a
        // u32 that doesn't fit in 3 bytes.
        let mut buf = [0u8; 3];
        let mut cursor: &mut [u8] = &mut buf;
        let err = cursor.write_u24(0x100_0000).unwrap_err();
        assert_eq!(err, Write24Error::Overflow);

        let mut cursor: &mut [u8] = &mut buf;
        cursor.write_u24(0xFF_FFFF).unwrap();
        assert_eq!(buf, [0xff, 0xff, 0xff]);
    }

    #[test]
    fn random_appears_at_correct_offset() {
        // Record(5) + hs_hdr(4) + legacy_version(2) = offset 11
        let mut random = [0u8; 32];
        for (i, b) in random.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut buf = [0u8; CLIENT_HELLO_LEN];
        let mut cursor: &mut [u8] = &mut buf;
        write_client_hello(&mut cursor, &random, &FIXTURE_X25519_PUB, None).unwrap();
        assert_eq!(&buf[11..11 + 32], &random);
    }

    #[test]
    fn x25519_pub_appears_at_correct_offset() {
        // The X25519 share is the last 32 bytes of the record.
        let mut pub_key = [0u8; 32];
        for (i, b) in pub_key.iter_mut().enumerate() {
            *b = (0x80 + i) as u8;
        }
        let mut buf = [0u8; CLIENT_HELLO_LEN];
        let mut cursor: &mut [u8] = &mut buf;
        write_client_hello(&mut cursor, &FIXTURE_RANDOM, &pub_key, None).unwrap();
        assert_eq!(&buf[CLIENT_HELLO_LEN - 32..], &pub_key);
    }

    // Captured from tls_fixture/packets/002_s2c_ServerHello.bin (seed 0).
    const FIXTURE_SERVER_HELLO: [u8; 95] = [
        0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0x64, 0x1c, 0x5b, 0xd9,
        0x34, 0xab, 0xe1, 0xc5, 0x98, 0xa9, 0xc9, 0x61, 0xf7, 0xcb, 0x1e, 0x06, 0x28, 0x0b, 0x4a,
        0x5e, 0x88, 0x0c, 0x1c, 0x19, 0xd2, 0xfe, 0x9e, 0xef, 0x33, 0x48, 0x0c, 0xae, 0x00, 0x13,
        0x01, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00,
        0x1d, 0x00, 0x20, 0x60, 0x4d, 0x7a, 0x17, 0x18, 0x38, 0xbd, 0xa2, 0x15, 0xd2, 0xb5, 0x4a,
        0x24, 0xfb, 0x7d, 0x3a, 0x88, 0x8d, 0xa5, 0xac, 0x36, 0x72, 0x72, 0x6d, 0x20, 0x06, 0x44,
        0x04, 0xf7, 0x06, 0xdb, 0x7e,
    ];
    // Offset of `cipher_suite` inside `FIXTURE_SERVER_HELLO`:
    // 5 (record hdr) + 4 (hs hdr) + 2 (legacy_ver) + 32 (random) + 1 (session_id len).
    const SH_CIPHER_SUITE_OFFSET: usize = 44;

    const FIXTURE_SERVER_RANDOM: [u8; 32] = [
        0x64, 0x1c, 0x5b, 0xd9, 0x34, 0xab, 0xe1, 0xc5, 0x98, 0xa9, 0xc9, 0x61, 0xf7, 0xcb, 0x1e,
        0x06, 0x28, 0x0b, 0x4a, 0x5e, 0x88, 0x0c, 0x1c, 0x19, 0xd2, 0xfe, 0x9e, 0xef, 0x33, 0x48,
        0x0c, 0xae,
    ];
    const FIXTURE_SERVER_X25519: [u8; 32] = [
        0x60, 0x4d, 0x7a, 0x17, 0x18, 0x38, 0xbd, 0xa2, 0x15, 0xd2, 0xb5, 0x4a, 0x24, 0xfb, 0x7d,
        0x3a, 0x88, 0x8d, 0xa5, 0xac, 0x36, 0x72, 0x72, 0x6d, 0x20, 0x06, 0x44, 0x04, 0xf7, 0x06,
        0xdb, 0x7e,
    ];

    #[test]
    fn parses_python_fixture_server_hello() {
        let v = parse_server_hello(&FIXTURE_SERVER_HELLO).unwrap();
        assert_eq!(v.random, &FIXTURE_SERVER_RANDOM);
        assert_eq!(v.session_id_echo, &[][..]);
        assert_eq!(v.cipher_suite, CIPHER_AES_128_GCM_SHA256);
        assert_eq!(v.selected_version, TLS_1_3);
        assert_eq!(v.x25519_share, &FIXTURE_SERVER_X25519);
    }

    #[test]
    fn truncated_buffer_rejected() {
        let truncated = &FIXTURE_SERVER_HELLO[..FIXTURE_SERVER_HELLO.len() - 1];
        let err = parse_server_hello(truncated).unwrap_err();
        // The TLS record length says 90, but only 89 bytes follow.
        assert!(matches!(err, ParseError::Truncated));
    }

    #[test]
    fn wrong_content_type_rejected() {
        let mut bad = FIXTURE_SERVER_HELLO;
        bad[0] = 23; // application_data
        assert_eq!(
            parse_server_hello(&bad),
            Err(ParseError::UnexpectedContentType(23)),
        );
    }

    #[test]
    fn wrong_handshake_type_rejected() {
        let mut bad = FIXTURE_SERVER_HELLO;
        bad[5] = 1; // client_hello byte at handshake header
        assert_eq!(
            parse_server_hello(&bad),
            Err(ParseError::UnexpectedHandshakeType(1)),
        );
    }

    #[cfg(feature = "chacha20")]
    #[test]
    fn server_hello_chacha20_accepted() {
        let mut sh = FIXTURE_SERVER_HELLO;
        sh[SH_CIPHER_SUITE_OFFSET] = 0x13;
        sh[SH_CIPHER_SUITE_OFFSET + 1] = 0x03;
        let v = parse_server_hello(&sh).unwrap();
        assert_eq!(v.cipher_suite, CIPHER_CHACHA20_POLY1305_SHA256);
    }

    #[cfg(not(feature = "chacha20"))]
    #[test]
    fn server_hello_chacha20_rejected_without_feature() {
        let mut sh = FIXTURE_SERVER_HELLO;
        sh[SH_CIPHER_SUITE_OFFSET] = 0x13;
        sh[SH_CIPHER_SUITE_OFFSET + 1] = 0x03;
        assert_eq!(
            parse_server_hello(&sh),
            Err(ParseError::UnsupportedCipherSuite(0x1303)),
        );
    }

    #[test]
    fn wrong_cipher_suite_rejected() {
        let mut bad = FIXTURE_SERVER_HELLO;
        // Patch to TLS_AES_256_GCM_SHA384 = 0x1302 (not in our profile).
        bad[SH_CIPHER_SUITE_OFFSET] = 0x13;
        bad[SH_CIPHER_SUITE_OFFSET + 1] = 0x02;
        assert_eq!(
            parse_server_hello(&bad),
            Err(ParseError::UnsupportedCipherSuite(0x1302)),
        );
    }

    #[test]
    fn trailing_bytes_after_record_rejected() {
        let mut padded = [0u8; FIXTURE_SERVER_HELLO.len() + 1];
        padded[..FIXTURE_SERVER_HELLO.len()].copy_from_slice(&FIXTURE_SERVER_HELLO);
        assert_eq!(parse_server_hello(&padded), Err(ParseError::TrailingBytes));
    }

    #[test]
    fn hello_retry_request_rejected() {
        // Patch random in place: offsets 11..43 hold the 32-byte random.
        let mut bad = FIXTURE_SERVER_HELLO;
        bad[11..43].copy_from_slice(&HRR_RANDOM);
        assert_eq!(
            parse_server_hello(&bad),
            Err(ParseError::HelloRetryRequested)
        );
    }

    #[test]
    fn downgrade_marker_rejected() {
        // Last 8 bytes of random = offsets 35..43.
        let mut bad = FIXTURE_SERVER_HELLO;
        bad[35..43].copy_from_slice(&DOWNGRADE_TLS12);
        assert_eq!(parse_server_hello(&bad), Err(ParseError::DowngradeDetected));

        bad[35..43].copy_from_slice(&DOWNGRADE_TLS11_OR_BELOW);
        assert_eq!(parse_server_hello(&bad), Err(ParseError::DowngradeDetected));
    }

    #[test]
    fn non_empty_session_id_echo_rejected() {
        // Original session_id_echo (offset 43) is length-byte 0x00. Inflate it
        // to length 1 + one body byte, which adds 1 byte total and pushes
        // everything after it one position to the right.
        let mut buf = [0u8; FIXTURE_SERVER_HELLO.len() + 1];
        buf[..43].copy_from_slice(&FIXTURE_SERVER_HELLO[..43]);
        buf[43] = 0x01; // session_id_echo length
        buf[44] = 0xab; // session_id_echo data
        buf[45..].copy_from_slice(&FIXTURE_SERVER_HELLO[44..]);
        // Patch record length (offsets 3..5): 90 + 1 = 91 = 0x005b
        buf[3..5].copy_from_slice(&[0x00, 0x5b]);
        // Patch handshake length (offsets 6..9): 86 + 1 = 87 = 0x000057
        buf[6..9].copy_from_slice(&[0x00, 0x00, 0x57]);

        assert_eq!(
            parse_server_hello(&buf),
            Err(ParseError::UnexpectedSessionIdEcho),
        );
    }

    #[test]
    fn unknown_extension_rejected() {
        // Append a fake extension (type 0x00ff, 3-byte body) at the end of the
        // extensions block. Total grows by 7 bytes; patch the three nested
        // length fields accordingly.
        let mut buf = [0u8; FIXTURE_SERVER_HELLO.len() + 7];
        buf[..FIXTURE_SERVER_HELLO.len()].copy_from_slice(&FIXTURE_SERVER_HELLO);
        buf[FIXTURE_SERVER_HELLO.len()..].copy_from_slice(&[
            0x00, 0xff, // ext type 0x00ff
            0x00, 0x03, // ext data length = 3
            0xaa, 0xbb, 0xcc, // ext data
        ]);
        // Record length: 90 + 7 = 97 = 0x0061
        buf[3..5].copy_from_slice(&[0x00, 0x61]);
        // Handshake length: 86 + 7 = 93 = 0x00005d
        buf[6..9].copy_from_slice(&[0x00, 0x00, 0x5d]);
        // Extensions length: 46 + 7 = 53 = 0x0035
        buf[47..49].copy_from_slice(&[0x00, 0x35]);

        assert_eq!(
            parse_server_hello(&buf),
            Err(ParseError::UnknownExtension(0x00ff)),
        );
    }

    #[test]
    fn duplicate_extension_rejected() {
        // Append a second supported_versions extension (6 bytes total).
        let mut buf = [0u8; FIXTURE_SERVER_HELLO.len() + 6];
        buf[..FIXTURE_SERVER_HELLO.len()].copy_from_slice(&FIXTURE_SERVER_HELLO);
        buf[FIXTURE_SERVER_HELLO.len()..].copy_from_slice(&[
            0x00, 0x2b, // ext type = supported_versions
            0x00, 0x02, // ext data length = 2
            0x03, 0x04, // selected version TLS 1.3
        ]);
        // Record length: 90 + 6 = 96 = 0x0060
        buf[3..5].copy_from_slice(&[0x00, 0x60]);
        // Handshake length: 86 + 6 = 92 = 0x00005c
        buf[6..9].copy_from_slice(&[0x00, 0x00, 0x5c]);
        // Extensions length: 46 + 6 = 52 = 0x0034
        buf[47..49].copy_from_slice(&[0x00, 0x34]);

        assert_eq!(
            parse_server_hello(&buf),
            Err(ParseError::DuplicateExtension(EXT_SUPPORTED_VERSIONS)),
        );
    }

    //
    // Two angles: RFC 8448 §3 publishes intermediate values for a full TLS 1.3
    // handshake (well-known, not derived from our fixture), and we also pin
    // against the tls_fixture seed-0 derivation chain so a backend swap can be
    // caught here before it ever reaches the QEMU demo.

    // RFC 8448 / fixture constants are kept as raw `[u8; N]` (const-
    // friendly) and wrapped into the secret-bearing newtypes at use
    // site via small helpers, because `Zeroizing::new` isn't `const fn`.

    /// RFC 8448 §3: `HKDF-Extract(salt=00..00, IKM=00..00)` → no-PSK early secret.
    const RFC8448_EARLY_SECRET_BYTES: [u8; 32] = [
        0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c,
        0xe2, 0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60, 0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70,
        0xf9, 0x2a,
    ];
    fn make_rfc8448_early_secret() -> Secret {
        Secret::new(ZeroBuf::<32>::new(RFC8448_EARLY_SECRET_BYTES))
    }
    /// RFC 8448 §3: `Derive-Secret(EarlySecret, "derived", "")`.
    /// The empty-string transcript hash is `SHA-256("")`.
    const RFC8448_DERIVED_FROM_EARLY_BYTES: [u8; 32] = [
        0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6,
        0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36,
        0x11, 0xba,
    ];
    /// `SHA-256("")` — the empty-transcript hash, used by `Derive-Secret(., "derived", "")`.
    const EMPTY_SHA256: TranscriptDigest = TranscriptDigest::new([
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ]);

    /// `tls_fixture` seed-0: handshake_secret computed from the recorded X25519 DHE.
    const FIXTURE_DHE: [u8; 32] = [
        0xd6, 0xe8, 0x68, 0xc2, 0x71, 0xfa, 0x06, 0x2a, 0x48, 0xab, 0x2a, 0xcc, 0x32, 0xfe, 0x98,
        0x58, 0x0d, 0x48, 0x77, 0x00, 0x91, 0x1f, 0x47, 0xad, 0x94, 0xcb, 0xb3, 0xb5, 0x35, 0x58,
        0xea, 0x51,
    ];
    const FIXTURE_HANDSHAKE_SECRET_BYTES: [u8; 32] = [
        0x67, 0x4c, 0x4a, 0x90, 0x69, 0x17, 0x0e, 0xcd, 0x7a, 0xc6, 0x92, 0x5e, 0x96, 0x22, 0x49,
        0xa2, 0xa8, 0x6d, 0x22, 0x50, 0xc1, 0x2f, 0x21, 0x7a, 0x2c, 0x2a, 0x28, 0x3c, 0x64, 0xbf,
        0x28, 0x7f,
    ];

    #[test]
    fn rfc8448_early_secret() {
        let zeros = [0u8; 32];
        let prk = Secret::new(RustCrypto::extract(&zeros, &zeros));
        assert_eq!(prk.as_bytes(), &RFC8448_EARLY_SECRET_BYTES);
    }

    #[test]
    fn rfc8448_derived_from_early() {
        let derived =
            derive_secret::<RustCrypto>(&make_rfc8448_early_secret(), b"derived", &EMPTY_SHA256)
                .unwrap();
        assert_eq!(derived.as_bytes(), &RFC8448_DERIVED_FROM_EARLY_BYTES);
    }

    #[test]
    fn hkdf_expand_label_rejects_oversized_public_inputs() {
        let secret = [0u8; 32];
        let mut out = [0u8; 32];
        let long = [0u8; 256];
        assert_eq!(
            hkdf_expand_label::<RustCrypto>(&secret, &long, &[], &mut out),
            Err(HkdfLabelError::LabelTooLong)
        );
        assert_eq!(
            hkdf_expand_label::<RustCrypto>(&secret, b"ok", &long, &mut out),
            Err(HkdfLabelError::ContextTooLong)
        );
        let too_big_for_scratch = [0u8; 58];
        assert_eq!(
            hkdf_expand_label::<RustCrypto>(&secret, &too_big_for_scratch, &[], &mut out),
            Err(HkdfLabelError::EncodedTooLong)
        );
        // out.len() > 255 * 32: backend rejects → Expand variant.
        let mut huge_out = vec![0u8; 8200];
        assert_eq!(
            hkdf_expand_label::<RustCrypto>(&secret, b"ok", b"", &mut huge_out),
            Err(HkdfLabelError::Expand(
                traits::HkdfExpandError::OutputTooLong
            ))
        );
    }

    #[test]
    fn fixture_handshake_secret() {
        // handshake_secret = HKDF-Extract(Derive-Secret(EarlySecret, "derived", ""), DHE)
        let derived =
            derive_secret::<RustCrypto>(&make_rfc8448_early_secret(), b"derived", &EMPTY_SHA256)
                .unwrap();
        let hs = Secret::new(RustCrypto::extract(derived.as_bytes(), &FIXTURE_DHE));
        assert_eq!(hs.as_bytes(), &FIXTURE_HANDSHAKE_SECRET_BYTES);
    }

    /// tls_fixture seed-0 client X25519 private (from state/client.json).
    const FIXTURE_CLIENT_X25519_PRIV: [u8; 32] = [
        0xac, 0xe1, 0xc2, 0x3b, 0x24, 0xdf, 0xad, 0x58, 0xc5, 0x4c, 0xcf, 0x4c, 0x1f, 0xe8, 0xdf,
        0xe8, 0x5e, 0x76, 0x0e, 0x02, 0x3b, 0x6c, 0xb6, 0x02, 0x2f, 0x70, 0x0f, 0x34, 0xde, 0x4c,
        0x28, 0x28,
    ];
    const FIXTURE_SERVER_X25519_PUB_2: [u8; 32] = [
        0x60, 0x4d, 0x7a, 0x17, 0x18, 0x38, 0xbd, 0xa2, 0x15, 0xd2, 0xb5, 0x4a, 0x24, 0xfb, 0x7d,
        0x3a, 0x88, 0x8d, 0xa5, 0xac, 0x36, 0x72, 0x72, 0x6d, 0x20, 0x06, 0x44, 0x04, 0xf7, 0x06,
        0xdb, 0x7e,
    ];
    /// SHA-256(ClientHello_handshake_msg || ServerHello_handshake_msg) at seed 0.
    const FIXTURE_TRANSCRIPT_HASH_CH_SH: TranscriptDigest = TranscriptDigest::new([
        0x7d, 0x93, 0x12, 0xf1, 0x9c, 0x0e, 0x57, 0x82, 0x2f, 0x53, 0xeb, 0x79, 0xe5, 0x52, 0x36,
        0x73, 0x7d, 0xaf, 0x66, 0xa1, 0x1a, 0x89, 0x75, 0x6a, 0xb4, 0xb4, 0x3e, 0xdd, 0x87, 0x45,
        0x3f, 0x39,
    ]);
    const FIXTURE_S_HS_TRAFFIC_SECRET_BYTES: [u8; 32] = [
        0x55, 0x59, 0xd1, 0xcf, 0x33, 0x31, 0x9c, 0x4b, 0x46, 0x2a, 0x11, 0x42, 0x92, 0x90, 0x2d,
        0x05, 0xb8, 0xcc, 0x08, 0xbc, 0x5a, 0xa5, 0xdd, 0x8e, 0x59, 0x84, 0x8b, 0xd0, 0x8d, 0xb2,
        0x82, 0x9b,
    ];
    fn make_fixture_s_hs_traffic_secret() -> Secret {
        Secret::new(ZeroBuf::<32>::new(FIXTURE_S_HS_TRAFFIC_SECRET_BYTES))
    }
    const FIXTURE_C_HS_TRAFFIC_SECRET_BYTES: [u8; 32] = [
        0xa4, 0xfa, 0x72, 0xf0, 0xcc, 0x9e, 0xef, 0xe8, 0xb1, 0xcb, 0x2a, 0x53, 0x3e, 0x40, 0x82,
        0x14, 0x65, 0x32, 0x95, 0x4a, 0x6d, 0x25, 0x57, 0x14, 0xa1, 0x7c, 0x2c, 0xef, 0x69, 0x08,
        0xa7, 0x8d,
    ];

    #[test]
    fn transcript_update_record_rejects_too_short() {
        let mut t = TranscriptHash::<RustCrypto>::new();
        // < 5 bytes can't even hold a TLS record header.
        assert_eq!(
            t.update_record(&[0x16, 0x03, 0x03]),
            Err(TranscriptError::RecordTooShort)
        );
        assert_eq!(t.update_record(&[]), Err(TranscriptError::RecordTooShort));
    }

    #[test]
    fn transcript_update_record_strips_5_byte_header() {
        // Confirm that update_record(full_record) produces the same hash as
        // feeding handshake-body bytes directly via update().
        let mut a = TranscriptHash::<RustCrypto>::new();
        a.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
        a.update_record(&FIXTURE_SERVER_HELLO).unwrap();

        let mut b = TranscriptHash::<RustCrypto>::new();
        b.update(&FIXTURE_CLIENT_HELLO[5..]);
        b.update(&FIXTURE_SERVER_HELLO[5..]);

        assert_eq!(a.snapshot(), b.snapshot());
    }

    #[test]
    fn transcript_update_record_honors_declared_length() {
        // A buffered-read scenario: caller's slice holds the full record
        // followed by an extra trailing byte (start of the next record).
        // The transcript must hash ONLY the declared `length` bytes,
        // otherwise it silently diverges from the peer's transcript and
        // every downstream MAC/derivation fails.
        //
        // Build a record whose body is 4 bytes "abcd", append a 5th
        // trailing 0xFF that does NOT belong.
        let mut record_plus_tail = [0u8; 5 + 4 + 1];
        record_plus_tail[0] = consts::CT_HANDSHAKE;
        record_plus_tail[1..3].copy_from_slice(&consts::LEGACY_VERSION.to_be_bytes());
        record_plus_tail[3..5].copy_from_slice(&4u16.to_be_bytes());
        record_plus_tail[5..9].copy_from_slice(b"abcd");
        record_plus_tail[9] = 0xFF;

        let mut a = TranscriptHash::<RustCrypto>::new();
        a.update_record(&record_plus_tail).unwrap();

        let mut b = TranscriptHash::<RustCrypto>::new();
        b.update(b"abcd");

        assert_eq!(
            a.snapshot(),
            b.snapshot(),
            "trailing 0xFF must NOT be hashed"
        );
    }

    #[test]
    fn transcript_update_record_rejects_short_body() {
        // Header declares 100 bytes of body but only 10 are present.
        let mut record = [0u8; 5 + 10];
        record[0] = consts::CT_HANDSHAKE;
        record[1..3].copy_from_slice(&consts::LEGACY_VERSION.to_be_bytes());
        record[3..5].copy_from_slice(&100u16.to_be_bytes());
        let mut t = TranscriptHash::<RustCrypto>::new();
        assert_eq!(
            t.update_record(&record),
            Err(TranscriptError::RecordTooShort)
        );
    }

    #[test]
    fn fixture_transcript_hash_ch_sh() {
        // TranscriptHash strips the 5-byte TLS record header internally and
        // hashes the handshake-message body — RFC 8446 §4.4.1.
        let mut t = TranscriptHash::<RustCrypto>::new();
        t.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
        t.update_record(&FIXTURE_SERVER_HELLO).unwrap();
        assert_eq!(t.snapshot(), FIXTURE_TRANSCRIPT_HASH_CH_SH);
    }

    #[test]
    fn fixture_dhe_via_x25519() {
        type T = fixed_bigint::FixedUInt<u32, 16, fixed_bigint::Ct>;
        let dhe = ed25519_heapless::x25519::<T>(
            &FIXTURE_CLIENT_X25519_PRIV,
            &FIXTURE_SERVER_X25519_PUB_2,
        );
        assert_eq!(dhe, FIXTURE_DHE);
    }

    #[test]
    fn fixture_s_hs_traffic_secret_full_chain() {
        type T = fixed_bigint::FixedUInt<u32, 16, fixed_bigint::Ct>;
        // 1. DHE = X25519(client_priv, server_pub)
        let dhe = ed25519_heapless::x25519::<T>(
            &FIXTURE_CLIENT_X25519_PRIV,
            &FIXTURE_SERVER_X25519_PUB_2,
        );
        // 2. handshake_secret = HKDF chain rooted at the no-PSK early_secret
        let hs = handshake_secret::<RustCrypto>(&dhe).unwrap();
        assert_eq!(hs.as_bytes(), &FIXTURE_HANDSHAKE_SECRET_BYTES);
        // 3. traffic secrets keyed on SHA-256(CH || SH)
        let th = {
            let mut t = TranscriptHash::<RustCrypto>::new();
            t.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            t.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            t.snapshot()
        };
        let (c_ts, s_ts) = handshake_traffic_secrets::<RustCrypto>(&hs, &th).unwrap();
        assert_eq!(c_ts.as_bytes(), &FIXTURE_C_HS_TRAFFIC_SECRET_BYTES);
        assert_eq!(s_ts.as_bytes(), &FIXTURE_S_HS_TRAFFIC_SECRET_BYTES);
    }

    const FIXTURE_S_HS_KEY_BYTES: [u8; 16] = [
        0x72, 0x34, 0xe7, 0x98, 0x57, 0x93, 0x61, 0xb1, 0x41, 0x61, 0x86, 0x3b, 0x79, 0x98, 0x86,
        0x3c,
    ];
    const FIXTURE_S_HS_IV_BYTES: [u8; 12] = [
        0x61, 0xcb, 0x91, 0xee, 0x64, 0xff, 0x4a, 0x91, 0xe7, 0x07, 0x1c, 0xbe,
    ];

    #[test]
    fn fixture_traffic_keys_match() {
        let (key, iv) = traffic_keys::<RustCrypto>(&make_fixture_s_hs_traffic_secret()).unwrap();
        assert_eq!(key.as_bytes(), &FIXTURE_S_HS_KEY_BYTES);
        assert_eq!(iv.as_bytes(), &FIXTURE_S_HS_IV_BYTES);
    }

    #[test]
    fn aead_nonce_xors_low_8_bytes() {
        // RFC 8446 §5.3: nonce = iv XOR (seq left-padded to iv_len).
        let iv = AeadIv::new(ZeroBuf::<12>::new([0u8; 12]));
        // seq = 1 should set last byte to 1
        assert_eq!(*aead_nonce(&iv, 1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // seq = 0x0102030405060708 should occupy bytes 4..12
        assert_eq!(
            *aead_nonce(&iv, 0x0102030405060708),
            [0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        );
    }

    /// packets/003_s2c_ServerFlight_encrypted.hex (380 bytes, decoded at compile time).
    const FIXTURE_PACKET_3: [u8; 380] = crate::hex_decode(include_str!(
        "../../testdata/packets/003_s2c_ServerFlight_encrypted.hex"
    ));

    /// First 32 bytes of the decrypted TLSInnerPlaintext of packet 003. Begins:
    ///   0x08 0x00 0x00 0x02 0x00 0x00       EncryptedExtensions (empty)
    ///   0x0b 0x00 0x00 0xf0 ...             Certificate (msg_type=11, len=0x0000f0)
    const FIXTURE_PACKET_3_PLAINTEXT_HEAD: [u8; 32] = [
        0x08, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0b, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0xec, 0x00,
        0x00, 0xe7, 0x30, 0x81, 0xe4, 0x30, 0x81, 0x97, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01,
        0x01, 0x30,
    ];

    /// Wrap the seed-0 server handshake AEAD key bytes into an `AeadKey`.
    /// `AeadKey::new` takes a `ZeroBuf<16>` (= `Zeroizing<[u8; 16]>`) which
    /// isn't const-constructible, so we wrap at the call site.
    fn make_fixture_s_hs_key() -> AeadKey {
        AeadKey::new(ZeroBuf::<16>::new(FIXTURE_S_HS_KEY_BYTES))
    }
    fn make_fixture_s_hs_iv() -> AeadIv {
        AeadIv::new(ZeroBuf::<12>::new(FIXTURE_S_HS_IV_BYTES))
    }

    #[test]
    fn fixture_packet_3_decrypts() {
        // record body length minus the 16-byte AEAD tag = expected plaintext length.
        // Packet 003 is 380 bytes total: 5 header + 375 body; plaintext = 375 - 16 = 359.
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut buf = [0u8; 400];
        let pt = decrypt_record::<RustCrypto>(
            &FIXTURE_PACKET_3,
            &key,
            &iv,
            0, // first record under s_hs_traffic_secret
            &mut buf,
        )
        .expect("decrypt_record");
        assert_eq!(pt.len(), 359);
        assert_eq!(&pt[..32], &FIXTURE_PACKET_3_PLAINTEXT_HEAD);

        // Inner plaintext = handshake_bytes || content_type(0x16) || zero padding.
        let (content, content_type) = split_inner_plaintext(pt).expect("split inner plaintext");
        assert_eq!(content_type, consts::CT_HANDSHAKE);
        // First handshake message is EncryptedExtensions: type=8 len=2 body=0000.
        assert_eq!(&content[..6], &[0x08, 0x00, 0x00, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn fixture_packet_3_decrypts_full_chain() {
        // The whole pipeline, starting from the X25519 client priv.
        type Bn = fixed_bigint::FixedUInt<u32, 16, fixed_bigint::Ct>;
        let dhe = ed25519_heapless::x25519::<Bn>(
            &FIXTURE_CLIENT_X25519_PRIV,
            &FIXTURE_SERVER_X25519_PUB_2,
        );
        let hs = handshake_secret::<RustCrypto>(&dhe).unwrap();
        let th = {
            let mut t = TranscriptHash::<RustCrypto>::new();
            t.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            t.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            t.snapshot()
        };
        let (_c_ts, s_ts) = handshake_traffic_secrets::<RustCrypto>(&hs, &th).unwrap();
        let (key, iv) = traffic_keys::<RustCrypto>(&s_ts).unwrap();

        let mut buf = [0u8; 400];
        let pt = decrypt_record::<RustCrypto>(&FIXTURE_PACKET_3, &key, &iv, 0, &mut buf).unwrap();
        let (content, content_type) = split_inner_plaintext(pt).unwrap();
        assert_eq!(content_type, consts::CT_HANDSHAKE);
        assert_eq!(&content[..6], &[0x08, 0x00, 0x00, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn fixture_packet_3_server_flight_verifies() {
        // Get the plaintext the same way the user-facing pipeline does.
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut buf = [0u8; 400];
        let pt = decrypt_record::<RustCrypto>(&FIXTURE_PACKET_3, &key, &iv, 0, &mut buf).unwrap();
        let (content, _ct) = split_inner_plaintext(pt).unwrap();

        // Walk it: EE / Cert / CertVerify / Finished.
        let flight = parse_server_flight(content).expect("parse_server_flight");

        // EncryptedExtensions is empty.
        assert_eq!(flight.ee_body, &[0x00, 0x00][..]);

        // Cert: extract Ed25519 pubkey via the DER walker.
        let cert_der = extract_cert_der(flight.cert_body).expect("extract_cert_der");
        let cert_view = <DerCert as CertParser>::parse(cert_der).expect("parse cert");
        const EXPECTED_SERVER_ID_PUB: [u8; 32] = [
            0x9d, 0xfe, 0x2a, 0xb0, 0x3e, 0x35, 0x70, 0x4b, 0x9c, 0xfb, 0x93, 0xb6, 0x03, 0xa6,
            0x61, 0x18, 0x82, 0x17, 0xa6, 0xb5, 0xfd, 0x6a, 0x1f, 0x75, 0xe6, 0x16, 0x1a, 0x39,
            0xe0, 0x53, 0x4c, 0x3f,
        ];
        match cert_view {
            CertView::Ed25519 { pubkey, .. } => assert_eq!(pubkey, &EXPECTED_SERVER_ID_PUB),
            #[cfg(feature = "rsa")]
            _ => panic!("fixture cert is Ed25519"),
        }

        // Verify cert's self-signature.
        let view = verify_self_signed_cert::<DerCert, RustCrypto>(cert_der).expect("cert self-sig");
        let pk = match view {
            CertView::Ed25519 { pubkey, .. } => *pubkey,
            #[cfg(feature = "rsa")]
            _ => panic!("fixture cert is Ed25519"),
        };
        assert_eq!(pk, EXPECTED_SERVER_ID_PUB);

        // End-to-end pipeline including CertVerify and Finished.
        let mut transcript = TranscriptHash::<RustCrypto>::new();
        transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
        transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
        let result = verify_server_flight::<RustCrypto, DerCert, RustCrypto>(
            &mut transcript,
            content,
            &make_fixture_s_hs_traffic_secret(),
        )
        .expect("verify_server_flight");
        assert_eq!(
            result.server_pubkey.as_ed25519(),
            Some(EXPECTED_SERVER_ID_PUB)
        );
    }

    /// Stub Ed25519Verify backend that always rejects. Used to prove the
    /// `E: Ed25519Verify` generic actually wires through to the verify
    /// callsites — swapping the backend should change observed behavior
    /// even with the same cert / signature bytes.
    struct AlwaysReject;
    impl crate::traits::Ed25519Verify for AlwaysReject {
        type Cache = ();
        fn new_cache() {}
        fn verify(_: &[u8; 32], _: &[u8], _: &[u8; 64]) -> bool {
            false
        }
        fn verify_with_cache(_: &(), _: &[u8; 32], _: &[u8], _: &[u8; 64]) -> bool {
            false
        }
    }

    #[test]
    fn ed25519_verify_trait_propagates_to_cert_self_sig() {
        // Same fixture cert that passes with RustCrypto. Plugging in
        // AlwaysReject must flip the result to CertSelfSignatureInvalid.
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let cert_der = &buf[..len];
        let err = verify_self_signed_cert::<DerCert, AlwaysReject>(cert_der).unwrap_err();
        assert_eq!(err, FlightError::CertSelfSignatureInvalid);
    }

    #[test]
    fn ed25519_verify_trait_propagates_to_certificate_verify() {
        // Run the full flight pipeline with AlwaysReject. The cert self-sig
        // check is the first place E::verify gets called, so that's what
        // fires — but the point is "if I swap the backend, behavior
        // changes," which proves the type param flows through.
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut pt_buf = [0u8; 400];
        let pt =
            decrypt_record::<RustCrypto>(&FIXTURE_PACKET_3, &key, &iv, 0, &mut pt_buf).unwrap();
        let (content, _) = split_inner_plaintext(pt).unwrap();
        let mut transcript = TranscriptHash::<RustCrypto>::new();
        transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
        transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
        let err = verify_server_flight::<RustCrypto, DerCert, AlwaysReject>(
            &mut transcript,
            content,
            &make_fixture_s_hs_traffic_secret(),
        )
        .unwrap_err();
        assert_eq!(err, FlightError::CertSelfSignatureInvalid);
    }

    /// Locate every occurrence of the Ed25519 OID DER byte sequence
    /// (`06 03 2B 65 70`) in a cert. In a self-signed Ed25519 cert there are
    /// exactly three, in this byte order:
    /// 1. `TBSCertificate.signature` AlgorithmIdentifier
    /// 2. `SubjectPublicKeyInfo.algorithm` AlgorithmIdentifier
    /// 3. outer `Certificate.signatureAlgorithm` AlgorithmIdentifier
    fn find_ed25519_oid_positions(cert_der: &[u8]) -> [usize; 3] {
        const ED25519_OID_BYTES: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
        let mut positions = [0usize; 3];
        let mut count = 0;
        let mut i = 0;
        while i + ED25519_OID_BYTES.len() <= cert_der.len() {
            if &cert_der[i..i + ED25519_OID_BYTES.len()] == ED25519_OID_BYTES {
                assert!(count < 3, "more than 3 Ed25519-OID occurrences in cert");
                positions[count] = i;
                count += 1;
            }
            i += 1;
        }
        assert_eq!(count, 3, "expected 3 Ed25519-OID occurrences in cert");
        positions
    }

    /// Decrypt server flight, walk to the cert SEQUENCE, return its DER bytes
    /// copied into a stack buffer the caller can mutate.
    fn fixture_cert_der_copy(buf: &mut [u8]) -> usize {
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut pt_buf = [0u8; 400];
        let pt =
            decrypt_record::<RustCrypto>(&FIXTURE_PACKET_3, &key, &iv, 0, &mut pt_buf).unwrap();
        let (content, _) = split_inner_plaintext(pt).unwrap();
        let flight = parse_server_flight(content).unwrap();
        let cert_der = extract_cert_der(flight.cert_body).unwrap();
        buf[..cert_der.len()].copy_from_slice(cert_der);
        cert_der.len()
    }

    #[test]
    fn cert_rejects_wrong_outer_signature_algorithm_oid_via_symmetry() {
        // Flip only the outer signatureAlgorithm OID. TBS.signature still
        // claims Ed25519, so the RFC 5280 §4.1.1.2 symmetry check fires
        // first — that's what catches the mismatch, since the parser no
        // longer interprets the outer OID at parse time (issuer-signed
        // leaves routinely carry unknown outer OIDs and must still parse).
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let positions = find_ed25519_oid_positions(&buf[..len]);
        buf[positions[2] + 4] ^= 0x01; // outer signatureAlgorithm OID
        let err = <DerCert as CertParser>::parse(&buf[..len]).unwrap_err();
        assert_eq!(err, CertParseError::SignatureAlgorithmMismatch);
    }

    #[test]
    fn cert_rejects_wrong_spki_algorithm_oid() {
        // Outer + symmetry pass; only the SPKI's algorithm OID is mangled.
        // The SPKI is what we dispatch on, so an unknown OID there is
        // `WrongAlgorithmOid` directly.
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let positions = find_ed25519_oid_positions(&buf[..len]);
        buf[positions[1] + 4] ^= 0x01; // SPKI algorithm OID
        let err = <DerCert as CertParser>::parse(&buf[..len]).unwrap_err();
        assert_eq!(err, CertParseError::WrongAlgorithmOid);
    }

    #[test]
    fn cert_with_unknown_outer_sig_algo_still_parses_if_spki_known() {
        // Codex review (PR#1): flip BOTH outer and TBS sig algorithm OIDs
        // to the same unknown value (keeping symmetry). The leaf's SPKI is
        // still valid Ed25519. The parser must accept — the outer sig algo
        // describes the *issuer*'s signature, which for real-world leaves
        // routinely isn't anything we recognize. Dispatch is on SPKI.
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let positions = find_ed25519_oid_positions(&buf[..len]);
        // Flip the same last byte in both TBS and outer sig OID so the
        // symmetry check still passes.
        buf[positions[0] + 4] ^= 0x01;
        buf[positions[2] + 4] ^= 0x01;
        let view = <DerCert as CertParser>::parse(&buf[..len]).expect("parse must succeed");
        assert!(matches!(view, CertView::Ed25519 { .. }));
    }

    #[test]
    fn cert_rejects_inner_outer_signature_alg_mismatch() {
        // Flip only the TBS.signature OID. Outer OID still claims Ed25519,
        // so symmetry check fires (TBS.signature bytes now differ from
        // Certificate.signatureAlgorithm).
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let positions = find_ed25519_oid_positions(&buf[..len]);
        buf[positions[0] + 4] ^= 0x01; // TBS.signature OID
        let err = <DerCert as CertParser>::parse(&buf[..len]).unwrap_err();
        assert_eq!(err, CertParseError::SignatureAlgorithmMismatch);
    }

    #[test]
    fn cert_rejects_unsupported_version() {
        // Locate the `[0] EXPLICIT { INTEGER 2 }` version field
        // (`A0 03 02 01 02`) and rewrite the inner version to `00` (v1
        // encoded explicitly — already malformed per DER, but a parser must
        // still surface a clear rejection rather than silent acceptance).
        const V3_VERSION_BYTES: &[u8] = &[0xA0, 0x03, 0x02, 0x01, 0x02];
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let pos = buf[..len]
            .windows(V3_VERSION_BYTES.len())
            .position(|w| w == V3_VERSION_BYTES)
            .expect("v3 version field");
        buf[pos + 4] = 0x00; // claim v1
        let err = <DerCert as CertParser>::parse(&buf[..len]).unwrap_err();
        assert_eq!(err, CertParseError::UnsupportedCertVersion);
    }

    #[test]
    fn fixture_bad_finished_rejected() {
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut buf = [0u8; 400];
        let pt = decrypt_record::<RustCrypto>(&FIXTURE_PACKET_3, &key, &iv, 0, &mut buf).unwrap();
        let (content, _) = split_inner_plaintext(pt).unwrap();

        // Tamper with the Finished verify_data (last 32 bytes of the inner content).
        let mut tampered = [0u8; 400];
        tampered[..content.len()].copy_from_slice(content);
        let last = content.len() - 1;
        tampered[last] ^= 0xFF;

        let mut transcript = TranscriptHash::<RustCrypto>::new();
        transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
        transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
        let err = verify_server_flight::<RustCrypto, DerCert, RustCrypto>(
            &mut transcript,
            &tampered[..content.len()],
            &make_fixture_s_hs_traffic_secret(),
        )
        .unwrap_err();
        assert_eq!(err, FlightError::FinishedMacInvalid);
    }

    /// packets/005_c2s_AppData_send_0.hex (52 bytes) — first client app-data record.
    const FIXTURE_PACKET_5: [u8; 52] = crate::hex_decode(include_str!(
        "../../testdata/packets/005_c2s_AppData_send_0.hex"
    ));
    /// packets/006_s2c_AppData_reply_0.hex (48 bytes) — first server app-data record.
    const FIXTURE_PACKET_6: [u8; 48] = crate::hex_decode(include_str!(
        "../../testdata/packets/006_s2c_AppData_reply_0.hex"
    ));

    /// Plaintext the fixture's `cli.py --send` sent.
    const PACKET_5_PLAINTEXT: &[u8] = b"hello from the embedded client";
    /// Plaintext the fixture's `serv.py --reply` sent — includes a UTF-8 em-dash
    /// (`\xe2\x80\x94`) which exercises non-ASCII handling.
    const PACKET_6_PLAINTEXT: &[u8] = b"hello back \xe2\x80\x94 server here";

    /// `((key, iv), (key, iv))` for `(c_ap, s_ap)` AEAD streams.
    type ApAeadKeys = (AeadKey, AeadIv);

    fn make_fixture_handshake_secret() -> Secret {
        Secret::new(ZeroBuf::<32>::new(FIXTURE_HANDSHAKE_SECRET_BYTES))
    }
    fn make_fixture_c_hs_traffic_secret() -> Secret {
        Secret::new(ZeroBuf::<32>::new(FIXTURE_C_HS_TRAFFIC_SECRET_BYTES))
    }

    /// Derive the application traffic secrets the same way the demo runs, then
    /// peel off `(c_ap_key, c_ap_iv)` and `(s_ap_key, s_ap_iv)`. Helper kept in
    /// the tests so the rest of the test file stays focused.
    fn application_keys() -> (ApAeadKeys, ApAeadKeys) {
        // master_secret -> (c_ap, s_ap) -> traffic_keys for each
        // Need transcript_hash_through_server_finished; pick it up by running the
        // verify pipeline as the test below does.
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut pt_buf = [0u8; 400];
        let pt =
            decrypt_record::<RustCrypto>(&FIXTURE_PACKET_3, &key, &iv, 0, &mut pt_buf).unwrap();
        let (content, _) = split_inner_plaintext(pt).unwrap();
        let mut transcript = TranscriptHash::<RustCrypto>::new();
        transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
        transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
        verify_server_flight::<RustCrypto, DerCert, RustCrypto>(
            &mut transcript,
            content,
            &make_fixture_s_hs_traffic_secret(),
        )
        .unwrap();
        let ms = master_secret::<RustCrypto>(&make_fixture_handshake_secret()).unwrap();
        let (c_ap_ts, s_ap_ts) =
            application_traffic_secrets::<RustCrypto>(&ms, &transcript.snapshot()).unwrap();
        (
            traffic_keys::<RustCrypto>(&c_ap_ts).unwrap(),
            traffic_keys::<RustCrypto>(&s_ap_ts).unwrap(),
        )
    }

    #[test]
    fn fixture_packet_5_encrypts_byte_identical() {
        let ((c_key, c_iv), _) = application_keys();
        assert_eq!(
            c_key.as_bytes(),
            &[
                0x3b, 0x69, 0x7f, 0x88, 0xe5, 0x6a, 0x98, 0x7b, 0x37, 0x53, 0xa1, 0xa8, 0x2b, 0x86,
                0x66, 0x18,
            ]
        );
        assert_eq!(
            c_iv.as_bytes(),
            &[
                0x77, 0x6e, 0xb4, 0xda, 0xbe, 0x1e, 0xa0, 0x3b, 0xac, 0xd5, 0x4f, 0xbb
            ]
        );

        // First app-data record under c_ap uses seq = 0.
        let mut out = [0u8; 80];
        let record = encrypt_record::<RustCrypto>(
            PACKET_5_PLAINTEXT,
            consts::CT_APPLICATION_DATA,
            &c_key,
            &c_iv,
            0,
            &mut out,
        )
        .unwrap();
        assert_eq!(record, &FIXTURE_PACKET_5[..]);
    }

    #[test]
    fn fixture_packet_6_decrypts_to_expected_plaintext() {
        let (_, (s_key, s_iv)) = application_keys();
        let mut pt = [0u8; 64];
        let inner = decrypt_record::<RustCrypto>(&FIXTURE_PACKET_6, &s_key, &s_iv, 0, &mut pt)
            .expect("decrypt packet 6");
        let (content, ct) = split_inner_plaintext(inner).unwrap();
        assert_eq!(ct, consts::CT_APPLICATION_DATA);
        assert_eq!(content, PACKET_6_PLAINTEXT);
    }

    /// packets/004_c2s_ClientFinished_encrypted.hex (58 bytes).
    const FIXTURE_PACKET_4: [u8; 58] = crate::hex_decode(include_str!(
        "../../testdata/packets/004_c2s_ClientFinished_encrypted.hex"
    ));

    #[test]
    fn fixture_client_finished_matches() {
        // Run the full verify chain to get the inputs for build_client_finished.
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut pt_buf = [0u8; 400];
        let pt =
            decrypt_record::<RustCrypto>(&FIXTURE_PACKET_3, &key, &iv, 0, &mut pt_buf).unwrap();
        let (content, _ct) = split_inner_plaintext(pt).unwrap();
        let mut transcript = TranscriptHash::<RustCrypto>::new();
        transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
        transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
        verify_server_flight::<RustCrypto, DerCert, RustCrypto>(
            &mut transcript,
            content,
            &make_fixture_s_hs_traffic_secret(),
        )
        .unwrap();

        // Now build the client Finished record and compare to fixture's packet 4.
        let mut out = [0u8; 64];
        let record =
            RecordKeys::<Aes128GcmSha256>::build_client_finished::<RustCrypto, RustCrypto>(
                &make_fixture_c_hs_traffic_secret(),
                &transcript.snapshot(),
                0, // first record under c_hs_traffic_secret
                &mut out,
            )
            .unwrap();
        assert_eq!(record.len(), CLIENT_FINISHED_LEN);
        assert_eq!(record, &FIXTURE_PACKET_4[..]);
    }

    #[test]
    fn fixture_application_traffic_secrets_match() {
        // master_secret = HKDF chain rooted at handshake_secret.
        let ms = master_secret::<RustCrypto>(&make_fixture_handshake_secret()).unwrap();
        // app secrets are keyed on the transcript hash through *server* Finished.
        // We can pick that up from verify_server_flight.
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut pt_buf = [0u8; 400];
        let pt =
            decrypt_record::<RustCrypto>(&FIXTURE_PACKET_3, &key, &iv, 0, &mut pt_buf).unwrap();
        let (content, _) = split_inner_plaintext(pt).unwrap();
        let mut transcript = TranscriptHash::<RustCrypto>::new();
        transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
        transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
        verify_server_flight::<RustCrypto, DerCert, RustCrypto>(
            &mut transcript,
            content,
            &make_fixture_s_hs_traffic_secret(),
        )
        .unwrap();

        let (c_ap, s_ap) =
            application_traffic_secrets::<RustCrypto>(&ms, &transcript.snapshot()).unwrap();

        const FIXTURE_C_AP_BYTES: [u8; 32] = [
            0x0b, 0x35, 0x2a, 0x04, 0x91, 0x96, 0x84, 0x43, 0x4b, 0x94, 0x50, 0x24, 0x30, 0x0c,
            0xf8, 0xc6, 0xd8, 0xea, 0xd3, 0x7b, 0x66, 0xcb, 0x58, 0x3d, 0x1e, 0xe5, 0x3c, 0xd0,
            0x43, 0x4e, 0x73, 0x21,
        ];
        const FIXTURE_S_AP_BYTES: [u8; 32] = [
            0x72, 0xac, 0xa2, 0x7e, 0x3f, 0x25, 0x70, 0x84, 0xa1, 0x7e, 0x2d, 0x61, 0x58, 0x18,
            0x38, 0xe9, 0xbf, 0x94, 0x70, 0xab, 0x4a, 0x4e, 0xf8, 0x4a, 0x16, 0xdc, 0x12, 0x0e,
            0xa7, 0x6d, 0xbd, 0xba,
        ];
        assert_eq!(c_ap.as_bytes(), &FIXTURE_C_AP_BYTES);
        assert_eq!(s_ap.as_bytes(), &FIXTURE_S_AP_BYTES);
    }

    #[test]
    fn bad_tag_returns_aead_failed() {
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut tampered = [0u8; 380];
        tampered.copy_from_slice(&FIXTURE_PACKET_3);
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF; // corrupt the auth tag
        let mut buf = [0u8; 400];
        // Pre-fill with a sentinel; the function should overwrite the
        // ciphertext window with zeroes on AEAD failure.
        buf.fill(0xAA);
        let err = decrypt_record::<RustCrypto>(&tampered, &key, &iv, 0, &mut buf).unwrap_err();
        assert_eq!(err, DecryptError::AeadFailed);

        // The bytes in the ciphertext window (record body minus 16-byte tag)
        // must be zeroed — RFC says callers MUST NOT use the buffer on
        // error, and we defensively zero it. Bytes outside that window
        // (anything beyond ct_len) are left alone, since `decrypt_record`
        // is documented to write only the `[..ct_len]` prefix.
        let body_len = u16::from_be_bytes([tampered[3], tampered[4]]) as usize;
        let ct_len = body_len - 16;
        assert!(
            buf[..ct_len].iter().all(|&b| b == 0),
            "ciphertext window must be zeroed on AeadFailed"
        );
        assert!(
            buf[ct_len..].iter().all(|&b| b == 0xAA),
            "bytes past ct_len must be untouched"
        );
    }

    #[test]
    fn decrypt_record_rejects_trailing_bytes() {
        // Two valid records glued together — caller MUST pass exactly one.
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut extra = [0u8; 381];
        extra[..380].copy_from_slice(&FIXTURE_PACKET_3);
        extra[380] = 0xAB; // one stray byte past the declared record body
        let mut buf = [0u8; 400];
        let err = decrypt_record::<RustCrypto>(&extra, &key, &iv, 0, &mut buf).unwrap_err();
        assert_eq!(err, DecryptError::TrailingBytes);
    }

    #[cfg(feature = "jedisct")]
    #[test]
    fn jedisct_matches_rustcrypto() {
        // HKDF is fully spec-determined, so both backends must produce identical
        // outputs on the same inputs. Easy parity property-style test.
        for ikm in &[&[0u8; 32][..], b"abc"[..].as_ref(), &FIXTURE_DHE[..]] {
            let rc = RustCrypto::extract(&[0u8; 32], ikm);
            let jd = JedisctCrypto::extract(&[0u8; 32], ikm);
            assert_eq!(&*rc, &*jd, "extract diverged for ikm len={}", ikm.len());
        }
        // Mid-length expand.
        let prk: [u8; 32] = [0x42; 32];
        for out_len in [16usize, 32, 48] {
            let mut rc = [0u8; 48];
            let mut jd = [0u8; 48];
            RustCrypto::expand(&prk, b"test info", &mut rc[..out_len]).unwrap();
            JedisctCrypto::expand(&prk, b"test info", &mut jd[..out_len]).unwrap();
            assert_eq!(rc, jd, "expand diverged at len={out_len}");
        }
        // Full TLS 1.3 chain through to s_hs_traffic_secret must match.
        type Bn = fixed_bigint::FixedUInt<u32, 16, fixed_bigint::Ct>;
        let dhe = ed25519_heapless::x25519::<Bn>(
            &FIXTURE_CLIENT_X25519_PRIV,
            &FIXTURE_SERVER_X25519_PUB_2,
        );
        let rc_hs = handshake_secret::<RustCrypto>(&dhe).unwrap();
        let jd_hs = handshake_secret::<JedisctCrypto>(&dhe).unwrap();
        assert_eq!(rc_hs, jd_hs);
        let th = {
            let mut t = TranscriptHash::<RustCrypto>::new();
            t.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            t.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            t.snapshot()
        };
        let rc_ts = handshake_traffic_secrets::<RustCrypto>(&rc_hs, &th).unwrap();
        let jd_ts = handshake_traffic_secrets::<JedisctCrypto>(&jd_hs, &th).unwrap();
        assert_eq!(rc_ts, jd_ts);
    }

    #[test]
    fn encrypt_record_rejects_oversize_plaintext() {
        // Content large enough that inner_plaintext + tag exceeds
        // TLSCiphertext.length cap (2^14 + 256). Out buffer size doesn't
        // matter — RecordTooLarge fires before BufferTooSmall.
        let big = vec![0u8; (1 << 14) + 256];
        let mut out = [0u8; 1];
        let err = encrypt_record::<RustCrypto>(
            &big,
            consts::CT_APPLICATION_DATA,
            &AeadKey::new(ZeroBuf::<16>::new([0u8; 16])),
            &AeadIv::new(ZeroBuf::<12>::new([0u8; 12])),
            0,
            &mut out,
        )
        .unwrap_err();
        assert_eq!(err, aead::EncryptError::RecordTooLarge);
    }

    #[cfg(feature = "chacha20")]
    #[test]
    fn chacha20_encrypt_decrypt_round_trip() {
        let key = AeadKey32::new(ZeroBuf::<32>::new([0x11; 32]));
        let iv = AeadIv::new(ZeroBuf::<12>::new([0x22; 12]));
        let plaintext = b"hello world";
        let mut record_buf = [0u8; 64];
        let record = encrypt_record_chacha::<RustCrypto>(
            plaintext,
            consts::CT_APPLICATION_DATA,
            &key,
            &iv,
            7,
            &mut record_buf,
        )
        .unwrap();
        let record_owned = record.to_vec();
        let mut pt_buf = [0u8; 64];
        let inner =
            decrypt_record_chacha::<RustCrypto>(&record_owned, &key, &iv, 7, &mut pt_buf).unwrap();
        let (content, content_type) = aead::split_inner_plaintext(inner).unwrap();
        assert_eq!(content, plaintext);
        assert_eq!(content_type, consts::CT_APPLICATION_DATA);
    }

    #[test]
    fn encrypt_record_rejects_plaintext_just_over_14k() {
        // RFC 8446 §5.1: TLSPlaintext.length max is 2^14. Content of
        // 2^14 + 1 bytes fits the §5.2 ciphertext cap (2^14 + 256) once
        // the AEAD tag + content_type are added, but violates the §5.1
        // plaintext cap — must surface as RecordTooLarge.
        let just_over = vec![0u8; (1 << 14) + 1];
        let mut out = vec![0u8; (1 << 14) + 256 + 5];
        let err = encrypt_record::<RustCrypto>(
            &just_over,
            consts::CT_APPLICATION_DATA,
            &AeadKey::new(ZeroBuf::<16>::new([0u8; 16])),
            &AeadIv::new(ZeroBuf::<12>::new([0u8; 12])),
            0,
            &mut out,
        )
        .unwrap_err();
        assert_eq!(err, aead::EncryptError::RecordTooLarge);
    }

    #[test]
    fn split_inner_plaintext_rejects_over_14k() {
        // Build a synthetic inner: 2^14 + 1 bytes of content, then the
        // content_type byte, no padding. §5.1 / §5.4 require content
        // (post-padding-strip) <= 2^14.
        let mut inner = vec![0xABu8; (1 << 14) + 2];
        let last = inner.len() - 1;
        inner[last] = consts::CT_APPLICATION_DATA;
        let err = split_inner_plaintext(&inner).unwrap_err();
        assert_eq!(err, aead::DecryptError::RecordTooLarge);
    }

    #[test]
    fn split_inner_plaintext_accepts_exactly_14k() {
        // 2^14 content bytes + 1 content_type byte = boundary case.
        let mut inner = vec![0xCDu8; (1 << 14) + 1];
        let last = inner.len() - 1;
        inner[last] = consts::CT_APPLICATION_DATA;
        let (content, ct) = split_inner_plaintext(&inner).unwrap();
        assert_eq!(content.len(), 1 << 14);
        assert_eq!(ct, consts::CT_APPLICATION_DATA);
    }

    #[test]
    fn certificate_verify_rejects_trailing_bytes() {
        // Synthetic CV body = u16(scheme) || u16(64) || 64 sig bytes || one trailing byte.
        let mut body = [0u8; 4 + 64 + 1];
        body[0..2].copy_from_slice(&consts::SIG_SCHEME_ED25519.to_be_bytes());
        body[2..4].copy_from_slice(&64u16.to_be_bytes());
        // sig bytes default 0 — verification would fail, but the trailing-bytes
        // check fires before any crypto.
        body[4 + 64] = 0xCC;
        // Synthetic CertView::Ed25519 with zero pubkey/signature; the trailing-
        // bytes check fires before any crypto.
        const ZERO_PUB: [u8; 32] = [0u8; 32];
        const ZERO_SIG: [u8; 64] = [0u8; 64];
        let view = CertView::Ed25519 {
            tbs: &[],
            signature: &ZERO_SIG,
            pubkey: &ZERO_PUB,
            san: None,
            validity_der: &[],
        };
        let th = TranscriptDigest::new([0u8; 32]);
        let err =
            server_flight::verify_certificate_verify::<RustCrypto>(&view, &th, &body).unwrap_err();
        assert_eq!(err, FlightError::TrailingBytes);
    }

    // extract_cert_der was relaxed to take the leaf (first entry) and tolerate
    // intermediate certs / per-cert extensions / list-trailing bytes — required
    // for talking to public servers that send leaf + chain. The previous
    // strict-rejection tests (`*_rejects_multiple_entries`, `*_rejects_non_-
    // empty_per_cert_extensions`, `*_rejects_trailing_bytes_after_list`) were
    // removed; the corresponding `FlightError` variants stay around for any
    // future caller that wants to layer strictness on top.

    #[test]
    fn extract_cert_der_returns_leaf_from_chain() {
        // Two cert entries in the list; extract_cert_der returns the FIRST.
        // ctx_len=0 || list_len=u24(2*(3+5+2)=20) || entry1 || entry2.
        let mut body = [0u8; 1 + 3 + 20];
        body[0] = 0;
        body[3] = 20;
        // entry 1: cert_data_len=5, body=[1,2,3,4,5], exts_len=0
        body[6] = 5;
        body[7..12].copy_from_slice(&[1, 2, 3, 4, 5]);
        // entry 2: cert_data_len=5, body=[6,7,8,9,10], exts_len=0
        body[16] = 5;
        body[17..22].copy_from_slice(&[6, 7, 8, 9, 10]);
        let leaf = extract_cert_der(&body).expect("first cert");
        assert_eq!(leaf, &[1, 2, 3, 4, 5]);
    }

    #[cfg(feature = "rsa")]
    mod rsa_tests {
        use super::*;

        /// RSA fixture, c→s ClientHello.
        const FIXTURE_RSA_CLIENT_HELLO: [u8; 117] = crate::hex_decode(include_str!(
            "../../testdata/packets_rsa/001_c2s_ClientHello.hex"
        ));
        /// RSA fixture, s→c ServerHello.
        const FIXTURE_RSA_SERVER_HELLO: [u8; 95] = crate::hex_decode(include_str!(
            "../../testdata/packets_rsa/002_s2c_ServerHello.hex"
        ));
        /// RSA fixture, encrypted server flight (1034 B — dominated by the
        /// 2048-bit RSA cert + 256-byte RSA-PSS signature).
        const FIXTURE_RSA_PACKET_3: [u8; 1034] = crate::hex_decode(include_str!(
            "../../testdata/packets_rsa/003_s2c_ServerFlight_encrypted.hex"
        ));

        /// Server handshake traffic secret from the RSA fixture.
        const FIXTURE_RSA_S_HS_TRAFFIC_SECRET_BYTES: [u8; 32] = [
            0x6e, 0xb5, 0xef, 0x9a, 0x73, 0xd2, 0x86, 0xdd, 0x12, 0x24, 0xb2, 0x33, 0xd3, 0xa4,
            0xac, 0xa7, 0xaa, 0x1b, 0x4a, 0x47, 0x58, 0x61, 0x26, 0x7b, 0x68, 0xac, 0x55, 0xa9,
            0x9d, 0xbb, 0x41, 0xe9,
        ];

        fn s_hs_traffic_secret() -> Secret {
            Secret::new(ZeroBuf::<32>::new(FIXTURE_RSA_S_HS_TRAFFIC_SECRET_BYTES))
        }

        #[test]
        fn fixture_rsa_server_flight_verifies() {
            // Derive AEAD (key, iv) from the fixture's server handshake traffic secret.
            let s_hs_ts = s_hs_traffic_secret();
            let (key, iv) = traffic_keys::<RustCrypto>(&s_hs_ts).expect("traffic_keys");

            // Decrypt the RSA fixture's server flight.
            let mut pt_buf = [0u8; 1100];
            let pt = decrypt_record::<RustCrypto>(&FIXTURE_RSA_PACKET_3, &key, &iv, 0, &mut pt_buf)
                .expect("decrypt packets_rsa/003");
            let (content, ct) = split_inner_plaintext(pt).unwrap();
            assert_eq!(ct, consts::CT_HANDSHAKE);

            // Walk the inner flight + verify cert (RSA-PKCS#1-v1.5 self-sig) +
            // CertificateVerify (rsa_pss_rsae_sha256) + Finished MAC.
            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_RSA_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_RSA_SERVER_HELLO).unwrap();
            verify_server_flight::<RustCrypto, DerCert, RustCrypto>(
                &mut transcript,
                content,
                &s_hs_ts,
            )
            .expect("verify RSA server flight");
        }

        #[test]
        fn rsa_verify_rejects_wrong_signature_length() {
            // `FixedUInt::from_be_bytes` requires an exact-length slice; the
            // public RSA verify APIs must guard against wrong-length input
            // and return `RsaVerifyError` instead of panicking. This test
            // would have panicked before the length checks were added.
            use crate::backends::rsa_verify::{verify_pkcs1v15_sha256, verify_pss_sha256};
            let modulus_2048 = [0xFFu8; 256]; // contents don't matter, only length
            let exponent: u32 = 65537;
            // 200-byte signature for a 256-byte modulus → reject.
            let short_sig = [0u8; 200];
            assert!(verify_pkcs1v15_sha256(&modulus_2048, exponent, b"msg", &short_sig).is_err());
            assert!(verify_pss_sha256(&modulus_2048, exponent, b"msg", &short_sig).is_err());
        }

        #[test]
        fn fixture_rsa_cert_parses_as_rsa_view() {
            // Spot-check that DerCert parses the fixture's RSA cert into the
            // RSA variant with a 2048-bit modulus and exponent 65537.
            let s_hs_ts = s_hs_traffic_secret();
            let (key, iv) = traffic_keys::<RustCrypto>(&s_hs_ts).unwrap();
            let mut pt_buf = [0u8; 1100];
            let pt = decrypt_record::<RustCrypto>(&FIXTURE_RSA_PACKET_3, &key, &iv, 0, &mut pt_buf)
                .unwrap();
            let (content, _) = split_inner_plaintext(pt).unwrap();
            let flight = parse_server_flight(content).unwrap();
            let cert_der = extract_cert_der(flight.cert_body).unwrap();
            let view = <DerCert as CertParser>::parse(cert_der).expect("RSA cert parses");
            match view {
                CertView::Rsa {
                    modulus, exponent, ..
                } => {
                    assert_eq!(modulus.len(), 256, "RSA-2048 modulus is 256 bytes");
                    assert_eq!(exponent, 65537, "fixture priv uses e=65537");
                }
                _ => panic!("expected CertView::Rsa, got {:?}", view),
            }
        }
    }
}
