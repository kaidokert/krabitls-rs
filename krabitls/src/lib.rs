//! `krabitls` — a sans-io, `no_std` TLS 1.3 client.
//!
//! Step zero: emit a minimal ClientHello and parse the matching ServerHello.
//! The wire format is locked to the same fixed profile the rest of the
//! embedded TLS stack uses:
//!
//! | Slot               | Value                              |
//! | ------------------ | ---------------------------------- |
//! | record version     | TLS 1.2 sentinel (`0x0303`)        |
//! | negotiated version | TLS 1.3 (via `supported_versions`) |
//! | cipher suite       | `TLS_AES_128_GCM_SHA256` (`0x1301`) |
//! | named group        | `x25519` (`0x001D`)                |
//! | signature scheme   | `ed25519` (`0x0807`)               |
//! | session id / SNI / PSK | none                           |
//!
//! Because the profile is fixed, the ClientHello is exactly
//! [`CLIENT_HELLO_LEN`] = 117 bytes; the caller supplies only the 32-byte
//! `random` and the 32-byte X25519 public key.
//!
//! Output goes through any [`embedded_io::Write`], so the caller decides
//! whether the destination is a borrowed `&mut [u8]`, a serial UART, or
//! anything else.

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

pub use aead::{
    DecryptError, EncryptError, aead_nonce, decrypt_record, encrypt_record, split_inner_plaintext,
};
#[cfg(feature = "jedisct")]
pub use backends::JedisctCrypto;
pub use backends::{DerCert, RustCrypto};
#[cfg(feature = "rsa")]
pub use backends::{RsaVerifierKey, RsaVerifyError};
pub use client_flight::{CLIENT_FINISHED_LEN, ClientFinishedError, build_client_finished};
pub use hkdf::{
    EMPTY_TRANSCRIPT_HASH, HkdfLabelError, TranscriptError, TranscriptHash,
    application_traffic_secrets, derive_secret, early_secret, finished_mac, handshake_secret,
    handshake_traffic_secrets, hkdf_expand_label, master_secret, traffic_keys,
};
#[cfg(feature = "validity")]
pub use identity::{ValidityError, verify_validity};
pub use newtype::{AeadIv, AeadKey, Secret, TranscriptDigest, ZeroBuf};
pub use server_flight::{
    FlightError, ServerFlightVerified, ServerFlightView, ServerPubkey, extract_cert_der,
    parse_server_flight, verify_certificate_verify, verify_self_signed_cert,
    verify_server_finished, verify_server_flight,
};
pub use traits::{
    AeadError, Aes128GcmAead, CertParseError, CertParser, CertView, Ed25519Verify, HkdfExpandError,
    HkdfSha256, Sha256Hasher,
};
#[cfg(feature = "validity")]
pub use traits::{FixedTime, TimeSource};

use embedded_io::Write;

/// Compile-time hex decoder for the readable `testdata/*.hex` fixtures.
///
/// **Not a TLS-API surface item** — this is a testdata helper. Gated behind
/// `feature = "dev-utils"` (and `#[cfg(test)]` for this crate's own tests)
/// so production library builds neither see nor compile it.
///
/// Skips whitespace (spaces, tabs, newlines) and `#`-to-EOL comments, so
/// the hex files can be hand-eyeball-friendly. Each remaining pair of hex
/// digits becomes one byte. `N` must match the post-decode byte count
/// exactly, or compilation fails with the const-eval panic below.
///
/// Usage:
///
/// ```ignore
/// pub const FIXTURE_PACKET_3: [u8; 380] =
///     krabitls::hex_decode(include_str!("../../testdata/packets/003_*.hex"));
/// ```
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
        // Two hex digits → one byte. The const panic on a bad nibble
        // gives a compile-time error pointing at the bad input.
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

/// Wire constants — straight out of RFC 8446.
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
// signature_algorithms: u16(list_len=2) + u16(ed25519)         = 4 inner -> 8 total
// key_share: u16(list_len=36) + u16(group) + u16(32) + 32B pub = 38 inner -> 42 total
// server_name (when present): u16(list_len) + u8(name_type=0) + u16(hostname_len) + N
//                            = 5 + N inner -> 9 + N total
const EXT_SUPPORTED_VERSIONS_TOTAL: u16 = 4 + 3;
const EXT_SUPPORTED_GROUPS_TOTAL: u16 = 4 + 4;
const EXT_SIGNATURE_ALGORITHMS_TOTAL: u16 = 4 + 4;
const EXT_KEY_SHARE_TOTAL: u16 = 4 + 38;

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
    //      + cipher_suites(2+2) + compression(1+1)
    //      + extensions_len(2) + fixed_extensions + sni_ext
    5 + 4 + 2 + 32 + 1 + (2 + 2) + (1 + 1) + 2 + CH_EXTENSIONS_FIXED_TOTAL as usize + sni
}

/// Serialized size of the ClientHello [`write_client_hello`] produces when
/// no SNI is supplied. 117 bytes for the locked Ed25519-only profile.
///
/// Composed from per-field lengths above — adding or dropping an extension
/// flows through `CH_EXTENSIONS_FIXED_TOTAL` automatically.
pub const CLIENT_HELLO_LEN: usize = client_hello_len(None);

// Sanity pin against the Python fixture's seed-0 ed25519-mode ClientHello.
const _: () = assert!(CLIENT_HELLO_LEN == 117);

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

    /// Writes the low 3 bytes of `n` big-endian. Caller is responsible for
    /// ensuring `n < 2^24`; this is debug-asserted but not checked in release.
    fn write_u24(&mut self, n: u32) -> Result<(), Self::Error> {
        debug_assert!(n < (1u32 << 24), "value 0x{:x} does not fit in 24 bits", n);
        let bytes = n.to_be_bytes();
        self.write_all(&bytes[1..])
    }
}

impl<W: Write + ?Sized> WriteExt for W {}

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
    /// The underlying writer returned an error.
    Write(E),
}

impl<E> From<E> for ClientHelloError<E> {
    fn from(e: E) -> Self {
        Self::Write(e)
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
/// `None`, that's [`CLIENT_HELLO_LEN`] (117 bytes).
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
    let body_len = (2 + 32 + 1 + (2 + 2) + (1 + 1) + 2 + extensions_total as usize) as u16;
    let hs_len = 4 + body_len;

    // ---- TLS record header (5 bytes) ----
    out.write_u8(CT_HANDSHAKE)?; // 0x16
    out.write_u16(LEGACY_VERSION)?; // 0x0303
    out.write_u16(hs_len)?; // length of handshake message that follows

    // ---- Handshake message header (4 bytes) ----
    out.write_u8(HS_CLIENT_HELLO)?; // 0x01
    out.write_u24(body_len as u32)?; // length of ClientHello body

    // ---- ClientHello body ----
    out.write_u16(LEGACY_VERSION)?; // legacy_version = 0x0303
    out.write_all(random)?; // random (32)
    out.write_u8(0)?; // legacy_session_id length = 0
    out.write_u16(2)?; // cipher_suites length = 2
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
    out.write_u16(4)?; // ext_data_len = list_len(2) + scheme(2)
    out.write_u16(2)?; // sig schemes list length
    out.write_u16(SIG_SCHEME_ED25519)?;

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

// =====================================================================
// ServerHello — parse the inverse of write_client_hello.
// =====================================================================

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
    /// Selected cipher suite. Validated to be `TLS_AES_128_GCM_SHA256`.
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
        core::fmt::Debug::fmt(self, f)
    }
}

/// Parse a complete TLS record carrying a `server_hello` handshake message.
///
/// Validates the locked profile (TLS 1.3 / AES-128-GCM-SHA256 / x25519) and
/// returns a [`ServerHelloView`] borrowing into `input`.
pub fn parse_server_hello(input: &[u8]) -> Result<ServerHelloView<'_>, ParseError> {
    let mut r = Reader::new(input);

    // ---- TLS record header ----
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

    // ---- Handshake message header ----
    let mut hr = Reader::new(record_body);
    let hs_type = hr.u8()?;
    if hs_type != HS_SERVER_HELLO {
        return Err(ParseError::UnexpectedHandshakeType(hs_type));
    }
    let hs_body = hr.vec_u24()?;
    if !hr.at_end() {
        return Err(ParseError::LengthMismatch);
    }

    // ---- ServerHello body ----
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
    if cipher_suite != CIPHER_AES_128_GCM_SHA256 {
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

    // ---- Extensions: walk the list, pick out the two we care about ----
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

// ---------------------------------------------------------------------
// Internal byte reader. Mirrors the Writer/WriteExt pair; returns ParseError
// on truncation / length-prefix overruns.
// ---------------------------------------------------------------------

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

// ---------------------------------------------------------------------
// Tests — cross-check against the Python fixture's seed-0 ClientHello.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn matches_python_fixture() {
        let mut buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut buf;
        let n =
            write_client_hello(&mut cursor, &FIXTURE_RANDOM, &FIXTURE_X25519_PUB, None).unwrap();
        assert_eq!(n, CLIENT_HELLO_LEN);
        assert_eq!(&buf[..CLIENT_HELLO_LEN], &FIXTURE_CLIENT_HELLO);
    }

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

    // ---- ServerHello tests ----

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

    #[test]
    fn wrong_cipher_suite_rejected() {
        let mut bad = FIXTURE_SERVER_HELLO;
        // cipher_suite is at offset 5 (hs hdr) + 4 (legacy_ver+random+session_id_len) ... let me just
        // patch the known offset: TLS_AES_256_GCM_SHA384 = 0x1302
        // offset = 5 (record) + 4 (hs hdr) + 2 (legacy_ver) + 32 (random) + 1 (sid len) = 44
        bad[44] = 0x13;
        bad[45] = 0x02;
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

    // ---- HKDF tests ----
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
    /// Source: `packets/002_s2c_ServerHello.txt` notes.
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

    // ---- Full chain: X25519 -> handshake_secret -> s_hs_traffic_secret ----

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

    // ---- traffic_keys + decrypt_record (the actual unlock of packet 003) ----

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

    // Note: the Ed25519Verify trait-propagation tests and the cert
    // OID-flip / version-flip tests need a decrypted server cert. They
    // came back out with the testdata vendoring; will return in the
    // fixture-restoration follow-up PR alongside the other integration
    // tests.

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

    // ---- RSA: end-to-end replay against captured packets_rsa/ fixtures ----

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

        /// Server handshake traffic secret from the fixture's packets_rsa/004 notes.
        /// Bare `[u8; 32]` because `Zeroizing::new` isn't const-stable; wrap into
        /// `Secret` at the use site.
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
