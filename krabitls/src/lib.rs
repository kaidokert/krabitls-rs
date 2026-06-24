//! `krabitls` — a sans-io, `no_std` TLS 1.3 client for a fixed embedded
//! profile.
//!
//! Public surface lives in [`client`] (connection facade) and
//! [`backends`] (config markers + RustCrypto trait impls). Everything
//! else is internal.
//!
//! # Quick start
//!
//! Drive a handshake with the bundled [`client::DefaultStream`] +
//! [`client::DefaultScratch`]:
//!
//! ```ignore
//! use krabitls::client::{
//!     ClientParams, DefaultScratch, DefaultStream, PinnedPubkey,
//! };
//!
//! let mut scratch = DefaultScratch::new();
//! let params = ClientParams::pinned(
//!     "example.com",
//!     PinnedPubkey::Ed25519(server_pubkey),
//! )?;
//!
//! let mut tls = DefaultStream::connect(
//!     &params, &mut scratch, transport, &mut rng,
//! )?;
//! tls.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")?;
//!
//! let mut buf = [0u8; 1024];
//! let n = tls.read(&mut buf)?;
//! tls.close()?;
//! ```
//!
//! `transport` is any [`client::Transport`] (typically a blocking
//! `TcpStream` wrapper); `rng` is any [`rand_core::TryCryptoRng`].

#![cfg_attr(not(test), no_std)]

pub(crate) mod aead;
pub mod backends;
pub mod client;
pub(crate) mod client_flight;
pub(crate) mod connection;
pub(crate) mod errors;
pub(crate) mod hkdf;
pub(crate) mod identity;
pub(crate) mod newtype;
pub(crate) mod reassembler;
pub(crate) mod server_flight;
pub(crate) mod traits;

use errors::{ClientHelloError, ParseError, Write24Error};

#[cfg(all(test, feature = "cipher-aes"))]
pub(crate) use aead::RecordKeys;
#[cfg(test)]
pub(crate) use aead::{aead_nonce, split_inner_plaintext};
#[cfg(all(test, feature = "cipher-aes"))]
pub(crate) use hkdf::{application_traffic_secrets, master_secret};
#[cfg(test)]
pub(crate) use hkdf::{
    derive_secret, handshake_secret, handshake_traffic_secrets, hkdf_expand_label,
};
#[cfg(all(test, feature = "cipher-aes"))]
pub(crate) use server_flight::{verify_self_signed_cert, verify_server_flight};

use embedded_io::Write;

/// Compile-time hex decoder for `testdata/*.hex` fixtures.
#[cfg(any(test, feature = "dev-utils"))]
pub const fn hex_decode<const N: usize>(s: &str) -> [u8; N] {
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    let mut o = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
            i += 1;
            continue;
        }
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

pub(crate) mod consts {
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
    // Only readers are at lib.rs and server_flight.rs, both gated on
    // `feature = "rsa"` — so the constant tracks the same gate.
    #[cfg(feature = "rsa")]
    pub const SIG_SCHEME_RSA_PSS_RSAE_SHA256: u16 = 0x0804;

    pub const EXT_SERVER_NAME: u16 = 0;
    pub const EXT_SUPPORTED_GROUPS: u16 = 10;
    pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
    pub const EXT_RECORD_SIZE_LIMIT: u16 = 28;
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

const EXT_SUPPORTED_VERSIONS_TOTAL: u16 = 4 + 3;
const EXT_SUPPORTED_GROUPS_TOTAL: u16 = 4 + 4;
#[cfg(not(feature = "rsa"))]
const EXT_SIGNATURE_ALGORITHMS_TOTAL: u16 = 4 + 4;
#[cfg(feature = "rsa")]
const EXT_SIGNATURE_ALGORITHMS_TOTAL: u16 = 4 + 6;
const EXT_KEY_SHARE_TOTAL: u16 = 4 + 38;

// At least one cipher feature must be on. We can't form a valid
// ClientHello otherwise — there's no cipher_suite to advertise.
#[cfg(not(any(feature = "cipher-aes", feature = "chacha20")))]
compile_error!(
    "krabitls requires at least one of `cipher-aes` (default) or `chacha20` to provide a cipher suite"
);

#[cfg(all(feature = "cipher-aes", not(feature = "chacha20")))]
const CH_CIPHER_SUITES_COUNT: usize = 1;
#[cfg(all(feature = "cipher-aes", feature = "chacha20"))]
const CH_CIPHER_SUITES_COUNT: usize = 2;
#[cfg(all(not(feature = "cipher-aes"), feature = "chacha20"))]
const CH_CIPHER_SUITES_COUNT: usize = 1;

/// Wire size of the RFC 8449 `record_size_limit` extension: 4-byte header
/// (ext_type + ext_data_len) + 2-byte value.
const EXT_RECORD_SIZE_LIMIT_TOTAL: u16 = 4 + 2;

/// Runtime narrowing of the compile-time suite advertisement.
///
/// Compile-time capability is fixed by the `chacha20` Cargo feature:
/// `Default` matches whatever was compiled in. `AesOnly` forces AES-only
/// advertisement even when `chacha20` is enabled — the facade uses this
/// to honour a caller's `ClientParams::aes_only()` request without
/// recompiling the crate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SuiteList {
    #[default]
    Default,
    #[cfg(feature = "cipher-aes")]
    AesOnly,
    #[cfg(feature = "chacha20")]
    ChaChaOnly,
}

/// Options for the opts-aware ClientHello writer and its typestate
/// wrapper, [`crate::TlsConnection::<Init>::write_client_hello_to_slice_with`].
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ClientHelloOptions<'a> {
    /// SNI hostname bytes. `None` omits the extension.
    pub hostname: Option<&'a [u8]>,
    /// RFC 8449 `record_size_limit` value to advertise. `None` omits the
    /// extension. Must be in `[64, 2^14 + 1]`; the writer enforces this
    /// and returns [`ClientHelloError::RecordSizeLimitOutOfRange`] otherwise.
    pub record_size_limit: Option<u16>,
    /// Suite list to advertise. See [`SuiteList`].
    pub suites: SuiteList,
}

impl<'a> ClientHelloOptions<'a> {
    /// Legacy default: no `record_size_limit`, no SNI, default suite list.
    #[cfg(test)]
    pub const fn legacy() -> Self {
        Self {
            hostname: None,
            record_size_limit: None,
            suites: SuiteList::Default,
        }
    }
}

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

/// Number of cipher_suites advertised on the wire for the given suite list.
const fn ch_n_suites(suites: SuiteList) -> usize {
    match suites {
        SuiteList::Default => CH_CIPHER_SUITES_COUNT,
        #[cfg(feature = "cipher-aes")]
        SuiteList::AesOnly => 1,
        #[cfg(feature = "chacha20")]
        SuiteList::ChaChaOnly => 1,
    }
}

/// Wire size of `cipher_suites`: 2-byte length prefix + 2 bytes per suite.
const fn ch_cipher_suites_field_len(suites: SuiteList) -> usize {
    2 + 2 * ch_n_suites(suites)
}

/// Total wire size of the variable extensions: fixed extensions + optional
/// SNI + optional `record_size_limit`.
const fn ch_extensions_total(sni_host_len: Option<usize>, has_record_size_limit: bool) -> usize {
    let sni = match sni_host_len {
        None => 0,
        Some(n) => sni_ext_total(n),
    };
    let rsl = if has_record_size_limit {
        EXT_RECORD_SIZE_LIMIT_TOTAL as usize
    } else {
        0
    };
    CH_EXTENSIONS_FIXED_TOTAL as usize + sni + rsl
}

/// ClientHello body length (the bytes after the 4-byte handshake header).
const fn ch_body_len(
    suites: SuiteList,
    sni_host_len: Option<usize>,
    has_record_size_limit: bool,
) -> usize {
    2 + 32
        + 1
        + ch_cipher_suites_field_len(suites)
        + (1 + 1)
        + 2
        + ch_extensions_total(sni_host_len, has_record_size_limit)
}

/// Total wire size of a ClientHello with the given dimensions (record
/// header + handshake header + body). Source of truth for both
/// [`client_hello_len`] and [`client_hello_len_with`].
const fn ch_total_len(
    suites: SuiteList,
    sni_host_len: Option<usize>,
    has_record_size_limit: bool,
) -> usize {
    5 + 4 + ch_body_len(suites, sni_host_len, has_record_size_limit)
}

/// Compute the exact serialized size of a ClientHello with the given
/// hostname option, using the compile-time default suite list and no
/// `record_size_limit` extension. Use [`client_hello_len_with`] when
/// emitting opts-driven extensions or narrowing the suite advertisement.
pub(crate) const fn client_hello_len(hostname_len: Option<usize>) -> usize {
    ch_total_len(SuiteList::Default, hostname_len, false)
}

/// Opts-aware sibling of [`client_hello_len`]. Returns the exact byte size
/// the corresponding opts-aware ClientHello writer call will emit for the
/// supplied options. Single source of truth shared with the writer — the
/// two cannot drift on the new (`record_size_limit` / `SuiteList::AesOnly`)
/// paths.
pub(crate) const fn client_hello_len_with(opts: &ClientHelloOptions<'_>) -> usize {
    let sni_host_len = match opts.hostname {
        None => None,
        Some(h) => Some(h.len()),
    };
    ch_total_len(opts.suites, sni_host_len, opts.record_size_limit.is_some())
}

/// Serialized size of the ClientHello the default-opts writer produces
/// when no SNI is supplied. 117 bytes by default, 119 with
/// `feature = "rsa"` (the signature_algorithms extension carries one
/// extra scheme entry).
pub(crate) const CLIENT_HELLO_LEN: usize = client_hello_len(None);

#[cfg(all(
    feature = "cipher-aes",
    not(feature = "rsa"),
    not(feature = "chacha20")
))]
const _: () = assert!(CLIENT_HELLO_LEN == 117);
#[cfg(all(feature = "cipher-aes", feature = "rsa", not(feature = "chacha20")))]
const _: () = assert!(CLIENT_HELLO_LEN == 119);
#[cfg(all(feature = "cipher-aes", not(feature = "rsa"), feature = "chacha20"))]
const _: () = assert!(CLIENT_HELLO_LEN == 119);
#[cfg(all(feature = "cipher-aes", feature = "rsa", feature = "chacha20"))]
const _: () = assert!(CLIENT_HELLO_LEN == 121);
#[cfg(all(
    not(feature = "cipher-aes"),
    feature = "chacha20",
    not(feature = "rsa")
))]
const _: () = assert!(CLIENT_HELLO_LEN == 117);
#[cfg(all(not(feature = "cipher-aes"), feature = "chacha20", feature = "rsa"))]
const _: () = assert!(CLIENT_HELLO_LEN == 119);

/// Big-endian byte-emission helpers layered on top of [`embedded_io::Write`].
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

/// TLS 1.3 plaintext fragment maximum (RFC 8446 §5.1). The record body of
/// a ClientHello must not exceed this; `write_client_hello` enforces it.
const TLS_PLAINTEXT_MAX: usize = 1 << 14;

/// Serialize a TLS 1.3 ClientHello into `out` using caller-supplied
/// [`ClientHelloOptions`]. `opts.hostname` (if `Some`) produces an SNI
/// extension (RFC 6066 §3); `opts.record_size_limit` (if `Some`) adds
/// the RFC 8449 extension; `opts.suites` narrows the suite advertisement.
/// Returns bytes written, equal to [`client_hello_len_with`]`(opts)`.
pub(crate) fn write_client_hello_with<W: Write>(
    out: &mut W,
    random: &[u8; 32],
    x25519_pub: &[u8; 32],
    opts: &ClientHelloOptions<'_>,
) -> Result<usize, ClientHelloError<W::Error>> {
    let hostname = opts.hostname;
    let host_len = hostname.map(|h| h.len()).unwrap_or(0);
    if host_len > u16::MAX as usize {
        return Err(ClientHelloError::HostnameTooLong);
    }
    // RFC 8449 §4: record_size_limit must be in [64, 2^14 + 1].
    if let Some(rsl) = opts.record_size_limit
        && !(64..=16385).contains(&rsl)
    {
        return Err(ClientHelloError::RecordSizeLimitOutOfRange);
    }

    // Compute the exact total in `usize` BEFORE any narrowing cast: an
    // oversized hostname can otherwise wrap intermediate `as u16` casts
    // and slip past the cap check, then panic on `host_len as u16` or
    // emit wrapped length fields on the wire. Route through the same
    // const helpers the public `client_hello_len_with` uses so the writer
    // and the sizer cannot drift on the new (RFC 8449 / `AesOnly`) paths.
    let total_len = client_hello_len_with(opts);
    if total_len > 5 + TLS_PLAINTEXT_MAX {
        return Err(ClientHelloError::MessageTooLong);
    }
    // Past this point every sub-length is provably ≤ total_len
    // ≤ 5 + 2^14 < u16::MAX, so the casts below are non-truncating.

    let sni_host_len = hostname.map(|h| h.len());
    let has_rsl = opts.record_size_limit.is_some();
    let n_suites = ch_n_suites(opts.suites);
    let extensions_total = ch_extensions_total(sni_host_len, has_rsl);
    let body_len = ch_body_len(opts.suites, sni_host_len, has_rsl);
    let hs_len = 4 + body_len;

    // ChaCha appears in the wire output iff the feature was compiled in
    // AND the runtime opts allow the default suite list. Only bound under
    // the feature — no-chacha20 builds have no use for the binding.
    #[cfg(feature = "chacha20")]
    let advertise_chacha = matches!(opts.suites, SuiteList::Default | SuiteList::ChaChaOnly);

    out.write_u8(CT_HANDSHAKE)?;
    out.write_u16(LEGACY_VERSION)?;
    out.write_u16(hs_len as u16)?;

    out.write_u8(HS_CLIENT_HELLO)?;
    out.write_u24(body_len as u32)?;

    out.write_u16(LEGACY_VERSION)?;
    out.write_all(random)?;
    out.write_u8(0)?;
    out.write_u16((2 * n_suites) as u16)?;
    // ChaCha first when offered (server preference convention). Then AES
    // when both `cipher-aes` is on and the suite list isn't ChaCha-only.
    #[cfg(feature = "chacha20")]
    if advertise_chacha {
        out.write_u16(CIPHER_CHACHA20_POLY1305_SHA256)?;
    }
    #[cfg(all(feature = "cipher-aes", feature = "chacha20"))]
    let advertise_aes = !matches!(opts.suites, SuiteList::ChaChaOnly);
    #[cfg(all(feature = "cipher-aes", not(feature = "chacha20")))]
    let advertise_aes = true;
    #[cfg(feature = "cipher-aes")]
    if advertise_aes {
        out.write_u16(CIPHER_AES_128_GCM_SHA256)?;
    }
    out.write_u8(1)?;
    out.write_u8(0)?;
    out.write_u16(extensions_total as u16)?;

    out.write_u16(EXT_SUPPORTED_VERSIONS)?;
    out.write_u16(3)?;
    out.write_u8(2)?;
    out.write_u16(TLS_1_3)?;

    out.write_u16(EXT_SUPPORTED_GROUPS)?;
    out.write_u16(4)?;
    out.write_u16(2)?;
    out.write_u16(NAMED_GROUP_X25519)?;

    out.write_u16(EXT_SIGNATURE_ALGORITHMS)?;
    #[cfg(not(feature = "rsa"))]
    {
        out.write_u16(4)?;
        out.write_u16(2)?;
        out.write_u16(SIG_SCHEME_ED25519)?;
    }
    #[cfg(feature = "rsa")]
    {
        out.write_u16(6)?;
        out.write_u16(4)?;
        out.write_u16(SIG_SCHEME_ED25519)?;
        out.write_u16(SIG_SCHEME_RSA_PSS_RSAE_SHA256)?;
    }

    if let Some(h) = hostname {
        let host_len = h.len() as u16;
        let list_len: u16 = 1 + 2 + host_len;
        let ext_data_len: u16 = 2 + list_len;
        out.write_u16(EXT_SERVER_NAME)?;
        out.write_u16(ext_data_len)?;
        out.write_u16(list_len)?;
        out.write_u8(SNI_NAME_TYPE_HOST_NAME)?;
        out.write_u16(host_len)?;
        out.write_all(h)?;
    }

    if let Some(value) = opts.record_size_limit {
        out.write_u16(EXT_RECORD_SIZE_LIMIT)?;
        out.write_u16(2)?;
        out.write_u16(value)?;
    }

    // x25519_pub at the end of the record.
    out.write_u16(EXT_KEY_SHARE)?;
    out.write_u16(38)?;
    out.write_u16(36)?;
    out.write_u16(NAMED_GROUP_X25519)?;
    out.write_u16(32)?;
    out.write_all(x25519_pub)?;

    Ok(total_len)
}

/// Parsed view of a ServerHello, with borrows into the caller's input.
///
/// Returned by [`parse_server_hello`]. Lifetime is tied to the input slice
/// so the random and X25519 share don't need to be copied out unless the
/// caller chooses to.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct ServerHelloView<'a> {
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

/// Parse a complete TLS record carrying a `server_hello` handshake message.
///
/// Validates the locked profile (TLS 1.3, x25519, AES-128-GCM-SHA256 or
/// `TLS_CHACHA20_POLY1305_SHA256` under `feature = "chacha20"`) and returns
/// a [`ServerHelloView`] borrowing into `input`.
pub(crate) fn parse_server_hello(input: &[u8]) -> Result<ServerHelloView<'_>, ParseError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "cipher-aes")]
    use crate::aead::Aes128GcmSha256;
    #[cfg(feature = "chacha20")]
    use crate::aead::ChaCha20Poly1305Sha256;
    use crate::aead::{DecryptError, NoCipher, decrypt_record, encrypt_record};
    #[cfg(feature = "cipher-aes")]
    use crate::backends::DerCert;
    #[cfg(feature = "jedisct")]
    use crate::backends::JedisctCrypto;
    #[cfg(all(feature = "rsa", not(feature = "rsa_pss_only"), feature = "cipher-aes"))]
    use crate::backends::RsaVerifierKey;
    use crate::backends::RustCrypto;
    #[cfg(feature = "cipher-aes")]
    use crate::client_flight::CLIENT_FINISHED_LEN;
    use crate::hkdf::{HkdfLabelError, TranscriptError, TranscriptHash, traffic_keys};
    #[cfg(feature = "chacha20")]
    use crate::newtype::AeadKey32;
    use crate::newtype::{AeadIv, AeadKey, Secret, TranscriptDigest, ZeroBuf};
    #[cfg(feature = "cipher-aes")]
    use crate::server_flight::parse_server_flight;
    use crate::server_flight::{FlightError, extract_cert_der, extract_chain};
    #[cfg(feature = "cipher-aes")]
    use crate::traits::verify_strategy::PreparedVerifier;
    #[cfg(feature = "cipher-aes")]
    use crate::traits::{CertParseError, CertParser, Ed25519VerifierProvider};
    use crate::traits::{CertView, HkdfSha256};
    use embedded_io::SliceWriteError;

    /// Ed25519 pubkey in the seed-0 self-signed leaf cert. Same constant
    /// as in connection.rs::tests; hoisted here so the verify-helper
    /// can stay test-module-level.
    #[cfg(feature = "cipher-aes")]
    const FIXTURE_LEAF_ED25519_PUB: [u8; 32] = [
        0x9d, 0xfe, 0x2a, 0xb0, 0x3e, 0x35, 0x70, 0x4b, 0x9c, 0xfb, 0x93, 0xb6, 0x03, 0xa6, 0x61,
        0x18, 0x82, 0x17, 0xa6, 0xb5, 0xfd, 0x6a, 0x1f, 0x75, 0xe6, 0x16, 0x1a, 0x39, 0xe0, 0x53,
        0x4c, 0x3f,
    ];

    #[cfg(feature = "cipher-aes")]
    fn fixture_prepared_ed25519<E: Ed25519VerifierProvider>() -> PreparedVerifier<E, RustCrypto> {
        PreparedVerifier::ed25519(E::prepare_ed25519(&FIXTURE_LEAF_ED25519_PUB))
    }

    #[cfg(feature = "cipher-aes")]
    fn fixture_leaf_ed25519() -> CertView<'static> {
        CertView::Ed25519 {
            tbs: &[],
            signature: &[0u8; 64],
            pubkey: &FIXTURE_LEAF_ED25519_PUB,
            san: None,
            validity_der: &[],
        }
    }

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
    /// (`packets/001_c2s_ClientHello.bin`), **149 bytes**.
    ///
    /// Advertises **both** the RFC 6066 SNI extension
    /// (server_name "tls-fixture.local") and the RFC 8449
    /// `record_size_limit` extension (value 16385). Extension order
    /// matches the Rust facade's wire emission: supported_versions →
    /// supported_groups → signature_algorithms → server_name →
    /// record_size_limit → key_share. The Python `tls_fixture` emits
    /// this shape by default; the typestate API's
    /// `ClientHelloOptions::legacy()` does **not**, so byte-identity
    /// testing requires explicit `hostname: Some(...)` +
    /// `record_size_limit: Some(16385)` opts.
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

    /// Helper: write into a fresh buffer through `&mut &mut [u8]`. Returns the
    /// borrowed slice as it stands after writing so we can confirm how many
    /// bytes were consumed.
    fn write_into(buf: &mut [u8]) -> Result<&mut [u8], ClientHelloError<SliceWriteError>> {
        let mut cursor: &mut [u8] = buf;
        write_client_hello_with(
            &mut cursor,
            &FIXTURE_RANDOM,
            &FIXTURE_X25519_PUB,
            &ClientHelloOptions::legacy(),
        )?;
        Ok(cursor)
    }

    // Byte-identity against the seed-0 Python fixture only holds when our CH
    // advertises ed25519 alone with AES-128-GCM only. With `feature = "rsa"`
    // we also advertise rsa_pss_rsae_sha256; with `feature = "chacha20"` we
    // also advertise CHACHA20_POLY1305_SHA256 — either changes the CH bytes.
    #[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
    #[test]
    fn matches_python_fixture() {
        // Python tls_fixture defaults to record_size_limit=16385
        // so the byte-identity test must pass the matching opts. The
        // `legacy()` path (no RSL) is covered by
        // `exact_sized_buffer_works_legacy` for length + writer plumbing
        // without byte-identity.
        let mut buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut buf;
        let opts = ClientHelloOptions {
            hostname: Some(b"tls-fixture.local"),
            record_size_limit: Some(16385),
            ..ClientHelloOptions::legacy()
        };
        let n = write_client_hello_with(&mut cursor, &FIXTURE_RANDOM, &FIXTURE_X25519_PUB, &opts)
            .unwrap();
        assert_eq!(n, FIXTURE_CLIENT_HELLO.len());
        assert_eq!(&buf[..n], &FIXTURE_CLIENT_HELLO);
    }

    #[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
    #[test]
    fn exact_sized_buffer_works_legacy() {
        let mut buf = [0u8; CLIENT_HELLO_LEN];
        let leftover = write_into(&mut buf).unwrap();
        assert!(
            leftover.is_empty(),
            "should fully consume a tightly-sized buffer"
        );
        // Length-only check on the legacy (no-RSL) writer path. Byte-identity
        // against the Python fixture lives in `matches_python_fixture`.
        assert_eq!(buf.len(), CLIENT_HELLO_LEN);
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
        let err = write_client_hello_with(
            &mut cursor,
            &FIXTURE_RANDOM,
            &FIXTURE_X25519_PUB,
            &ClientHelloOptions {
                hostname: Some(&huge),
                ..ClientHelloOptions::legacy()
            },
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
        let err = write_client_hello_with(
            &mut cursor,
            &FIXTURE_RANDOM,
            &FIXTURE_X25519_PUB,
            &ClientHelloOptions {
                hostname: Some(&big),
                ..ClientHelloOptions::legacy()
            },
        )
        .unwrap_err();
        assert_eq!(err, ClientHelloError::MessageTooLong);
    }

    // body_len is computed in usize before the cap check so a near-u16::MAX
    // hostname surfaces as MessageTooLong instead of wrapping a u16 and
    // either panicking in debug or emitting wrapped length fields in release.
    #[test]
    fn rejects_hostname_near_u16_max_without_wrap() {
        let host = vec![b'a'; 65500];
        let mut buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut buf;
        let err = write_client_hello_with(
            &mut cursor,
            &FIXTURE_RANDOM,
            &FIXTURE_X25519_PUB,
            &ClientHelloOptions {
                hostname: Some(&host),
                ..ClientHelloOptions::legacy()
            },
        )
        .unwrap_err();
        assert_eq!(err, ClientHelloError::MessageTooLong);
    }

    #[test]
    fn rejects_record_size_limit_out_of_rfc8449_range() {
        // RFC 8449 §4: valid range is [64, 2^14 + 1] = [64, 16385].
        let mut buf = [0u8; 512];
        for rsl in [0u16, 1, 63, 16386, u16::MAX] {
            let mut cursor: &mut [u8] = &mut buf;
            let err = write_client_hello_with(
                &mut cursor,
                &FIXTURE_RANDOM,
                &FIXTURE_X25519_PUB,
                &ClientHelloOptions {
                    record_size_limit: Some(rsl),
                    ..ClientHelloOptions::legacy()
                },
            )
            .unwrap_err();
            assert_eq!(
                err,
                ClientHelloError::RecordSizeLimitOutOfRange,
                "rsl={rsl} must reject"
            );
        }
        for rsl in [64u16, 16385] {
            let mut cursor: &mut [u8] = &mut buf;
            write_client_hello_with(
                &mut cursor,
                &FIXTURE_RANDOM,
                &FIXTURE_X25519_PUB,
                &ClientHelloOptions {
                    record_size_limit: Some(rsl),
                    ..ClientHelloOptions::legacy()
                },
            )
            .unwrap_or_else(|_| panic!("rsl={rsl} must accept"));
        }
    }

    #[test]
    fn client_hello_len_with_agrees_with_legacy_for_default_opts() {
        for host_len in [None, Some(0), Some(1), Some(64), Some(255), Some(8192)] {
            let legacy = client_hello_len(host_len);
            let host_bytes;
            let hostname: Option<&[u8]> = match host_len {
                None => None,
                Some(n) => {
                    host_bytes = vec![b'x'; n];
                    Some(host_bytes.leak())
                }
            };
            let opts = ClientHelloOptions {
                hostname,
                record_size_limit: None,
                suites: SuiteList::Default,
            };
            assert_eq!(
                client_hello_len_with(&opts),
                legacy,
                "host_len={host_len:?}"
            );
        }
    }

    #[test]
    fn client_hello_len_with_accounts_for_record_size_limit() {
        let base = client_hello_len_with(&ClientHelloOptions::legacy());
        let with_rsl = client_hello_len_with(&ClientHelloOptions {
            record_size_limit: Some(16385),
            ..ClientHelloOptions::legacy()
        });
        assert_eq!(with_rsl, base + 6);
    }

    #[cfg(all(feature = "cipher-aes", feature = "chacha20"))]
    #[test]
    fn client_hello_len_with_aes_only_shrinks_by_two_bytes_under_chacha20() {
        let default = client_hello_len_with(&ClientHelloOptions::legacy());
        let aes_only = client_hello_len_with(&ClientHelloOptions {
            suites: SuiteList::AesOnly,
            ..ClientHelloOptions::legacy()
        });
        assert_eq!(aes_only + 2, default);
    }

    #[test]
    fn writer_emits_exactly_client_hello_len_with_bytes() {
        for opts in [
            ClientHelloOptions::legacy(),
            ClientHelloOptions {
                record_size_limit: Some(16385),
                ..ClientHelloOptions::legacy()
            },
            ClientHelloOptions {
                hostname: Some(b"example.com"),
                ..ClientHelloOptions::legacy()
            },
            ClientHelloOptions {
                hostname: Some(b"example.com"),
                record_size_limit: Some(4096),
                ..ClientHelloOptions::legacy()
            },
        ] {
            let expected = client_hello_len_with(&opts);
            let mut buf = [0u8; 512];
            let mut cursor: &mut [u8] = &mut buf;
            let n =
                write_client_hello_with(&mut cursor, &FIXTURE_RANDOM, &FIXTURE_X25519_PUB, &opts)
                    .unwrap();
            assert_eq!(n, expected, "opts={opts:?}");
        }
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
        // Not reachable from `write_client_hello` (body_len is u16-typed); the
        // trait method must reject any u32 that doesn't fit in 3 bytes.
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
        let mut random = [0u8; 32];
        for (i, b) in random.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut buf = [0u8; CLIENT_HELLO_LEN];
        let mut cursor: &mut [u8] = &mut buf;
        write_client_hello_with(
            &mut cursor,
            &random,
            &FIXTURE_X25519_PUB,
            &ClientHelloOptions::legacy(),
        )
        .unwrap();
        assert_eq!(&buf[11..11 + 32], &random);
    }

    #[test]
    fn x25519_pub_appears_at_correct_offset() {
        let mut pub_key = [0u8; 32];
        for (i, b) in pub_key.iter_mut().enumerate() {
            *b = (0x80 + i) as u8;
        }
        let mut buf = [0u8; CLIENT_HELLO_LEN];
        let mut cursor: &mut [u8] = &mut buf;
        write_client_hello_with(
            &mut cursor,
            &FIXTURE_RANDOM,
            &pub_key,
            &ClientHelloOptions::legacy(),
        )
        .unwrap();
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
        assert!(matches!(err, ParseError::Truncated));
    }

    #[test]
    fn wrong_content_type_rejected() {
        let mut bad = FIXTURE_SERVER_HELLO;
        bad[0] = 23;
        assert_eq!(
            parse_server_hello(&bad),
            Err(ParseError::UnexpectedContentType(23)),
        );
    }

    #[test]
    fn wrong_handshake_type_rejected() {
        let mut bad = FIXTURE_SERVER_HELLO;
        bad[5] = 1;
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
        // TLS_AES_256_GCM_SHA384 is not in our profile.
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
        let mut bad = FIXTURE_SERVER_HELLO;
        bad[11..43].copy_from_slice(&HRR_RANDOM);
        assert_eq!(
            parse_server_hello(&bad),
            Err(ParseError::HelloRetryRequested)
        );
    }

    #[test]
    fn downgrade_marker_rejected() {
        let mut bad = FIXTURE_SERVER_HELLO;
        bad[35..43].copy_from_slice(&DOWNGRADE_TLS12);
        assert_eq!(parse_server_hello(&bad), Err(ParseError::DowngradeDetected));

        bad[35..43].copy_from_slice(&DOWNGRADE_TLS11_OR_BELOW);
        assert_eq!(parse_server_hello(&bad), Err(ParseError::DowngradeDetected));
    }

    #[test]
    fn non_empty_session_id_echo_rejected() {
        let mut buf = [0u8; FIXTURE_SERVER_HELLO.len() + 1];
        buf[..43].copy_from_slice(&FIXTURE_SERVER_HELLO[..43]);
        buf[43] = 0x01;
        buf[44] = 0xab;
        buf[45..].copy_from_slice(&FIXTURE_SERVER_HELLO[44..]);
        buf[3..5].copy_from_slice(&[0x00, 0x5b]);
        buf[6..9].copy_from_slice(&[0x00, 0x00, 0x57]);

        assert_eq!(
            parse_server_hello(&buf),
            Err(ParseError::UnexpectedSessionIdEcho),
        );
    }

    #[test]
    fn unknown_extension_rejected() {
        let mut buf = [0u8; FIXTURE_SERVER_HELLO.len() + 7];
        buf[..FIXTURE_SERVER_HELLO.len()].copy_from_slice(&FIXTURE_SERVER_HELLO);
        buf[FIXTURE_SERVER_HELLO.len()..]
            .copy_from_slice(&[0x00, 0xff, 0x00, 0x03, 0xaa, 0xbb, 0xcc]);
        buf[3..5].copy_from_slice(&[0x00, 0x61]);
        buf[6..9].copy_from_slice(&[0x00, 0x00, 0x5d]);
        buf[47..49].copy_from_slice(&[0x00, 0x35]);

        assert_eq!(
            parse_server_hello(&buf),
            Err(ParseError::UnknownExtension(0x00ff)),
        );
    }

    #[test]
    fn duplicate_extension_rejected() {
        let mut buf = [0u8; FIXTURE_SERVER_HELLO.len() + 6];
        buf[..FIXTURE_SERVER_HELLO.len()].copy_from_slice(&FIXTURE_SERVER_HELLO);
        buf[FIXTURE_SERVER_HELLO.len()..].copy_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        buf[3..5].copy_from_slice(&[0x00, 0x60]);
        buf[6..9].copy_from_slice(&[0x00, 0x00, 0x5c]);
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
    /// SHA-256(ClientHello_handshake_msg || ServerHello_handshake_msg) at
    /// seed 0. CH carries SNI + RSL; cert carries SAN.
    const FIXTURE_TRANSCRIPT_HASH_CH_SH: TranscriptDigest = TranscriptDigest::new([
        0xa8, 0xc5, 0x43, 0x11, 0x16, 0x98, 0x90, 0x0f, 0x4a, 0x5f, 0x43, 0xeb, 0x51, 0x0d, 0xe6,
        0x3f, 0xb5, 0x47, 0xd9, 0xbd, 0x5a, 0x50, 0x6b, 0x68, 0xe1, 0x7d, 0x70, 0xb1, 0x7a, 0x8e,
        0xae, 0x74,
    ]);
    /// Server handshake traffic secret. From tls_fixture/state/client.json `s_hs_ts`.
    const FIXTURE_S_HS_TRAFFIC_SECRET_BYTES: [u8; 32] = [
        0x03, 0xab, 0xb1, 0x1c, 0x49, 0xde, 0x80, 0x93, 0xb3, 0x78, 0x60, 0x9b, 0x5b, 0x0a, 0xb4,
        0xab, 0x40, 0x8b, 0x7e, 0xe2, 0x23, 0xb4, 0x59, 0xef, 0x63, 0x14, 0xbb, 0x1b, 0xae, 0xa1,
        0x3d, 0xea,
    ];
    fn make_fixture_s_hs_traffic_secret() -> Secret {
        Secret::new(ZeroBuf::<32>::new(FIXTURE_S_HS_TRAFFIC_SECRET_BYTES))
    }
    /// Client handshake traffic secret. From tls_fixture/state/client.json `c_hs_ts`.
    const FIXTURE_C_HS_TRAFFIC_SECRET_BYTES: [u8; 32] = [
        0xbb, 0xe1, 0xcb, 0x05, 0x42, 0x4c, 0x27, 0xe7, 0x0d, 0x7e, 0xf5, 0x7c, 0x6f, 0x96, 0xd8,
        0x3f, 0x44, 0x8a, 0x7d, 0xa0, 0xd0, 0x15, 0x3b, 0xa6, 0x64, 0xfe, 0xe6, 0x05, 0xb4, 0x00,
        0x30, 0x01,
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
        let dhe = ed25519_heapless::x25519::<T>(
            &FIXTURE_CLIENT_X25519_PRIV,
            &FIXTURE_SERVER_X25519_PUB_2,
        );
        let hs = handshake_secret::<RustCrypto>(&dhe).unwrap();
        assert_eq!(hs.as_bytes(), &FIXTURE_HANDSHAKE_SECRET_BYTES);
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

    /// HKDF-Expand-Label(s_hs_ts, "key"/"iv", ""). All AEAD keys/IVs
    /// below derive from the regenerated
    /// traffic secrets above.
    const FIXTURE_S_HS_KEY_BYTES: [u8; 16] = [
        0xca, 0xf7, 0xdb, 0x48, 0x88, 0xeb, 0x19, 0x16, 0x1b, 0x2f, 0x90, 0x8d, 0x9d, 0xc5, 0x87,
        0x44,
    ];
    const FIXTURE_S_HS_IV_BYTES: [u8; 12] = [
        0x96, 0xaa, 0x3a, 0x44, 0xd8, 0x1f, 0x1b, 0x6b, 0xc2, 0x13, 0x31, 0xd7,
    ];

    #[test]
    fn fixture_traffic_keys_match() {
        let (k, iv) = traffic_keys::<RustCrypto, 16>(&make_fixture_s_hs_traffic_secret()).unwrap();
        let key = AeadKey::new(k);
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

    /// packets/003_s2c_ServerFlight_encrypted.hex (415 bytes, decoded at
    /// compile time). Cert carries SAN matching `tls-fixture.local`.
    const FIXTURE_PACKET_3: [u8; 415] = crate::hex_decode(include_str!(
        "../../testdata/packets/003_s2c_ServerFlight_encrypted.hex"
    ));

    /// First 32 bytes of the decrypted TLSInnerPlaintext of packet 003. Begins:
    ///   0x08 0x00 0x00 0x02 0x00 0x00       EncryptedExtensions (empty)
    ///   0x0b 0x00 0x00 0xf0 ...             Certificate (msg_type=11, len=0x0000f0)
    /// First 32 bytes of the SF plaintext.
    #[cfg(feature = "cipher-aes")]
    const FIXTURE_PACKET_3_PLAINTEXT_HEAD: [u8; 32] = [
        0x08, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x13, 0x00, 0x00, 0x01, 0x0f, 0x00,
        0x01, 0x0a, 0x30, 0x82, 0x01, 0x06, 0x30, 0x81, 0xb9, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
        0x01, 0x01,
    ];

    /// Wrap the seed-0 server handshake AEAD key bytes into an `AeadKey`.
    /// `AeadKey::new` takes a `ZeroBuf<16>` (= `Zeroizing<[u8; 16]>`) which
    /// isn't const-constructible, so we wrap at the call site.
    #[cfg(feature = "cipher-aes")]
    fn make_fixture_s_hs_key() -> AeadKey {
        AeadKey::new(ZeroBuf::<16>::new(FIXTURE_S_HS_KEY_BYTES))
    }
    #[cfg(feature = "cipher-aes")]
    fn make_fixture_s_hs_iv() -> AeadIv {
        AeadIv::new(ZeroBuf::<12>::new(FIXTURE_S_HS_IV_BYTES))
    }

    /// Stub Ed25519VerifierProvider backend that always rejects. Swapping it
    /// in at the `E` generic must flip verify results even with identical
    /// cert / signature bytes.
    #[cfg(feature = "cipher-aes")]
    struct AlwaysReject;
    #[cfg(feature = "cipher-aes")]
    struct AlwaysRejectVerifier;
    #[cfg(feature = "cipher-aes")]
    impl signature::Verifier<[u8; 64]> for AlwaysRejectVerifier {
        fn verify(&self, _: &[u8], _: &[u8; 64]) -> Result<(), signature::Error> {
            Err(signature::Error::new())
        }
    }
    #[cfg(feature = "cipher-aes")]
    impl crate::traits::verify_strategy::VerifierKeyMaterial<[u8; 32]> for AlwaysRejectVerifier {
        fn matches(&self, _: [u8; 32]) -> subtle::Choice {
            subtle::Choice::from(0)
        }
    }
    #[cfg(feature = "cipher-aes")]
    impl crate::traits::Ed25519VerifierProvider for AlwaysReject {
        type Verifier = AlwaysRejectVerifier;
        fn prepare_ed25519(_: &[u8; 32]) -> Self::Verifier {
            AlwaysRejectVerifier
        }
    }

    #[cfg(feature = "cipher-aes")]
    #[test]
    fn ed25519_verify_trait_propagates_to_cert_self_sig() {
        // Same fixture cert that passes with RustCrypto. Plugging in
        // AlwaysReject must flip the result to CertSelfSignatureInvalid.
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let cert_der = &buf[..len];
        let err =
            verify_self_signed_cert::<DerCert, AlwaysReject, RustCrypto>(cert_der).unwrap_err();
        assert_eq!(err, FlightError::CertSelfSignatureInvalid);
    }

    /// Locate every occurrence of the Ed25519 OID DER byte sequence
    /// (`06 03 2B 65 70`) in a cert. In a self-signed Ed25519 cert there are
    /// exactly three, in this byte order:
    /// 1. `TBSCertificate.signature` AlgorithmIdentifier
    /// 2. `SubjectPublicKeyInfo.algorithm` AlgorithmIdentifier
    /// 3. outer `Certificate.signatureAlgorithm` AlgorithmIdentifier
    #[cfg(feature = "cipher-aes")]
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
    #[cfg(feature = "cipher-aes")]
    fn fixture_cert_der_copy(buf: &mut [u8]) -> usize {
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut pt_buf = [0u8; 400];
        let pt = decrypt_record::<Aes128GcmSha256>(
            &FIXTURE_PACKET_3,
            key.as_zeroizing(),
            &iv,
            0,
            &mut pt_buf,
        )
        .unwrap();
        let (content, _) = split_inner_plaintext(pt).unwrap();
        let flight = parse_server_flight(content).unwrap();
        let cert_der = extract_cert_der(flight.cert_body).unwrap();
        buf[..cert_der.len()].copy_from_slice(cert_der);
        cert_der.len()
    }

    #[cfg(feature = "cipher-aes")]
    #[test]
    fn cert_rejects_wrong_outer_signature_algorithm_oid_via_symmetry() {
        // Flip only the outer signatureAlgorithm OID. TBS.signature still
        // claims Ed25519, so the RFC 5280 §4.1.1.2 symmetry check is what
        // catches the mismatch — the parser leaves outer OIDs uninterpreted
        // since issuer-signed leaves routinely carry unknown ones.
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let positions = find_ed25519_oid_positions(&buf[..len]);
        buf[positions[2] + 4] ^= 0x01; // outer signatureAlgorithm OID
        let err = <DerCert as CertParser>::parse(&buf[..len]).unwrap_err();
        assert_eq!(err, CertParseError::SignatureAlgorithmMismatch);
    }

    #[cfg(feature = "cipher-aes")]
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

    #[cfg(feature = "cipher-aes")]
    #[test]
    fn cert_with_unknown_outer_sig_algo_still_parses_if_spki_known() {
        // SPKI stays valid Ed25519. The parser must accept — outer sig algo
        // describes the *issuer*'s signature, which for real leaves routinely
        // isn't anything we recognize. Dispatch is on SPKI.
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let positions = find_ed25519_oid_positions(&buf[..len]);
        // Same byte in TBS and outer keeps the symmetry check passing.
        buf[positions[0] + 4] ^= 0x01;
        buf[positions[2] + 4] ^= 0x01;
        let view = <DerCert as CertParser>::parse(&buf[..len]).expect("parse must succeed");
        assert!(matches!(view, CertView::Ed25519 { .. }));
    }

    #[cfg(feature = "cipher-aes")]
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

    #[cfg(feature = "cipher-aes")]
    #[test]
    fn cert_rejects_unsupported_version() {
        // v1 encoded explicitly is malformed per DER, but the parser must
        // surface a clear rejection rather than silent acceptance.
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

    /// packets/005_c2s_AppData_send_0.hex (52 bytes) — first client app-data record.
    #[cfg(feature = "cipher-aes")]
    const FIXTURE_PACKET_5: [u8; 52] = crate::hex_decode(include_str!(
        "../../testdata/packets/005_c2s_AppData_send_0.hex"
    ));
    /// packets/006_s2c_AppData_reply_0.hex (48 bytes) — first server app-data record.
    #[cfg(feature = "cipher-aes")]
    const FIXTURE_PACKET_6: [u8; 48] = crate::hex_decode(include_str!(
        "../../testdata/packets/006_s2c_AppData_reply_0.hex"
    ));

    /// Plaintext the fixture's `cli.py --send` sent.
    #[cfg(feature = "cipher-aes")]
    const PACKET_5_PLAINTEXT: &[u8] = b"hello from the embedded client";
    /// Plaintext the fixture's `serv.py --reply` sent — includes a UTF-8 em-dash
    /// (`\xe2\x80\x94`) which exercises non-ASCII handling.
    #[cfg(feature = "cipher-aes")]
    const PACKET_6_PLAINTEXT: &[u8] = b"hello back \xe2\x80\x94 server here";

    /// `((key, iv), (key, iv))` for `(c_ap, s_ap)` AEAD streams.
    #[cfg(feature = "cipher-aes")]
    type ApAeadKeys = (AeadKey, AeadIv);

    #[cfg(feature = "cipher-aes")]
    fn make_fixture_handshake_secret() -> Secret {
        Secret::new(ZeroBuf::<32>::new(FIXTURE_HANDSHAKE_SECRET_BYTES))
    }
    #[cfg(feature = "cipher-aes")]
    fn make_fixture_c_hs_traffic_secret() -> Secret {
        Secret::new(ZeroBuf::<32>::new(FIXTURE_C_HS_TRAFFIC_SECRET_BYTES))
    }

    /// Derive the application traffic secrets the same way the demo runs, then
    /// peel off `(c_ap_key, c_ap_iv)` and `(s_ap_key, s_ap_iv)`.
    #[cfg(feature = "cipher-aes")]
    fn application_keys() -> (ApAeadKeys, ApAeadKeys) {
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut pt_buf = [0u8; 400];
        let pt = decrypt_record::<Aes128GcmSha256>(
            &FIXTURE_PACKET_3,
            key.as_zeroizing(),
            &iv,
            0,
            &mut pt_buf,
        )
        .unwrap();
        let (content, _) = split_inner_plaintext(pt).unwrap();
        let mut transcript = TranscriptHash::<RustCrypto>::new();
        transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
        transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
        verify_server_flight::<RustCrypto, RustCrypto, RustCrypto>(
            &mut transcript,
            content,
            &make_fixture_s_hs_traffic_secret(),
            &fixture_prepared_ed25519::<RustCrypto>(),
            &fixture_leaf_ed25519(),
        )
        .unwrap();
        let ms = master_secret::<RustCrypto>(&make_fixture_handshake_secret()).unwrap();
        let (c_ap_ts, s_ap_ts) =
            application_traffic_secrets::<RustCrypto>(&ms, &transcript.snapshot()).unwrap();
        let aes_keys = |secret: &Secret| {
            let (k, iv) = traffic_keys::<RustCrypto, 16>(secret).unwrap();
            (AeadKey::new(k), iv)
        };
        (aes_keys(&c_ap_ts), aes_keys(&s_ap_ts))
    }

    /// packets/004_c2s_ClientFinished_encrypted.hex (58 bytes).
    #[cfg(feature = "cipher-aes")]
    const FIXTURE_PACKET_4: [u8; 58] = crate::hex_decode(include_str!(
        "../../testdata/packets/004_c2s_ClientFinished_encrypted.hex"
    ));

    #[test]
    fn decrypt_record_rejects_trailing_bytes() {
        // Two valid records glued together — caller MUST pass exactly one.
        // TrailingBytes is checked BEFORE the AEAD call so the cipher
        // never runs. Use NoCipher so the test is cipher-feature-agnostic.
        let key = ZeroBuf::<16>::new([0u8; 16]);
        let iv = AeadIv::new(ZeroBuf::<12>::new([0u8; 12]));
        let mut extra = [0u8; 416];
        extra[..415].copy_from_slice(&FIXTURE_PACKET_3);
        extra[415] = 0xAB; // one stray byte past the declared record body
        let mut buf = [0u8; 416];
        let err = decrypt_record::<NoCipher>(&extra, &key, &iv, 0, &mut buf).unwrap_err();
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
        // matter — RecordTooLarge fires before BufferTooSmall. Size check
        // runs before the AEAD call; NoCipher keeps the test cipher-agnostic.
        let big = vec![0u8; (1 << 14) + 256];
        let mut out = [0u8; 1];
        let err = encrypt_record::<NoCipher>(
            &big,
            consts::CT_APPLICATION_DATA,
            &ZeroBuf::<16>::new([0u8; 16]),
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
        let record = encrypt_record::<ChaCha20Poly1305Sha256>(
            plaintext,
            consts::CT_APPLICATION_DATA,
            key.as_zeroizing(),
            &iv,
            7,
            &mut record_buf,
        )
        .unwrap();
        let record_owned = record.to_vec();
        let mut pt_buf = [0u8; 64];
        let inner = decrypt_record::<ChaCha20Poly1305Sha256>(
            &record_owned,
            key.as_zeroizing(),
            &iv,
            7,
            &mut pt_buf,
        )
        .unwrap();
        let (content, content_type) = aead::split_inner_plaintext(inner).unwrap();
        assert_eq!(content, plaintext);
        assert_eq!(content_type, consts::CT_APPLICATION_DATA);
    }

    #[test]
    fn encrypt_record_rejects_plaintext_just_over_14k() {
        // RFC 8446 §5.1: TLSPlaintext.length max is 2^14. Content of
        // 2^14 + 1 bytes fits the §5.2 ciphertext cap (2^14 + 256) once
        // the AEAD tag + content_type are added, but violates the §5.1
        // plaintext cap — must surface as RecordTooLarge. NoCipher keeps
        // the test cipher-agnostic.
        let just_over = vec![0u8; (1 << 14) + 1];
        let mut out = vec![0u8; (1 << 14) + 256 + 5];
        let err = encrypt_record::<NoCipher>(
            &just_over,
            consts::CT_APPLICATION_DATA,
            &ZeroBuf::<16>::new([0u8; 16]),
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
            server_flight::verify_certificate_verify::<RustCrypto, RustCrypto>(&view, &th, &body)
                .unwrap_err();
        assert_eq!(err, FlightError::TrailingBytes);
    }

    #[test]
    fn extract_cert_der_returns_leaf_from_chain() {
        // Two cert entries in the list; extract_cert_der returns the FIRST.
        let mut body = [0u8; 1 + 3 + 20];
        body[0] = 0;
        body[3] = 20;
        body[6] = 5;
        body[7..12].copy_from_slice(&[1, 2, 3, 4, 5]);
        body[16] = 5;
        body[17..22].copy_from_slice(&[6, 7, 8, 9, 10]);
        let leaf = extract_cert_der(&body).expect("first cert");
        assert_eq!(leaf, &[1, 2, 3, 4, 5]);
    }

    fn make_cert_body(n: usize) -> Vec<u8> {
        let entry_size = 3 + 1 + 2;
        let list_len = (n * entry_size) as u32;
        let mut body = Vec::with_capacity(4 + n * entry_size);
        body.push(0);
        body.extend_from_slice(&list_len.to_be_bytes()[1..4]);
        for i in 0..n {
            body.extend_from_slice(&[0, 0, 1]);
            body.push((i + 1) as u8);
            body.extend_from_slice(&[0, 0]);
        }
        body
    }

    #[test]
    fn extract_chain_returns_all_entries() {
        let body = make_cert_body(3);
        let chain = extract_chain::<8>(&body).expect("chain parses");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0], &[1u8][..]);
        assert_eq!(chain[1], &[2u8][..]);
        assert_eq!(chain[2], &[3u8][..]);
    }

    #[test]
    fn extract_chain_rejects_overflow() {
        let body = make_cert_body(3);
        let err = extract_chain::<2>(&body).expect_err("must reject overflow");
        assert_eq!(err, FlightError::CertChainTooLong);
    }

    /// Fixture-bound AES tests: each test decrypts or encrypts a
    /// captured wire fixture generated with AES-128-GCM, so the
    /// cipher choice is intrinsic.
    #[cfg(feature = "cipher-aes")]
    mod aes_tests {
        use super::*;

        #[test]
        fn fixture_packet_3_decrypts() {
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut buf,
            )
            .expect("decrypt_record");
            assert_eq!(pt.len(), 394);
            assert_eq!(&pt[..32], &FIXTURE_PACKET_3_PLAINTEXT_HEAD);

            let (content, content_type) = split_inner_plaintext(pt).expect("split inner plaintext");
            assert_eq!(content_type, consts::CT_HANDSHAKE);
            assert_eq!(&content[..6], &[0x08, 0x00, 0x00, 0x02, 0x00, 0x00]);
        }

        #[test]
        fn fixture_packet_3_decrypts_full_chain() {
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
            let (k, iv) = traffic_keys::<RustCrypto, 16>(&s_ts).unwrap();
            let key = AeadKey::new(k);

            let mut buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut buf,
            )
            .unwrap();
            let (content, content_type) = split_inner_plaintext(pt).unwrap();
            assert_eq!(content_type, consts::CT_HANDSHAKE);
            assert_eq!(&content[..6], &[0x08, 0x00, 0x00, 0x02, 0x00, 0x00]);
        }

        #[test]
        fn fixture_packet_3_server_flight_verifies() {
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut buf,
            )
            .unwrap();
            let (content, _ct) = split_inner_plaintext(pt).unwrap();

            let flight = parse_server_flight(content).expect("parse_server_flight");

            assert_eq!(flight.ee_body, &[0x00, 0x00][..]);

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

            let view = verify_self_signed_cert::<DerCert, RustCrypto, RustCrypto>(cert_der)
                .expect("cert self-sig");
            let pk = match view {
                CertView::Ed25519 { pubkey, .. } => *pubkey,
                #[cfg(feature = "rsa")]
                _ => panic!("fixture cert is Ed25519"),
            };
            assert_eq!(pk, EXPECTED_SERVER_ID_PUB);

            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            let result = verify_server_flight::<RustCrypto, RustCrypto, RustCrypto>(
                &mut transcript,
                content,
                &make_fixture_s_hs_traffic_secret(),
                &fixture_prepared_ed25519::<RustCrypto>(),
                &fixture_leaf_ed25519(),
            )
            .expect("verify_server_flight");
            assert_eq!(
                result.server_pubkey.as_ed25519(),
                Some(EXPECTED_SERVER_ID_PUB)
            );
        }

        #[test]
        fn ed25519_verify_trait_propagates_to_certificate_verify() {
            // Swap the backend on the prepared verifier — AlwaysReject's
            // `verify` returns Err, so CV must fail with
            // `CertVerifyInvalid`. Confirms `E` flows through to the
            // CV-check path.
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut pt_buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut pt_buf,
            )
            .unwrap();
            let (content, _) = split_inner_plaintext(pt).unwrap();
            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            let err = verify_server_flight::<RustCrypto, AlwaysReject, RustCrypto>(
                &mut transcript,
                content,
                &make_fixture_s_hs_traffic_secret(),
                &fixture_prepared_ed25519::<AlwaysReject>(),
                &fixture_leaf_ed25519(),
            )
            .unwrap_err();
            assert_eq!(err, FlightError::CertVerifyInvalid);
        }

        #[test]
        fn fixture_bad_finished_rejected() {
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut buf,
            )
            .unwrap();
            let (content, _) = split_inner_plaintext(pt).unwrap();

            let mut tampered = [0u8; 400];
            tampered[..content.len()].copy_from_slice(content);
            let last = content.len() - 1;
            tampered[last] ^= 0xFF;

            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            let err = verify_server_flight::<RustCrypto, RustCrypto, RustCrypto>(
                &mut transcript,
                &tampered[..content.len()],
                &make_fixture_s_hs_traffic_secret(),
                &fixture_prepared_ed25519::<RustCrypto>(),
                &fixture_leaf_ed25519(),
            )
            .unwrap_err();
            assert_eq!(err, FlightError::FinishedMacInvalid);
        }

        #[test]
        fn fixture_packet_5_encrypts_byte_identical() {
            let ((c_key, c_iv), _) = application_keys();
            // Regenerated from the c_ap_ts under the RSL-bearing CH transcript
            // with SAN-bearing cert.
            assert_eq!(
                c_key.as_bytes(),
                &[
                    0xe6, 0xfc, 0x45, 0x60, 0x91, 0x90, 0x27, 0x4e, 0x6f, 0xda, 0xae, 0x67, 0xc3,
                    0x06, 0x2f, 0xb0,
                ]
            );
            assert_eq!(
                c_iv.as_bytes(),
                &[
                    0x6f, 0x04, 0xf5, 0xff, 0x3d, 0x43, 0x2a, 0x54, 0x4b, 0xa1, 0x4c, 0xef,
                ]
            );

            let mut out = [0u8; 80];
            let record = encrypt_record::<Aes128GcmSha256>(
                PACKET_5_PLAINTEXT,
                consts::CT_APPLICATION_DATA,
                c_key.as_zeroizing(),
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
            let inner = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_6,
                s_key.as_zeroizing(),
                &s_iv,
                0,
                &mut pt,
            )
            .expect("decrypt packet 6");
            let (content, ct) = split_inner_plaintext(inner).unwrap();
            assert_eq!(ct, consts::CT_APPLICATION_DATA);
            assert_eq!(content, PACKET_6_PLAINTEXT);
        }

        #[test]
        fn fixture_client_finished_matches() {
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut pt_buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut pt_buf,
            )
            .unwrap();
            let (content, _ct) = split_inner_plaintext(pt).unwrap();
            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            verify_server_flight::<RustCrypto, RustCrypto, RustCrypto>(
                &mut transcript,
                content,
                &make_fixture_s_hs_traffic_secret(),
                &fixture_prepared_ed25519::<RustCrypto>(),
                &fixture_leaf_ed25519(),
            )
            .unwrap();

            let mut out = [0u8; 64];
            let record = RecordKeys::<Aes128GcmSha256>::build_client_finished::<RustCrypto>(
                &make_fixture_c_hs_traffic_secret(),
                &transcript.snapshot(),
                0,
                &mut out,
            )
            .unwrap();
            assert_eq!(record.len(), CLIENT_FINISHED_LEN);
            assert_eq!(record, &FIXTURE_PACKET_4[..]);
        }

        #[test]
        fn fixture_application_traffic_secrets_match() {
            let ms = master_secret::<RustCrypto>(&make_fixture_handshake_secret()).unwrap();
            // App secrets are keyed on the transcript hash through *server* Finished.
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut pt_buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut pt_buf,
            )
            .unwrap();
            let (content, _) = split_inner_plaintext(pt).unwrap();
            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            verify_server_flight::<RustCrypto, RustCrypto, RustCrypto>(
                &mut transcript,
                content,
                &make_fixture_s_hs_traffic_secret(),
                &fixture_prepared_ed25519::<RustCrypto>(),
                &fixture_leaf_ed25519(),
            )
            .unwrap();

            let (c_ap, s_ap) =
                application_traffic_secrets::<RustCrypto>(&ms, &transcript.snapshot()).unwrap();

            // From tls_fixture/state/client.json `c_ap_ts` / `s_ap_ts` at seed 0.
            const FIXTURE_C_AP_BYTES: [u8; 32] = [
                0x54, 0x1a, 0xd5, 0xfc, 0xef, 0x9e, 0x66, 0x5f, 0x2b, 0x1b, 0xdb, 0x37, 0xfc, 0x05,
                0xd6, 0xcf, 0x94, 0x8f, 0x4a, 0x10, 0xda, 0x18, 0xe0, 0x9f, 0x57, 0x10, 0x48, 0x5b,
                0xf4, 0xf6, 0x64, 0x88,
            ];
            const FIXTURE_S_AP_BYTES: [u8; 32] = [
                0xa1, 0x04, 0xee, 0xae, 0xe6, 0xfa, 0x92, 0x7c, 0x2a, 0x64, 0xbd, 0x79, 0x86, 0xcb,
                0xac, 0xeb, 0x40, 0xa1, 0x69, 0xcf, 0x3a, 0xfb, 0x8c, 0xa0, 0x1a, 0x67, 0x13, 0xdb,
                0xa7, 0x04, 0xb5, 0x65,
            ];
            assert_eq!(c_ap.as_bytes(), &FIXTURE_C_AP_BYTES);
            assert_eq!(s_ap.as_bytes(), &FIXTURE_S_AP_BYTES);
        }

        #[test]
        fn bad_tag_returns_aead_failed() {
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut tampered = [0u8; 415];
            tampered.copy_from_slice(&FIXTURE_PACKET_3);
            let last = tampered.len() - 1;
            tampered[last] ^= 0xFF; // corrupt the auth tag
            let mut buf = [0u8; 400];
            // Pre-fill with a sentinel; the function should overwrite the
            // ciphertext window with zeroes on AEAD failure.
            buf.fill(0xAA);
            let err =
                decrypt_record::<Aes128GcmSha256>(&tampered, key.as_zeroizing(), &iv, 0, &mut buf)
                    .unwrap_err();
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
    }

    #[cfg(all(feature = "rsa", not(feature = "rsa_pss_only"), feature = "cipher-aes"))]
    mod rsa_tests {
        use super::*;

        /// RSA fixture, c→s ClientHello.
        const FIXTURE_RSA_CLIENT_HELLO: [u8; 151] = crate::hex_decode(include_str!(
            "../../testdata/packets_rsa/001_c2s_ClientHello.hex"
        ));
        /// RSA fixture, s→c ServerHello.
        const FIXTURE_RSA_SERVER_HELLO: [u8; 95] = crate::hex_decode(include_str!(
            "../../testdata/packets_rsa/002_s2c_ServerHello.hex"
        ));
        /// RSA fixture, encrypted server flight (dominated by the
        /// 2048-bit RSA cert + 256-byte RSA-PSS signature).
        const FIXTURE_RSA_PACKET_3: [u8; 1172] = crate::hex_decode(include_str!(
            "../../testdata/packets_rsa/003_s2c_ServerFlight_encrypted.hex"
        ));

        /// Server handshake traffic secret from the RSA fixture.
        const FIXTURE_RSA_S_HS_TRAFFIC_SECRET_BYTES: [u8; 32] = [
            0x8a, 0x47, 0x0c, 0x72, 0x55, 0x05, 0x3a, 0xc3, 0x11, 0xaf, 0x9a, 0x04, 0xf1, 0xb9,
            0xa5, 0xd2, 0x9d, 0x51, 0x58, 0x81, 0xf4, 0xf4, 0x22, 0x0e, 0xc0, 0x68, 0xc6, 0x8f,
            0x66, 0xe0, 0xca, 0xfd,
        ];

        fn s_hs_traffic_secret() -> Secret {
            Secret::new(ZeroBuf::<32>::new(FIXTURE_RSA_S_HS_TRAFFIC_SECRET_BYTES))
        }

        #[test]
        fn fixture_rsa_server_flight_verifies() {
            // Derive AEAD (key, iv) from the fixture's server handshake traffic secret.
            let s_hs_ts = s_hs_traffic_secret();
            let (k, iv) = traffic_keys::<RustCrypto, 16>(&s_hs_ts).expect("traffic_keys");
            let key = AeadKey::new(k);

            // Decrypt the RSA fixture's server flight.
            let mut pt_buf = [0u8; 1200];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_RSA_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut pt_buf,
            )
            .expect("decrypt packets_rsa/003");
            let (content, ct) = split_inner_plaintext(pt).unwrap();
            assert_eq!(ct, consts::CT_HANDSHAKE);

            // Build the RSA prepared verifier directly from the leaf.
            let flight_pre = parse_server_flight(content).expect("parse_server_flight");
            let leaf_der = extract_cert_der(flight_pre.cert_body).expect("extract_cert_der");
            let leaf_view = <DerCert as CertParser>::parse(leaf_der).expect("parse RSA leaf");
            let prepared = match &leaf_view {
                CertView::Rsa {
                    modulus, exponent, ..
                } => PreparedVerifier::Rsa(
                    <RustCrypto as crate::traits::RsaVerifierProvider>::prepare_rsa(
                        modulus, *exponent,
                    )
                    .expect("prepare_rsa"),
                ),
                CertView::Ed25519 { .. } => panic!("fixture is RSA"),
            };

            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_RSA_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_RSA_SERVER_HELLO).unwrap();
            verify_server_flight::<RustCrypto, RustCrypto, RustCrypto>(
                &mut transcript,
                content,
                &s_hs_ts,
                &prepared,
                &leaf_view,
            )
            .expect("verify RSA server flight");
        }

        #[test]
        fn rsa_verify_rejects_wrong_signature_length() {
            // `FixedUInt::from_be_bytes` requires an exact-length slice; the
            // RSA verify APIs must guard against wrong-length input and
            // return `RsaVerifyError` instead of panicking.
            let modulus_2048 = [0xFFu8; 256];
            let exponent: u32 = 65537;
            let vk = RsaVerifierKey::new(&modulus_2048, exponent).expect("vk");
            let short_sig = [0u8; 200];
            assert!(vk.verify_pkcs1v15_sha256(b"msg", &short_sig).is_err());
            assert!(vk.verify_pss_sha256(b"msg", &short_sig).is_err());
        }

        #[test]
        fn fixture_rsa_cert_parses_as_rsa_view() {
            let s_hs_ts = s_hs_traffic_secret();
            let (k, iv) = traffic_keys::<RustCrypto, 16>(&s_hs_ts).unwrap();
            let key = AeadKey::new(k);
            let mut pt_buf = [0u8; 1200];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_RSA_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut pt_buf,
            )
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
