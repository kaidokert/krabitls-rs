//! `krabitls` — a sans-io, `no_std` TLS 1.3 client for a fixed embedded
//! profile.
//!
//! Public surface lives in [`client`] (connection facade) and
//! [`backends`] (config markers + RustCrypto trait impls). Everything
//! else is internal.
//!
//! # Security
//!
//! A hobby project — don't use it for anything you care about. The crypto is
//! hand-rolled, unaudited, not constant-time, and has no scalar blinding. The
//! bundled trust is pin-a-pubkey or trust-SAN — no CA bundle or chain walking —
//! but verification is a pluggable `VerifyStrategy`, so a caller can
//! supply their own. See the README for the full threat model.
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
pub(crate) use {
    aead::RecordKeys,
    hkdf::{application_traffic_secrets, master_secret},
    server_flight::{tests::verify_self_signed_cert, verify_server_flight},
};
#[cfg(test)]
pub(crate) use {
    aead::{aead_nonce, split_inner_plaintext},
    hkdf::{derive_secret, handshake_secret, handshake_traffic_secrets, hkdf_expand_label},
};

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
    pub const CT_ALERT: u8 = 21;
    /// Middlebox-compat ChangeCipherSpec — accepted and dropped without
    /// bumping `seq_in` in TLS 1.3.
    pub const CT_CHANGE_CIPHER_SPEC: u8 = 0x14;
    /// `warning` (level 1) + `close_notify` (description 0) — the only alert
    /// krabitls ever sends.
    pub const CLOSE_NOTIFY_ALERT: [u8; 2] = [0x01, 0x00];

    /// RFC 8446 mandates 0x0303 in the record header and in
    /// `ClientHello.legacy_version`, even when negotiating TLS 1.3.
    pub const LEGACY_VERSION: u16 = 0x0303;
    pub const TLS_1_3: u16 = 0x0304;

    pub const HS_CLIENT_HELLO: u8 = 1;
    pub const HS_SERVER_HELLO: u8 = 2;
    pub const HS_NEW_SESSION_TICKET: u8 = 4;
    pub const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
    pub const HS_CERTIFICATE_REQUEST: u8 = 13;
    pub const HS_CERTIFICATE: u8 = 11;
    pub const HS_CERTIFICATE_VERIFY: u8 = 15;
    pub const HS_FINISHED: u8 = 20;
    pub const HS_KEY_UPDATE: u8 = 24;

    /// TLS 1.3 `TLSInnerPlaintext` content-type byte appended before
    /// encryption; counts against the peer's `record_size_limit` (RFC 8449 §4).
    pub const CONTENT_TYPE_LEN: usize = 1;

    pub const CIPHER_AES_128_GCM_SHA256: u16 = 0x1301;
    pub const CIPHER_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
    pub const NAMED_GROUP_X25519: u16 = 0x001D;
    pub const SIG_SCHEME_ED25519: u16 = 0x0807;
    /// `rsa_pss_rsae_sha256` — RSASSA-PSS with the leaf's RSAE key encoding,
    /// MGF1-SHA-256, salt_len = hash output (32 B). RFC 8446 §4.2.3.
    // Unconditional so it can be named from `cfg!(feature = "rsa")`-false
    // branches in the ClientHello writer; the actual emission stays gated.
    pub const SIG_SCHEME_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    /// `mldsa44` / `mldsa65` / `mldsa87` — pure ML-DSA (FIPS 204) over the
    /// CertificateVerify content, empty context. Codepoints from
    /// draft-ietf-tls-mldsa. Gated on `feature = "mldsa"` (the only consumer is
    /// the CertificateVerify dispatch); the ClientHello advertisement that will
    /// name them from a `cfg!`-false branch lands separately.
    #[cfg(feature = "mldsa")]
    pub const SIG_SCHEME_MLDSA44: u16 = 0x0904;
    #[cfg(feature = "mldsa")]
    pub const SIG_SCHEME_MLDSA65: u16 = 0x0905;
    #[cfg(feature = "mldsa")]
    pub const SIG_SCHEME_MLDSA87: u16 = 0x0906;

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
// Schemes advertised in signature_algorithms: ed25519 always, rsa_pss when
// `rsa` is on. Single source for both the ext sizing and the writer below.
const SIG_SCHEME_COUNT: u16 = 1 + cfg!(feature = "rsa") as u16;
// 4-byte ext header + 2-byte list-len + 2 bytes per scheme.
const EXT_SIGNATURE_ALGORITHMS_TOTAL: u16 = 4 + 2 + 2 * SIG_SCHEME_COUNT;
const EXT_KEY_SHARE_TOTAL: u16 = 4 + 38;

// At least one cipher feature must be on. We can't form a valid
// ClientHello otherwise — there's no cipher_suite to advertise.
#[cfg(not(any(feature = "cipher-aes", feature = "chacha20")))]
compile_error!(
    "krabitls requires at least one of `cipher-aes` (default) or `chacha20` to provide a cipher suite"
);

const CH_CIPHER_SUITES_COUNT: usize =
    cfg!(feature = "cipher-aes") as usize + cfg!(feature = "chacha20") as usize;

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

// Combo-independent pin: 117-byte baseline (1 suite, ed25519-only) + 2 per
// extra advertised suite + 2 when rsa adds the second sig scheme.
const _: () = assert!(
    CLIENT_HELLO_LEN
        == 117
            + 2 * CH_CIPHER_SUITES_COUNT.saturating_sub(1)
            + if cfg!(feature = "rsa") { 2 } else { 0 }
);

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
    out.write_u16(2 + 2 * SIG_SCHEME_COUNT)?; // ext_data: list_len field (2) + schemes
    out.write_u16(2 * SIG_SCHEME_COUNT)?; // supported_signature_algorithms list_len
    out.write_u16(SIG_SCHEME_ED25519)?;
    if cfg!(feature = "rsa") {
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
mod tests;
