//! Parse + verify the server flight that arrives encrypted in packet 3 of
//! the TLS 1.3 handshake: `EncryptedExtensions || Certificate ||
//! CertificateVerify || Finished`.
//!
//! Three independent verification jobs, sharing a transcript hash that grows
//! as we walk the messages:
//!
//! 1. **Cert self-signature** — the server's Ed25519 X.509 is self-signed in
//!    our profile; verifying the inner signature is internal-consistency
//!    proof (it does *not* prove identity by itself).
//! 2. **CertificateVerify** — proves the server holds the cert's private key.
//!    The signed data is `0x20*64 || "TLS 1.3, server CertificateVerify" ||
//!    0x00 || SHA-256(CH..Cert)`. Sig scheme must be `ed25519` per our profile.
//! 3. **Finished** — MAC over the transcript-so-far with `finished_key =
//!    HKDF-Expand-Label(s_hs_traffic_secret, "finished", "", 32)`, proving
//!    the server picked the same handshake keys we did.

use crate::consts::SIG_SCHEME_ED25519;
#[cfg(feature = "rsa")]
use crate::consts::SIG_SCHEME_RSA_PSS_RSAE_SHA256;
use crate::hkdf::{HkdfLabelError, TranscriptHash, hkdf_expand_label};
use crate::newtype::{Secret, TranscriptDigest, ZeroBuf};
use crate::traits::{CertParseError, CertParser, CertView, Ed25519Verify, HkdfSha256};

// =====================================================================
// Inner-handshake message types we expect inside packet 003.
// =====================================================================

const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

/// Parsed view of the four messages, borrowing into the decrypted plaintext.
///
/// `*_full` slices include the 4-byte handshake header (`type || u24 length`)
/// and are what gets fed into the transcript hash. `*_body` slices skip the
/// header and are what each verification function actually consumes.
#[derive(Debug, Clone, Copy)]
pub struct ServerFlightView<'a> {
    pub ee_full: &'a [u8],
    pub ee_body: &'a [u8],
    pub cert_full: &'a [u8],
    pub cert_body: &'a [u8],
    pub cv_full: &'a [u8],
    pub cv_body: &'a [u8],
    pub fin_full: &'a [u8],
    pub fin_body: &'a [u8],
}

/// Reasons walking or verifying the server flight may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FlightError {
    /// A handshake message header or body claimed more bytes than remained.
    Truncated,
    /// Trailing bytes after we'd consumed all four expected messages.
    TrailingBytes,
    /// Handshake messages didn't appear in `EE -> Cert -> CV -> Finished` order.
    UnexpectedHandshakeType { expected: u8, got: u8 },
    /// `EncryptedExtensions` body wasn't an empty extensions list.
    NonEmptyEncryptedExtensions,
    /// `Certificate` message carried more than one `CertificateEntry`. Our
    /// locked profile uses a single self-signed cert.
    MultipleCertificateEntries,
    /// A `CertificateEntry.extensions` field was non-empty. RFC 8446 §4.4.2
    /// requires it be empty unless the client requested specific extensions
    /// in ClientHello (we don't).
    NonEmptyCertificateExtensions,

    /// X.509 DER parse error.
    BadCert(CertParseError),
    /// `Ed25519::verify` returned false for the cert's self-signature.
    CertSelfSignatureInvalid,

    /// `CertificateVerify.signature_scheme` wasn't `ed25519` (0x0807).
    UnexpectedSignatureScheme(u16),
    /// `CertificateVerify.signature` length didn't match what the scheme
    /// requires (64 B for Ed25519; modulus byte length for RSA-PSS).
    WrongSignatureLength,
    /// `Ed25519::verify` returned false for `CertificateVerify`.
    CertVerifyInvalid,

    /// `Finished.verify_data` length wasn't 32 bytes.
    FinishedWrongLength,
    /// Finished MAC didn't match what we computed locally.
    FinishedMacInvalid,
    /// Internal HKDF label encoding failed.
    HkdfLabel(HkdfLabelError),
    /// Internal encoding buffer overflowed. Statically unreachable for the
    /// fixed `CertificateVerify` signed-data shape we build, but the variant
    /// exists so the encoding path can propagate via `?` instead of
    /// `.expect` / panic.
    InternalEncoding,
}

impl From<heapless::CapacityError> for FlightError {
    fn from(_: heapless::CapacityError) -> Self {
        FlightError::InternalEncoding
    }
}

impl From<CertParseError> for FlightError {
    fn from(e: CertParseError) -> Self {
        FlightError::BadCert(e)
    }
}

/// Walk the 4-message server flight in the decrypted plaintext.
pub fn parse_server_flight(content: &[u8]) -> Result<ServerFlightView<'_>, FlightError> {
    let mut r = HsReader::new(content);

    let (ee_type, ee_body, ee_full) = r.next_msg()?;
    if ee_type != HS_ENCRYPTED_EXTENSIONS {
        return Err(FlightError::UnexpectedHandshakeType {
            expected: HS_ENCRYPTED_EXTENSIONS,
            got: ee_type,
        });
    }
    // RFC 8446 §4.3.1: body is `Extension extensions<0..2^16-1>`. The Python
    // fixture sends an empty list (`0x00 0x00`). Real public servers commonly
    // echo SNI, advertise ALPN, etc. — we accept any well-formed EE body and
    // don't inspect its contents. The walker has already consumed the inner
    // bytes via `r.next_msg()`, so we're done with EE here.
    let _ = ee_body;

    let (cert_type, cert_body, cert_full) = r.next_msg()?;
    if cert_type != HS_CERTIFICATE {
        return Err(FlightError::UnexpectedHandshakeType {
            expected: HS_CERTIFICATE,
            got: cert_type,
        });
    }

    let (cv_type, cv_body, cv_full) = r.next_msg()?;
    if cv_type != HS_CERTIFICATE_VERIFY {
        return Err(FlightError::UnexpectedHandshakeType {
            expected: HS_CERTIFICATE_VERIFY,
            got: cv_type,
        });
    }

    let (fin_type, fin_body, fin_full) = r.next_msg()?;
    if fin_type != HS_FINISHED {
        return Err(FlightError::UnexpectedHandshakeType {
            expected: HS_FINISHED,
            got: fin_type,
        });
    }

    if !r.at_end() {
        return Err(FlightError::TrailingBytes);
    }

    Ok(ServerFlightView {
        ee_full,
        ee_body,
        cert_full,
        cert_body,
        cv_full,
        cv_body,
        fin_full,
        fin_body,
    })
}

// =====================================================================
// Handshake-message walker (4-byte header: type || u24 length).
// =====================================================================

struct HsReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> HsReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
    fn next_msg(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), FlightError> {
        if self.buf.len() < self.pos + 4 {
            return Err(FlightError::Truncated);
        }
        let msg_type = self.buf[self.pos];
        let len: usize = u32::from_be_bytes([
            0,
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ])
        .try_into()
        .map_err(|_| FlightError::Truncated)?;
        // Rewrite `body_start + len > self.buf.len()` to avoid overflow
        // on 16-bit `usize`: the `self.buf.len() < self.pos + 4` guard
        // above guarantees `self.buf.len() >= self.pos + 4`, so
        // `self.buf.len() - self.pos - 4` can't underflow.
        if len > self.buf.len() - self.pos - 4 {
            return Err(FlightError::Truncated);
        }
        let body_start = self.pos + 4;
        let body_end = body_start + len;
        let body = &self.buf[body_start..body_end];
        let full = &self.buf[self.pos..body_end];
        self.pos = body_end;
        Ok((msg_type, body, full))
    }
}

// =====================================================================
// Certificate-message body -> cert DER.
//
// `Certificate` body = u8(ctx_len) || ctx || u24(list_len) || (entries) ...
// One entry = u24(cert_data_len) || cert_data || u16(exts_len) || exts.
// Locked-profile parser: require exactly one entry, empty per-entry
// extensions, and no trailing bytes after the list.
// =====================================================================

/// Pull the DER bytes of the single certificate out of a `Certificate`
/// handshake message body. Rejects:
/// - more than one `CertificateEntry`
/// - non-empty per-entry `extensions` (RFC 8446 §4.4.2)
/// - trailing bytes after `certificate_list`
pub fn extract_cert_der(cert_body: &[u8]) -> Result<&[u8], FlightError> {
    if cert_body.is_empty() {
        return Err(FlightError::Truncated);
    }
    let ctx_len = cert_body[0] as usize;
    let after_ctx = 1 + ctx_len;
    if cert_body.len() < after_ctx + 3 {
        return Err(FlightError::Truncated);
    }
    let list_len = usize::try_from(read_u24(&cert_body[after_ctx..after_ctx + 3]))
        .map_err(|_| FlightError::Truncated)?;
    let list_start = after_ctx + 3;
    // `list_start + list_len > cert_body.len()` reformulated to avoid
    // overflow on 16-bit `usize`: the `cert_body.len() < after_ctx + 3`
    // check above guarantees `cert_body.len() >= list_start`, so the
    // subtraction is safe.
    if list_len > cert_body.len() - list_start {
        return Err(FlightError::Truncated);
    }
    let list_end = list_start + list_len;
    let list = &cert_body[list_start..list_end];

    // First entry: u24(cert_data_len) || cert_data || u16(exts_len) || exts.
    //
    // We return the FIRST cert (the leaf) and ignore everything after it:
    //   - Any further CertificateEntry items in the list (intermediates) —
    //     real public servers send leaf + chain; this parser is leaf-only,
    //     callers do their own chain verification or pinning.
    //   - The first entry's `extensions` payload — real servers may include
    //     OCSP / SCT / SAN extensions here; nothing we want to act on for
    //     our locked profile.
    //   - Trailing bytes after the list (none expected, but tolerated).
    if list.len() < 3 {
        return Err(FlightError::Truncated);
    }
    let cert_data_len =
        usize::try_from(read_u24(&list[0..3])).map_err(|_| FlightError::Truncated)?;
    // `cert_end + 2 = 3 + cert_data_len + 2 = 5 + cert_data_len > list.len()`
    // reformulated to avoid overflow on 16-bit `usize`: bail if the list
    // is too short for the 3+2 framing bytes or if cert_data_len doesn't
    // fit the remaining window.
    if list.len() < 5 || cert_data_len > list.len() - 5 {
        return Err(FlightError::Truncated);
    }
    let cert_end = 3 + cert_data_len;
    // Verify the exts length is internally consistent (so we can't get past
    // the cert by miscounting), but don't inspect its content.
    let exts_len = u16::from_be_bytes([list[cert_end], list[cert_end + 1]]) as usize;
    // `cert_end + 2 + exts_len > list.len()` reformulated against
    // overflow: the previous guard ensures `list.len() >= cert_end + 2`.
    if exts_len > list.len() - cert_end - 2 {
        return Err(FlightError::Truncated);
    }
    Ok(&list[3..cert_end])
}

/// Read a big-endian 24-bit length. Returned as `u32`: a 24-bit value
/// can hold `2^24 - 1 ≈ 16.7 MiB`, which exceeds `u16::MAX` on 16-bit
/// platforms — leaving the conversion to `usize` (with `try_from`) to
/// the call site lets each callsite emit a clean error instead of
/// silently truncating.
fn read_u24(b: &[u8]) -> u32 {
    debug_assert!(b.len() == 3);
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32)
}

// =====================================================================
// The three verifications. Each is a small function — composed into
// `verify_server_flight` below.
// =====================================================================

/// Verify a self-signed X.509 cert (Ed25519) by checking the cert's
/// signature against the cert's own SubjectPublicKey. Returns the parsed
/// `CertView` for downstream `CertificateVerify` dispatch.
///
/// `C` is the cert-parser backend; today only [`crate::DerCert`]. `E` is
/// the Ed25519 verify backend — see [`Ed25519Verify`]; [`crate::RustCrypto`]
/// is the bundled default and uses `ed25519_heapless` under the hood.
pub fn verify_self_signed_cert<C: CertParser, E: Ed25519Verify>(
    cert_der: &[u8],
) -> Result<CertView<'_>, FlightError> {
    let cache = E::new_cache();
    let view = C::parse(cert_der)?;
    verify_self_signed_cert_with_cache::<E>(
        &cache,
        &view,
        #[cfg(feature = "rsa")]
        None,
    )?;
    Ok(view)
}

/// Like [`verify_self_signed_cert`] but takes a caller-supplied
/// `E::Cache` to amortize the per-key precomputes when the caller is
/// going to verify more signatures against the same cert (notably the
/// `CertificateVerify` immediately after). [`verify_server_flight`]
/// uses this internally; one-shot users keep calling
/// [`verify_self_signed_cert`].
pub fn verify_self_signed_cert_with_cache<E: Ed25519Verify>(
    cache: &E::Cache,
    view: &CertView<'_>,
    #[cfg(feature = "rsa")] rsa_cache: Option<&crate::backends::rsa_verify::RsaVerifierKey>,
) -> Result<(), FlightError> {
    match view {
        CertView::Ed25519 {
            tbs,
            signature,
            pubkey,
            ..
        } => {
            if !E::verify_with_cache(cache, pubkey, tbs, signature) {
                return Err(FlightError::CertSelfSignatureInvalid);
            }
        }
        #[cfg(feature = "rsa")]
        CertView::Rsa {
            tbs,
            signature,
            modulus,
            exponent,
            ..
        } => {
            // Self-signed RSA cert: outer signature is `sha256WithRSAEncryption`
            // (PKCS#1-v1.5). If the caller passed an `RsaVerifierKey` we reuse
            // its cached `ModMathParams` (the ~400-800k-cycle precompute on
            // M3 for U2048); otherwise fall through to the free function,
            // which rebuilds the params per call.
            if let Some(rk) = rsa_cache {
                rk.verify_pkcs1v15_sha256(tbs, signature)
                    .map_err(|_| FlightError::CertSelfSignatureInvalid)?;
            } else {
                crate::backends::rsa_verify::verify_pkcs1v15_sha256(
                    modulus, *exponent, tbs, signature,
                )
                .map_err(|_| FlightError::CertSelfSignatureInvalid)?;
            }
        }
    }
    Ok(())
}

/// Verify a `CertificateVerify` body against the running transcript hash and
/// the server's pubkey (carried inside `cert_view`). Dispatches on the
/// signature scheme + cert variant — mismatches reject.
///
/// `E` is the Ed25519 verify backend; see [`Ed25519Verify`].
pub fn verify_certificate_verify<E: Ed25519Verify>(
    cert_view: &CertView<'_>,
    transcript_hash_ch_through_cert: &TranscriptDigest,
    cv_body: &[u8],
) -> Result<(), FlightError> {
    let cache = E::new_cache();
    verify_certificate_verify_with_cache::<E>(
        &cache,
        cert_view,
        transcript_hash_ch_through_cert,
        cv_body,
        #[cfg(feature = "rsa")]
        None,
    )
}

/// Like [`verify_certificate_verify`] but takes a caller-supplied
/// `E::Cache` to amortize the per-key precomputes. Used by
/// [`verify_server_flight`] so a single cache is shared across the
/// pipeline's two verifies.
pub fn verify_certificate_verify_with_cache<E: Ed25519Verify>(
    cache: &E::Cache,
    cert_view: &CertView<'_>,
    transcript_hash_ch_through_cert: &TranscriptDigest,
    cv_body: &[u8],
    #[cfg(feature = "rsa")] rsa_cache: Option<&crate::backends::rsa_verify::RsaVerifierKey>,
) -> Result<(), FlightError> {
    if cv_body.len() < 4 {
        return Err(FlightError::Truncated);
    }
    let scheme = u16::from_be_bytes([cv_body[0], cv_body[1]]);
    let sig_len = u16::from_be_bytes([cv_body[2], cv_body[3]]) as usize;
    if cv_body.len() != 4 + sig_len {
        return Err(FlightError::TrailingBytes);
    }
    let sig_bytes = &cv_body[4..4 + sig_len];

    // The signed data: 64 octets of 0x20, the ASCII context string, a 0 byte,
    // then the transcript hash. RFC 8446 §4.4.3.
    //
    // Built on a heapless::Vec so every write is a fallible
    // `extend_from_slice(...)?` and there are no panicking slice indices.
    // The capacity is set to the exact final size, so the `?` paths are
    // statically unreachable — the From<CapacityError> impl maps them to
    // FlightError::InternalEncoding for the type system's benefit only.
    const CTX: &[u8] = b"TLS 1.3, server CertificateVerify";
    const SIGNED_LEN: usize = 64 + CTX.len() + 1 + 32;
    let mut signed: heapless::Vec<u8, SIGNED_LEN> = heapless::Vec::new();
    signed.extend_from_slice(&[0x20u8; 64])?;
    signed.extend_from_slice(CTX)?;
    signed.extend_from_slice(&[0u8])?;
    signed.extend_from_slice(transcript_hash_ch_through_cert.as_bytes())?;

    match (scheme, cert_view) {
        (SIG_SCHEME_ED25519, CertView::Ed25519 { pubkey, .. }) => {
            if sig_len != 64 {
                return Err(FlightError::WrongSignatureLength);
            }
            let signature: &[u8; 64] = sig_bytes.try_into().expect("length checked above");
            if !E::verify_with_cache(cache, pubkey, &signed, signature) {
                return Err(FlightError::CertVerifyInvalid);
            }
            Ok(())
        }
        #[cfg(feature = "rsa")]
        (
            SIG_SCHEME_RSA_PSS_RSAE_SHA256,
            CertView::Rsa {
                modulus, exponent, ..
            },
        ) => {
            // PSS signature length equals the RSA modulus length.
            if sig_len != modulus.len() {
                return Err(FlightError::WrongSignatureLength);
            }
            // Reuse the cached `RsaVerifierKey` if provided — same amortization
            // rationale as in `verify_self_signed_cert_with_cache`.
            if let Some(rk) = rsa_cache {
                rk.verify_pss_sha256(&signed, sig_bytes)
                    .map_err(|_| FlightError::CertVerifyInvalid)?;
            } else {
                crate::backends::rsa_verify::verify_pss_sha256(
                    modulus, *exponent, &signed, sig_bytes,
                )
                .map_err(|_| FlightError::CertVerifyInvalid)?;
            }
            Ok(())
        }
        _ => Err(FlightError::UnexpectedSignatureScheme(scheme)),
    }
}

/// Verify a `Finished` body using HMAC-SHA256 over the running transcript hash.
///
/// `s_hs_traffic_secret` is the server handshake traffic secret. The
/// `transcript_hash_ch_through_cv` is `SHA-256(CH || SH || EE || Cert ||
/// CertVerify)` — the hash at the point just *before* the server emits
/// Finished. RFC 8446 §4.4.4.
pub fn verify_server_finished<H: HkdfSha256>(
    s_hs_traffic_secret: &Secret,
    transcript_hash_ch_through_cv: &TranscriptDigest,
    finished_body: &[u8],
) -> Result<(), FlightError> {
    if finished_body.len() != 32 {
        return Err(FlightError::FinishedWrongLength);
    }
    let mut finished_key = ZeroBuf::<32>::new([0; 32]);
    hkdf_expand_label::<H>(
        s_hs_traffic_secret.as_bytes(),
        b"finished",
        &[],
        &mut finished_key[..],
    )
    .map_err(FlightError::HkdfLabel)?;
    // `HKDF-Extract(salt, IKM)` is literally `HMAC(salt, IKM)`, so this gives
    // us HMAC-SHA256(finished_key, transcript_hash).
    let expected = H::extract(&finished_key[..], transcript_hash_ch_through_cv.as_bytes());
    // Constant-time-ish compare. Both inputs are public after the fact but
    // it's still good hygiene to avoid early-exit on the first mismatching byte.
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= expected[i] ^ finished_body[i];
    }
    if diff != 0 {
        return Err(FlightError::FinishedMacInvalid);
    }
    Ok(())
}

// =====================================================================
// One-shot pipeline: parse + verify everything.
// =====================================================================

/// The server's identity pubkey, as carried by the cert that satisfied
/// `verify_server_flight`'s `CertificateVerify` check. Variant matches the
/// cert SPKI's algorithm; RSA borrows the modulus + exponent out of the
/// `plaintext` buffer that was passed to `verify_server_flight`.
///
/// The `'a` lifetime always binds to the `plaintext` buffer even when the
/// only inhabited variant is `Ed25519`; that keeps `ServerFlightVerified<'a>`
/// + `verify_server_flight<'a>` signatures stable across feature configs.
///
/// The Ed25519 variant carries a zero-sized `PhantomData<&'a ()>` so the
/// enum-level lifetime is in scope without any runtime cost.
#[derive(Debug, Clone, Copy)]
pub enum ServerPubkey<'a> {
    /// 32-byte Ed25519 pubkey (RFC 8410). Owned by value — pubkey is tiny.
    /// The phantom binds the enum's lifetime parameter without contributing
    /// any storage.
    Ed25519([u8; 32], core::marker::PhantomData<&'a ()>),
    /// RSA modulus + exponent. Borrowed: the modulus is up to 256 B; the
    /// caller's `cert_view` owns it.
    #[cfg(feature = "rsa")]
    Rsa { modulus: &'a [u8], exponent: u32 },
}

impl<'a> ServerPubkey<'a> {
    /// Construct an Ed25519 variant. Hides the `PhantomData` plumbing.
    pub fn ed25519(pubkey: [u8; 32]) -> Self {
        ServerPubkey::Ed25519(pubkey, core::marker::PhantomData)
    }

    /// If the variant is Ed25519, return the 32-byte pubkey.
    pub fn as_ed25519(&self) -> Option<[u8; 32]> {
        match self {
            ServerPubkey::Ed25519(pk, _) => Some(*pk),
            #[cfg(feature = "rsa")]
            ServerPubkey::Rsa { .. } => None,
        }
    }

    /// If the variant is RSA, return the `(modulus, exponent)` pair.
    #[cfg(feature = "rsa")]
    pub fn as_rsa(&self) -> Option<(&'a [u8], u32)> {
        match self {
            ServerPubkey::Rsa { modulus, exponent } => Some((*modulus, *exponent)),
            ServerPubkey::Ed25519(_, _) => None,
        }
    }
}

/// End-to-end result of `verify_server_flight`.
///
/// The transcript hash after server Finished lives on the caller's
/// [`TranscriptHash`] — pull it with `transcript.snapshot()` after this
/// function returns. Keeping the hash off this struct prevents callers from
/// accidentally feeding a *different* transcript object into downstream
/// derivations (client Finished, application traffic secrets).
#[derive(Debug, Clone, Copy)]
pub struct ServerFlightVerified<'a> {
    pub server_pubkey: ServerPubkey<'a>,
}

/// Run the three server-flight verifications back-to-back, threading the
/// transcript hash through them.
///
/// **Precondition:** `transcript` has already absorbed the ClientHello and
/// ServerHello records (the caller fed them with `update_record`). On return,
/// the transcript reflects the full handshake through server Finished, which
/// is what the client Finished MAC and the application traffic secrets need
/// next.
pub fn verify_server_flight<'a, H: HkdfSha256, C: CertParser, E: Ed25519Verify>(
    transcript: &mut TranscriptHash<H>,
    plaintext: &'a [u8],
    s_hs_traffic_secret: &Secret,
) -> Result<ServerFlightVerified<'a>, FlightError> {
    let flight = parse_server_flight(plaintext)?;

    // Build the ed25519 verify cache ONCE — both verifications below run
    // against the same backend and share the per-curve precompute. Saves
    // one `Curve25519Field::new` call (~100-150k M3 cycles) per handshake
    // for the `RustCrypto` backend; no-op for backends with `Cache = ()`.
    let ed_cache = E::new_cache();

    let cert_der = extract_cert_der(flight.cert_body)?;
    let cert_view = C::parse(cert_der)?;

    // If this is an RSA cert, build the `RsaVerifierKey` ONCE and share it
    // across the self-sig + CertVerify checks below. The cost
    // (`ModMathParams::new`) is ~400-800k cycles for U2048 on M3 and would
    // otherwise be paid twice. Ed25519 certs get `None` and pay nothing.
    #[cfg(feature = "rsa")]
    let rsa_cache: Option<crate::backends::rsa_verify::RsaVerifierKey> = match &cert_view {
        CertView::Rsa {
            modulus, exponent, ..
        } => Some(
            crate::backends::rsa_verify::RsaVerifierKey::new(modulus, *exponent)
                .map_err(|_| FlightError::CertSelfSignatureInvalid)?,
        ),
        _ => None,
    };

    // 1. Cert self-sig.
    verify_self_signed_cert_with_cache::<E>(
        &ed_cache,
        &cert_view,
        #[cfg(feature = "rsa")]
        rsa_cache.as_ref(),
    )?;

    // 2. CertVerify against SHA-256(CH || SH || EE || Cert). EE + Cert are
    //    inner-handshake bytes (no record header) so they go through `.update`.
    transcript.update(flight.ee_full);
    transcript.update(flight.cert_full);
    let th_after_cert = transcript.snapshot();
    verify_certificate_verify_with_cache::<E>(
        &ed_cache,
        &cert_view,
        &th_after_cert,
        flight.cv_body,
        #[cfg(feature = "rsa")]
        rsa_cache.as_ref(),
    )?;

    // 3. Finished MAC against SHA-256(CH || SH || EE || Cert || CertVerify).
    transcript.update(flight.cv_full);
    let th_after_cv = transcript.snapshot();
    verify_server_finished::<H>(s_hs_traffic_secret, &th_after_cv, flight.fin_body)?;

    // Hash forward through Finished so the caller's transcript covers the
    // full "ClientHello..server Finished" range expected by RFC 8446 §7.1.
    transcript.update(flight.fin_full);

    let server_pubkey = match cert_view {
        CertView::Ed25519 { pubkey, .. } => ServerPubkey::ed25519(*pubkey),
        #[cfg(feature = "rsa")]
        CertView::Rsa {
            modulus, exponent, ..
        } => ServerPubkey::Rsa { modulus, exponent },
    };
    Ok(ServerFlightVerified { server_pubkey })
}
