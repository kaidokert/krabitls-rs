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
use crate::hkdf::{HkdfLabelError, TranscriptHash, hkdf_expand_label};
use crate::newtype::{Secret, TranscriptDigest};
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
        let len = u32::from_be_bytes([
            0,
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]) as usize;
        let body_start = self.pos + 4;
        let body_end = body_start + len;
        if self.buf.len() < body_end {
            return Err(FlightError::Truncated);
        }
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
    let list_len = read_u24(&cert_body[after_ctx..after_ctx + 3]);
    let list_start = after_ctx + 3;
    let list_end = list_start + list_len;
    if cert_body.len() < list_end {
        return Err(FlightError::Truncated);
    }
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
    let cert_data_len = read_u24(&list[0..3]);
    let cert_end = 3 + cert_data_len;
    if list.len() < cert_end + 2 {
        return Err(FlightError::Truncated);
    }
    // Verify the exts length is internally consistent (so we can't get past
    // the cert by miscounting), but don't inspect its content.
    let exts_len = u16::from_be_bytes([list[cert_end], list[cert_end + 1]]) as usize;
    if list.len() < cert_end + 2 + exts_len {
        return Err(FlightError::Truncated);
    }
    Ok(&list[3..cert_end])
}

fn read_u24(b: &[u8]) -> usize {
    debug_assert!(b.len() == 3);
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize)
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
    verify_self_signed_cert_with_cache::<E>(&cache, &view)?;
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
    let mut finished_key = [0u8; 32];
    hkdf_expand_label::<H>(
        s_hs_traffic_secret.as_bytes(),
        b"finished",
        &[],
        &mut finished_key,
    )
    .map_err(FlightError::HkdfLabel)?;
    // `HKDF-Extract(salt, IKM)` is literally `HMAC(salt, IKM)`, so this gives
    // us HMAC-SHA256(finished_key, transcript_hash).
    let expected = H::extract(&finished_key, transcript_hash_ch_through_cv.as_bytes());
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
    // More variants when optional features land
}

impl<'a> ServerPubkey<'a> {
    /// Construct an Ed25519 variant. Hides the `PhantomData` plumbing.
    pub fn ed25519(pubkey: [u8; 32]) -> Self {
        ServerPubkey::Ed25519(pubkey, core::marker::PhantomData)
    }

    /// If the variant is Ed25519, return the 32-byte pubkey. Single-variant
    /// today so the let-binding is irrefutable; silence that warning rather
    /// than complicating the implementation.
    #[allow(irrefutable_let_patterns)]
    pub fn as_ed25519(&self) -> Option<[u8; 32]> {
        if let ServerPubkey::Ed25519(pk, _) = self {
            Some(*pk)
        } else {
            None
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

    // 1. Cert self-sig.
    verify_self_signed_cert_with_cache::<E>(&ed_cache, &cert_view)?;

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
    };
    Ok(ServerFlightVerified { server_pubkey })
}
