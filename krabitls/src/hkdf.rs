//! TLS 1.3 key-schedule helpers on top of the
//! [`HkdfSha256`](crate::traits::HkdfSha256) trait.
//!
//! Trait definitions (`HkdfSha256`, `Sha256Hasher`, `HkdfExpandError`)
//! live in [`crate::traits::hkdf`]. This module owns the TLS-1.3-specific
//! key-schedule layer: `early_secret`, `handshake_secret`, `derive_secret`,
//! `traffic_keys`, `application_traffic_secrets`, `finished_mac`, the
//! `TranscriptHash` running-hash wrapper, the `hkdf_expand_label`
//! encoder, and the `HkdfLabelError` enum.

use crate::newtype::{AeadIv, AeadKey, Secret, TranscriptDigest};
use crate::traits::{HkdfExpandError, HkdfSha256, Sha256Hasher};

// =====================================================================
// TLS 1.3 derivation helpers built on top of the HKDF trait.
// =====================================================================

/// Maximum size of the encoded `HkdfLabel` struct in TLS 1.3.
///
/// `HkdfLabel = uint16 length || opaque label<7..255> || opaque context<0..255>`.
/// All TLS 1.3 labels are short (longest is `"derived"` or `"finished"`, both
/// under 16 chars after the `"tls13 "` prefix), and the context is at most a
/// 32-byte transcript hash. 64 bytes is a comfortable upper bound that fits
/// every standard label.
const HKDF_LABEL_MAX: usize = 64;

/// Errors while encoding a TLS 1.3 `HkdfLabel`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HkdfLabelError {
    /// The requested output length does not fit in the `uint16 length` field.
    OutputTooLong,
    /// `"tls13 " || label` does not fit in the TLS vector's `u8` length field.
    LabelTooLong,
    /// The context does not fit in the TLS vector's `u8` length field.
    ContextTooLong,
    /// The encoded label exceeds krabitls's fixed scratch buffer.
    EncodedTooLong,
    /// The HKDF backend rejected the requested output length.
    Expand(HkdfExpandError),
}

impl From<heapless::CapacityError> for HkdfLabelError {
    fn from(_: heapless::CapacityError) -> Self {
        HkdfLabelError::EncodedTooLong
    }
}

impl From<HkdfExpandError> for HkdfLabelError {
    fn from(e: HkdfExpandError) -> Self {
        HkdfLabelError::Expand(e)
    }
}

/// `HKDF-Expand-Label(secret, label, context, len)` per RFC 8446 §7.1.
///
/// Builds the `HkdfLabel` structure and dispatches to [`HkdfSha256::expand`].
/// Returns an error instead of panicking if a caller supplies non-TLS-sized
/// inputs. All labels used by krabitls's own TLS 1.3 key schedule are fixed
/// short strings and fit by construction.
pub fn hkdf_expand_label<H: HkdfSha256>(
    secret: &[u8; 32],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), HkdfLabelError> {
    const PREFIX: &[u8] = b"tls13 ";

    // Encoding-limit checks for the length fields the wire format carries.
    // The Vec capacity below covers EncodedTooLong on its own.
    if out.len() > u16::MAX as usize {
        return Err(HkdfLabelError::OutputTooLong);
    }
    let label_total = PREFIX.len() + label.len();
    if label_total > u8::MAX as usize {
        return Err(HkdfLabelError::LabelTooLong);
    }
    if context.len() > u8::MAX as usize {
        return Err(HkdfLabelError::ContextTooLong);
    }

    // HkdfLabel wire format:
    //   uint16 length
    //   opaque label<7..255>    = u8(len) || "tls13 " || label
    //   opaque context<0..255>  = u8(len) || context
    let mut info: heapless::Vec<u8, HKDF_LABEL_MAX> = heapless::Vec::new();
    info.extend_from_slice(&(out.len() as u16).to_be_bytes())?;
    info.extend_from_slice(&[label_total as u8])?;
    info.extend_from_slice(PREFIX)?;
    info.extend_from_slice(label)?;
    info.extend_from_slice(&[context.len() as u8])?;
    info.extend_from_slice(context)?;

    H::expand(secret, &info, out)?;
    Ok(())
}

fn hkdf_expand_label_tls<H: HkdfSha256>(
    secret: &[u8; 32],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) {
    hkdf_expand_label::<H>(secret, label, context, out)
        .expect("krabitls's fixed TLS 1.3 HKDF labels fit HKDF_LABEL_MAX")
}

/// `Derive-Secret(secret, label, transcript_hash)` per RFC 8446 §7.1.
///
/// This is `HKDF-Expand-Label` specialized to a 32-byte transcript-hash
/// context and a 32-byte output, the shape used everywhere in the TLS 1.3
/// key schedule.
pub fn derive_secret<H: HkdfSha256>(
    secret: &Secret,
    label: &[u8],
    transcript_hash: &TranscriptDigest,
) -> Result<Secret, HkdfLabelError> {
    let mut out = [0u8; 32];
    hkdf_expand_label::<H>(
        secret.as_bytes(),
        label,
        transcript_hash.as_bytes(),
        &mut out,
    )?;
    Ok(Secret::new(out))
}

fn derive_secret_tls<H: HkdfSha256>(
    secret: &Secret,
    label: &[u8],
    transcript_hash: &TranscriptDigest,
) -> Secret {
    derive_secret::<H>(secret, label, transcript_hash)
        .expect("krabitls's fixed TLS 1.3 HKDF labels fit HKDF_LABEL_MAX")
}

// =====================================================================
// TLS 1.3 key schedule wired up end-to-end.
//
// All transcript hashes here are SHA-256 of the concatenated handshake
// messages (the inner body, NOT the TLS record header) up to and
// including the latest message — see RFC 8446 §4.4.1.
// =====================================================================

/// `SHA-256("")` — the empty-transcript hash used by `Derive-Secret(., x, "")`.
pub const EMPTY_TRANSCRIPT_HASH: TranscriptDigest = TranscriptDigest::new([
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
]);

/// Running SHA-256 over the TLS 1.3 handshake transcript (RFC 8446 §4.4.1).
///
/// Owns the incremental hasher state so each handshake message gets fed in
/// exactly once. The wrapper exposes two `update_*` flavors — one that takes
/// a TLS *record* (5-byte header + handshake body) and strips the header, and
/// one that takes raw handshake-message bytes — so callers don't have to
/// remember to do `&record[5..]` slicing themselves (which was the original
/// bug class).
///
/// Snapshots clone the hasher state, so a single `TranscriptHash` covers
/// every intermediate hash boundary the TLS 1.3 handshake needs (after CH+SH
/// for handshake traffic secrets, after each verification step inside the
/// server flight, and after server Finished for client Finished + app traffic
/// secrets).
pub struct TranscriptHash<H: HkdfSha256> {
    hasher: H::Hasher,
}

impl<H: HkdfSha256> TranscriptHash<H> {
    /// Start with an empty transcript.
    pub fn new() -> Self {
        Self {
            hasher: H::hasher(),
        }
    }

    /// Feed a complete TLS record (5-byte record header + handshake-message
    /// body). The transcript hash covers only the handshake-message bytes per
    /// RFC 8446 §4.4.1, so the 5-byte header is stripped internally.
    ///
    /// Returns `Err(TranscriptError::RecordTooShort)` if `record.len() < 5`.
    pub fn update_record(&mut self, record: &[u8]) -> Result<(), TranscriptError> {
        if record.len() < 5 {
            return Err(TranscriptError::RecordTooShort);
        }
        self.hasher.update(&record[5..]);
        Ok(())
    }

    /// Feed raw handshake-message bytes that have no TLS record header.
    /// Use this for inner handshake messages recovered from decrypted records
    /// (EncryptedExtensions / Certificate / CertificateVerify / Finished).
    pub fn update(&mut self, msg: &[u8]) {
        self.hasher.update(msg);
    }

    /// Snapshot the transcript hash at the current point without consuming
    /// the hasher. Cheap (a clone of the SHA-256 state + a finalize call).
    pub fn snapshot(&self) -> TranscriptDigest {
        TranscriptDigest::new(self.hasher.clone().finalize())
    }
}

impl<H: HkdfSha256> Default for TranscriptHash<H> {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors returnable by [`TranscriptHash::update_record`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TranscriptError {
    /// `update_record` was called with a slice shorter than the 5-byte TLS
    /// record header — almost always a caller bug (wrong slice end).
    RecordTooShort,
}

/// `early_secret` for no-PSK: `HKDF-Extract(salt=00..00, IKM=00..00)`. RFC 8446 §7.1.
pub fn early_secret<H: HkdfSha256>() -> Secret {
    let zeros = [0u8; 32];
    Secret::new(H::extract(&zeros, &zeros))
}

/// `handshake_secret = HKDF-Extract(Derive-Secret(early_secret, "derived", H("")), DHE)`.
///
/// `dhe` is the X25519 shared secret (output of `ed25519_heapless::x25519` or
/// any other (EC)DHE algorithm — krabitls doesn't care, it's 32 bytes).
pub fn handshake_secret<H: HkdfSha256>(dhe: &[u8; 32]) -> Secret {
    let salt = derive_secret_tls::<H>(&early_secret::<H>(), b"derived", &EMPTY_TRANSCRIPT_HASH);
    Secret::new(H::extract(salt.as_bytes(), dhe))
}

/// `(client_handshake_traffic_secret, server_handshake_traffic_secret)` from
/// `handshake_secret` and `transcript_hash(ClientHello || ServerHello)`.
pub fn handshake_traffic_secrets<H: HkdfSha256>(
    hs: &Secret,
    transcript_hash_ch_sh: &TranscriptDigest,
) -> (Secret, Secret) {
    (
        derive_secret_tls::<H>(hs, b"c hs traffic", transcript_hash_ch_sh),
        derive_secret_tls::<H>(hs, b"s hs traffic", transcript_hash_ch_sh),
    )
}

/// Derive the `(key, iv)` pair for AES-128-GCM from a traffic secret per
/// RFC 8446 §7.3. Key is 16 bytes, IV is 12 bytes (the AEAD nonce size).
pub fn traffic_keys<H: HkdfSha256>(traffic_secret: &Secret) -> (AeadKey, AeadIv) {
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    hkdf_expand_label_tls::<H>(traffic_secret.as_bytes(), b"key", &[], &mut key);
    hkdf_expand_label_tls::<H>(traffic_secret.as_bytes(), b"iv", &[], &mut iv);
    (AeadKey::new(key), AeadIv::new(iv))
}

/// `master_secret = HKDF-Extract(Derive-Secret(handshake_secret, "derived", H("")), 0_hash)`
/// per RFC 8446 §7.1.
pub fn master_secret<H: HkdfSha256>(handshake_secret: &Secret) -> Secret {
    let salt = derive_secret_tls::<H>(handshake_secret, b"derived", &EMPTY_TRANSCRIPT_HASH);
    Secret::new(H::extract(salt.as_bytes(), &[0u8; 32]))
}

/// `(client_application_traffic_secret_0, server_application_traffic_secret_0)`
/// from `master_secret` and `transcript_hash(CH..server Finished)` (RFC 8446 §7.1).
///
/// Note: the transcript hash here ends at the *server's* Finished — the
/// client's own Finished does NOT enter the app-traffic-secret derivation.
pub fn application_traffic_secrets<H: HkdfSha256>(
    master_secret: &Secret,
    transcript_hash_through_server_finished: &TranscriptDigest,
) -> (Secret, Secret) {
    (
        derive_secret_tls::<H>(
            master_secret,
            b"c ap traffic",
            transcript_hash_through_server_finished,
        ),
        derive_secret_tls::<H>(
            master_secret,
            b"s ap traffic",
            transcript_hash_through_server_finished,
        ),
    )
}

/// Finished MAC: HMAC-SHA256 keyed by `finished_key` over the running
/// transcript hash. Used for both server and client Finished verify_data —
/// the only thing that changes is which traffic secret you derive
/// `finished_key` from.
///
/// Returns the raw 32-byte MAC (not wrapped in `Secret` — it's verify_data,
/// not key material, and gets compared against the wire bytes immediately).
pub fn finished_mac<H: HkdfSha256>(
    traffic_secret: &Secret,
    transcript_hash: &TranscriptDigest,
) -> [u8; 32] {
    let mut finished_key = [0u8; 32];
    hkdf_expand_label_tls::<H>(
        traffic_secret.as_bytes(),
        b"finished",
        &[],
        &mut finished_key,
    );
    // HKDF-Extract(salt, IKM) == HMAC(salt, IKM) under SHA-256.
    H::extract(&finished_key, transcript_hash.as_bytes())
}
