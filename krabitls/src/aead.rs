//! TLS 1.3 record-layer encrypt / decrypt on top of the
//! [`Aes128GcmAead`](crate::traits::Aes128GcmAead) trait.
//!
//! Trait definition lives in [`crate::traits::aead`]. This module owns the
//! `decrypt_record` / `encrypt_record` / `aead_nonce` helpers and their
//! error types.

use crate::newtype::{AeadIv, AeadKey};
use crate::traits::Aes128GcmAead;

/// Per-record AEAD nonce: `iv` XOR `seq` (8-byte sequence number,
/// big-endian, left-padded). RFC 8446 §5.3.
#[inline]
pub fn aead_nonce(iv: &AeadIv, seq: u64) -> [u8; 12] {
    let seq_be = seq.to_be_bytes(); // 8 bytes
    let mut nonce = *iv.as_bytes();
    // XOR seq into the low 8 bytes of the IV (high 4 bytes untouched).
    for i in 0..8 {
        nonce[4 + i] ^= seq_be[i];
    }
    nonce
}

/// Decrypt one TLS 1.3 application_data-wrapped record.
///
/// `record` is the full record including its 5-byte header. The record is
/// validated to be `application_data / 0x0303 / len` and then the body's tag
/// is verified and its ciphertext decrypted into `plaintext_buf`. Returns the
/// slice of `plaintext_buf` containing the plaintext (which is then a
/// `TLSInnerPlaintext`; call [`split_inner_plaintext`] to peel off the
/// content_type byte and trailing zero padding).
pub fn decrypt_record<'a, A: Aes128GcmAead>(
    record: &[u8],
    key: &AeadKey,
    iv: &AeadIv,
    seq: u64,
    plaintext_buf: &'a mut [u8],
) -> Result<&'a [u8], DecryptError> {
    // ---- record header ----
    if record.len() < 5 {
        return Err(DecryptError::Truncated);
    }
    let content_type = record[0];
    if content_type != crate::consts::CT_APPLICATION_DATA {
        return Err(DecryptError::UnexpectedContentType(content_type));
    }
    let legacy_version = u16::from_be_bytes([record[1], record[2]]);
    if legacy_version != crate::consts::LEGACY_VERSION {
        return Err(DecryptError::UnexpectedLegacyVersion(legacy_version));
    }
    let body_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    // RFC 8446 §5.2 caps TLSCiphertext.length at 2^14 + 256. Symmetric with
    // the encrypt path's `TLS_CIPHERTEXT_MAX` enforcement.
    if body_len > TLS_CIPHERTEXT_MAX {
        return Err(DecryptError::RecordTooLarge);
    }
    if record.len() < 5 + body_len {
        return Err(DecryptError::Truncated);
    }
    // Strict: caller must pass exactly one record. Bytes past `5 + body_len`
    // would be a second record we'd silently ignore — surface them instead.
    // (Switch to `Ok((plaintext, consumed))` if/when we add multi-record
    // server-flight support — see PRODUCTION_GAPS #4 / #21.)
    if record.len() != 5 + body_len {
        return Err(DecryptError::TrailingBytes);
    }

    // ---- body = ciphertext || 16-byte tag ----
    if body_len < 16 {
        return Err(DecryptError::Truncated);
    }
    let ct_len = body_len - 16;
    let body = &record[5..5 + body_len];
    let (ciphertext, tag_slice) = body.split_at(ct_len);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(tag_slice);

    if plaintext_buf.len() < ct_len {
        return Err(DecryptError::BufferTooSmall {
            needed: ct_len,
            got: plaintext_buf.len(),
        });
    }
    let plaintext = &mut plaintext_buf[..ct_len];
    plaintext.copy_from_slice(ciphertext);

    // ---- AEAD ----
    let nonce = aead_nonce(iv, seq);
    let aad = &record[..5];
    match A::decrypt(key.as_bytes(), &nonce, aad, plaintext, &tag) {
        Ok(()) => Ok(plaintext),
        Err(_) => {
            // AEAD verification failed: the buffer currently holds either
            // ciphertext (if the AEAD impl never wrote) or the decrypted-
            // with-this-key-anyway plaintext (if it wrote before checking
            // the tag, common for in-place AEADs). The contract says
            // callers MUST NOT use the buffer on Err, but a defensive
            // zeroize closes the hole if a caller forgets.
            use zeroize::Zeroize;
            plaintext.zeroize();
            Err(DecryptError::AeadFailed)
        }
    }
}

/// Split a TLS 1.3 `TLSInnerPlaintext` (content || content_type || zero
/// padding) into its inner content and `content_type` byte. RFC 8446 §5.2.
///
/// Enforces the §5.4 cap: after padding is stripped, the
/// `TLSInnerPlaintext.content` may not exceed `2^14` bytes (the
/// content + content_type byte together fit in `2^14 + 1`). The
/// ciphertext cap that gated [`decrypt_record`] permits up to `2^14 +
/// 256` (the AEAD-overhead allowance), so a peer can construct a
/// record whose ciphertext fits but whose plaintext fragment violates
/// the §5.4 limit; this check surfaces that as `RecordTooLarge`.
pub fn split_inner_plaintext(inner: &[u8]) -> Result<(&[u8], u8), DecryptError> {
    let mut end = inner.len();
    while end > 0 && inner[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return Err(DecryptError::EmptyInnerPlaintext);
    }
    // After stripping padding, the remaining bytes are `content || content_type`
    // (= `end` bytes total). `content.len() = end - 1` must be <= 2^14.
    if end - 1 > TLS_PLAINTEXT_MAX {
        return Err(DecryptError::RecordTooLarge);
    }
    let content_type = inner[end - 1];
    Ok((&inner[..end - 1], content_type))
}

/// Encrypt one piece of TLS 1.3 inner plaintext into an application_data record.
///
/// Builds `header(5) || aead_encrypt(plaintext || content_type, key, nonce, aad=header) || tag(16)`
/// into `out_buf` and returns the slice covering the record bytes. No padding.
pub fn encrypt_record<'a, A: Aes128GcmAead>(
    content: &[u8],
    content_type: u8,
    key: &AeadKey,
    iv: &AeadIv,
    seq: u64,
    out_buf: &'a mut [u8],
) -> Result<&'a [u8], EncryptError> {
    // TLSPlaintext.length cap (RFC 8446 §5.1): the inner-plaintext content
    // must not exceed 2^14 bytes. This is *separate* from the §5.2
    // ciphertext-body cap below — without it, callers could pass content in
    // [2^14+1, 2^14+255] which fits the ciphertext cap but produces records
    // a spec-compliant peer will reject.
    if content.len() > TLS_PLAINTEXT_MAX {
        return Err(EncryptError::RecordTooLarge);
    }
    // Inner plaintext = content || content_type (1 byte); no zero padding.
    let inner_len = content
        .len()
        .checked_add(1)
        .ok_or(EncryptError::RecordTooLarge)?;
    let cipher_body_len = inner_len
        .checked_add(AEAD_TAG_LEN)
        .ok_or(EncryptError::RecordTooLarge)?;
    let total_len = cipher_body_len
        .checked_add(5)
        .ok_or(EncryptError::RecordTooLarge)?;
    // TLSCiphertext.length cap (RFC 8446 §5.2): the encrypted body
    // (inner_plaintext || tag) must fit in 2^14 + 256 bytes.
    if cipher_body_len > TLS_CIPHERTEXT_MAX {
        return Err(EncryptError::RecordTooLarge);
    }
    if out_buf.len() < total_len {
        return Err(EncryptError::BufferTooSmall {
            needed: total_len,
            got: out_buf.len(),
        });
    }

    // ---- record header ----
    // The cipher_body_len <= TLS_CIPHERTEXT_MAX (= 2^14 + 256 = 16640) cap
    // above means the `as u16` cast here is provably non-truncating.
    out_buf[0] = crate::consts::CT_APPLICATION_DATA;
    out_buf[1..3].copy_from_slice(&crate::consts::LEGACY_VERSION.to_be_bytes());
    out_buf[3..5].copy_from_slice(&(cipher_body_len as u16).to_be_bytes());
    let aad: [u8; 5] = out_buf[..5].try_into().expect("header slice is 5 bytes");

    // ---- inner plaintext ----
    out_buf[5..5 + content.len()].copy_from_slice(content);
    out_buf[5 + content.len()] = content_type;

    // ---- AEAD seal ----
    let nonce = aead_nonce(iv, seq);
    let tag = A::encrypt(key.as_bytes(), &nonce, &aad, &mut out_buf[5..5 + inner_len]);
    out_buf[5 + inner_len..5 + inner_len + AEAD_TAG_LEN].copy_from_slice(&tag);

    Ok(&out_buf[..total_len])
}

const AEAD_TAG_LEN: usize = 16;

/// TLS 1.3 `TLSPlaintext.length` cap (RFC 8446 §5.1 / §5.4): the
/// inner-plaintext content (before the `content_type` byte and any
/// zero padding) must not exceed `2^14` bytes.
const TLS_PLAINTEXT_MAX: usize = 1 << 14;

/// TLS 1.3 `TLSCiphertext.length` cap (RFC 8446 §5.2): the encrypted body
/// (inner plaintext + AEAD tag) must not exceed `2^14 + 256` bytes.
const TLS_CIPHERTEXT_MAX: usize = (1 << 14) + 256;

/// Reasons an `encrypt_record` call may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EncryptError {
    /// `out_buf` cannot fit the resulting record.
    BufferTooSmall { needed: usize, got: usize },
    /// Plaintext is too large to fit in a single TLS 1.3 record. Hits
    /// either the `TLSPlaintext.length` cap (`2^14`, RFC 8446 §5.1) or
    /// the `TLSCiphertext.length` cap (`2^14 + 256`, §5.2). Caller must
    /// split across multiple records.
    RecordTooLarge,
}

/// Reasons a `decrypt_record` call may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DecryptError {
    /// Record shorter than its declared length, or shorter than `5 + tag_len`.
    Truncated,
    /// Record size exceeds spec. Fires for `TLSCiphertext.length > 2^14 +
    /// 256` (RFC 8446 §5.2, in [`decrypt_record`]) or for an inner-plaintext
    /// content longer than `2^14` after padding stripping (§5.1 / §5.4, in
    /// [`split_inner_plaintext`]). Symmetric with
    /// [`EncryptError::RecordTooLarge`].
    RecordTooLarge,
    /// Bytes left in `record` after the declared `5 + body_len`. Almost
    /// always means the caller handed in more than one TLS record at once.
    TrailingBytes,
    /// Record `content_type` wasn't `application_data` (23).
    UnexpectedContentType(u8),
    /// Record `legacy_version` wasn't 0x0303.
    UnexpectedLegacyVersion(u16),
    /// `plaintext_buf` cannot fit the ciphertext (= plaintext length).
    BufferTooSmall { needed: usize, got: usize },
    /// AES-128-GCM tag verification failed — almost certainly a wrong key or
    /// tampered ciphertext.
    AeadFailed,
    /// `TLSInnerPlaintext` was all zeros — has no `content_type` byte.
    EmptyInnerPlaintext,
}
