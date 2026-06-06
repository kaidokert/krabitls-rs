//! TLS 1.3 record-layer encrypt / decrypt on top of the
//! [`Aes128GcmAead`](crate::traits::Aes128GcmAead) trait.
//!
//! Trait definition lives in [`crate::traits::aead`]. This module owns the
//! `decrypt_record` / `encrypt_record` / `aead_nonce` helpers and their
//! error types.

#[cfg(feature = "chacha20")]
use crate::newtype::AeadKey32;
use crate::newtype::{AeadIv, AeadKey, ZeroBuf};
use crate::traits::Aes128GcmAead;
#[cfg(feature = "chacha20")]
use crate::traits::ChaCha20Poly1305Aead;

/// Per-record AEAD nonce: `iv` XOR `seq` (8-byte sequence number,
/// big-endian, left-padded). RFC 8446 §5.3.
///
/// Returned wrapped in [`ZeroBuf`] so the nonce bytes don't linger on
/// the caller's stack after the AEAD operation. The nonce is
/// `IV XOR seq_be`; the seq is a public counter, so leaking the nonce
/// is equivalent to leaking the secret IV. Same hygiene level as
/// [`AeadIv`] itself.
pub fn aead_nonce(iv: &AeadIv, seq: u64) -> ZeroBuf<12> {
    let seq_be = seq.to_be_bytes(); // 8 bytes
    let mut nonce = ZeroBuf::<12>::new(*iv.as_bytes());
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
    decrypt_record_with(record, iv, seq, plaintext_buf, |nonce, aad, pt, tag| {
        A::decrypt(key.as_zeroizing(), nonce, aad, pt, tag)
    })
}

/// `decrypt_record` for the `TLS_CHACHA20_POLY1305_SHA256` suite.
#[cfg(feature = "chacha20")]
pub fn decrypt_record_chacha<'a, C: ChaCha20Poly1305Aead>(
    record: &[u8],
    key: &AeadKey32,
    iv: &AeadIv,
    seq: u64,
    plaintext_buf: &'a mut [u8],
) -> Result<&'a [u8], DecryptError> {
    decrypt_record_with(record, iv, seq, plaintext_buf, |nonce, aad, pt, tag| {
        C::decrypt(key.as_zeroizing(), nonce, aad, pt, tag)
    })
}

/// Shared record-layer decrypt; the closure performs the AEAD verify+decrypt.
fn decrypt_record_with<'a, F>(
    record: &[u8],
    iv: &AeadIv,
    seq: u64,
    plaintext_buf: &'a mut [u8],
    aead_decrypt: F,
) -> Result<&'a [u8], DecryptError>
where
    F: FnOnce(&ZeroBuf<12>, &[u8], &mut [u8], &[u8; 16]) -> Result<(), crate::traits::AeadError>,
{
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
    // Reject trailing bytes so callers do not accidentally drop a second record.
    if record.len() != 5 + body_len {
        return Err(DecryptError::TrailingBytes);
    }

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

    let nonce = aead_nonce(iv, seq);
    let aad = &record[..5];
    match aead_decrypt(&nonce, aad, plaintext, &tag) {
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

/// Split TLS 1.3 inner plaintext into content and content type.
pub fn split_inner_plaintext(inner: &[u8]) -> Result<(&[u8], u8), DecryptError> {
    let mut end = inner.len();
    while end > 0 && inner[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return Err(DecryptError::EmptyInnerPlaintext);
    }
    if end - 1 > TLS_PLAINTEXT_MAX {
        return Err(DecryptError::RecordTooLarge);
    }
    let content_type = inner[end - 1];
    Ok((&inner[..end - 1], content_type))
}

/// Encrypt one TLS 1.3 inner plaintext into an application_data record.
pub fn encrypt_record<'a, A: Aes128GcmAead>(
    content: &[u8],
    content_type: u8,
    key: &AeadKey,
    iv: &AeadIv,
    seq: u64,
    out_buf: &'a mut [u8],
) -> Result<&'a [u8], EncryptError> {
    encrypt_record_with(
        content,
        content_type,
        iv,
        seq,
        out_buf,
        |nonce, aad, buf| A::encrypt(key.as_zeroizing(), nonce, aad, buf),
    )
}

/// `encrypt_record` for the `TLS_CHACHA20_POLY1305_SHA256` suite.
#[cfg(feature = "chacha20")]
pub fn encrypt_record_chacha<'a, C: ChaCha20Poly1305Aead>(
    content: &[u8],
    content_type: u8,
    key: &AeadKey32,
    iv: &AeadIv,
    seq: u64,
    out_buf: &'a mut [u8],
) -> Result<&'a [u8], EncryptError> {
    encrypt_record_with(
        content,
        content_type,
        iv,
        seq,
        out_buf,
        |nonce, aad, buf| C::encrypt(key.as_zeroizing(), nonce, aad, buf),
    )
}

/// Shared record-layer encrypt; the closure performs the AEAD seal.
fn encrypt_record_with<'a, F>(
    content: &[u8],
    content_type: u8,
    iv: &AeadIv,
    seq: u64,
    out_buf: &'a mut [u8],
    aead_encrypt: F,
) -> Result<&'a [u8], EncryptError>
where
    F: FnOnce(&ZeroBuf<12>, &[u8], &mut [u8]) -> [u8; 16],
{
    // TLSPlaintext.length cap (RFC 8446 §5.1): the inner-plaintext content
    // must not exceed 2^14 bytes. This is *separate* from the §5.2
    // ciphertext-body cap below — without it, callers could pass content in
    // [2^14+1, 2^14+255] which fits the ciphertext cap but produces records
    // a spec-compliant peer will reject.
    if content.len() > TLS_PLAINTEXT_MAX {
        return Err(EncryptError::RecordTooLarge);
    }
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

    // The cipher_body_len <= TLS_CIPHERTEXT_MAX (= 2^14 + 256 = 16640) cap
    // above means the `as u16` cast here is provably non-truncating.
    // Build the AAD directly (no `try_into().expect(...)`), then copy it
    // into the buffer. The header IS the AAD by definition; constructing
    // it once eliminates a panic path.
    let legacy = crate::consts::LEGACY_VERSION.to_be_bytes();
    let body_len_be = (cipher_body_len as u16).to_be_bytes();
    let aad: [u8; 5] = [
        crate::consts::CT_APPLICATION_DATA,
        legacy[0],
        legacy[1],
        body_len_be[0],
        body_len_be[1],
    ];
    out_buf[..5].copy_from_slice(&aad);

    out_buf[5..5 + content.len()].copy_from_slice(content);
    out_buf[5 + content.len()] = content_type;

    let nonce = aead_nonce(iv, seq);
    let tag = aead_encrypt(&nonce, &aad, &mut out_buf[5..5 + inner_len]);
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
