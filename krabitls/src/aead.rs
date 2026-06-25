//! TLS 1.3 record-layer encrypt / decrypt.

use crate::newtype::{AeadIv, ZeroBuf};
use ::aead::generic_array::GenericArray;
use ::aead::{AeadCore, AeadInPlace, KeyInit};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// Per-record AEAD nonce: `iv` XOR `seq` (8-byte sequence number,
/// big-endian, left-padded). RFC 8446 §5.3.
pub(crate) fn aead_nonce(iv: &AeadIv, seq: u64) -> ZeroBuf<12> {
    let seq_be = seq.to_be_bytes();
    let mut nonce = ZeroBuf::<12>::new(*iv.as_bytes());
    for (n, s) in nonce[4..12].iter_mut().zip(seq_be) {
        *n ^= s;
    }
    nonce
}

/// Decrypt one TLS 1.3 application_data-wrapped record.
///
/// On `Ok` the returned slice is `TLSInnerPlaintext`; call
/// [`split_inner_plaintext`] to peel off the content_type byte and padding.
#[cfg(test)]
pub(crate) fn decrypt_record<'a, S: CipherSuite>(
    record: &[u8],
    key: &zeroize::Zeroizing<S::KeyBytes>,
    iv: &AeadIv,
    seq: u64,
    plaintext_buf: &'a mut [u8],
) -> Result<&'a [u8], DecryptError> {
    let cipher = S::make_cipher(key);
    decrypt_record_with(record, iv, seq, plaintext_buf, |nonce, aad, pt, tag| {
        run_decrypt::<S>(&cipher, nonce, aad, pt, tag)
    })
}

#[cfg(test)]
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
            // Defensive zeroize: AEADs may have written partial plaintext before tag check failed.
            plaintext.zeroize();
            Err(DecryptError::AeadFailed)
        }
    }
}

/// On `Ok(ct_len)`, the inner plaintext occupies `record[5..5 + ct_len]`.
/// On `Err`, the plaintext region is zeroed.
fn decrypt_record_inplace_with<F>(
    record: &mut [u8],
    iv: &AeadIv,
    seq: u64,
    aead_decrypt: F,
) -> Result<usize, DecryptError>
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
    if body_len > TLS_CIPHERTEXT_MAX {
        return Err(DecryptError::RecordTooLarge);
    }
    if record.len() < 5 + body_len {
        return Err(DecryptError::Truncated);
    }
    if record.len() != 5 + body_len {
        return Err(DecryptError::TrailingBytes);
    }
    if body_len < 16 {
        return Err(DecryptError::Truncated);
    }
    let ct_len = body_len - 16;

    let (header, body) = record.split_at_mut(5);
    let (ciphertext, tag_slice) = body.split_at_mut(ct_len);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(tag_slice);

    let nonce = aead_nonce(iv, seq);
    let aad: &[u8] = header;
    match aead_decrypt(&nonce, aad, ciphertext, &tag) {
        Ok(()) => Ok(ct_len),
        Err(_) => {
            ciphertext.zeroize();
            Err(DecryptError::AeadFailed)
        }
    }
}

/// Split TLS 1.3 inner plaintext into content and content type.
///
/// The trailing-zero padding (RFC 8446 §5.4) is meant to hide the true
/// payload length from a network observer. A naive `while end > 0 &&
/// inner[end - 1] == 0` scan short-circuits at the first non-zero from the
/// end, so its run-time leaks the exact padding length — physically
/// defeating the padding. We iterate every byte of `inner` unconditionally
/// and use `subtle`'s conditional-select primitives to remember the
/// position of the most recent non-zero byte without branching on its
/// value.
///
/// The post-loop bounds and emptiness checks branch on the final
/// content_type-position, but that value is the public protocol-level
/// outcome (record-too-large / empty-record), not the padding length.
pub(crate) fn split_inner_plaintext(inner: &[u8]) -> Result<(&[u8], u8), DecryptError> {
    // Upfront DoS / overflow guard. Without this a public caller could
    // hand in a multi-GB slice and force a full unconditional scan, and
    // the `(i + 1) as u32` cast below would wrap on `inner.len() > u32::MAX`
    // — silently breaking the bounds check.
    if inner.len() > TLS_CIPHERTEXT_MAX {
        return Err(DecryptError::RecordTooLarge);
    }

    // u32 so `conditional_select` works on a small type even when usize is 64-bit
    // on the host; inner.len() is now bounded by `TLS_CIPHERTEXT_MAX`, well
    // under 2^32.
    let mut last_nonzero_plus_one: u32 = 0;
    let mut content_type: u8 = 0;
    for (i, &b) in inner.iter().enumerate() {
        let is_nonzero = !b.ct_eq(&0u8);
        last_nonzero_plus_one =
            u32::conditional_select(&last_nonzero_plus_one, &((i + 1) as u32), is_nonzero);
        content_type = u8::conditional_select(&content_type, &b, is_nonzero);
    }

    let end = last_nonzero_plus_one as usize;
    if end == 0 {
        return Err(DecryptError::EmptyInnerPlaintext);
    }
    if end - 1 > TLS_PLAINTEXT_MAX {
        return Err(DecryptError::RecordTooLarge);
    }
    Ok((&inner[..end - 1], content_type))
}

#[cfg(test)]
pub(crate) fn encrypt_record<'a, S: CipherSuite>(
    content: &[u8],
    content_type: u8,
    key: &zeroize::Zeroizing<S::KeyBytes>,
    iv: &AeadIv,
    seq: u64,
    out_buf: &'a mut [u8],
) -> Result<&'a [u8], EncryptError> {
    let cipher = S::make_cipher(key);
    encrypt_record_with(
        content,
        content_type,
        iv,
        seq,
        out_buf,
        |nonce, aad, buf| run_encrypt::<S>(&cipher, nonce, aad, buf),
    )
}

fn encrypt_record_with<'a, F>(
    content: &[u8],
    content_type: u8,
    iv: &AeadIv,
    seq: u64,
    out_buf: &'a mut [u8],
    aead_encrypt: F,
) -> Result<&'a [u8], EncryptError>
where
    F: FnOnce(&ZeroBuf<12>, &[u8], &mut [u8]) -> Result<[u8; 16], crate::traits::AeadError>,
{
    // RFC 8446 §5.1: TLSPlaintext.length cap (separate from the §5.2 cap below).
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

    // u16 cast safe given the cap above.
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
    let tag = aead_encrypt(&nonce, &aad, &mut out_buf[5..5 + inner_len])
        .map_err(|_| EncryptError::AeadFailed)?;
    out_buf[5 + inner_len..5 + inner_len + AEAD_TAG_LEN].copy_from_slice(&tag);

    Ok(&out_buf[..total_len])
}

const AEAD_TAG_LEN: usize = 16;

mod sealed {
    pub trait Sealed {}
}

/// TLS 1.3 cipher suite marker. Sealed.
pub trait CipherSuite: sealed::Sealed + Sized {
    type KeyBytes: zeroize::Zeroize;
    type Cipher: AeadInPlace
        + KeyInit
        + AeadCore<NonceSize = ::aead::consts::U12, TagSize = ::aead::consts::U16>;
    fn make_cipher(key: &zeroize::Zeroizing<Self::KeyBytes>) -> Self::Cipher;
    fn derive_keys<H: crate::traits::HkdfSha256>(
        traffic_secret: &crate::newtype::Secret,
    ) -> Result<RecordKeys<Self>, crate::hkdf::HkdfLabelError>;
}

/// Compile-time default cipher. Tests and other call sites that need
/// "some concrete cipher" (and are not exercising AES- or ChaCha-specific
/// wire behavior) refer to this alias rather than naming a specific
/// suite. Resolves to whichever cipher feature is enabled. Test-only.
#[cfg(all(test, feature = "cipher-aes"))]
pub(crate) type DefaultCipher = Aes128GcmSha256;
#[cfg(all(test, not(feature = "cipher-aes"), feature = "chacha20"))]
pub(crate) type DefaultCipher = ChaCha20Poly1305Sha256;

#[cfg(feature = "cipher-aes")]
mod aes {
    use super::*;

    /// `TLS_AES_128_GCM_SHA256` (`0x1301`).
    pub struct Aes128GcmSha256;
    impl sealed::Sealed for Aes128GcmSha256 {}
    impl CipherSuite for Aes128GcmSha256 {
        type KeyBytes = [u8; 16];
        type Cipher = aes_gcm::Aes128Gcm;
        fn make_cipher(key: &zeroize::Zeroizing<[u8; 16]>) -> Self::Cipher {
            aes_gcm::Aes128Gcm::new(&GenericArray::from(**key))
        }
        fn derive_keys<H: crate::traits::HkdfSha256>(
            traffic_secret: &crate::newtype::Secret,
        ) -> Result<RecordKeys<Self>, crate::hkdf::HkdfLabelError> {
            let (key_bytes, iv) = crate::hkdf::traffic_keys::<H, 16>(traffic_secret)?;
            Ok(RecordKeys {
                cipher: Self::make_cipher(&key_bytes),
                iv,
            })
        }
    }
}
#[cfg(feature = "cipher-aes")]
pub use aes::Aes128GcmSha256;

#[cfg(feature = "chacha20")]
mod chacha {
    use super::*;

    /// `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`).
    pub struct ChaCha20Poly1305Sha256;
    impl sealed::Sealed for ChaCha20Poly1305Sha256 {}
    impl CipherSuite for ChaCha20Poly1305Sha256 {
        type KeyBytes = [u8; 32];
        type Cipher = chacha20poly1305::ChaCha20Poly1305;
        fn make_cipher(key: &zeroize::Zeroizing<[u8; 32]>) -> Self::Cipher {
            chacha20poly1305::ChaCha20Poly1305::new(&GenericArray::from(**key))
        }
        fn derive_keys<H: crate::traits::HkdfSha256>(
            traffic_secret: &crate::newtype::Secret,
        ) -> Result<RecordKeys<Self>, crate::hkdf::HkdfLabelError> {
            let (key_bytes, iv) = crate::hkdf::traffic_keys::<H, 32>(traffic_secret)?;
            Ok(RecordKeys {
                cipher: Self::make_cipher(&key_bytes),
                iv,
            })
        }
    }
}
#[cfg(feature = "chacha20")]
pub use chacha::ChaCha20Poly1305Sha256;

pub struct RecordKeys<S: CipherSuite> {
    pub(crate) cipher: S::Cipher,
    pub iv: AeadIv,
}

#[cfg(test)]
mod no_cipher {
    use super::*;
    use ::aead::consts::{U0, U12, U16};
    use ::aead::{Error as AeadError, Key, KeySizeUser, Nonce, Tag};

    /// No-op AEAD: implements the AEAD trait surface required by
    /// [`CipherSuite::Cipher`] but does no actual cryptography.
    pub struct NoopAead;

    impl KeySizeUser for NoopAead {
        type KeySize = U16;
    }

    impl KeyInit for NoopAead {
        fn new(_: &Key<Self>) -> Self {
            NoopAead
        }
    }

    impl AeadCore for NoopAead {
        type NonceSize = U12;
        type TagSize = U16;
        type CiphertextOverhead = U0;
    }

    impl AeadInPlace for NoopAead {
        fn encrypt_in_place_detached(
            &self,
            _: &Nonce<Self>,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<Tag<Self>, AeadError> {
            Ok(GenericArray::default())
        }

        fn decrypt_in_place_detached(
            &self,
            _: &Nonce<Self>,
            _: &[u8],
            _: &mut [u8],
            _: &Tag<Self>,
        ) -> Result<(), AeadError> {
            Ok(())
        }
    }

    /// Test-only no-op cipher satisfying [`CipherSuite`].
    pub struct NoCipher;

    impl sealed::Sealed for NoCipher {}

    impl CipherSuite for NoCipher {
        type KeyBytes = [u8; 16];
        type Cipher = NoopAead;
        fn make_cipher(_: &zeroize::Zeroizing<[u8; 16]>) -> Self::Cipher {
            NoopAead
        }
        fn derive_keys<H: crate::traits::HkdfSha256>(
            traffic_secret: &crate::newtype::Secret,
        ) -> Result<RecordKeys<Self>, crate::hkdf::HkdfLabelError> {
            let (_, iv) = crate::hkdf::traffic_keys::<H, 16>(traffic_secret)?;
            Ok(RecordKeys {
                cipher: NoopAead,
                iv,
            })
        }
    }
}

#[cfg(test)]
pub use no_cipher::NoCipher;

impl<S: CipherSuite> RecordKeys<S> {
    pub fn derive<H: crate::traits::HkdfSha256>(
        traffic_secret: &crate::newtype::Secret,
    ) -> Result<Self, crate::hkdf::HkdfLabelError> {
        S::derive_keys::<H>(traffic_secret)
    }

    /// Decrypt one `application_data` record under this suite's AEAD.
    #[cfg(test)]
    pub fn decrypt_record<'a>(
        &self,
        record: &[u8],
        seq: u64,
        plaintext_buf: &'a mut [u8],
    ) -> Result<&'a [u8], DecryptError> {
        decrypt_record_with(
            record,
            &self.iv,
            seq,
            plaintext_buf,
            |nonce, aad, pt, tag| run_decrypt::<S>(&self.cipher, nonce, aad, pt, tag),
        )
    }

    pub fn decrypt_record_inplace(
        &self,
        record: &mut [u8],
        seq: u64,
    ) -> Result<usize, DecryptError> {
        decrypt_record_inplace_with(record, &self.iv, seq, |nonce, aad, pt, tag| {
            run_decrypt::<S>(&self.cipher, nonce, aad, pt, tag)
        })
    }

    /// Encrypt one inner plaintext into an `application_data` record.
    pub fn encrypt_record<'a>(
        &self,
        content: &[u8],
        content_type: u8,
        seq: u64,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], EncryptError> {
        encrypt_record_with(
            content,
            content_type,
            &self.iv,
            seq,
            out_buf,
            |nonce, aad, buf| run_encrypt::<S>(&self.cipher, nonce, aad, buf),
        )
    }
}

fn run_decrypt<S: CipherSuite>(
    cipher: &S::Cipher,
    nonce: &ZeroBuf<12>,
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), crate::traits::AeadError> {
    let nonce_arr = GenericArray::from(**nonce);
    let tag_arr = GenericArray::from(*tag);
    cipher
        .decrypt_in_place_detached(&nonce_arr, aad, buffer, &tag_arr)
        .map_err(|_| crate::traits::AeadError)
}

fn run_encrypt<S: CipherSuite>(
    cipher: &S::Cipher,
    nonce: &ZeroBuf<12>,
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; 16], crate::traits::AeadError> {
    let nonce_arr = GenericArray::from(**nonce);
    let tag = cipher
        .encrypt_in_place_detached(&nonce_arr, aad, buffer)
        .map_err(|_| crate::traits::AeadError)?;
    Ok(tag.into())
}

/// TLS 1.3 `TLSPlaintext.length` cap (RFC 8446 §5.1 / §5.4): the
/// inner-plaintext content (before the `content_type` byte and any
/// zero padding) must not exceed `2^14` bytes.
const TLS_PLAINTEXT_MAX: usize = 1 << 14;

/// TLS 1.3 `TLSCiphertext.length` cap (RFC 8446 §5.2): the encrypted body
/// (inner plaintext + AEAD tag) must not exceed `2^14 + 256` bytes.
const TLS_CIPHERTEXT_MAX: usize = (1 << 14) + 256;

#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum EncryptError {
    /// `out_buf` cannot fit the resulting record.
    #[error("encrypt output buffer too small (needed {needed}, got {got})")]
    BufferTooSmall { needed: usize, got: usize },
    /// Plaintext is too large to fit in a single TLS 1.3 record. Hits
    /// either the `TLSPlaintext.length` cap (`2^14`, RFC 8446 §5.1) or
    /// the `TLSCiphertext.length` cap (`2^14 + 256`, §5.2). Caller must
    /// split across multiple records.
    #[error("plaintext exceeds the TLS 1.3 record-size cap")]
    RecordTooLarge,
    /// AEAD backend rejected; statically unreachable for TLS-bounded sizes.
    #[error("AEAD backend rejected the encrypt call")]
    AeadFailed,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum DecryptError {
    /// Record shorter than its declared length, or shorter than `5 + tag_len`.
    #[error("record shorter than its declared length or AEAD tag")]
    Truncated,
    /// Record size exceeds spec (RFC 8446 §5.1 / §5.2 / §5.4).
    #[error("record exceeds the TLS 1.3 record-size cap")]
    RecordTooLarge,
    /// Bytes left in `record` after the declared `5 + body_len`. Almost
    /// always means the caller handed in more than one TLS record at once.
    #[error("bytes left after the declared record body")]
    TrailingBytes,
    /// Record `content_type` wasn't `application_data` (23).
    #[error("record content_type was 0x{0:02x}, expected application_data (23)")]
    UnexpectedContentType(u8),
    /// Record `legacy_version` wasn't 0x0303.
    #[error("record legacy_version was 0x{0:04x}, expected 0x0303")]
    UnexpectedLegacyVersion(u16),
    /// `plaintext_buf` cannot fit the ciphertext (= plaintext length).
    #[error("plaintext buffer too small (needed {needed}, got {got})")]
    BufferTooSmall { needed: usize, got: usize },
    /// AEAD tag verification failed.
    #[error("AEAD tag verification failed")]
    AeadFailed,
    /// `TLSInnerPlaintext` was all zeros — has no `content_type` byte.
    #[error("inner plaintext was all zeros")]
    EmptyInnerPlaintext,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::newtype::{AeadIv, ZeroBuf};

    #[test]
    fn split_no_padding() {
        let inner = b"hello\x17";
        let (content, ct) = split_inner_plaintext(inner).unwrap();
        assert_eq!(content, b"hello");
        assert_eq!(ct, 0x17);
    }

    #[test]
    fn split_strips_trailing_zeros() {
        let inner = b"hello\x17\x00\x00\x00";
        let (content, ct) = split_inner_plaintext(inner).unwrap();
        assert_eq!(content, b"hello");
        assert_eq!(ct, 0x17);
    }

    #[test]
    fn split_empty_inner_rejected() {
        assert_eq!(
            split_inner_plaintext(&[]),
            Err(DecryptError::EmptyInnerPlaintext)
        );
    }

    #[test]
    fn split_all_zero_inner_rejected() {
        let inner = [0u8; 16];
        assert_eq!(
            split_inner_plaintext(&inner),
            Err(DecryptError::EmptyInnerPlaintext)
        );
    }

    #[test]
    fn split_oversize_rejected_upfront() {
        // DoS / `(i + 1) as u32` cast safety.
        let inner = vec![0xab; TLS_CIPHERTEXT_MAX + 1];
        assert_eq!(
            split_inner_plaintext(&inner),
            Err(DecryptError::RecordTooLarge)
        );
    }

    #[test]
    fn split_zero_then_nonzero_keeps_zero_as_content() {
        let inner = b"\x00\x00\xab\x17";
        let (content, ct) = split_inner_plaintext(inner).unwrap();
        assert_eq!(content, b"\x00\x00\xab");
        assert_eq!(ct, 0x17);
    }

    #[test]
    fn decrypt_record_inplace_matches_copying() {
        const N: usize = core::mem::size_of::<<DefaultCipher as CipherSuite>::KeyBytes>();
        let key = ZeroBuf::new([0xa5u8; N]);
        let iv = AeadIv::new(ZeroBuf::new([0x42; 12]));
        let content = b"hello world, this is plaintext";
        let seq = 7;
        let keys = RecordKeys::<DefaultCipher> {
            cipher: DefaultCipher::make_cipher(&key),
            iv: iv.clone(),
        };

        let mut record_buf = [0u8; 128];
        let record = keys
            .encrypt_record(
                content,
                crate::consts::CT_APPLICATION_DATA,
                seq,
                &mut record_buf,
            )
            .expect("encrypt");
        let record_len = record.len();

        let mut copy_pt = [0u8; 128];
        let copy = keys
            .decrypt_record(&record_buf[..record_len], seq, &mut copy_pt)
            .expect("copying decrypt");
        let copy_bytes: heapless::Vec<u8, 128> = heapless::Vec::from_slice(copy).unwrap();

        let mut inplace = [0u8; 128];
        inplace[..record_len].copy_from_slice(&record_buf[..record_len]);
        let pt_len = keys
            .decrypt_record_inplace(&mut inplace[..record_len], seq)
            .expect("in-place decrypt");

        assert_eq!(&inplace[5..5 + pt_len], &copy_bytes[..]);
    }

    #[cfg(feature = "chacha20")]
    #[test]
    fn decrypt_record_inplace_matches_copying_chacha() {
        let key = ZeroBuf::new([0xc3u8; 32]);
        let iv = AeadIv::new(ZeroBuf::new([0x99; 12]));
        let content = b"chacha plaintext sample bytes";
        let seq = 11;
        let keys = RecordKeys::<ChaCha20Poly1305Sha256> {
            cipher: ChaCha20Poly1305Sha256::make_cipher(&key),
            iv: iv.clone(),
        };

        let mut record_buf = [0u8; 128];
        let record = keys
            .encrypt_record(
                content,
                crate::consts::CT_APPLICATION_DATA,
                seq,
                &mut record_buf,
            )
            .expect("encrypt");
        let record_len = record.len();

        let mut copy_pt = [0u8; 128];
        let copy = keys
            .decrypt_record(&record_buf[..record_len], seq, &mut copy_pt)
            .expect("copying decrypt");
        let copy_bytes: heapless::Vec<u8, 128> = heapless::Vec::from_slice(copy).unwrap();

        let mut inplace = [0u8; 128];
        inplace[..record_len].copy_from_slice(&record_buf[..record_len]);
        let pt_len = keys
            .decrypt_record_inplace(&mut inplace[..record_len], seq)
            .expect("in-place decrypt");

        assert_eq!(&inplace[5..5 + pt_len], &copy_bytes[..]);
    }
}
