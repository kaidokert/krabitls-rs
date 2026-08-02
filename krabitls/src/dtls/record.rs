//! DTLS 1.3 record layer (RFC 9147 §4): the unified header codec, record-number
//! encryption (§4.2.3), and per-epoch key material.
//!
//! The AEAD itself is the shared TLS 1.3 cipher ([`RecordKeys`]) — DTLS differs
//! only in the header, the header-as-AAD, and the extra pass that encrypts the
//! on-wire sequence number. The 64-bit AEAD nonce is the epoch-local record
//! sequence number XOR the write IV, identical to TLS 1.3, so
//! [`RecordKeys::seal_in_place`] / [`RecordKeys::open_in_place`] are reused
//! verbatim.
//!
//! Not RFC-interop-verified yet: encode/decode is proven self-consistent by
//! round-trip and the AES mask by a known-answer test; interop against a DTLS
//! 1.3 peer lands with the handshake.

use crate::aead::{CipherSuite, RecordKeys, split_inner_plaintext};
use crate::hkdf::{HkdfLabelError, sn_key};
use crate::newtype::Secret;
use crate::traits::HkdfSha256;

/// Top three bits of the first header byte mark a DTLSCiphertext with the
/// unified header (RFC 9147 §4): `0b001`. The remaining bits are flags.
const UNIFIED_HDR_FIXED: u8 = 0b0010_0000;
const UNIFIED_HDR_FIXED_MASK: u8 = 0b1110_0000;
const HDR_CID_PRESENT: u8 = 0b0001_0000;
const HDR_SEQ_16BIT: u8 = 0b0000_1000;
const HDR_LENGTH_PRESENT: u8 = 0b0000_0100;
const HDR_EPOCH_LOW2: u8 = 0b0000_0011;

/// The AEAD tag length shared by both suites (RFC 8446 §5.2). The
/// record-number-encryption sample also needs at least this many ciphertext
/// bytes (RFC 9147 §4.2.3), which every sealed record satisfies (min body =
/// 1 inner-type byte + tag).
const TAG_LEN: usize = 16;
const SN_SAMPLE_LEN: usize = 16;

/// On-wire sequence-number width, the `S` header bit (RFC 9147 §4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SeqNumLen {
    One,
    Two,
}

impl SeqNumLen {
    fn bytes(self) -> usize {
        match self {
            SeqNumLen::One => 1,
            SeqNumLen::Two => 2,
        }
    }

    fn bits(self) -> u32 {
        match self {
            SeqNumLen::One => 8,
            SeqNumLen::Two => 16,
        }
    }
}

/// The epoch and sequence-number framing for one sealed record.
pub(crate) struct SealHeader<'a> {
    /// Full epoch; only the low two bits reach the wire (RFC 9147 §4).
    pub(crate) epoch: u16,
    /// Epoch-local record sequence number.
    pub(crate) seq: u64,
    /// On-wire width of the sequence number.
    pub(crate) seq_len: SeqNumLen,
    /// Negotiated peer connection id, if the `connection_id` extension is in use.
    pub(crate) cid: Option<&'a [u8]>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub(crate) enum DtlsRecordError {
    #[error("output buffer too small (needed {needed}, got {got})")]
    BufferTooSmall { needed: usize, got: usize },
    #[error("record content exceeds the DTLS record-size cap")]
    RecordTooLarge,
    #[error("not a DTLS 1.3 unified-header record")]
    BadHeader,
    #[error("record truncated")]
    Truncated,
    #[error("connection id length disagrees with what was negotiated")]
    CidMismatch,
    #[error("ciphertext too short to protect the sequence number")]
    CiphertextTooShort,
    #[error("AEAD authentication failed")]
    Aead,
    #[error("inner plaintext malformed")]
    InnerPlaintext,
}

/// Per-epoch key material: the AEAD keys plus the record-number-encryption
/// primitive keyed with this epoch's `sn_key` (RFC 9147 §5.9).
pub(crate) struct EpochKeys<S: DtlsSuite> {
    keys: RecordKeys<S>,
    masker: S::Masker,
}

impl<S: DtlsSuite> EpochKeys<S> {
    /// Derive both the AEAD keys and the sequence-number masker from one
    /// traffic secret.
    pub(crate) fn derive<H: HkdfSha256>(traffic_secret: &Secret) -> Result<Self, HkdfLabelError> {
        Ok(Self {
            keys: RecordKeys::<S>::derive::<H>(traffic_secret)?,
            masker: S::derive_masker::<H>(traffic_secret)?,
        })
    }

    /// Seal `content` into a DTLS 1.3 record in `out`, returning the record
    /// slice. `hdr` fixes the epoch/sequence-number framing; the length field is
    /// always emitted (`L = 1`).
    pub(crate) fn seal<'o>(
        &self,
        hdr: SealHeader<'_>,
        content: &[u8],
        content_type: u8,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], DtlsRecordError> {
        let SealHeader {
            epoch,
            seq,
            seq_len,
            cid,
        } = hdr;
        let cid_len = cid.map_or(0, <[u8]>::len);
        let seq_pos = 1 + cid_len;
        let header_len = seq_pos + seq_len.bytes() + 2;
        let inner_len = content
            .len()
            .checked_add(1)
            .ok_or(DtlsRecordError::RecordTooLarge)?;
        let body_len = inner_len
            .checked_add(TAG_LEN)
            .ok_or(DtlsRecordError::RecordTooLarge)?;
        let total = header_len
            .checked_add(body_len)
            .ok_or(DtlsRecordError::RecordTooLarge)?;
        if body_len > u16::MAX as usize {
            return Err(DtlsRecordError::RecordTooLarge);
        }
        if out.len() < total {
            return Err(DtlsRecordError::BufferTooSmall {
                needed: total,
                got: out.len(),
            });
        }

        let mut first = UNIFIED_HDR_FIXED | HDR_LENGTH_PRESENT | (epoch as u8 & HDR_EPOCH_LOW2);
        if cid.is_some() {
            first |= HDR_CID_PRESENT;
        }
        if seq_len == SeqNumLen::Two {
            first |= HDR_SEQ_16BIT;
        }
        out[0] = first;
        if let Some(cid) = cid {
            out[1..1 + cid_len].copy_from_slice(cid);
        }
        write_seq(&mut out[seq_pos..seq_pos + seq_len.bytes()], seq);
        out[seq_pos + seq_len.bytes()..header_len]
            .copy_from_slice(&(body_len as u16).to_be_bytes());

        out[header_len..header_len + content.len()].copy_from_slice(content);
        out[header_len + content.len()] = content_type;

        // AAD is the header with the cleartext sequence number, which both sides
        // agree on: the receiver decrypts the sequence number before opening.
        let (header, body) = out.split_at_mut(header_len);
        let tag = self
            .keys
            .seal_in_place(header, seq, &mut body[..inner_len])
            .map_err(|_| DtlsRecordError::Aead)?;
        body[inner_len..body_len].copy_from_slice(&tag);

        // Sample the ciphertext and mask the sequence number in place (§4.2.3).
        let mut sample = [0u8; SN_SAMPLE_LEN];
        sample.copy_from_slice(&body[..SN_SAMPLE_LEN]);
        S::mask_seq(
            &self.masker,
            &sample,
            &mut header[seq_pos..seq_pos + seq_len.bytes()],
        );

        Ok(&out[..total])
    }

    /// Open a DTLS 1.3 record in place. `cid_len` is the negotiated local
    /// connection id length (0 if none); `expected_seq` seeds the reconstruction
    /// of the full sequence number from its truncated on-wire form.
    pub(crate) fn open<'r>(
        &self,
        cid_len: usize,
        expected_seq: u64,
        record: &'r mut [u8],
    ) -> Result<Opened<'r>, DtlsRecordError> {
        let first = *record.first().ok_or(DtlsRecordError::Truncated)?;
        if first & UNIFIED_HDR_FIXED_MASK != UNIFIED_HDR_FIXED {
            return Err(DtlsRecordError::BadHeader);
        }
        let cid_present = first & HDR_CID_PRESENT != 0;
        if cid_present != (cid_len > 0) {
            return Err(DtlsRecordError::CidMismatch);
        }
        let seq_len = if first & HDR_SEQ_16BIT != 0 {
            SeqNumLen::Two
        } else {
            SeqNumLen::One
        };
        let epoch_low2 = first & HDR_EPOCH_LOW2;
        let length_present = first & HDR_LENGTH_PRESENT != 0;

        let seq_pos = 1 + cid_len;
        let len_pos = seq_pos + seq_len.bytes();
        let header_len = len_pos + if length_present { 2 } else { 0 };
        if record.len() < header_len {
            return Err(DtlsRecordError::Truncated);
        }
        let body_len = if length_present {
            u16::from_be_bytes([record[len_pos], record[len_pos + 1]]) as usize
        } else {
            record.len() - header_len
        };
        let body_end = header_len
            .checked_add(body_len)
            .ok_or(DtlsRecordError::Truncated)?;
        if record.len() < body_end || body_len < SN_SAMPLE_LEN || body_len < TAG_LEN + 1 {
            return Err(DtlsRecordError::CiphertextTooShort);
        }

        // Decrypt the sequence number: sample the ciphertext, unmask the header
        // bytes, then reconstruct the full 64-bit value.
        let mut sample = [0u8; SN_SAMPLE_LEN];
        sample.copy_from_slice(&record[header_len..header_len + SN_SAMPLE_LEN]);
        S::mask_seq(
            &self.masker,
            &sample,
            &mut record[seq_pos..seq_pos + seq_len.bytes()],
        );
        let wire_low = read_seq(&record[seq_pos..seq_pos + seq_len.bytes()]);
        let seq = reconstruct_seq(wire_low, seq_len.bits(), expected_seq);

        let (header, rest) = record.split_at_mut(header_len);
        let (body, _) = rest.split_at_mut(body_len);
        let inner_len = body_len - TAG_LEN;
        let (ciphertext, tag) = body.split_at_mut(inner_len);
        let mut tag_arr = [0u8; TAG_LEN];
        tag_arr.copy_from_slice(&tag[..TAG_LEN]);
        self.keys
            .open_in_place(header, seq, ciphertext, &tag_arr)
            .map_err(|_| DtlsRecordError::Aead)?;

        let (content, content_type) =
            split_inner_plaintext(ciphertext).map_err(|_| DtlsRecordError::InnerPlaintext)?;
        Ok(Opened {
            epoch_low2,
            seq,
            content_type,
            content,
        })
    }
}

/// A decrypted DTLS record.
pub(crate) struct Opened<'r> {
    pub(crate) epoch_low2: u8,
    pub(crate) seq: u64,
    pub(crate) content_type: u8,
    pub(crate) content: &'r [u8],
}

fn write_seq(out: &mut [u8], seq: u64) {
    match out.len() {
        1 => out[0] = seq as u8,
        _ => out.copy_from_slice(&(seq as u16).to_be_bytes()),
    }
}

fn read_seq(bytes: &[u8]) -> u64 {
    match bytes.len() {
        1 => bytes[0] as u64,
        _ => u16::from_be_bytes([bytes[0], bytes[1]]) as u64,
    }
}

/// Reconstruct the full 64-bit record sequence number from its low `bits` and
/// the receiver's expected next value, choosing the congruent candidate closest
/// to `expected` (RFC 9147 §4.2.1, generalised). In-order delivery makes the
/// base candidate the answer; the near-neighbour check handles a low-bit
/// wrap straddling `expected`.
fn reconstruct_seq(wire_low: u64, bits: u32, expected: u64) -> u64 {
    let step = 1u64 << bits;
    let mask = step - 1;
    let candidate = (expected & !mask) | (wire_low & mask);
    let mut best = candidate;
    let mut best_dist = candidate.abs_diff(expected);
    if let Some(up) = candidate.checked_add(step) {
        if up.abs_diff(expected) < best_dist {
            best = up;
            best_dist = up.abs_diff(expected);
        }
    }
    if let Some(down) = candidate.checked_sub(step) {
        if down.abs_diff(expected) < best_dist {
            best = down;
        }
    }
    best
}

/// A cipher suite's DTLS record-number protection (RFC 9147 §4.2.3). Sealed
/// through the supertrait: [`CipherSuite`] admits only the two in-tree suites.
pub(crate) trait DtlsSuite: CipherSuite {
    type Masker;
    fn derive_masker<H: HkdfSha256>(
        traffic_secret: &Secret,
    ) -> Result<Self::Masker, HkdfLabelError>;
    /// XOR the record-number mask (derived from `sample`) into `seq_bytes` in
    /// place. Symmetric: the same call encrypts and decrypts.
    fn mask_seq(masker: &Self::Masker, sample: &[u8; SN_SAMPLE_LEN], seq_bytes: &mut [u8]);
}

#[cfg(feature = "cipher-aes")]
mod aes_mask {
    use super::{DtlsSuite, HkdfLabelError, SN_SAMPLE_LEN, Secret, sn_key};
    use crate::aead::Aes128GcmSha256;
    use crate::traits::HkdfSha256;
    use aes_gcm::aes::Aes128;
    use aes_gcm::aes::cipher::{Array, BlockCipherEncrypt, KeyInit};

    impl DtlsSuite for Aes128GcmSha256 {
        type Masker = Aes128;

        fn derive_masker<H: HkdfSha256>(
            traffic_secret: &Secret,
        ) -> Result<Self::Masker, HkdfLabelError> {
            let key = sn_key::<H, 16>(traffic_secret)?;
            Ok(Aes128::new(&Array::from(*key)))
        }

        fn mask_seq(masker: &Self::Masker, sample: &[u8; SN_SAMPLE_LEN], seq_bytes: &mut [u8]) {
            // Mask = AES-ECB(sn_key, Ciphertext[0..16]).
            let mut block = Array::from(*sample);
            masker.encrypt_block(&mut block);
            for (s, m) in seq_bytes.iter_mut().zip(block.iter()) {
                *s ^= *m;
            }
        }
    }
}

#[cfg(feature = "chacha20")]
mod chacha_mask {
    use super::{DtlsSuite, HkdfLabelError, SN_SAMPLE_LEN, Secret, sn_key};
    use crate::aead::ChaCha20Poly1305Sha256;
    use crate::newtype::ZeroBuf;
    use crate::traits::HkdfSha256;
    use chacha20::cipher::{Array, KeyIvInit, StreamCipher, StreamCipherSeek};
    use chacha20::{ChaCha20, Key};

    impl DtlsSuite for ChaCha20Poly1305Sha256 {
        type Masker = ZeroBuf<32>;

        fn derive_masker<H: HkdfSha256>(
            traffic_secret: &Secret,
        ) -> Result<Self::Masker, HkdfLabelError> {
            sn_key::<H, 32>(traffic_secret)
        }

        fn mask_seq(masker: &Self::Masker, sample: &[u8; SN_SAMPLE_LEN], seq_bytes: &mut [u8]) {
            // Mask = ChaCha20(sn_key, counter = Ciphertext[0..4], nonce =
            // Ciphertext[4..16]); apply_keystream XORs it into the seq bytes.
            // Key by reference so the only `sn_key` copy is the zeroizing masker.
            let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&sample[4..16]);
            let key = <&Key>::try_from(&masker[..]).expect("sn_key is the ChaCha20 key length");
            let mut cipher = ChaCha20::new(key, &Array::from(nonce));
            cipher.seek(counter as u64 * 64);
            cipher.apply_keystream(seq_bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::RustCrypto;
    use crate::consts::CT_APPLICATION_DATA;
    use zeroize::Zeroizing;

    fn secret(b: u8) -> Secret {
        Secret::new(Zeroizing::new([b; 32]))
    }

    #[test]
    fn reconstruct_seq_picks_the_nearest_congruent_value() {
        assert_eq!(reconstruct_seq(0x01, 8, 0x100), 0x101);
        // 0xFF near 0x100: 0x0FF (255) beats 0x1FF (511).
        assert_eq!(reconstruct_seq(0xFF, 8, 0x100), 0xFF);
        // 0x00 near 0x1FF: 0x200 beats 0x100.
        assert_eq!(reconstruct_seq(0x00, 8, 0x1FF), 0x200);
        assert_eq!(reconstruct_seq(0x05, 16, 0x05), 0x05);
    }

    #[cfg(feature = "cipher-aes")]
    mod aes {
        use super::*;
        use crate::aead::Aes128GcmSha256 as Suite;
        use crate::consts::CT_HANDSHAKE;

        fn epoch(b: u8) -> EpochKeys<Suite> {
            EpochKeys::<Suite>::derive::<RustCrypto>(&secret(b)).unwrap()
        }

        #[test]
        fn round_trips_both_seq_widths() {
            for seq_len in [SeqNumLen::One, SeqNumLen::Two] {
                let ek = epoch(0x11);
                let mut buf = [0u8; 128];
                let content = b"datagram payload";
                let hdr = SealHeader {
                    epoch: 2,
                    seq: 7,
                    seq_len,
                    cid: None,
                };
                let n = ek
                    .seal(hdr, content, CT_APPLICATION_DATA, &mut buf)
                    .unwrap()
                    .len();
                let opened = ek.open(0, 7, &mut buf[..n]).unwrap();
                assert_eq!(opened.content, content);
                assert_eq!(opened.content_type, CT_APPLICATION_DATA);
                assert_eq!(opened.seq, 7);
                assert_eq!(opened.epoch_low2, 2);
            }
        }

        #[test]
        fn round_trips_with_connection_id() {
            let ek = epoch(0x11);
            let cid = [0xAB, 0xCD, 0xEF];
            let mut buf = [0u8; 128];
            let content = b"cid record";
            let hdr = SealHeader {
                epoch: 1,
                seq: 3,
                seq_len: SeqNumLen::Two,
                cid: Some(&cid),
            };
            let n = ek.seal(hdr, content, CT_HANDSHAKE, &mut buf).unwrap().len();
            let opened = ek.open(cid.len(), 3, &mut buf[..n]).unwrap();
            assert_eq!(opened.content, content);
            assert_eq!(opened.seq, 3);
        }

        #[test]
        fn sequence_number_is_aes_ecb_masked() {
            use aes_gcm::aes::Aes128;
            use aes_gcm::aes::cipher::{Array, BlockCipherEncrypt, KeyInit};

            let s = secret(0x22);
            let ek = EpochKeys::<Suite>::derive::<RustCrypto>(&s).unwrap();
            let mut buf = [0u8; 128];
            // No CID, 16-bit seq: header is [first][seq_hi][seq_lo][len_hi][len_lo].
            let hdr = SealHeader {
                epoch: 0,
                seq: 0x0102,
                seq_len: SeqNumLen::Two,
                cid: None,
            };
            let rec = ek.seal(hdr, b"xy", CT_APPLICATION_DATA, &mut buf).unwrap();
            let on_wire_seq = [rec[1], rec[2]];

            let sn = crate::hkdf::sn_key::<RustCrypto, 16>(&s).unwrap();
            let cipher = Aes128::new(&Array::from(*sn));
            let mut block = Array::from(<[u8; 16]>::try_from(&rec[5..21]).unwrap());
            cipher.encrypt_block(&mut block);
            assert_eq!(on_wire_seq, [0x01 ^ block[0], 0x02 ^ block[1]]);
        }

        #[test]
        fn tampered_tag_fails_to_open() {
            let ek = epoch(0x11);
            let mut buf = [0u8; 128];
            let hdr = SealHeader {
                epoch: 0,
                seq: 1,
                seq_len: SeqNumLen::Two,
                cid: None,
            };
            let n = ek
                .seal(hdr, b"hello", CT_APPLICATION_DATA, &mut buf)
                .unwrap()
                .len();
            buf[n - 1] ^= 0x01;
            assert!(matches!(
                ek.open(0, 1, &mut buf[..n]),
                Err(DtlsRecordError::Aead)
            ));
        }

        #[test]
        fn rejects_non_unified_header() {
            let ek = epoch(0x11);
            let mut rec = [0u8; 32];
            rec[0] = CT_APPLICATION_DATA; // a TLS content type, not a unified header
            assert!(matches!(
                ek.open(0, 0, &mut rec),
                Err(DtlsRecordError::BadHeader)
            ));
        }

        #[test]
        fn rejects_cid_length_mismatch() {
            let ek = epoch(0x11);
            let cid = [0x01, 0x02];
            let mut buf = [0u8; 128];
            let hdr = SealHeader {
                epoch: 0,
                seq: 1,
                seq_len: SeqNumLen::Two,
                cid: Some(&cid),
            };
            let n = ek
                .seal(hdr, b"hi", CT_APPLICATION_DATA, &mut buf)
                .unwrap()
                .len();
            // Opening without expecting a CID must not silently misparse.
            assert!(matches!(
                ek.open(0, 1, &mut buf[..n]),
                Err(DtlsRecordError::CidMismatch)
            ));
        }
    }

    #[cfg(feature = "chacha20")]
    #[test]
    fn chacha_round_trips() {
        use crate::aead::ChaCha20Poly1305Sha256 as Suite;
        let ek = EpochKeys::<Suite>::derive::<RustCrypto>(&secret(0x33)).unwrap();
        let mut buf = [0u8; 128];
        let content = b"chacha datagram";
        let hdr = SealHeader {
            epoch: 3,
            seq: 9,
            seq_len: SeqNumLen::Two,
            cid: None,
        };
        let n = ek
            .seal(hdr, content, CT_APPLICATION_DATA, &mut buf)
            .unwrap()
            .len();
        let opened = ek.open(0, 9, &mut buf[..n]).unwrap();
        assert_eq!(opened.content, content);
        assert_eq!(opened.content_type, CT_APPLICATION_DATA);
        assert_eq!(opened.seq, 9);
        assert_eq!(opened.epoch_low2, 3);
    }
}
