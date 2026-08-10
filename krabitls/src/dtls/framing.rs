//! DTLS 1.3 plaintext framing (RFC 9147): the epoch-0 `DTLSPlaintext` record
//! header and the 12-byte handshake-message header.
//!
//! The initial flights (ClientHello, HelloRetryRequest, ServerHello) travel in
//! `DTLSPlaintext` records — a 13-byte header with an explicit epoch and 48-bit
//! sequence number — not the protected unified header from [`super::record`].
//! Handshake messages carry `message_seq` + fragment offset/length so they can
//! be split across datagrams and reassembled.

/// Legacy record version stamped in `DTLSPlaintext` (and echoed in
/// `legacy_version`): DTLS 1.2 (`0xFEFD`), per RFC 9147 §5.
pub(crate) const DTLS_1_2_LEGACY_VERSION: u16 = 0xFEFD;
/// The real negotiated version, carried in `supported_versions`: DTLS 1.3
/// (`0xFEFC`).
pub(crate) const DTLS_1_3_VERSION: u16 = 0xFEFC;

/// `DTLSPlaintext` header is `type(1) version(2) epoch(2) seq(6) length(2)`.
pub(crate) const PLAINTEXT_HEADER_LEN: usize = 13;
/// DTLS handshake header is `type(1) length(3) message_seq(2) frag_off(3)
/// frag_len(3)`.
pub(crate) const HS_HEADER_LEN: usize = 12;

#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub(crate) enum FramingError {
    #[error("buffer too small for the framed output")]
    BufferTooSmall,
    #[error("record or message truncated")]
    Truncated,
    #[error("field exceeds its 24-bit width")]
    FieldTooLarge,
}

/// A parsed `DTLSPlaintext` record (borrowed fragment).
pub(crate) struct PlaintextRecord<'a> {
    pub(crate) content_type: u8,
    pub(crate) epoch: u16,
    pub(crate) seq: u64,
    pub(crate) fragment: &'a [u8],
}

impl<'a> PlaintextRecord<'a> {
    /// Parse one record at the start of `buf`, returning it and the offset of
    /// the next record.
    pub(crate) fn parse(buf: &'a [u8]) -> Result<(Self, usize), FramingError> {
        if buf.len() < PLAINTEXT_HEADER_LEN {
            return Err(FramingError::Truncated);
        }
        let content_type = buf[0];
        let epoch = u16::from_be_bytes([buf[3], buf[4]]);
        let seq = read_u48(&buf[5..11]);
        let length = u16::from_be_bytes([buf[11], buf[12]]) as usize;
        let end = PLAINTEXT_HEADER_LEN
            .checked_add(length)
            .ok_or(FramingError::Truncated)?;
        if buf.len() < end {
            return Err(FramingError::Truncated);
        }
        Ok((
            Self {
                content_type,
                epoch,
                seq,
                fragment: &buf[PLAINTEXT_HEADER_LEN..end],
            },
            end,
        ))
    }

    /// Write a `DTLSPlaintext` record wrapping `fragment` into `out`, returning
    /// the record slice.
    pub(crate) fn write<'o>(
        content_type: u8,
        epoch: u16,
        seq: u64,
        fragment: &[u8],
        out: &'o mut [u8],
    ) -> Result<&'o [u8], FramingError> {
        let total = PLAINTEXT_HEADER_LEN + fragment.len();
        if fragment.len() > u16::MAX as usize {
            return Err(FramingError::FieldTooLarge);
        }
        if out.len() < total {
            return Err(FramingError::BufferTooSmall);
        }
        out[0] = content_type;
        out[1..3].copy_from_slice(&DTLS_1_2_LEGACY_VERSION.to_be_bytes());
        out[3..5].copy_from_slice(&epoch.to_be_bytes());
        write_u48(&mut out[5..11], seq);
        out[11..13].copy_from_slice(&(fragment.len() as u16).to_be_bytes());
        out[PLAINTEXT_HEADER_LEN..total].copy_from_slice(fragment);
        Ok(&out[..total])
    }
}

/// A DTLS handshake-message header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct HandshakeHeader {
    pub(crate) msg_type: u8,
    pub(crate) length: u32,
    pub(crate) message_seq: u16,
    pub(crate) fragment_offset: u32,
    pub(crate) fragment_length: u32,
}

impl HandshakeHeader {
    pub(crate) fn parse(buf: &[u8]) -> Result<Self, FramingError> {
        if buf.len() < HS_HEADER_LEN {
            return Err(FramingError::Truncated);
        }
        Ok(Self {
            msg_type: buf[0],
            length: read_u24(&buf[1..4]),
            message_seq: u16::from_be_bytes([buf[4], buf[5]]),
            fragment_offset: read_u24(&buf[6..9]),
            fragment_length: read_u24(&buf[9..12]),
        })
    }

    /// Write this header into the first [`HS_HEADER_LEN`] bytes of `out`.
    pub(crate) fn write(&self, out: &mut [u8]) -> Result<(), FramingError> {
        if out.len() < HS_HEADER_LEN {
            return Err(FramingError::BufferTooSmall);
        }
        out[0] = self.msg_type;
        write_u24(&mut out[1..4], self.length)?;
        out[4..6].copy_from_slice(&self.message_seq.to_be_bytes());
        write_u24(&mut out[6..9], self.fragment_offset)?;
        write_u24(&mut out[9..12], self.fragment_length)?;
        Ok(())
    }
}

fn read_u24(b: &[u8]) -> u32 {
    u32::from_be_bytes([0, b[0], b[1], b[2]])
}

fn write_u24(out: &mut [u8], v: u32) -> Result<(), FramingError> {
    if v > 0x00FF_FFFF {
        return Err(FramingError::FieldTooLarge);
    }
    let be = v.to_be_bytes();
    out[..3].copy_from_slice(&be[1..4]);
    Ok(())
}

fn read_u48(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for &byte in &b[..6] {
        v = (v << 8) | byte as u64;
    }
    v
}

fn write_u48(out: &mut [u8], v: u64) {
    let be = v.to_be_bytes();
    out[..6].copy_from_slice(&be[2..8]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{CT_HANDSHAKE, HS_CLIENT_HELLO, HS_SERVER_HELLO};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Captured from the DTLS 1.3 server.
    const CH1: &str = "16fefd0000000000000000009d010000910000000000000091fefd7163a0557695941c469381d34f1248339c2ce5cf57c5d1bdc2374863a52fee4a00000002130101000065002b000302fefc000d001e001c06030503040308070806080b0805080a08040809060105010401030100160000003300260024001d00207aa112ef4ec2a8130509fa81b9be35c422e3436667a85502ca404ed18ef06741000a000a0008001d001800170100";
    const HRR: &str = "16fefd00000000000000000083020000770000000000000077fefdcf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c00130100004f002b0002fefc002c0045004320e33ec347cc57f35d058d68cba061f15deb179939f01fc2cdcbed463b284063891301a8a3d91799f0bbbd8c869def24e56b09b8148fd752a866cafd3e4a458bf1918e";

    #[test]
    fn parses_captured_client_hello_record() {
        let bytes = unhex(CH1);
        let (rec, end) = PlaintextRecord::parse(&bytes).unwrap();
        assert_eq!(rec.content_type, CT_HANDSHAKE);
        assert_eq!(rec.epoch, 0);
        assert_eq!(rec.seq, 0);
        assert_eq!(end, bytes.len());

        let hh = HandshakeHeader::parse(rec.fragment).unwrap();
        assert_eq!(hh.msg_type, HS_CLIENT_HELLO);
        assert_eq!(hh.message_seq, 0);
        assert_eq!(hh.fragment_offset, 0);
        // Unfragmented: the message and fragment lengths agree.
        assert_eq!(hh.length, hh.fragment_length);
    }

    #[test]
    fn parses_captured_hello_retry_request() {
        let bytes = unhex(HRR);
        let (rec, _) = PlaintextRecord::parse(&bytes).unwrap();
        let hh = HandshakeHeader::parse(rec.fragment).unwrap();
        // HRR is a ServerHello with the special random (RFC 8446 §4.1.3).
        assert_eq!(hh.msg_type, HS_SERVER_HELLO);
        assert_eq!(hh.message_seq, 0);
    }

    #[test]
    fn record_round_trips() {
        let body = [0xAAu8; 40];
        let mut buf = [0u8; 64];
        let rec = PlaintextRecord::write(CT_HANDSHAKE, 0, 1, &body, &mut buf).unwrap();
        let (parsed, end) = PlaintextRecord::parse(rec).unwrap();
        assert_eq!(end, rec.len());
        assert_eq!(parsed.content_type, CT_HANDSHAKE);
        assert_eq!(parsed.seq, 1);
        assert_eq!(parsed.fragment, &body);
    }

    #[test]
    fn handshake_header_round_trips() {
        let hh = HandshakeHeader {
            msg_type: HS_CLIENT_HELLO,
            length: 0x0123,
            message_seq: 1,
            fragment_offset: 0x10,
            fragment_length: 0x0113,
        };
        let mut out = [0u8; HS_HEADER_LEN];
        hh.write(&mut out).unwrap();
        assert_eq!(HandshakeHeader::parse(&out).unwrap(), hh);
    }

    #[test]
    fn u24_rejects_overflow() {
        let mut out = [0u8; 3];
        assert_eq!(
            write_u24(&mut out, 0x0100_0000),
            Err(FramingError::FieldTooLarge)
        );
    }
}
