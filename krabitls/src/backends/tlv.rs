//! Minimal X.509 / SAN TLV walker. Replaces the `der` crate's generic
//! `AnyRef::decode` + `SliceReader` chain on the cert parsing hot path.
//!
//! DER is canonical: length is always definite, tag is a single byte for
//! every shape we care about (low-tag-number form, tag < 31). Multi-byte
//! lengths use the long-form `0x80 | n_octets` prefix.

/// Parse error from the walker. Mapped to `CertParseError::Malformed`
/// or `IdentityError::MalformedSan` at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlvError;

/// One TLV: tag byte, body slice, and the slice that remains after this
/// TLV. `header_len` is the byte count consumed by tag + length prefix
/// (so the original buffer's `[..header_len]` is the header bytes and
/// `[..header_len + body.len()]` is the full TLV bytes).
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    // Only `tlv_cert.rs` (cfg `not(feature = "cert-der")`) reads
    // `header_len`; `identity.rs`'s SAN walker uses tag + body only.
    #[cfg_attr(all(feature = "cert-der", not(test)), allow(dead_code))]
    pub header_len: usize,
    pub body: &'a [u8],
    pub rest: &'a [u8],
}

/// Decode one TLV at the start of `buf`. Returns the tag, body, and the
/// rest of `buf` after consuming this TLV. Rejects multi-byte tags
/// (tag >= 31 with low-tag-number = 31 — unused in X.509 leaf certs we
/// see) and indefinite-length encoding (DER forbids it).
pub fn read_tlv(buf: &[u8]) -> Result<Tlv<'_>, TlvError> {
    if buf.is_empty() {
        return Err(TlvError);
    }
    let tag = buf[0];
    // Low-tag-number form only: bits 0..4 = tag number, must be < 31
    // (0x1F). 0x1F signals long-form tag — rejected here.
    if (tag & 0x1F) == 0x1F {
        return Err(TlvError);
    }
    if buf.len() < 2 {
        return Err(TlvError);
    }
    let len_first = buf[1];
    let (header_len, body_len) = if len_first & 0x80 == 0 {
        (2usize, len_first as usize)
    } else {
        let n = (len_first & 0x7F) as usize;
        // n=0 would be indefinite-length, illegal in DER.
        // n>4 means length > 4 GB, not seen in cert/SAN.
        if n == 0 || n > 4 {
            return Err(TlvError);
        }
        if buf.len() < 2 + n {
            return Err(TlvError);
        }
        let mut len = 0usize;
        for &b in &buf[2..2 + n] {
            len = len
                .checked_shl(8)
                .ok_or(TlvError)?
                .checked_add(b as usize)
                .ok_or(TlvError)?;
        }
        // DER requires minimal-length encoding: long form only when
        // length >= 128; first length byte must be non-zero.
        if len < 0x80 || buf[2] == 0 {
            return Err(TlvError);
        }
        (2 + n, len)
    };
    let end = header_len.checked_add(body_len).ok_or(TlvError)?;
    if buf.len() < end {
        return Err(TlvError);
    }
    Ok(Tlv {
        tag,
        header_len,
        body: &buf[header_len..end],
        rest: &buf[end..],
    })
}

// ASN.1 universal-class tags + the cert-parser-only helpers. Only the
// in-tree TLV cert parser (`tlv_cert.rs`, `not(cert-der)`) consumes these;
// the `der`-crate parser and the SAN walker don't. Gated once on the module
// rather than per-const. `tag_ctx_primitive` stays outside — the SAN walker
// needs it in every build.
#[cfg(not(feature = "cert-der"))]
mod cert_parser_tags {
    use super::TlvError;

    pub const TAG_BOOLEAN: u8 = 0x01;
    pub const TAG_INTEGER: u8 = 0x02;
    pub const TAG_BIT_STRING: u8 = 0x03;
    pub const TAG_OCTET_STRING: u8 = 0x04;
    #[cfg(feature = "rsa")]
    pub const TAG_NULL: u8 = 0x05;
    pub const TAG_OID: u8 = 0x06;
    pub const TAG_SEQUENCE: u8 = 0x30;

    /// `[N]` EXPLICIT (constructed) context-specific tag byte.
    pub const fn tag_ctx_constructed(n: u8) -> u8 {
        0xA0 | (n & 0x1F)
    }

    /// Peek the tag byte at the start of `buf` without consuming it.
    pub fn peek_tag(buf: &[u8]) -> Result<u8, TlvError> {
        buf.first().copied().ok_or(TlvError)
    }
}
#[cfg(not(feature = "cert-der"))]
pub use cert_parser_tags::*;

/// `[N]` IMPLICIT (primitive) context-specific tag byte.
pub const fn tag_ctx_primitive(n: u8) -> u8 {
    0x80 | (n & 0x1F)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_form_length() {
        let buf = [0x04, 0x03, 0xAA, 0xBB, 0xCC, 0xFF];
        let t = read_tlv(&buf).unwrap();
        assert_eq!(t.tag, 0x04);
        assert_eq!(t.body, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(t.rest, &[0xFF]);
        assert_eq!(t.header_len, 2);
    }

    #[test]
    fn long_form_length() {
        let mut buf = vec![0x04, 0x81, 0x80];
        buf.extend(core::iter::repeat_n(0xAB, 128));
        let t = read_tlv(&buf).unwrap();
        assert_eq!(t.tag, 0x04);
        assert_eq!(t.body.len(), 128);
        assert_eq!(t.body[0], 0xAB);
        assert!(t.rest.is_empty());
    }

    #[test]
    fn long_form_two_bytes() {
        let mut buf = vec![0x04, 0x82, 0x01, 0x00];
        buf.extend(core::iter::repeat_n(0xCD, 256));
        let t = read_tlv(&buf).unwrap();
        assert_eq!(t.body.len(), 256);
    }

    #[test]
    fn rejects_long_form_under_128() {
        // 0x81 0x7F is non-minimal (could use short form).
        let buf = [0x04, 0x81, 0x7F];
        assert!(read_tlv(&buf).is_err());
    }

    #[test]
    fn rejects_truncated_body() {
        let buf = [0x04, 0x10, 0xAA];
        assert!(read_tlv(&buf).is_err());
    }

    #[test]
    fn rejects_indefinite_length() {
        // 0x80 = indefinite length (BER but not DER).
        let buf = [0x04, 0x80, 0x00, 0x00];
        assert!(read_tlv(&buf).is_err());
    }

    #[test]
    fn rejects_long_tag() {
        // Low-tag-number form: bits 0..4 = 0x1F is reserved for long-tag.
        let buf = [0x1F, 0x05];
        assert!(read_tlv(&buf).is_err());
    }

    #[cfg(not(feature = "cert-der"))]
    #[test]
    fn ctx_tags_constructed() {
        assert_eq!(tag_ctx_constructed(0), 0xA0);
        assert_eq!(tag_ctx_constructed(3), 0xA3);
    }

    #[test]
    fn ctx_tags_primitive() {
        assert_eq!(tag_ctx_primitive(2), 0x82);
        assert_eq!(tag_ctx_primitive(7), 0x87);
    }
}
