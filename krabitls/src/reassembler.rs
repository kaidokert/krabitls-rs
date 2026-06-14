//! Multi-record server-flight reassembly.
//!
//! TLS 1.3 servers may split the encrypted handshake flight
//! (EncryptedExtensions / Certificate / CertificateVerify / Finished)
//! across multiple records, especially when the certificate chain is
//! large enough to overflow one MTU. Each record decrypts to one
//! contiguous chunk of inner-handshake content; the four handshake
//! messages span the concatenation of those chunks.
//!
//! `ServerFlightReassembler` is a small `heapless::Vec`-backed accumulator
//! that owns the reassembled bytes and answers "have we seen the whole
//! flight yet?" by walking message-by-message looking for `Finished`.
//!
//! Driver responsibilities (read records off the socket, drop
//! `change_cipher_spec`, AEAD-decrypt under the server handshake key,
//! peel off the trailing `content_type` byte) stay in the caller. The
//! reassembler only handles the concat + end-of-flight detection.

use heapless::Vec;

use crate::server_flight::FlightError;

/// Handshake message type for `Finished` (RFC 8446 §4.4.4).
const HS_FINISHED: u8 = 20;
/// Handshake message type for `EncryptedExtensions` (RFC 8446 §4.3.1).
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
/// Extension ID for `record_size_limit` (RFC 8449 §4).
const EXT_RECORD_SIZE_LIMIT: u16 = 0x001C;

/// Owns the concatenated inner-handshake bytes from one or more records.
///
/// `N` is the capacity in bytes. Pick it to fit the largest server flight
/// you expect to receive — public RSA chains routinely run 5-8 KiB, so
/// 8 KiB is a comfortable upper bound for general-internet endpoints.
/// Controlled-profile endpoints (single Ed25519 leaf, no intermediates)
/// fit in well under 1 KiB.
pub struct ServerFlightReassembler<const N: usize> {
    buf: Vec<u8, N>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum ReassemblyError {
    /// Appending the chunk would exceed capacity `N`.
    #[error("server-flight reassembler capacity exceeded")]
    Overflow,
}

impl<const N: usize> ServerFlightReassembler<N> {
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append one record's worth of decrypted inner-handshake content.
    pub fn push_content(&mut self, content: &[u8]) -> Result<(), ReassemblyError> {
        self.buf
            .extend_from_slice(content)
            .map_err(|_| ReassemblyError::Overflow)
    }

    /// Walk the accumulated buffer message-by-message. Returns `true` once a
    /// complete `Finished` message has arrived — even if there are bytes
    /// after it. RFC 8446 permits a server to pack post-handshake messages
    /// (e.g. NewSessionTicket) into the same encrypted record as the server
    /// `Finished`; without this tolerance the reassembler would wait
    /// indefinitely for more data that never comes.
    ///
    /// Callers feeding the bytes into [`crate::parse_server_flight`] (which
    /// is strict about trailing bytes) should use [`Self::flight_bytes`] to
    /// get the slice up to and including `Finished`, rather than
    /// [`Self::as_slice`].
    pub fn is_complete(&self) -> bool {
        self.flight_end_offset().is_some()
    }

    /// If the buffer contains a complete server flight (a well-framed
    /// `Finished` message), return the inner-handshake bytes through the
    /// end of that `Finished`. Returns `None` while the flight is still
    /// being reassembled. Bytes after `Finished` (post-handshake messages
    /// like NewSessionTicket that the server may pack into the same
    /// record, or fragmentation slop) are *not* included; reach them via
    /// `as_slice()[flight_bytes().len()..]` if you need them.
    pub fn flight_bytes(&self) -> Option<&[u8]> {
        let end = self.flight_end_offset()?;
        Some(&self.buf[..end])
    }

    /// Internal: byte offset just past the first well-framed `Finished`.
    fn flight_end_offset(&self) -> Option<usize> {
        let buf: &[u8] = &self.buf;
        let mut i = 0;
        while i + 4 <= buf.len() {
            let msg_type = buf[i];
            // 24-bit handshake-message length. Decode as `u32` (24 bits don't
            // fit a 16-bit `usize`) and bail out on conversion failure rather
            // than silently truncating on 16-bit targets.
            let len = usize::try_from(u32::from_be_bytes([0, buf[i + 1], buf[i + 2], buf[i + 3]]))
                .ok()?;
            // Rewrite of `i + 4 + len > buf.len()` to avoid overflow on
            // 16-bit `usize`: the loop guarantees `i + 4 <= buf.len()`,
            // so `buf.len() - i - 4` can't underflow.
            if len > buf.len() - i - 4 {
                return None;
            }
            i += 4 + len;
            if msg_type == HS_FINISHED {
                return Some(i);
            }
        }
        None
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Walk the EncryptedExtensions message in the reassembled flight and
    /// return the peer's RFC 8449 `record_size_limit` value if present.
    /// Returns `Ok(None)` if the extension is absent.
    ///
    /// Runs on AEAD-authenticated but handshake-unverified bytes (the
    /// caller invokes this *before* `finalize_server_flight`). All
    /// parsing is strictly bounds-checked; no panics, no OOB reads,
    /// even on adversarially-crafted server bytes.
    ///
    /// Validity of the returned value (RFC 8449's `[64, 2^14 + 1]`
    /// range) is the caller's responsibility — peek surfaces what's on
    /// the wire; the engine maps out-of-range values to its own error
    /// variant.
    pub fn peek_ee_record_size_limit(&self) -> Result<Option<u16>, FlightError> {
        let buf = self.flight_bytes().ok_or(FlightError::Truncated)?;
        // First handshake message in the flight must be EncryptedExtensions.
        if buf.len() < 4 {
            return Err(FlightError::Truncated);
        }
        if buf[0] != HS_ENCRYPTED_EXTENSIONS {
            return Err(FlightError::UnexpectedHandshakeType {
                expected: HS_ENCRYPTED_EXTENSIONS,
                got: buf[0],
            });
        }
        let ee_body_len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < 4 + ee_body_len {
            return Err(FlightError::Truncated);
        }
        let ee_body = &buf[4..4 + ee_body_len];

        // EncryptedExtensions body: u16 extensions_total, then extensions.
        if ee_body.len() < 2 {
            return Err(FlightError::Truncated);
        }
        let ext_total = u16::from_be_bytes([ee_body[0], ee_body[1]]) as usize;
        if ee_body.len() != 2 + ext_total {
            return Err(FlightError::Truncated);
        }

        let mut rest = &ee_body[2..];
        let mut found: Option<u16> = None;
        while !rest.is_empty() {
            if rest.len() < 4 {
                return Err(FlightError::Truncated);
            }
            let ext_type = u16::from_be_bytes([rest[0], rest[1]]);
            let ext_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
            if rest.len() < 4 + ext_len {
                return Err(FlightError::Truncated);
            }
            let body = &rest[4..4 + ext_len];
            if ext_type == EXT_RECORD_SIZE_LIMIT {
                if body.len() != 2 {
                    return Err(FlightError::Truncated);
                }
                if found.is_some() {
                    return Err(FlightError::DuplicateExtension { ext_type });
                }
                found = Some(u16::from_be_bytes([body[0], body[1]]));
            }
            rest = &rest[4 + ext_len..];
        }
        Ok(found)
    }
}

impl<const N: usize> Default for ServerFlightReassembler<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ee(body_len: usize) -> alloc_helper::Msg {
        alloc_helper::msg(8, body_len)
    }
    fn cert(body_len: usize) -> alloc_helper::Msg {
        alloc_helper::msg(11, body_len)
    }
    fn cv(body_len: usize) -> alloc_helper::Msg {
        alloc_helper::msg(15, body_len)
    }
    fn fin(body_len: usize) -> alloc_helper::Msg {
        alloc_helper::msg(HS_FINISHED, body_len)
    }

    mod alloc_helper {
        pub struct Msg(pub [u8; 1024], pub usize);
        pub fn msg(ty: u8, body_len: usize) -> Msg {
            assert!(body_len + 4 <= 1024);
            let mut buf = [0u8; 1024];
            buf[0] = ty;
            buf[1] = ((body_len >> 16) & 0xff) as u8;
            buf[2] = ((body_len >> 8) & 0xff) as u8;
            buf[3] = (body_len & 0xff) as u8;
            Msg(buf, 4 + body_len)
        }
        impl Msg {
            pub fn as_slice(&self) -> &[u8] {
                &self.0[..self.1]
            }
        }
    }

    #[test]
    fn empty_buffer_is_not_complete() {
        let r: ServerFlightReassembler<128> = ServerFlightReassembler::new();
        assert!(!r.is_complete());
        assert!(r.is_empty());
    }

    #[test]
    fn single_record_full_flight_is_complete() {
        let mut r: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut combined = heapless::Vec::<u8, 512>::new();
        combined.extend_from_slice(ee(2).as_slice()).unwrap();
        combined.extend_from_slice(cert(40).as_slice()).unwrap();
        combined.extend_from_slice(cv(70).as_slice()).unwrap();
        combined.extend_from_slice(fin(32).as_slice()).unwrap();
        r.push_content(&combined).unwrap();
        assert!(r.is_complete());
    }

    #[test]
    fn partial_finished_is_not_complete() {
        let mut r: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        r.push_content(ee(2).as_slice()).unwrap();
        r.push_content(cert(40).as_slice()).unwrap();
        // CV header but body truncated halfway:
        let cv_full = cv(70);
        let cv_slice = cv_full.as_slice();
        r.push_content(&cv_slice[..cv_slice.len() - 5]).unwrap();
        assert!(!r.is_complete());
    }

    #[test]
    fn multi_record_concat_completes() {
        let mut r: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        // Record 1: EE + part of Cert
        let cert_full = cert(60);
        let cert_slice = cert_full.as_slice();
        let mut rec1 = heapless::Vec::<u8, 128>::new();
        rec1.extend_from_slice(ee(2).as_slice()).unwrap();
        rec1.extend_from_slice(&cert_slice[..30]).unwrap();
        r.push_content(&rec1).unwrap();
        assert!(!r.is_complete());
        // Record 2: rest of Cert + CV
        let mut rec2 = heapless::Vec::<u8, 256>::new();
        rec2.extend_from_slice(&cert_slice[30..]).unwrap();
        rec2.extend_from_slice(cv(70).as_slice()).unwrap();
        r.push_content(&rec2).unwrap();
        assert!(!r.is_complete());
        // Record 3: Finished
        r.push_content(fin(32).as_slice()).unwrap();
        assert!(r.is_complete());
    }

    #[test]
    fn trailing_bytes_after_finished_still_complete() {
        // RFC 8446 lets a server pack post-handshake messages (e.g.
        // NewSessionTicket, msg_type=4) into the same encrypted record as
        // the server `Finished`. The reassembler must treat the first
        // well-framed `Finished` as end-of-flight; `flight_bytes()` slices
        // the buffer up to and including `Finished` so the strict
        // `parse_server_flight` doesn't choke on the trailing payload.
        let mut r: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut combined = heapless::Vec::<u8, 512>::new();
        combined.extend_from_slice(ee(2).as_slice()).unwrap();
        combined.extend_from_slice(cert(40).as_slice()).unwrap();
        combined.extend_from_slice(cv(70).as_slice()).unwrap();
        combined.extend_from_slice(fin(32).as_slice()).unwrap();
        let flight_only_len = combined.len();
        // Synthesize a NewSessionTicket-shaped trailing message.
        let nst = alloc_helper::msg(4, 8);
        combined.extend_from_slice(nst.as_slice()).unwrap();

        r.push_content(&combined).unwrap();
        assert!(
            r.is_complete(),
            "is_complete must tolerate trailing post-handshake bytes"
        );
        let flight = r.flight_bytes().expect("flight_bytes after Finished");
        assert_eq!(flight.len(), flight_only_len);
        // Trailing bytes still visible via the full buffer.
        assert!(r.as_slice().len() > flight.len());
        assert_eq!(&r.as_slice()[flight.len()..], nst.as_slice());
    }

    #[test]
    fn flight_bytes_returns_none_until_finished() {
        let mut r: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        r.push_content(ee(2).as_slice()).unwrap();
        r.push_content(cert(40).as_slice()).unwrap();
        assert!(r.flight_bytes().is_none());
        r.push_content(cv(70).as_slice()).unwrap();
        assert!(r.flight_bytes().is_none());
        r.push_content(fin(32).as_slice()).unwrap();
        assert!(r.flight_bytes().is_some());
    }

    #[test]
    fn overflow_returns_error() {
        let mut r: ServerFlightReassembler<32> = ServerFlightReassembler::new();
        let big = [0u8; 64];
        assert_eq!(r.push_content(&big), Err(ReassemblyError::Overflow));
    }

    #[test]
    fn clear_resets_state() {
        let mut r: ServerFlightReassembler<128> = ServerFlightReassembler::new();
        r.push_content(ee(2).as_slice()).unwrap();
        r.push_content(fin(32).as_slice()).unwrap();
        assert!(r.is_complete());
        r.clear();
        assert!(r.is_empty());
        assert!(!r.is_complete());
    }

    /// Build an EE message whose body is a u16 extensions-total followed by
    /// the given extensions. Returns the full handshake message bytes.
    fn ee_with_extensions(extensions: &[u8]) -> heapless::Vec<u8, 512> {
        let mut body = heapless::Vec::<u8, 512>::new();
        let total = extensions.len() as u16;
        body.extend_from_slice(&total.to_be_bytes()).unwrap();
        body.extend_from_slice(extensions).unwrap();
        let mut msg = heapless::Vec::<u8, 512>::new();
        msg.push(HS_ENCRYPTED_EXTENSIONS).unwrap();
        let len = body.len() as u32;
        msg.push(((len >> 16) & 0xff) as u8).unwrap();
        msg.push(((len >> 8) & 0xff) as u8).unwrap();
        msg.push((len & 0xff) as u8).unwrap();
        msg.extend_from_slice(&body).unwrap();
        msg
    }

    fn record_size_limit_ext(value: u16) -> [u8; 6] {
        let v = value.to_be_bytes();
        [
            (EXT_RECORD_SIZE_LIMIT >> 8) as u8,
            (EXT_RECORD_SIZE_LIMIT & 0xff) as u8,
            0x00,
            0x02, // ext data len = 2
            v[0],
            v[1],
        ]
    }

    fn complete_flight_with_ee(ee_bytes: &[u8]) -> ServerFlightReassembler<1024> {
        let mut r: ServerFlightReassembler<1024> = ServerFlightReassembler::new();
        let mut combined = heapless::Vec::<u8, 1024>::new();
        combined.extend_from_slice(ee_bytes).unwrap();
        combined.extend_from_slice(cert(40).as_slice()).unwrap();
        combined.extend_from_slice(cv(70).as_slice()).unwrap();
        combined.extend_from_slice(fin(32).as_slice()).unwrap();
        r.push_content(&combined).unwrap();
        r
    }

    #[test]
    fn peek_ee_record_size_limit_absent_returns_none() {
        let ee_bytes = ee_with_extensions(&[]);
        let r = complete_flight_with_ee(&ee_bytes);
        assert_eq!(r.peek_ee_record_size_limit(), Ok(None));
    }

    #[test]
    fn peek_ee_record_size_limit_present_returns_value() {
        let ext = record_size_limit_ext(8192);
        let ee_bytes = ee_with_extensions(&ext);
        let r = complete_flight_with_ee(&ee_bytes);
        assert_eq!(r.peek_ee_record_size_limit(), Ok(Some(8192)));
    }

    #[test]
    fn peek_ee_record_size_limit_skips_unrelated_extensions() {
        // Build extensions: [unknown_ext(4 bytes payload), record_size_limit].
        let mut exts = heapless::Vec::<u8, 32>::new();
        // ext type 0x002A (custom), len=4, payload=[0xab; 4]
        exts.extend_from_slice(&[0x00, 0x2A, 0x00, 0x04, 0xab, 0xab, 0xab, 0xab])
            .unwrap();
        exts.extend_from_slice(&record_size_limit_ext(2048))
            .unwrap();
        let ee_bytes = ee_with_extensions(&exts);
        let r = complete_flight_with_ee(&ee_bytes);
        assert_eq!(r.peek_ee_record_size_limit(), Ok(Some(2048)));
    }

    #[test]
    fn peek_ee_record_size_limit_duplicate_rejected() {
        let mut exts = heapless::Vec::<u8, 32>::new();
        exts.extend_from_slice(&record_size_limit_ext(2048))
            .unwrap();
        exts.extend_from_slice(&record_size_limit_ext(4096))
            .unwrap();
        let ee_bytes = ee_with_extensions(&exts);
        let r = complete_flight_with_ee(&ee_bytes);
        assert_eq!(
            r.peek_ee_record_size_limit(),
            Err(FlightError::DuplicateExtension {
                ext_type: EXT_RECORD_SIZE_LIMIT
            })
        );
    }

    #[test]
    fn peek_ee_record_size_limit_wrong_first_msg_type() {
        // First handshake message is Certificate (11), not EE.
        let mut r: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut combined = heapless::Vec::<u8, 512>::new();
        combined.extend_from_slice(cert(40).as_slice()).unwrap();
        combined.extend_from_slice(fin(32).as_slice()).unwrap();
        r.push_content(&combined).unwrap();
        assert_eq!(
            r.peek_ee_record_size_limit(),
            Err(FlightError::UnexpectedHandshakeType {
                expected: HS_ENCRYPTED_EXTENSIONS,
                got: 11
            })
        );
    }

    #[test]
    fn peek_ee_record_size_limit_returns_truncated_before_flight_complete() {
        let r: ServerFlightReassembler<128> = ServerFlightReassembler::new();
        assert_eq!(r.peek_ee_record_size_limit(), Err(FlightError::Truncated));
    }

    #[test]
    fn peek_ee_record_size_limit_ext_with_wrong_len_rejected() {
        // record_size_limit with claimed len=3 instead of 2.
        let bad_ext = [
            (EXT_RECORD_SIZE_LIMIT >> 8) as u8,
            (EXT_RECORD_SIZE_LIMIT & 0xff) as u8,
            0x00,
            0x03,
            0x10,
            0x00,
            0x00,
        ];
        let ee_bytes = ee_with_extensions(&bad_ext);
        let r = complete_flight_with_ee(&ee_bytes);
        assert_eq!(r.peek_ee_record_size_limit(), Err(FlightError::Truncated));
    }

    #[test]
    fn peek_ee_record_size_limit_extensions_total_inconsistent() {
        // ext_total in EE body claims more bytes than are present.
        let mut body = heapless::Vec::<u8, 32>::new();
        body.extend_from_slice(&20u16.to_be_bytes()).unwrap(); // ext_total = 20
        body.extend_from_slice(&record_size_limit_ext(1024))
            .unwrap(); // only 6 bytes
        let mut msg = heapless::Vec::<u8, 32>::new();
        msg.push(HS_ENCRYPTED_EXTENSIONS).unwrap();
        let len = body.len() as u32;
        msg.push(((len >> 16) & 0xff) as u8).unwrap();
        msg.push(((len >> 8) & 0xff) as u8).unwrap();
        msg.push((len & 0xff) as u8).unwrap();
        msg.extend_from_slice(&body).unwrap();
        let r = complete_flight_with_ee(&msg);
        assert_eq!(r.peek_ee_record_size_limit(), Err(FlightError::Truncated));
    }

    #[test]
    fn peek_ee_record_size_limit_ext_header_truncated() {
        // Extension header claims 3 bytes of ext header + ext_len overflows body.
        // ext_total = 3, then 3 bytes of partial extension header (need 4).
        let mut body = heapless::Vec::<u8, 16>::new();
        body.extend_from_slice(&3u16.to_be_bytes()).unwrap();
        body.extend_from_slice(&[0x00, 0x2A, 0x00]).unwrap();
        let mut msg = heapless::Vec::<u8, 16>::new();
        msg.push(HS_ENCRYPTED_EXTENSIONS).unwrap();
        let len = body.len() as u32;
        msg.push(((len >> 16) & 0xff) as u8).unwrap();
        msg.push(((len >> 8) & 0xff) as u8).unwrap();
        msg.push((len & 0xff) as u8).unwrap();
        msg.extend_from_slice(&body).unwrap();
        let r = complete_flight_with_ee(&msg);
        assert_eq!(r.peek_ee_record_size_limit(), Err(FlightError::Truncated));
    }
}
