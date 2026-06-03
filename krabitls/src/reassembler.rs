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

/// Handshake message type for `Finished` (RFC 8446 §4.4.4).
const HS_FINISHED: u8 = 20;

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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ReassemblyError {
    /// Appending the chunk would exceed capacity `N`.
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

    /// Walk the accumulated buffer message-by-message. Returns `true` once
    /// the buffer ends exactly at a complete `Finished` message — i.e. the
    /// server flight has fully arrived.
    pub fn is_complete(&self) -> bool {
        let buf: &[u8] = &self.buf;
        let mut i = 0;
        while i + 4 <= buf.len() {
            let msg_type = buf[i];
            let len = ((buf[i + 1] as usize) << 16)
                | ((buf[i + 2] as usize) << 8)
                | (buf[i + 3] as usize);
            if i + 4 + len > buf.len() {
                return false;
            }
            i += 4 + len;
            if msg_type == HS_FINISHED {
                return i == buf.len();
            }
        }
        false
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
}
