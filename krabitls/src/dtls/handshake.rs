//! DTLS 1.3 handshake-message bodies for the client's flights.
//!
//! Only the record/handshake framing and a few version/cookie fields differ
//! from the TLS 1.3 ClientHello ([`crate::write_client_hello_with`]); the
//! extension bodies (key_share, supported_groups, signature_algorithms) are
//! byte-identical. The TLS writer is tightly coupled to the TLS record shape,
//! so the DTLS ClientHello is written here rather than by parameterising it.

use crate::consts::{
    CIPHER_AES_128_GCM_SHA256, HS_CLIENT_HELLO, LEGACY_SESSION_ID_LEN, NAMED_GROUP_X25519,
    SIG_SCHEME_ED25519,
};
use crate::dtls::framing::{DTLS_1_2_LEGACY_VERSION, DTLS_1_3_VERSION};

const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_COOKIE: u16 = 44;
const EXT_KEY_SHARE: u16 = 51;

#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub(crate) enum ClientHelloError {
    #[error("output buffer too small for the ClientHello")]
    BufferTooSmall,
}

/// A minimal fallible cursor over a byte buffer. Every write is bounds-checked;
/// on overflow the whole message-build fails rather than truncating.
struct Cursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
    overflow: bool,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            overflow: false,
        }
    }

    fn put(&mut self, bytes: &[u8]) {
        match self.buf.get_mut(self.pos..self.pos + bytes.len()) {
            Some(slot) => {
                slot.copy_from_slice(bytes);
                self.pos += bytes.len();
            }
            None => self.overflow = true,
        }
    }

    fn u8(&mut self, v: u8) {
        self.put(&[v]);
    }

    fn u16(&mut self, v: u16) {
        self.put(&v.to_be_bytes());
    }

    /// Reserve a 2-byte big-endian length placeholder; returns its offset so a
    /// later [`patch_u16`](Self::patch_u16) can backfill the measured length.
    fn reserve_u16(&mut self) -> usize {
        let at = self.pos;
        self.u16(0);
        at
    }

    fn patch_u16(&mut self, at: usize, v: u16) {
        if let Some(slot) = self.buf.get_mut(at..at + 2) {
            slot.copy_from_slice(&v.to_be_bytes());
        }
    }
}

/// Write a DTLS 1.3 ClientHello *handshake-message body* (the bytes after the
/// handshake header) into `out`. `cookie` carries the HRR cookie on the second
/// flight (`None` on the first). Returns the body length.
///
/// Body: `legacy_version(0xFEFD) random session_id<0..32> cookie<0..2^8-1>
/// cipher_suites compression extensions` (RFC 9147 §5.3 keeps DTLS 1.2's
/// `legacy_cookie` field, always empty in 1.3; the real cookie rides the
/// cookie extension).
pub(crate) fn write_client_hello(
    random: &[u8; 32],
    x25519_pub: &[u8; 32],
    session_id: Option<&[u8; LEGACY_SESSION_ID_LEN]>,
    cookie: Option<&[u8]>,
    out: &mut [u8],
) -> Result<usize, ClientHelloError> {
    let mut c = Cursor::new(out);

    c.u16(DTLS_1_2_LEGACY_VERSION);
    c.put(random);
    match session_id {
        Some(id) => {
            c.u8(LEGACY_SESSION_ID_LEN as u8);
            c.put(id);
        }
        None => c.u8(0),
    }
    // legacy_cookie: always empty in DTLS 1.3.
    c.u8(0);
    // cipher_suites: AES-128-GCM-SHA256 only for the initial datagram client.
    c.u16(2);
    c.u16(CIPHER_AES_128_GCM_SHA256);
    // legacy_compression_methods: just null.
    c.u8(1);
    c.u8(0);

    let ext_len_at = c.reserve_u16();
    let ext_start = c.pos;

    // supported_versions: DTLS 1.3.
    c.u16(EXT_SUPPORTED_VERSIONS);
    c.u16(3);
    c.u8(2);
    c.u16(DTLS_1_3_VERSION);

    // supported_groups: X25519.
    c.u16(EXT_SUPPORTED_GROUPS);
    c.u16(4);
    c.u16(2);
    c.u16(NAMED_GROUP_X25519);

    // signature_algorithms: Ed25519.
    c.u16(EXT_SIGNATURE_ALGORITHMS);
    c.u16(4);
    c.u16(2);
    c.u16(SIG_SCHEME_ED25519);

    // key_share: one X25519 KeyShareEntry.
    c.u16(EXT_KEY_SHARE);
    c.u16(2 + 2 + 2 + 32);
    c.u16(2 + 2 + 32);
    c.u16(NAMED_GROUP_X25519);
    c.u16(32);
    c.put(x25519_pub);

    // cookie (only on the post-HRR ClientHello).
    if let Some(cookie) = cookie {
        c.u16(EXT_COOKIE);
        c.u16((2 + cookie.len()) as u16);
        c.u16(cookie.len() as u16);
        c.put(cookie);
    }

    let ext_len = c.pos - ext_start;
    c.patch_u16(ext_len_at, ext_len as u16);

    if c.overflow {
        return Err(ClientHelloError::BufferTooSmall);
    }
    Ok(c.pos)
}

/// The `msg_type` of a ClientHello, for the caller assembling the handshake
/// header around the body from [`write_client_hello`].
pub(crate) const CLIENT_HELLO_MSG_TYPE: u8 = HS_CLIENT_HELLO;

/// The fixed ServerHello.random that marks a HelloRetryRequest: SHA-256 of
/// "HelloRetryRequest" (RFC 8446 §4.1.3).
pub(crate) const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub(crate) enum ParseError {
    #[error("server hello truncated or malformed")]
    Malformed,
    #[error("server selected an unexpected key-share group")]
    UnexpectedGroup,
    #[error("HelloRetryRequest without a cookie")]
    MissingCookie,
    #[error("ServerHello without a key_share")]
    MissingKeyShare,
}

/// A parsed ServerHello handshake-message body.
pub(crate) enum ServerHelloKind<'a> {
    /// HelloRetryRequest — resend the ClientHello echoing this cookie.
    Retry { cookie: &'a [u8] },
    /// The real ServerHello, carrying the server's X25519 key share.
    Hello { server_key_share: &'a [u8; 32] },
}

/// Parse a ServerHello *handshake-message body* (after the handshake header).
/// Distinguishes a HelloRetryRequest (fixed random) from the real ServerHello
/// and pulls the field the client needs next.
pub(crate) fn parse_server_hello(body: &[u8]) -> Result<ServerHelloKind<'_>, ParseError> {
    // legacy_version(2) random(32) session_id<0..32> cipher_suite(2)
    // legacy_compression(1) extensions<..>
    let mut i = 2usize;
    let random = body.get(i..i + 32).ok_or(ParseError::Malformed)?;
    let is_retry = random == HRR_RANDOM;
    i += 32;
    let sid_len = *body.get(i).ok_or(ParseError::Malformed)? as usize;
    i += 1 + sid_len;
    i += 2 + 1; // cipher_suite + compression
    let ext_len = read_u16(body, i)? as usize;
    i += 2;
    let ext_end = i.checked_add(ext_len).ok_or(ParseError::Malformed)?;
    if body.len() < ext_end {
        return Err(ParseError::Malformed);
    }

    let mut cookie: Option<&[u8]> = None;
    let mut key_share: Option<&[u8; 32]> = None;
    while i + 4 <= ext_end {
        let et = read_u16(body, i)?;
        let el = read_u16(body, i + 2)? as usize;
        let data = body.get(i + 4..i + 4 + el).ok_or(ParseError::Malformed)?;
        match et {
            EXT_COOKIE => {
                // cookie<2..2^16-1>: 2-byte length then the cookie.
                let clen = read_u16(data, 0)? as usize;
                cookie = Some(data.get(2..2 + clen).ok_or(ParseError::Malformed)?);
            }
            EXT_KEY_SHARE => {
                // ServerHello key_share is a single KeyShareEntry: group(2) len(2) key.
                let group = read_u16(data, 0)?;
                if group != NAMED_GROUP_X25519 {
                    return Err(ParseError::UnexpectedGroup);
                }
                let klen = read_u16(data, 2)? as usize;
                let key = data.get(4..4 + klen).ok_or(ParseError::Malformed)?;
                key_share = Some(key.try_into().map_err(|_| ParseError::UnexpectedGroup)?);
            }
            _ => {}
        }
        i += 4 + el;
    }

    if is_retry {
        Ok(ServerHelloKind::Retry {
            cookie: cookie.ok_or(ParseError::MissingCookie)?,
        })
    } else {
        Ok(ServerHelloKind::Hello {
            server_key_share: key_share.ok_or(ParseError::MissingKeyShare)?,
        })
    }
}

fn read_u16(b: &[u8], at: usize) -> Result<u16, ParseError> {
    let bytes = b.get(at..at + 2).ok_or(ParseError::Malformed)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dtls::framing::{HS_HEADER_LEN, HandshakeHeader, PlaintextRecord};

    #[test]
    fn client_hello_body_is_well_formed() {
        let random = [0x11u8; 32];
        let pubkey = [0x22u8; 32];
        let mut body = [0u8; 256];
        let n = write_client_hello(&random, &pubkey, None, None, &mut body).unwrap();
        let body = &body[..n];

        // legacy_version, random, empty session_id, empty cookie, then suites.
        assert_eq!(&body[0..2], &[0xFE, 0xFD]);
        assert_eq!(&body[2..34], &random);
        assert_eq!(body[34], 0, "session_id length");
        assert_eq!(body[35], 0, "legacy_cookie length");
        assert_eq!(&body[36..38], &[0x00, 0x02], "cipher_suites length");
        assert_eq!(&body[38..40], &CIPHER_AES_128_GCM_SHA256.to_be_bytes());
        // The X25519 public key appears verbatim in the key_share.
        assert!(body.windows(32).any(|w| w == pubkey));
    }

    #[test]
    fn frames_into_a_parseable_record() {
        let random = [0x33u8; 32];
        let pubkey = [0x44u8; 32];
        let mut body = [0u8; 256];
        let n = write_client_hello(&random, &pubkey, None, None, &mut body).unwrap();

        // Wrap body in a 12-byte handshake header, then a DTLSPlaintext record.
        let mut msg = [0u8; 300];
        let hh = HandshakeHeader {
            msg_type: CLIENT_HELLO_MSG_TYPE,
            length: n as u32,
            message_seq: 0,
            fragment_offset: 0,
            fragment_length: n as u32,
        };
        hh.write(&mut msg).unwrap();
        msg[12..12 + n].copy_from_slice(&body[..n]);

        let mut dgram = [0u8; 320];
        let rec = PlaintextRecord::write(
            crate::consts::CT_HANDSHAKE,
            0,
            0,
            &msg[..12 + n],
            &mut dgram,
        )
        .unwrap();
        let (parsed, _) = PlaintextRecord::parse(rec).unwrap();
        let ph = HandshakeHeader::parse(parsed.fragment).unwrap();
        assert_eq!(ph.msg_type, CLIENT_HELLO_MSG_TYPE);
        assert_eq!(ph.fragment_length as usize, n);
    }

    #[test]
    fn cookie_extension_present_on_retry() {
        let random = [0x55u8; 32];
        let pubkey = [0x66u8; 32];
        let cookie = [0xABu8; 20];
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        let na = write_client_hello(&random, &pubkey, None, None, &mut a).unwrap();
        let nb = write_client_hello(&random, &pubkey, None, Some(&cookie), &mut b).unwrap();
        assert_eq!(nb - na, 4 + 2 + cookie.len(), "cookie ext header + body");
        assert!(b[..nb].windows(cookie.len()).any(|w| w == cookie));
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Captured wolfSSL HelloRetryRequest and real ServerHello (testdata/dtls/).
    const HRR: &str = "16fefd00000000000000000083020000770000000000000077fefdcf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c00130100004f002b0002fefc002c0045004320e33ec347cc57f35d058d68cba061f15deb179939f01fc2cdcbed463b284063891301a8a3d91799f0bbbd8c869def24e56b09b8148fd752a866cafd3e4a458bf1918e";
    const SH: &str = "16fefd00000000000000010062020000560001000000000056fefd24ed4dc49e4a797e5705a6434a563d1c04569128adcef7d4e79b5c88e235ee2300130100002e00330024001d0020b748adf1b22ecfdc07de16ac75c0f8e90d8c6b7215cf67edd9096a12e39b4f0f002b0002fefc";

    fn hello_body(datagram_hex: &str) -> Vec<u8> {
        let bytes = unhex(datagram_hex);
        let (rec, _) = PlaintextRecord::parse(&bytes).unwrap();
        let hh = HandshakeHeader::parse(rec.fragment).unwrap();
        rec.fragment[HS_HEADER_LEN..HS_HEADER_LEN + hh.fragment_length as usize].to_vec()
    }

    #[test]
    fn parses_hello_retry_request_cookie() {
        let body = hello_body(HRR);
        match parse_server_hello(&body).unwrap() {
            ServerHelloKind::Retry { cookie } => assert_eq!(cookie.len(), 67),
            ServerHelloKind::Hello { .. } => panic!("expected a retry"),
        }
    }

    #[test]
    fn parses_server_hello_key_share() {
        let body = hello_body(SH);
        match parse_server_hello(&body).unwrap() {
            ServerHelloKind::Hello { server_key_share } => {
                assert_eq!(server_key_share.len(), 32);
                assert_eq!(server_key_share[0], 0xb7);
            }
            ServerHelloKind::Retry { .. } => panic!("expected the real ServerHello"),
        }
    }

    /// Send a ClientHello with the given cookie/message_seq/record seq and
    /// return the raw reply datagram.
    fn live_send_ch(
        sock: &std::net::UdpSocket,
        pubkey: &[u8; 32],
        cookie: Option<&[u8]>,
        msg_seq: u16,
        seq: u64,
    ) -> Vec<u8> {
        let random = [0x77u8; 32];
        let mut body = [0u8; 512];
        let n = write_client_hello(&random, pubkey, None, cookie, &mut body).unwrap();
        let mut msg = [0u8; 560];
        HandshakeHeader {
            msg_type: CLIENT_HELLO_MSG_TYPE,
            length: n as u32,
            message_seq: msg_seq,
            fragment_offset: 0,
            fragment_length: n as u32,
        }
        .write(&mut msg)
        .unwrap();
        msg[12..12 + n].copy_from_slice(&body[..n]);
        let mut dgram = [0u8; 600];
        let rec = PlaintextRecord::write(
            crate::consts::CT_HANDSHAKE,
            0,
            seq,
            &msg[..12 + n],
            &mut dgram,
        )
        .unwrap();
        sock.send(rec).unwrap();
        let mut resp = vec![0u8; 2048];
        let len = sock.recv(&mut resp).expect("no reply from server");
        resp.truncate(len);
        resp
    }

    fn hello_body_of(reply: &[u8]) -> Vec<u8> {
        let (rec, _) = PlaintextRecord::parse(reply).unwrap();
        assert_eq!(rec.content_type, crate::consts::CT_HANDSHAKE);
        let hh = HandshakeHeader::parse(rec.fragment).unwrap();
        rec.fragment[HS_HEADER_LEN..HS_HEADER_LEN + hh.fragment_length as usize].to_vec()
    }

    /// Live check against a running wolfSSL DTLS 1.3 server: the full plaintext
    /// exchange CH1 → HelloRetryRequest → CH2(+cookie) → ServerHello. Proves the
    /// record/handshake framing, extensions, and cookie echo are accepted by a
    /// real peer. Requires `KRABITLS_DTLS_PORT`; ignored so CI needs no peer.
    #[test]
    #[ignore = "needs a live wolfSSL DTLS 1.3 server (set KRABITLS_DTLS_PORT)"]
    fn live_handshake_reaches_server_hello() {
        use std::net::UdpSocket;
        use std::time::Duration;

        let port: u16 = std::env::var("KRABITLS_DTLS_PORT")
            .expect("set KRABITLS_DTLS_PORT")
            .parse()
            .unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let pubkey = [0x88u8; 32];

        // CH1 → HelloRetryRequest with a cookie.
        let reply = live_send_ch(&sock, &pubkey, None, 0, 0);
        let cookie = match parse_server_hello(&hello_body_of(&reply)).unwrap() {
            ServerHelloKind::Retry { cookie } => cookie.to_vec(),
            ServerHelloKind::Hello { .. } => panic!("expected HelloRetryRequest first"),
        };

        // CH2 echoing the cookie (message_seq=1, record seq=1) → real ServerHello.
        let reply = live_send_ch(&sock, &pubkey, Some(&cookie), 1, 1);
        match parse_server_hello(&hello_body_of(&reply)).unwrap() {
            ServerHelloKind::Hello { server_key_share } => {
                assert_eq!(server_key_share.len(), 32)
            }
            ServerHelloKind::Retry { .. } => panic!("expected ServerHello after the cookie"),
        }
    }

    #[cfg(test)]
    fn transcript_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + body.len());
        v.push(msg_type);
        v.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        v.extend_from_slice(body);
        v
    }

    #[cfg(test)]
    fn x25519_keypair(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        let mut base = [0u8; 32];
        base[0] = 9;
        let public =
            ed25519_heapless::x25519::<crate::bigint::Curve25519CtBn>(&seed, &base).unwrap();
        (seed, public)
    }

    #[cfg(test)]
    fn send_ch_body(sock: &std::net::UdpSocket, body: &[u8], msg_seq: u16, seq: u64) {
        let mut msg = [0u8; 560];
        HandshakeHeader {
            msg_type: CLIENT_HELLO_MSG_TYPE,
            length: body.len() as u32,
            message_seq: msg_seq,
            fragment_offset: 0,
            fragment_length: body.len() as u32,
        }
        .write(&mut msg)
        .unwrap();
        msg[12..12 + body.len()].copy_from_slice(body);
        let mut dgram = [0u8; 600];
        let rec = PlaintextRecord::write(
            crate::consts::CT_HANDSHAKE,
            0,
            seq,
            &msg[..12 + body.len()],
            &mut dgram,
        )
        .unwrap();
        sock.send(rec).unwrap();
    }

    #[cfg(test)]
    fn recv_dgram(sock: &std::net::UdpSocket) -> Vec<u8> {
        let mut resp = vec![0u8; 2048];
        let len = sock.recv(&mut resp).unwrap();
        resp.truncate(len);
        resp
    }

    /// The end-to-end milestone: after the plaintext handshake, build the HRR
    /// transcript, derive the handshake-epoch keys (DTLS `"dtls13"` schedule),
    /// and decrypt the server's first epoch-2 record — proving the key schedule
    /// and protected record layer interoperate with a real DTLS 1.3 peer.
    #[test]
    #[ignore = "needs a live wolfSSL DTLS 1.3 server (set KRABITLS_DTLS_PORT)"]
    fn live_derives_keys_and_decrypts_encrypted_extensions() {
        use crate::aead::Aes128GcmSha256 as Suite;
        use crate::backends::RustCrypto;
        use crate::consts::{CT_HANDSHAKE, HS_ENCRYPTED_EXTENSIONS};
        use crate::dtls::keys::derive_handshake_keys;
        use crate::hkdf::TranscriptHash;
        use std::net::UdpSocket;
        use std::time::Duration;

        let port: u16 = std::env::var("KRABITLS_DTLS_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

        let (priv_key, pub_key) = x25519_keypair([0x42u8; 32]);
        let random = [0x77u8; 32];

        let mut ch1 = [0u8; 512];
        let ch1_len = write_client_hello(&random, &pub_key, None, None, &mut ch1).unwrap();
        send_ch_body(&sock, &ch1[..ch1_len], 0, 0);
        let hrr_body = hello_body_of(&recv_dgram(&sock));
        let cookie = match parse_server_hello(&hrr_body).unwrap() {
            ServerHelloKind::Retry { cookie } => cookie.to_vec(),
            _ => panic!("expected HRR"),
        };

        let mut ch2 = [0u8; 512];
        let ch2_len = write_client_hello(&random, &pub_key, None, Some(&cookie), &mut ch2).unwrap();
        send_ch_body(&sock, &ch2[..ch2_len], 1, 1);
        let sh_body = hello_body_of(&recv_dgram(&sock));
        let server_share = match parse_server_hello(&sh_body).unwrap() {
            ServerHelloKind::Hello { server_key_share } => *server_key_share,
            _ => panic!("expected ServerHello"),
        };
        let mut flight = recv_dgram(&sock);

        // HRR transcript: message_hash(H(CH1)) ‖ HRR ‖ CH2 ‖ SH (RFC 8446 §4.4.1).
        let ch1_hash = {
            let mut t = TranscriptHash::<RustCrypto>::new();
            t.update(&transcript_msg(1, &ch1[..ch1_len]));
            t.snapshot()
        };
        let mut transcript = TranscriptHash::<RustCrypto>::new();
        transcript.update(&[0xFE, 0x00, 0x00, 0x20]);
        transcript.update(ch1_hash.as_bytes());
        transcript.update(&transcript_msg(2, &hrr_body));
        transcript.update(&transcript_msg(1, &ch2[..ch2_len]));
        transcript.update(&transcript_msg(2, &sh_body));
        let th = transcript.snapshot();

        let hk = derive_handshake_keys::<Suite, RustCrypto>(&priv_key, &server_share, &th).unwrap();
        let opened = hk
            .server
            .open(0, 0, &mut flight)
            .expect("AEAD open of the epoch-2 flight failed");
        assert_eq!(opened.content_type, CT_HANDSHAKE);
        let hh = HandshakeHeader::parse(opened.content).unwrap();
        assert_eq!(hh.msg_type, HS_ENCRYPTED_EXTENSIONS);
    }
}
