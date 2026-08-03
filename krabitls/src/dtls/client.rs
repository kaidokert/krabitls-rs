//! DTLS 1.3 client handshake driver over a [`DatagramTransport`].
//!
//! This lifts the record/handshake framing, the `"dtls13"` key schedule, and the
//! epoch progression into a reusable driver: [`DtlsClient::connect`] runs
//! CH1 → HelloRetryRequest → CH2 → ServerHello, decrypts and reassembles the
//! epoch-2 server flight, sends the client Finished, and derives the epoch-3
//! application keys, then [`DtlsClient::send`] / [`DtlsClient::recv`] carry
//! application data.
//!
//! Server-certificate verification reuses the TLS path behind a caller
//! [`VerifyStrategy`]: the same chain trust decision, leaf pubkey cross-check,
//! hostname match, and CertificateVerify signature check. The server Finished MAC
//! is the one piece that cannot be reused — the TLS `verify_server_flight` bundles
//! a `"tls13 "`-prefixed Finished — so DTLS sequences the transcript here and
//! verifies the Finished with the `"dtls13"` schedule.
//!
//! Reliability (RFC 9147 §5.8): each ClientHello flight is buffered and
//! retransmitted on a receive timeout, up to [`MAX_FLIGHT_ATTEMPTS`] sends, so an
//! early lost datagram no longer aborts the handshake. Still absent: ACK records
//! (§7) and retransmission of the encrypted epoch-2/epoch-3 flights; a persistent
//! loss there surfaces as [`DtlsClientError::Timeout`].

use crate::bigint::Curve25519CtBn as Bn;
use crate::consts::{CT_APPLICATION_DATA, CT_HANDSHAKE, HS_FINISHED};
use crate::dtls::framing::{HS_HEADER_LEN, HandshakeHeader, PlaintextRecord};
use crate::dtls::handshake::{
    CLIENT_HELLO_MSG_TYPE, ServerHelloKind, parse_server_hello, write_client_hello,
};
use crate::dtls::keys::derive_handshake_keys;
use crate::dtls::record::{DtlsSuite, EpochKeys, SealHeader, SeqNumLen};
use crate::dtls::replay::ReplayWindow;
use crate::dtls::transport::DatagramTransport;
use crate::hkdf::{
    TranscriptHash, dtls_application_traffic_secrets, dtls_finished_mac, dtls_master_secret,
};
use crate::identity::verify_hostname;
use crate::server_flight::{
    extract_chain, parse_server_flight, verify_certificate_verify_with_prepared,
};
use crate::traits::verify_strategy::{CertChainView, PreparedVerifier, VerifyStrategy};
use crate::traits::{CertParser, Ed25519VerifierProvider, HkdfSha256, RsaVerifierProvider};
use subtle::ConstantTimeEq;

/// The two DTLS 1.3 epochs this driver produces after the handshake plus the
/// per-epoch send/receive counters. Epoch 2 (handshake) keys are consumed during
/// [`DtlsClient::connect`] and dropped; only the epoch-3 application keys live on.
pub(crate) struct DtlsClient<S: DtlsSuite> {
    client_app: EpochKeys<S>,
    server_app: EpochKeys<S>,
    send_seq: u64,
    /// Monotonic hint for reconstructing the next inbound record's full sequence
    /// number from its truncated on-wire form; the replay window is the actual
    /// duplicate/too-old gate.
    recv_hint: u64,
    /// Anti-replay window over the epoch-3 record sequence space (RFC 9147 §4.5.1).
    server_replay: ReplayWindow,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DtlsClientError<E> {
    /// The transport surfaced an error.
    Transport(E),
    /// No reply arrived after exhausting a flight's retransmissions, or an
    /// encrypted flight (which is not yet retransmitted) timed out.
    Timeout,
    /// A received datagram was not a well-formed DTLS record for this phase.
    Protocol,
    /// The server sent a HelloRetryRequest without a cookie, or a ServerHello
    /// missing its key share, or otherwise deviated from the expected flight.
    Handshake,
    /// Key derivation failed (all-zero DH share or an HKDF error).
    KeySchedule,
    /// A working buffer (ClientHello, record, or the flight-reassembly buffer)
    /// was too small.
    BufferTooSmall,
    /// The verify strategy rejected the server certificate chain.
    StrategyRejected,
    /// The strategy's prepared verifier did not match the leaf certificate.
    PubkeyMismatch,
    /// The leaf certificate did not match the requested hostname.
    HostnameMismatch,
    /// CertificateVerify signature or the server Finished MAC failed.
    CertVerify,
}

/// Total sends of a handshake flight before giving up (RFC 9147 §5.8): the
/// initial transmission plus retransmissions on receive timeout.
const MAX_FLIGHT_ATTEMPTS: u8 = 5;

/// The X25519 basepoint (u = 9); a scalar-mult against it yields the client's
/// public key from its private scalar.
const X25519_BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

impl<S: DtlsSuite> DtlsClient<S> {
    /// Drive a full DTLS 1.3 handshake against the connected peer and return a
    /// client ready to carry application data. `strategy` decides trust in the
    /// server chain; `hostname`, when `Some`, is matched against the leaf SAN
    /// (`None` skips the check — sound only when the strategy pins the key, since
    /// then the pin is the identity binding). `flight_buf` receives the
    /// reassembled epoch-2 server flight (`msg_type ‖ u24 len ‖ body` messages);
    /// it must be large enough for the whole flight (a few KiB for a typical
    /// certificate chain).
    pub(crate) fn connect<T, H, V, E, R, P, const MAX_CHAIN: usize>(
        transport: &mut T,
        strategy: &V,
        hostname: Option<&str>,
        x25519_priv: &[u8; 32],
        client_random: &[u8; 32],
        flight_buf: &mut [u8],
    ) -> Result<Self, DtlsClientError<T::Error>>
    where
        T: DatagramTransport,
        H: HkdfSha256,
        V: VerifyStrategy<E, R>,
        E: Ed25519VerifierProvider,
        R: RsaVerifierProvider,
        P: CertParser,
    {
        let pub_key = ed25519_heapless::x25519::<Bn>(x25519_priv, &X25519_BASEPOINT)
            .map_err(|_| DtlsClientError::KeySchedule)?;

        // A single reused receive buffer + a reused flight buffer carry both
        // ClientHello exchanges; each flight is retransmitted on timeout. The
        // transcript is folded in as messages arrive, so no borrowed datagram has
        // to outlive the reused receive buffer.
        let mut rbuf = [0u8; 2048];
        let mut ch_dgram = [0u8; HS_HEADER_LEN + 512 + 16];
        let mut transcript = TranscriptHash::<H>::new();

        // --- CH1 -> HelloRetryRequest ---
        let mut ch1 = [0u8; 512];
        let ch1_len = write_client_hello(client_random, &pub_key, None, None, &mut ch1)
            .map_err(|_| DtlsClientError::BufferTooSmall)?;
        let ch1_rec = build_client_hello_record(&ch1[..ch1_len], 0, 0, &mut ch_dgram)?;
        let hrr_len = send_flight_await_reply(transport, ch1_rec, &mut rbuf, MAX_FLIGHT_ATTEMPTS)?;
        let cookie_buf = {
            let hrr_body = parse_hello_body::<T::Error>(&rbuf[..hrr_len])?;
            // HRR message-hash substitution: message_hash(H(CH1)) ‖ HRR.
            let ch1_hash = {
                let mut t = TranscriptHash::<H>::new();
                t.update(&transcript_msg_header(CLIENT_HELLO_MSG_TYPE, ch1_len));
                t.update(&ch1[..ch1_len]);
                t.snapshot()
            };
            transcript.update(&[0xFE, 0x00, 0x00, 0x20]);
            transcript.update(ch1_hash.as_bytes());
            transcript.update(&transcript_msg_header(2, hrr_body.len()));
            transcript.update(hrr_body);

            let mut cb = [0u8; 256];
            let cookie =
                match parse_server_hello(hrr_body).map_err(|_| DtlsClientError::Handshake)? {
                    ServerHelloKind::Retry { cookie } => cookie,
                    ServerHelloKind::Hello { .. } => return Err(DtlsClientError::Handshake),
                };
            let n = cookie.len();
            cb.get_mut(..n)
                .ok_or(DtlsClientError::BufferTooSmall)?
                .copy_from_slice(cookie);
            (cb, n)
        };

        // --- CH2 (echo cookie) -> ServerHello ---
        let mut ch2 = [0u8; 512];
        let ch2_len = write_client_hello(
            client_random,
            &pub_key,
            None,
            Some(&cookie_buf.0[..cookie_buf.1]),
            &mut ch2,
        )
        .map_err(|_| DtlsClientError::BufferTooSmall)?;
        let ch2_rec = build_client_hello_record(&ch2[..ch2_len], 1, 1, &mut ch_dgram)?;
        let sh_len = send_flight_await_reply(transport, ch2_rec, &mut rbuf, MAX_FLIGHT_ATTEMPTS)?;
        transcript.update(&transcript_msg_header(CLIENT_HELLO_MSG_TYPE, ch2_len));
        transcript.update(&ch2[..ch2_len]);
        let server_share = {
            let sh_body = parse_hello_body::<T::Error>(&rbuf[..sh_len])?;
            transcript.update(&transcript_msg_header(2, sh_body.len()));
            transcript.update(sh_body);
            match parse_server_hello(sh_body).map_err(|_| DtlsClientError::Handshake)? {
                ServerHelloKind::Hello { server_key_share } => *server_key_share,
                ServerHelloKind::Retry { .. } => return Err(DtlsClientError::Handshake),
            }
        };

        let hk = derive_handshake_keys::<S, H>(x25519_priv, &server_share, &transcript.snapshot())
            .map_err(|_| DtlsClientError::KeySchedule)?;

        // --- decrypt + reassemble the epoch-2 server flight into `flight_buf` ---
        let mut flight_len = 0usize;
        let mut srv_seq = 0u64;
        loop {
            let mut dg = [0u8; 2048];
            let n = recv_datagram(transport, &mut dg)?;
            let opened = hk
                .server
                .open(0, srv_seq, &mut dg[..n])
                .map_err(|_| DtlsClientError::Protocol)?;
            let hh =
                HandshakeHeader::parse(opened.content).map_err(|_| DtlsClientError::Protocol)?;
            let body = opened
                .content
                .get(HS_HEADER_LEN..HS_HEADER_LEN + hh.length as usize)
                .ok_or(DtlsClientError::Protocol)?;
            flight_len = append_transcript_msg(flight_buf, flight_len, hh.msg_type, body)?;
            srv_seq += 1;
            if hh.msg_type == HS_FINISHED {
                break;
            }
        }
        // Verify the flight. The cert-chain trust decision, the leaf pubkey
        // cross-check, the hostname match, and the CertificateVerify signature
        // reuse the TLS path unchanged. The server Finished MAC does NOT:
        // `verify_server_flight` bundles a `"tls13 "`-prefixed Finished check, so
        // DTLS must sequence the transcript itself and verify the Finished with
        // the `"dtls13"` schedule (`dtls_finished_mac`).
        let flight_plaintext = &flight_buf[..flight_len];
        let flight_view =
            parse_server_flight(flight_plaintext).map_err(|_| DtlsClientError::Protocol)?;
        let chain = extract_chain::<MAX_CHAIN>(flight_view.cert_body)
            .map_err(|_| DtlsClientError::Protocol)?;
        let mut slot: Option<PreparedVerifier<E, R>> = None;
        let trusted = strategy
            .verify_chain(CertChainView { certs: &chain }, &mut slot)
            .map_err(|_| DtlsClientError::StrategyRejected)?;
        let leaf_der = chain.first().copied().ok_or(DtlsClientError::Protocol)?;
        let leaf_view = P::parse(leaf_der).map_err(|_| DtlsClientError::Protocol)?;
        if !bool::from(trusted.prepared().matches_cert(&leaf_view)) {
            return Err(DtlsClientError::PubkeyMismatch);
        }
        if let Some(host) = hostname {
            verify_hostname(&leaf_view, host).map_err(|_| DtlsClientError::HostnameMismatch)?;
        }

        transcript.update(flight_view.ee_full);
        if let Some(creq) = flight_view.cert_request_full {
            transcript.update(creq);
        }
        transcript.update(flight_view.cert_full);
        let th_after_cert = transcript.snapshot();
        verify_certificate_verify_with_prepared::<E, R>(
            trusted.prepared(),
            &th_after_cert,
            flight_view.cv_body,
        )
        .map_err(|_| DtlsClientError::CertVerify)?;
        transcript.update(flight_view.cv_full);
        let th_after_cv = transcript.snapshot();

        // Server Finished: recompute the verify-data with the DTLS schedule and
        // compare in constant time.
        let expected_fin = dtls_finished_mac::<H>(&hk.server_hs_ts, &th_after_cv)
            .map_err(|_| DtlsClientError::KeySchedule)?;
        if flight_view.fin_body.len() != expected_fin.len()
            || !bool::from(expected_fin[..].ct_eq(flight_view.fin_body))
        {
            return Err(DtlsClientError::CertVerify);
        }
        transcript.update(flight_view.fin_full);
        let th_server_fin = transcript.snapshot();

        // --- client Finished (epoch 2). The server accepts a bare Finished when
        // it does not require client auth; message_seq continues 0,1,2. ---
        let fin_data = dtls_finished_mac::<H>(&hk.client_hs_ts, &th_server_fin)
            .map_err(|_| DtlsClientError::KeySchedule)?;
        let mut fin_msg = [0u8; HS_HEADER_LEN + 48];
        let fin_msg = write_hs_msg(&mut fin_msg, HS_FINISHED, 2, &fin_data[..])?;
        let mut rec = [0u8; 128];
        let sealed = hk
            .client
            .seal(
                SealHeader {
                    epoch: 2,
                    seq: 0,
                    seq_len: SeqNumLen::Two,
                    cid: None,
                },
                fin_msg,
                CT_HANDSHAKE,
                &mut rec,
            )
            .map_err(|_| DtlsClientError::Protocol)?;
        transport.send(sealed).map_err(DtlsClientError::Transport)?;

        // --- epoch-3 application keys ---
        let master =
            dtls_master_secret::<H>(&hk.hs_secret).map_err(|_| DtlsClientError::KeySchedule)?;
        let (c_ap, s_ap) = dtls_application_traffic_secrets::<H>(&master, &th_server_fin)
            .map_err(|_| DtlsClientError::KeySchedule)?;
        Ok(Self {
            client_app: EpochKeys::<S>::derive::<H>(&c_ap)
                .map_err(|_| DtlsClientError::KeySchedule)?,
            server_app: EpochKeys::<S>::derive::<H>(&s_ap)
                .map_err(|_| DtlsClientError::KeySchedule)?,
            send_seq: 0,
            recv_hint: 0,
            server_replay: ReplayWindow::new(),
        })
    }

    /// Seal `payload` as an epoch-3 application_data record and send it.
    pub(crate) fn send<T>(
        &mut self,
        transport: &mut T,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<(), DtlsClientError<T::Error>>
    where
        T: DatagramTransport,
    {
        let sealed = self
            .client_app
            .seal(
                SealHeader {
                    epoch: 3,
                    seq: self.send_seq,
                    seq_len: SeqNumLen::Two,
                    cid: None,
                },
                payload,
                CT_APPLICATION_DATA,
                out,
            )
            .map_err(|_| DtlsClientError::BufferTooSmall)?;
        transport.send(sealed).map_err(DtlsClientError::Transport)?;
        self.send_seq += 1;
        Ok(())
    }

    /// Receive and decrypt the next epoch-3 application_data record into `buf`,
    /// returning the plaintext length. Non-application records (the server's
    /// post-handshake NewSessionTicket/ACK) are skipped. `Ok(None)` on timeout.
    /// Duplicates and records older than the anti-replay window are dropped.
    pub(crate) fn recv<T>(
        &mut self,
        transport: &mut T,
        buf: &mut [u8],
    ) -> Result<Option<usize>, DtlsClientError<T::Error>>
    where
        T: DatagramTransport,
    {
        let mut dg = [0u8; 2048];
        loop {
            let n = match transport
                .recv(&mut dg)
                .map_err(DtlsClientError::Transport)?
            {
                Some(n) => n,
                None => return Ok(None),
            };
            // Only unified-header (epoch >0) records can be application data.
            if dg[..n].first().is_none_or(|&b| b & 0xE0 != 0x20) {
                continue;
            }
            let Ok(opened) = self.server_app.open(0, self.recv_hint, &mut dg[..n]) else {
                // Injected/garbage record: fails AEAD, skipped without touching
                // the replay window or the reconstruction hint.
                continue;
            };
            // Anti-replay over the epoch-3 sequence space, marked only after the
            // AEAD tag verifies (RFC 9147 §4.5.1). Applies to every authenticated
            // record, so a replayed NewSessionTicket/ACK is dropped too.
            if !self.server_replay.accepts(opened.seq) {
                continue;
            }
            self.server_replay.mark(opened.seq);
            self.recv_hint = self.recv_hint.max(opened.seq + 1);
            if opened.content_type == CT_APPLICATION_DATA {
                let len = opened.content.len();
                buf.get_mut(..len)
                    .ok_or(DtlsClientError::BufferTooSmall)?
                    .copy_from_slice(opened.content);
                return Ok(Some(len));
            }
            // Authenticated non-application record (handshake/ACK): counted for
            // replay, not delivered to the caller.
        }
    }
}

/// Frame a ClientHello body in a 12-byte DTLS handshake header + a plaintext
/// (epoch-0) record into `out`, returning the record slice. The bytes are
/// retained by the caller so a lost flight can be retransmitted.
fn build_client_hello_record<'o, E>(
    body: &[u8],
    message_seq: u16,
    record_seq: u64,
    out: &'o mut [u8],
) -> Result<&'o [u8], DtlsClientError<E>> {
    let mut msg = [0u8; HS_HEADER_LEN + 512];
    let msg = write_hs_msg(&mut msg, CLIENT_HELLO_MSG_TYPE, message_seq, body)?;
    PlaintextRecord::write(CT_HANDSHAKE, 0, record_seq, msg, out)
        .map_err(|_| DtlsClientError::BufferTooSmall)
}

/// Send `flight`, then wait for one reply datagram, retransmitting the buffered
/// flight on each timeout up to `max_attempts` sends total (RFC 9147 §5.8). The
/// per-attempt deadline is the transport's own receive timeout; true exponential
/// backoff would need a transport deadline hook, so this retransmits at a fixed
/// interval. Returns the reply length in `reply`.
fn send_flight_await_reply<T: DatagramTransport>(
    transport: &mut T,
    flight: &[u8],
    reply: &mut [u8],
    max_attempts: u8,
) -> Result<usize, DtlsClientError<T::Error>> {
    transport.send(flight).map_err(DtlsClientError::Transport)?;
    let mut attempts: u8 = 1;
    loop {
        match transport.recv(reply).map_err(DtlsClientError::Transport)? {
            Some(n) => return Ok(n),
            None => {
                if attempts >= max_attempts {
                    return Err(DtlsClientError::Timeout);
                }
                attempts += 1;
                transport.send(flight).map_err(DtlsClientError::Transport)?;
            }
        }
    }
}

/// Parse a received plaintext handshake datagram and return its ServerHello/HRR
/// message body.
fn parse_hello_body<E>(datagram: &[u8]) -> Result<&[u8], DtlsClientError<E>> {
    let (rec, _) = PlaintextRecord::parse(datagram).map_err(|_| DtlsClientError::Protocol)?;
    if rec.content_type != CT_HANDSHAKE {
        return Err(DtlsClientError::Protocol);
    }
    let hh = HandshakeHeader::parse(rec.fragment).map_err(|_| DtlsClientError::Protocol)?;
    rec.fragment
        .get(HS_HEADER_LEN..HS_HEADER_LEN + hh.fragment_length as usize)
        .ok_or(DtlsClientError::Protocol)
}

/// Receive one datagram, mapping a timeout (`Ok(None)`) to a terminal error
/// until the reliability layer lands.
fn recv_datagram<T: DatagramTransport>(
    transport: &mut T,
    buf: &mut [u8],
) -> Result<usize, DtlsClientError<T::Error>> {
    transport
        .recv(buf)
        .map_err(DtlsClientError::Transport)?
        .ok_or(DtlsClientError::Timeout)
}

/// Write a 12-byte DTLS handshake header (unfragmented) + `body` into `out`,
/// returning the message slice.
fn write_hs_msg<'o, E>(
    out: &'o mut [u8],
    msg_type: u8,
    message_seq: u16,
    body: &[u8],
) -> Result<&'o [u8], DtlsClientError<E>> {
    HandshakeHeader {
        msg_type,
        length: body.len() as u32,
        message_seq,
        fragment_offset: 0,
        fragment_length: body.len() as u32,
    }
    .write(out)
    .map_err(|_| DtlsClientError::BufferTooSmall)?;
    let end = HS_HEADER_LEN + body.len();
    out.get_mut(HS_HEADER_LEN..end)
        .ok_or(DtlsClientError::BufferTooSmall)?
        .copy_from_slice(body);
    out.get(..end).ok_or(DtlsClientError::BufferTooSmall)
}

/// The 4-byte TLS handshake-message header (`msg_type ‖ u24 length`) used for
/// transcript hashing, which strips DTLS's fragment fields (RFC 9147 §5.2).
fn transcript_msg_header(msg_type: u8, len: usize) -> [u8; 4] {
    let l = len as u32;
    [msg_type, (l >> 16) as u8, (l >> 8) as u8, l as u8]
}

/// Append a reassembled flight message to `buf` in transcript form
/// (`msg_type ‖ u24 len ‖ body`), returning the new length.
fn append_transcript_msg<E>(
    buf: &mut [u8],
    at: usize,
    msg_type: u8,
    body: &[u8],
) -> Result<usize, DtlsClientError<E>> {
    let hdr = transcript_msg_header(msg_type, body.len());
    let end = at + hdr.len() + body.len();
    if end > buf.len() {
        return Err(DtlsClientError::BufferTooSmall);
    }
    buf[at..at + 4].copy_from_slice(&hdr);
    buf[at + 4..end].copy_from_slice(body);
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dtls::transport::UdpTransport;
    use std::net::UdpSocket;
    use std::time::Duration;

    /// Drive the production [`DtlsClient`] against a live wolfSSL DTLS 1.3 server
    /// over the real [`DatagramTransport`], completing the handshake and an
    /// application-data round trip. Same peer contract as the handshake-module
    /// live tests: server on `KRABITLS_DTLS_PORT`, run with `-d` (no client auth)
    /// and an Ed25519 certificate.
    #[test]
    #[ignore = "needs a live wolfSSL DTLS 1.3 server (set KRABITLS_DTLS_PORT)"]
    fn live_client_round_trips_app_data() {
        use crate::aead::Aes128GcmSha256 as Suite;
        use crate::backends::{DerCert, PinOrSelfSigned, PinnedPubkeyOwned, RustCrypto};
        use crate::traits::verify_strategy::SafeStrategy;

        let port: u16 = std::env::var("KRABITLS_DTLS_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut transport = UdpTransport::new(sock);

        // Pin the wolfSSL server-ed25519.pem leaf key (the cert carries no SAN,
        // so hostname matching is skipped and the pin is the identity binding).
        let pin = PinnedPubkeyOwned::ed25519([
            0x23, 0xaa, 0x4d, 0x60, 0x50, 0xe0, 0x13, 0xd3, 0x3a, 0xed, 0xab, 0xf6, 0xa9, 0xcc,
            0x4a, 0xfe, 0xd7, 0x4d, 0x2f, 0xd2, 0x5b, 0x1a, 0x10, 0x05, 0xef, 0x5a, 0x41, 0x25,
            0xce, 0x1b, 0x53, 0x78,
        ]);
        let strategy = SafeStrategy::<_, DerCert>::new(PinOrSelfSigned::pinned(pin));

        let mut flight_buf = [0u8; 4096];
        let mut client =
            DtlsClient::<Suite>::connect::<_, RustCrypto, _, RustCrypto, RustCrypto, DerCert, 4>(
                &mut transport,
                &strategy,
                None,
                &[0x42u8; 32],
                &[0x77u8; 32],
                &mut flight_buf,
            )
            .expect("handshake completes");

        let mut out = [0u8; 128];
        client
            .send(&mut transport, b"hello from krabitls", &mut out)
            .expect("app data sends");

        // `recv` skips the server's post-handshake records internally, so the
        // server's application reply comes back on a single call. (The wolfSSL
        // example server sends a fixed reply, not an echo, so only the decrypt
        // is asserted, not the content.)
        let mut buf = [0u8; 256];
        let reply = client
            .recv(&mut transport, &mut buf)
            .expect("recv succeeds")
            .expect("an application_data reply, not a timeout");
        assert!(reply > 0, "decrypted a non-empty application_data reply");
    }

    /// A [`DatagramTransport`] that replays queued datagrams — no socket needed.
    struct QueueTransport {
        inbound: std::collections::VecDeque<Vec<u8>>,
    }

    impl DatagramTransport for QueueTransport {
        type Error = ();
        fn send(&mut self, _datagram: &[u8]) -> Result<(), ()> {
            Ok(())
        }
        fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ()> {
            match self.inbound.pop_front() {
                Some(d) => {
                    buf[..d.len()].copy_from_slice(&d);
                    Ok(Some(d.len()))
                }
                None => Ok(None),
            }
        }
    }

    /// A duplicated epoch-3 application record must be delivered once and then
    /// dropped by the anti-replay window (RFC 9147 §4.5.1), even though its AEAD
    /// tag verifies on the replay.
    #[cfg(feature = "cipher-aes")]
    #[test]
    fn recv_delivers_once_then_drops_replay() {
        use crate::aead::Aes128GcmSha256 as Suite;
        use crate::backends::RustCrypto;
        use crate::newtype::Secret;
        use zeroize::Zeroizing;

        let s_ap = Secret::new(Zeroizing::new([0x5au8; 32]));
        let mut client = DtlsClient::<Suite> {
            client_app: EpochKeys::<Suite>::derive::<RustCrypto>(&Secret::new(Zeroizing::new(
                [0xc1u8; 32],
            )))
            .unwrap(),
            server_app: EpochKeys::<Suite>::derive::<RustCrypto>(&s_ap).unwrap(),
            send_seq: 0,
            recv_hint: 0,
            server_replay: ReplayWindow::new(),
        };

        // Seal one epoch-3 record with the server's app keys, then feed it twice.
        let sealer = EpochKeys::<Suite>::derive::<RustCrypto>(&s_ap).unwrap();
        let mut rec = [0u8; 128];
        let sealed = sealer
            .seal(
                SealHeader {
                    epoch: 3,
                    seq: 0,
                    seq_len: SeqNumLen::Two,
                    cid: None,
                },
                b"payload",
                CT_APPLICATION_DATA,
                &mut rec,
            )
            .unwrap()
            .to_vec();
        let mut transport = QueueTransport {
            inbound: [sealed.clone(), sealed].into(),
        };

        let mut buf = [0u8; 64];
        assert_eq!(client.recv(&mut transport, &mut buf).unwrap(), Some(7));
        assert_eq!(&buf[..7], b"payload");
        // Second copy authenticates but is a replay → dropped; the queue then
        // drains to a timeout (`Ok(None)`).
        assert_eq!(client.recv(&mut transport, &mut buf).unwrap(), None);
    }

    /// A transport that reports `n` receive timeouts before finally delivering a
    /// reply, counting every send so a test can assert the retransmit behaviour.
    struct FlakyTransport {
        sent: usize,
        timeouts_before_reply: usize,
        reply: Vec<u8>,
    }

    impl DatagramTransport for FlakyTransport {
        type Error = ();
        fn send(&mut self, _datagram: &[u8]) -> Result<(), ()> {
            self.sent += 1;
            Ok(())
        }
        fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ()> {
            if self.timeouts_before_reply > 0 {
                self.timeouts_before_reply -= 1;
                return Ok(None);
            }
            buf[..self.reply.len()].copy_from_slice(&self.reply);
            Ok(Some(self.reply.len()))
        }
    }

    #[test]
    fn flight_is_retransmitted_until_the_reply_arrives() {
        let mut t = FlakyTransport {
            sent: 0,
            timeouts_before_reply: 2,
            reply: vec![1, 2, 3],
        };
        let mut buf = [0u8; 8];
        let n = send_flight_await_reply(&mut t, b"flight", &mut buf, MAX_FLIGHT_ATTEMPTS).unwrap();
        assert_eq!(&buf[..n], &[1, 2, 3]);
        assert_eq!(t.sent, 3, "1 initial send + 2 retransmits after 2 timeouts");
    }

    #[test]
    fn flight_gives_up_after_max_attempts() {
        let mut t = FlakyTransport {
            sent: 0,
            timeouts_before_reply: usize::MAX,
            reply: vec![],
        };
        let mut buf = [0u8; 8];
        let err = send_flight_await_reply(&mut t, b"flight", &mut buf, MAX_FLIGHT_ATTEMPTS);
        assert_eq!(err, Err(DtlsClientError::Timeout));
        assert_eq!(t.sent, MAX_FLIGHT_ATTEMPTS as usize);
    }

    /// Wraps a transport and silently drops the first `drop_sends` outbound
    /// datagrams, simulating early-flight loss on the wire.
    struct DropFirstSends<T> {
        inner: T,
        drop_sends: usize,
    }

    impl<T: DatagramTransport> DatagramTransport for DropFirstSends<T> {
        type Error = T::Error;
        fn send(&mut self, datagram: &[u8]) -> Result<(), T::Error> {
            if self.drop_sends > 0 {
                self.drop_sends -= 1;
                return Ok(());
            }
            self.inner.send(datagram)
        }
        fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, T::Error> {
            self.inner.recv(buf)
        }
    }

    /// The handshake still completes when the first ClientHello datagram is lost:
    /// the client retransmits CH1 after the receive timeout. Uses a short socket
    /// timeout so the single retransmit is quick. Same wolfSSL contract as
    /// [`live_client_round_trips_app_data`].
    #[test]
    #[ignore = "needs a live wolfSSL DTLS 1.3 server (set KRABITLS_DTLS_PORT)"]
    fn live_handshake_survives_first_flight_loss() {
        use crate::aead::Aes128GcmSha256 as Suite;
        use crate::backends::{DerCert, PinOrSelfSigned, PinnedPubkeyOwned, RustCrypto};
        use crate::traits::verify_strategy::SafeStrategy;

        let port: u16 = std::env::var("KRABITLS_DTLS_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(800)))
            .unwrap();
        let mut transport = DropFirstSends {
            inner: UdpTransport::new(sock),
            drop_sends: 1,
        };

        let pin = PinnedPubkeyOwned::ed25519([
            0x23, 0xaa, 0x4d, 0x60, 0x50, 0xe0, 0x13, 0xd3, 0x3a, 0xed, 0xab, 0xf6, 0xa9, 0xcc,
            0x4a, 0xfe, 0xd7, 0x4d, 0x2f, 0xd2, 0x5b, 0x1a, 0x10, 0x05, 0xef, 0x5a, 0x41, 0x25,
            0xce, 0x1b, 0x53, 0x78,
        ]);
        let strategy = SafeStrategy::<_, DerCert>::new(PinOrSelfSigned::pinned(pin));

        let mut flight_buf = [0u8; 4096];
        let mut client =
            DtlsClient::<Suite>::connect::<_, RustCrypto, _, RustCrypto, RustCrypto, DerCert, 4>(
                &mut transport,
                &strategy,
                None,
                &[0x42u8; 32],
                &[0x77u8; 32],
                &mut flight_buf,
            )
            .expect("handshake completes despite the dropped CH1");

        let mut out = [0u8; 128];
        client
            .send(&mut transport, b"hello from krabitls", &mut out)
            .expect("app data sends");
    }
}
