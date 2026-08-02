//! `TlsEngine` — the `pub(crate)` state machine the [`TlsStream`] wrapper
//! drives. Pure orchestration over the existing typestate API.

use super::error::{HandshakeError, InternalError};
use super::scratch::{
    AEAD_TAG, MIN_RECORD_SIZE_LIMIT, PROTO_MAX_INNER_PLAINTEXT, RECORD_OVERHEAD, RecordSizeLimit,
    TLS_HEADER,
};
use super::{ClientConfig, ClientParams, Scratch};
#[cfg(feature = "cipher-aes")]
use crate::aead::Aes128GcmSha256;
#[cfg(feature = "chacha20")]
use crate::aead::ChaCha20Poly1305Sha256;
use crate::client_flight::ClientAuthPolicy;
use crate::connection::{
    AppData, FlightStep, NegotiatedSuite, ServerFlightDone, WaitServerFlight, WaitServerHello,
};
use crate::connection::{ConnectionError, TlsConnection};
use crate::consts::{
    CLOSE_NOTIFY_ALERT, CT_ALERT, CT_APPLICATION_DATA, CT_HANDSHAKE, HS_KEY_UPDATE,
    HS_NEW_SESSION_TICKET,
};
use crate::identity::verify_hostname;
use crate::server_flight::{
    certificate_request_context, certificate_request_sig_algs, extract_chain, parse_server_flight,
};
use crate::traits::CertParser;
use crate::traits::verify_strategy::{CertChainView, PreparedVerifier, VerifyStrategy};

/// Recv-buffer cursor state.
///
/// Invariants:
/// - **I1** `0 ≤ plain_start ≤ plain_end ≤ next_record ≤ filled ≤ RECV`
/// - **I3** `plain_end > plain_start` ⇒ `step()` must yield `AppData`;
///   `advance(n > 0)` is illegal; `recv_buffer()` returns `&mut []`
/// - **I6** post-drain with `next_record > 0` requires compaction
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecvState {
    pub filled: usize,
    pub plain_start: usize,
    pub plain_end: usize,
    pub next_record: usize,
}

impl RecvState {
    pub const fn new() -> Self {
        Self {
            filled: 0,
            plain_start: 0,
            plain_end: 0,
            next_record: 0,
        }
    }

    pub fn plaintext_parked(&self) -> bool {
        self.plain_start < self.plain_end
    }
}

/// 4-byte handshake header + the 1-byte `KeyUpdate` body — the most we ever
/// need to stage to parse a post-handshake message (NewSessionTicket bodies
/// are skipped, not buffered).
const PH_STAGE_MAX: usize = 5;

/// Reassembly state for post-handshake handshake messages, which a peer may
/// fragment across records (RFC 8446 §5.1). `stage` accumulates an incomplete
/// header plus the `KeyUpdate` body across `feed_post_handshake` calls;
/// `skip_remaining` counts the still-unconsumed body bytes of a message we
/// ignore (NewSessionTicket) that spans records. Per-record AEAD decryption
/// and `seq_in` are unaffected — reassembly is purely at the plaintext level.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PostHandshakeReasm {
    stage: [u8; PH_STAGE_MAX],
    stage_len: u8,
    /// `u32`, not `usize`: a handshake message length is a 24-bit field, which
    /// would truncate on a 16-bit-`usize` target.
    skip_remaining: u32,
}

impl PostHandshakeReasm {
    /// A post-handshake message is partway reassembled (RFC 8446 §5.1): the
    /// next record from the peer must be another handshake record, not app
    /// data or an alert interleaved between fragments.
    fn in_progress(&self) -> bool {
        self.stage_len != 0 || self.skip_remaining != 0
    }
}

/// Wrapped typestate states — one variant per `(handshake-phase × suite)`
/// plus pre-suite and terminal states.
#[allow(clippy::large_enum_variant)] // post-handshake variants carry app keys; size is dominated by the typestate, not the enum tag
pub(crate) enum EngineState<C: ClientConfig> {
    WaitServerHello(TlsConnection<WaitServerHello, C::Hkdf>),
    #[cfg(feature = "cipher-aes")]
    WaitFlightAes(TlsConnection<WaitServerFlight<Aes128GcmSha256>, C::Hkdf>),
    #[cfg(feature = "chacha20")]
    WaitFlightChaCha(TlsConnection<WaitServerFlight<ChaCha20Poly1305Sha256>, C::Hkdf>),
    #[cfg(feature = "cipher-aes")]
    AppAes(TlsConnection<AppData<Aes128GcmSha256>, C::Hkdf>),
    #[cfg(feature = "chacha20")]
    AppChaCha(TlsConnection<AppData<ChaCha20Poly1305Sha256>, C::Hkdf>),
    /// Terminal sentinel; also used as the `mem::replace` placeholder
    /// during state transitions.
    Closed,
}

impl<C: ClientConfig> EngineState<C> {
    pub fn in_data_phase(&self) -> bool {
        match self {
            #[cfg(feature = "cipher-aes")]
            EngineState::AppAes(_) => true,
            #[cfg(feature = "chacha20")]
            EngineState::AppChaCha(_) => true,
            _ => false,
        }
    }
}

/// One step of the engine state machine yields one [`EngineEvent`].
///
/// Priority: `Send > HandshakeDone > AppData > Closed > Recv`. `Send(n)`
/// carries the unsent remainder, not the original record size.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum EngineEvent {
    Send(usize),
    Recv,
    AppData,
    HandshakeDone,
    Closed,
}

pub(crate) struct TlsEngine<
    's,
    C: ClientConfig,
    const FLIGHT: usize,
    const RECV: usize,
    const SEND: usize,
    const MAX_CHAIN: usize,
> {
    pub(crate) scratch: &'s mut Scratch<FLIGHT, RECV, SEND>,
    pub(crate) state: EngineState<C>,
    pub(crate) recv: RecvState,

    /// Total bytes of the current outgoing record in `scratch.send_record`.
    pub(crate) send_pending_len: usize,
    pub(crate) send_acked: usize,

    /// Set between Server Finished verification and `HandshakeDone` emission.
    pub(crate) pending_handshake_done: bool,
    /// `HandshakeDone` cannot fire until the Client Finished is fully `mark_sent`-acknowledged.
    pub(crate) handshake_finished_pending_ack: bool,

    pub(crate) closed: bool,

    /// RFC 8449 limit we advertised; caps incoming protected record body.
    pub(crate) our_recv_limit: RecordSizeLimit,
    /// RFC 8449 limit peer advertised; caps outgoing inner plaintext.
    pub(crate) peer_recv_limit: RecordSizeLimit,

    /// Reassembly state for post-handshake handshake messages fragmented
    /// across records (RFC 8446 §5.1).
    pub(crate) ph: PostHandshakeReasm,

    /// Fresh RNG output drawn at `connect()` for the client
    /// `CertificateVerify` (randomized schemes use it as signing entropy —
    /// RSA-PSS salt). All-zero when the policy never signs
    /// (`!A::ACCEPT_CERT_REQUEST`); consumed at most once per connection.
    pub(crate) cv_entropy: [u8; 32],
}

impl<
    's,
    C: ClientConfig,
    const FLIGHT: usize,
    const RECV: usize,
    const SEND: usize,
    const MAX_CHAIN: usize,
> TlsEngine<'s, C, FLIGHT, RECV, SEND, MAX_CHAIN>
{
    pub(crate) fn new(
        scratch: &'s mut Scratch<FLIGHT, RECV, SEND>,
        init_state: EngineState<C>,
        our_recv_limit: RecordSizeLimit,
        peer_recv_limit: RecordSizeLimit,
        cv_entropy: [u8; 32],
    ) -> Self {
        // A reused static `Scratch` may still hold the previous connection's
        // reassembled flight; start each handshake with an empty reassembler so
        // a reconnect can't fold stale bytes into the new transcript (which
        // otherwise surfaces as a `CertificateVerify` failure).
        scratch.reassembler.clear();
        Self {
            scratch,
            state: init_state,
            recv: RecvState::new(),
            send_pending_len: 0,
            send_acked: 0,
            pending_handshake_done: false,
            handshake_finished_pending_ack: false,
            closed: false,
            our_recv_limit,
            peer_recv_limit,
            ph: PostHandshakeReasm::default(),
            cv_entropy,
        }
    }

    pub(crate) const fn default_our_recv_limit() -> RecordSizeLimit {
        // Clamp both ends so the result is always a valid `RecordSizeLimit`
        // regardless of `RECV`. An undersized `RECV` is still rejected
        // gracefully by `validate_construction` before this value is used.
        let from_buf = RECV.saturating_sub(RECORD_OVERHEAD);
        let value = if from_buf > PROTO_MAX_INNER_PLAINTEXT as usize {
            PROTO_MAX_INNER_PLAINTEXT
        } else if from_buf < MIN_RECORD_SIZE_LIMIT as usize {
            MIN_RECORD_SIZE_LIMIT
        } else {
            from_buf as u16
        };
        RecordSizeLimit::from_clamped(value)
    }

    pub(crate) fn is_send_pending(&self) -> bool {
        self.send_pending_len > self.send_acked
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed || matches!(self.state, EngineState::Closed)
    }

    /// Unacknowledged tail of the pending send; matches the byte count
    /// in the most recent `EngineEvent::Send(n)`.
    pub(crate) fn send_bytes(&self) -> &[u8] {
        if self.send_pending_len == 0 {
            return &[];
        }
        &self.scratch.send_record[self.send_acked..self.send_pending_len]
    }

    /// Drive the handshake phase one event. Priority:
    /// `Send > HandshakeDone > AppData > Closed > Recv`. Loop, never recursion.
    pub(crate) fn step_handshake<V, A>(
        &mut self,
        params: &ClientParams<'_, V, A>,
    ) -> Result<EngineEvent, HandshakeError>
    where
        V: VerifyStrategy<C::Ed25519, C::Rsa>,
        A: ClientAuthPolicy,
    {
        loop {
            if self.is_send_pending() {
                let remaining = self.send_pending_len - self.send_acked;
                return Ok(EngineEvent::Send(remaining));
            }

            if self.pending_handshake_done && !self.handshake_finished_pending_ack {
                self.pending_handshake_done = false;
                return Ok(EngineEvent::HandshakeDone);
            }

            // 0.5-RTT landing: handshake-phase dispatch refuses to decrypt
            // protected records, so this normally fires only via the
            // dispatcher's wrong-state check.
            if self.recv.plaintext_parked() {
                return Ok(EngineEvent::AppData);
            }

            if self.closed {
                return Ok(EngineEvent::Closed);
            }

            match self.frame_one_record()? {
                Framed::Need => return Ok(EngineEvent::Recv),
                Framed::Record {
                    start,
                    end,
                    outer_type,
                    ..
                } => {
                    self.dispatch_handshake_record(start, end, outer_type, params)?;
                }
            }
        }
    }
}

/// Either a complete record staged in `recv_record[start..end]`, or
/// `Need` for more transport bytes.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Framed {
    Record {
        start: usize,
        end: usize,
        outer_type: u8,
        length_field: usize,
    },
    Need,
}

// ============================================================================
// Dispatch helpers
// ============================================================================

impl<
    's,
    C: ClientConfig,
    const FLIGHT: usize,
    const RECV: usize,
    const SEND: usize,
    const MAX_CHAIN: usize,
> TlsEngine<'s, C, FLIGHT, RECV, SEND, MAX_CHAIN>
{
    /// Reclaim the consumed prefix of `recv_record` by moving the tail
    /// to offset 0. Requires I6 (no parked plaintext).
    fn compact_recv(&mut self) {
        debug_assert!(
            !self.recv.plaintext_parked(),
            "compact_recv with parked plaintext violates I6",
        );
        let src_start = self.recv.next_record;
        if src_start == 0 {
            return;
        }
        let count = self.recv.filled - src_start;
        if count > 0 {
            self.scratch
                .recv_record
                .copy_within(src_start..self.recv.filled, 0);
        }
        self.recv.filled = count;
        self.recv.plain_start = 0;
        self.recv.plain_end = 0;
        self.recv.next_record = 0;
    }

    /// Shared boundary-finder for both phases. RFC 8449 limit is enforced
    /// by dispatch, not here (plaintext SH/CCS are exempt).
    fn frame_one_record(&mut self) -> Result<Framed, HandshakeError> {
        if self.recv.plaintext_parked() {
            debug_assert!(
                false,
                "frame_one_record with parked plaintext (caller must drain via AppData)"
            );
            return Err(HandshakeError::Internal(
                InternalError::FrameWithParkedPlaintext,
            ));
        }

        // Lazy compaction: only compact on `Need`, where it actually
        // buys the caller more `recv_buffer()` space. Per-record-eager
        // compaction would be O(tail · k) when a peer coalesces many
        // small records into one transport segment.
        let start = self.recv.next_record;
        let buffered = self.recv.filled - start;
        if buffered < TLS_HEADER {
            if self.recv.next_record > 0 {
                self.compact_recv();
            }
            return Ok(Framed::Need);
        }

        let outer_type = self.scratch.recv_record[start];
        let length_field = u16::from_be_bytes([
            self.scratch.recv_record[start + 3],
            self.scratch.recv_record[start + 4],
        ]) as usize;

        // Physical-capacity guard: reject fast rather than block on a
        // transport read that can never make progress.
        let record_body_capacity = RECV.saturating_sub(TLS_HEADER);
        if length_field > record_body_capacity {
            return Err(HandshakeError::RecordTooLarge {
                limit: self.our_recv_limit.get(),
                got: length_field as u16,
            });
        }

        let end = start + TLS_HEADER + length_field;
        if self.recv.filled < end {
            if self.recv.next_record > 0 {
                self.compact_recv();
            }
            return Ok(Framed::Need);
        }

        Ok(Framed::Record {
            start,
            end,
            outer_type,
            length_field,
        })
    }

    fn dispatch_handshake_record<V, A>(
        &mut self,
        start: usize,
        end: usize,
        outer_type: u8,
        params: &ClientParams<'_, V, A>,
    ) -> Result<(), HandshakeError>
    where
        V: VerifyStrategy<C::Ed25519, C::Rsa>,
        A: ClientAuthPolicy,
    {
        match &self.state {
            EngineState::WaitServerHello(_) => {
                self.handle_server_hello(start, end, outer_type)?;
            }
            #[cfg(feature = "cipher-aes")]
            EngineState::WaitFlightAes(_) => {
                self.handle_flight_record(start, end, params)?;
            }
            #[cfg(feature = "chacha20")]
            EngineState::WaitFlightChaCha(_) => {
                self.handle_flight_record(start, end, params)?;
            }
            #[cfg(feature = "cipher-aes")]
            EngineState::AppAes(_) => {
                return Err(HandshakeError::Internal(
                    InternalError::HandshakeStepInDataPhase,
                ));
            }
            #[cfg(feature = "chacha20")]
            EngineState::AppChaCha(_) => {
                return Err(HandshakeError::Internal(
                    InternalError::HandshakeStepInDataPhase,
                ));
            }
            EngineState::Closed => {
                return Err(HandshakeError::Internal(
                    InternalError::HandshakeStepWrongState,
                ));
            }
        }
        // Centralized so a panicking handler can't half-consume the record.
        self.recv.next_record = end;
        Ok(())
    }

    /// Parse plaintext ServerHello, transition to `WaitFlight*`, and
    /// enforce the suite-must-be-advertised check.
    fn handle_server_hello(
        &mut self,
        start: usize,
        end: usize,
        outer_type: u8,
    ) -> Result<(), HandshakeError> {
        if outer_type != CT_HANDSHAKE {
            return Err(HandshakeError::Connection(ConnectionError::Decrypt(
                crate::aead::DecryptError::UnexpectedContentType(outer_type),
            )));
        }

        let conn = match core::mem::replace(&mut self.state, EngineState::Closed) {
            EngineState::WaitServerHello(c) => c,
            other => {
                self.state = other;
                return Err(HandshakeError::Internal(
                    InternalError::ServerHelloWrongState,
                ));
            }
        };

        let record = &self.scratch.recv_record[start..end];
        let negotiated = conn.read_server_hello(record).map_err(|e| {
            self.closed = true;
            HandshakeError::Connection(e)
        })?;

        // The advertised-suites check lives in the typestate's
        // `read_server_hello`; by the time we reach this match the
        // selected suite is known to have been on the advertised list.
        self.state = match negotiated {
            #[cfg(feature = "cipher-aes")]
            NegotiatedSuite::Aes128Gcm(c) => EngineState::WaitFlightAes(c),
            #[cfg(feature = "chacha20")]
            NegotiatedSuite::ChaCha20Poly1305(c) => EngineState::WaitFlightChaCha(c),
        };

        Ok(())
    }

    /// In-place feed of a flight record. On `FlightStep::Ready`, drives
    /// the strategy → identity → finalize → finish transition.
    fn handle_flight_record<V, A>(
        &mut self,
        start: usize,
        end: usize,
        params: &ClientParams<'_, V, A>,
    ) -> Result<(), HandshakeError>
    where
        V: VerifyStrategy<C::Ed25519, C::Rsa>,
        A: ClientAuthPolicy,
    {
        // RFC 8449 limit applies to protected records only; CCS is
        // handled by `feed_server_record_inplace` without decryption.
        let outer_type = self.scratch.recv_record[start];
        if outer_type == CT_APPLICATION_DATA {
            let length_field = end - start - TLS_HEADER;
            if length_field > self.our_recv_limit.get() as usize + AEAD_TAG {
                return Err(HandshakeError::RecordTooLarge {
                    limit: self.our_recv_limit.get(),
                    got: length_field as u16,
                });
            }
        }

        let step = {
            let scratch = &mut *self.scratch;
            match &mut self.state {
                #[cfg(feature = "cipher-aes")]
                EngineState::WaitFlightAes(conn) => conn.feed_server_record_inplace(
                    &mut scratch.recv_record[start..end],
                    &mut scratch.reassembler,
                ),
                #[cfg(feature = "chacha20")]
                EngineState::WaitFlightChaCha(conn) => conn.feed_server_record_inplace(
                    &mut scratch.recv_record[start..end],
                    &mut scratch.reassembler,
                ),
                _ => {
                    return Err(HandshakeError::Internal(InternalError::FlightWrongState));
                }
            }
        }
        .map_err(HandshakeError::Connection)?;

        if matches!(step, FlightStep::Ready) {
            self.finalize_and_finish(params)?;
        }
        Ok(())
    }

    /// Consume `WaitFlight*` → strategy + identity → finalize → finish,
    /// installing `App*` with the Client Finished queued for send.
    fn finalize_and_finish<V, A>(
        &mut self,
        params: &ClientParams<'_, V, A>,
    ) -> Result<(), HandshakeError>
    where
        V: VerifyStrategy<C::Ed25519, C::Rsa>,
        A: ClientAuthPolicy,
    {
        if let Some(peer_limit) = self
            .scratch
            .reassembler
            .peek_ee_record_size_limit()
            .map_err(|e| HandshakeError::Connection(ConnectionError::Flight(e)))?
        {
            self.peer_recv_limit = RecordSizeLimit::try_from(peer_limit)
                .map_err(|_| HandshakeError::InvalidRecordSizeLimit(peer_limit))?;
        }

        // Strategy-driven trust + stack-owned identity binding. Runs
        // before `finalize_server_flight` so a rejected chain aborts
        // before any transcript advance commits to derived keys.
        let flight_bytes =
            self.scratch
                .reassembler
                .flight_bytes()
                .ok_or(HandshakeError::Connection(
                    ConnectionError::IncompleteFlight,
                ))?;
        let flight_view = parse_server_flight(flight_bytes)
            .map_err(|e| HandshakeError::Connection(ConnectionError::Flight(e)))?;

        // `A::ACCEPT_CERT_REQUEST` is a `const`, so for the default
        // `NoClientAuth` (false) the entire certificate-response path
        // const-folds away — `certificate_request_context` /
        // `_sig_algs`, `finish_handshake_with_policy`, and every certificate
        // builder drop out of the monomorphization. A server request aborts.
        let cert_request: Option<(&[u8], &[u8])> = if A::ACCEPT_CERT_REQUEST {
            match flight_view.cert_request_full {
                Some(creq) => {
                    let ctx = certificate_request_context(creq)
                        .map_err(|e| HandshakeError::Connection(ConnectionError::Flight(e)))?;
                    let sig_algs = certificate_request_sig_algs(creq)
                        .map_err(|e| HandshakeError::Connection(ConnectionError::Flight(e)))?;
                    Some((ctx, sig_algs))
                }
                None => None,
            }
        } else {
            if flight_view.cert_request_full.is_some() {
                return Err(HandshakeError::Connection(ConnectionError::ClientAuth(
                    crate::client_flight::ClientAuthFlightError::CertificateRequested,
                )));
            }
            None
        };

        let chain = extract_chain::<MAX_CHAIN>(flight_view.cert_body)
            .map_err(|e| HandshakeError::Connection(ConnectionError::Flight(e)))?;
        let chain_view = CertChainView { certs: &chain };

        let mut slot: Option<PreparedVerifier<C::Ed25519, C::Rsa>> = None;
        let trusted = params
            .verify
            .verify_chain(chain_view, &mut slot)
            .map_err(|_| HandshakeError::StrategyRejected)?;

        // Cross-check: a strategy that returns a prepared verifier built
        // from non-chain bytes (intentional or otherwise) gets caught
        // here before any signature lands against it. `.first()` covers
        // the (impossible-via-`SafeStrategy`) case where a custom impl
        // returns Ok on an empty chain.
        let leaf_der =
            chain
                .first()
                .copied()
                .ok_or(HandshakeError::Connection(ConnectionError::Flight(
                    crate::server_flight::FlightError::Truncated,
                )))?;
        let leaf_view = <C::CertParser as CertParser>::parse(leaf_der)
            .map_err(|e| HandshakeError::Connection(ConnectionError::Flight(e.into())))?;
        if !bool::from(trusted.prepared().matches_cert(&leaf_view)) {
            return Err(HandshakeError::StrategyPubkeyMismatch);
        }
        verify_hostname(&leaf_view, params.hostname)?;

        let prepared = trusted.prepared();

        let prev = core::mem::replace(&mut self.state, EngineState::Closed);
        let done = match prev {
            #[cfg(feature = "cipher-aes")]
            EngineState::WaitFlightAes(conn) => {
                let d = conn
                    .finalize_server_flight::<FLIGHT, C::Ed25519, C::Rsa>(
                        &self.scratch.reassembler,
                        prepared,
                        &leaf_view,
                    )
                    .map_err(HandshakeError::Connection)?;
                FlightDone::<C>::Aes(d)
            }
            #[cfg(feature = "chacha20")]
            EngineState::WaitFlightChaCha(conn) => {
                let d = conn
                    .finalize_server_flight::<FLIGHT, C::Ed25519, C::Rsa>(
                        &self.scratch.reassembler,
                        prepared,
                        &leaf_view,
                    )
                    .map_err(HandshakeError::Connection)?;
                FlightDone::<C>::ChaCha(d)
            }
            other => {
                self.state = other;
                return Err(HandshakeError::Internal(InternalError::FinalizeWrongState));
            }
        };

        // The client-auth flight plaintext is built into the idle `recv_record`
        // buffer (the server flight already lives in the reassembler), avoiding
        // a ~1.6 KB stack frame. `recv_record` and `send_record` are disjoint
        // `scratch` fields, so the borrows don't conflict.
        let peer_limit = self.peer_recv_limit.get();
        let cv_entropy = self.cv_entropy;
        let cf_len = match done {
            #[cfg(feature = "cipher-aes")]
            FlightDone::Aes(d) => {
                let (cf_bytes, app) = match cert_request {
                    Some((ctx, sig_algs)) => d.finish_handshake_with_policy(
                        &params.client_auth,
                        ctx,
                        sig_algs,
                        &cv_entropy,
                        peer_limit,
                        &mut self.scratch.recv_record,
                        &mut self.scratch.send_record,
                    ),
                    None => d.finish_handshake(&mut self.scratch.send_record),
                }
                .map_err(HandshakeError::Connection)?;
                let cf_len = cf_bytes.len();
                self.state = EngineState::AppAes(app);
                cf_len
            }
            #[cfg(feature = "chacha20")]
            FlightDone::ChaCha(d) => {
                let (cf_bytes, app) = match cert_request {
                    Some((ctx, sig_algs)) => d.finish_handshake_with_policy(
                        &params.client_auth,
                        ctx,
                        sig_algs,
                        &cv_entropy,
                        peer_limit,
                        &mut self.scratch.recv_record,
                        &mut self.scratch.send_record,
                    ),
                    None => d.finish_handshake(&mut self.scratch.send_record),
                }
                .map_err(HandshakeError::Connection)?;
                let cf_len = cf_bytes.len();
                self.state = EngineState::AppChaCha(app);
                cf_len
            }
        };

        self.send_pending_len = cf_len;
        self.send_acked = 0;
        self.pending_handshake_done = true;
        self.handshake_finished_pending_ack = true;
        Ok(())
    }
}

enum FlightDone<C: ClientConfig> {
    #[cfg(feature = "cipher-aes")]
    Aes(TlsConnection<ServerFlightDone<Aes128GcmSha256>, C::Hkdf>),
    #[cfg(feature = "chacha20")]
    ChaCha(TlsConnection<ServerFlightDone<ChaCha20Poly1305Sha256>, C::Hkdf>),
}

// ============================================================================
// Data-phase loop + public lifecycle
// ============================================================================

impl<
    's,
    C: ClientConfig,
    const FLIGHT: usize,
    const RECV: usize,
    const SEND: usize,
    const MAX_CHAIN: usize,
> TlsEngine<'s, C, FLIGHT, RECV, SEND, MAX_CHAIN>
{
    /// Drive the data phase one event. Priority `Send > AppData > Closed > Recv`.
    pub(crate) fn step(&mut self) -> Result<EngineEvent, HandshakeError> {
        loop {
            if self.is_send_pending() {
                let remaining = self.send_pending_len - self.send_acked;
                return Ok(EngineEvent::Send(remaining));
            }

            if self.recv.plaintext_parked() {
                return Ok(EngineEvent::AppData);
            }

            if self.closed {
                return Ok(EngineEvent::Closed);
            }

            match self.frame_one_record()? {
                Framed::Need => return Ok(EngineEvent::Recv),
                Framed::Record {
                    start,
                    end,
                    outer_type,
                    ..
                } => {
                    self.dispatch_data_record(start, end, outer_type)?;
                }
            }
        }
    }

    /// Data-phase records must be outer-type `application_data` (RFC 8446 §5).
    /// Any error here is fatal; outer wrapper flips `self.closed`.
    fn dispatch_data_record(
        &mut self,
        start: usize,
        end: usize,
        outer_type: u8,
    ) -> Result<(), HandshakeError> {
        match self.dispatch_data_record_inner(start, end, outer_type) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.closed = true;
                Err(e)
            }
        }
    }

    fn dispatch_data_record_inner(
        &mut self,
        start: usize,
        end: usize,
        outer_type: u8,
    ) -> Result<(), HandshakeError> {
        if outer_type != CT_APPLICATION_DATA {
            return Err(HandshakeError::Connection(
                ConnectionError::UnknownContentType(outer_type),
            ));
        }

        // RFC 8449: protected body = ciphertext + 16-byte AEAD tag.
        let length_field = end - start - TLS_HEADER;
        if length_field > self.our_recv_limit.get() as usize + AEAD_TAG {
            return Err(HandshakeError::RecordTooLarge {
                limit: self.our_recv_limit.get(),
                got: length_field as u16,
            });
        }

        let (content_len, inner_ct) = self.decrypt_current_data_record(start, end)?;
        // Pre-advance: AEAD seq_in already stepped, framer never re-sees
        // consumed bytes.
        self.recv.next_record = end;
        self.handle_inner_content(start + TLS_HEADER, content_len, inner_ct)
    }

    fn decrypt_current_data_record(
        &mut self,
        start: usize,
        end: usize,
    ) -> Result<(usize, u8), HandshakeError> {
        let scratch = &mut *self.scratch;
        match &mut self.state {
            #[cfg(feature = "cipher-aes")]
            EngineState::AppAes(conn) => conn
                .decrypt_record_inplace(&mut scratch.recv_record[start..end])
                .map_err(HandshakeError::Connection),
            #[cfg(feature = "chacha20")]
            EngineState::AppChaCha(conn) => conn
                .decrypt_record_inplace(&mut scratch.recv_record[start..end])
                .map_err(HandshakeError::Connection),
            _ => Err(HandshakeError::Internal(
                InternalError::HandshakeStepWrongState,
            )),
        }
    }

    /// Inner-content dispatch after data-phase decrypt. `body_offset`
    /// is the first plaintext byte.
    fn handle_inner_content(
        &mut self,
        body_offset: usize,
        content_len: usize,
        inner_ct: u8,
    ) -> Result<(), HandshakeError> {
        // RFC 8446 §5.1: once a post-handshake handshake message is split
        // across records, no other record type may appear until it completes.
        if inner_ct != CT_HANDSHAKE && self.ph.in_progress() {
            return Err(HandshakeError::InterleavedPostHandshake);
        }
        match inner_ct {
            CT_APPLICATION_DATA => {
                if content_len > 0 {
                    self.recv.plain_start = body_offset;
                    self.recv.plain_end = body_offset + content_len;
                }
                Ok(())
            }
            CT_ALERT => {
                if content_len < 2 {
                    return Err(HandshakeError::Connection(ConnectionError::Decrypt(
                        crate::aead::DecryptError::Truncated,
                    )));
                }
                let level = self.scratch.recv_record[body_offset];
                let description = self.scratch.recv_record[body_offset + 1];
                if level == 1 && description == 0 {
                    self.closed = true;
                    Ok(())
                } else {
                    Err(HandshakeError::Connection(ConnectionError::Alert {
                        level,
                        description,
                    }))
                }
            }
            CT_HANDSHAKE => self.feed_post_handshake(body_offset, content_len),
            other => Err(HandshakeError::Connection(
                ConnectionError::UnknownContentType(other),
            )),
        }
    }

    /// Walk post-handshake handshake messages out of one decrypted record's
    /// plaintext `recv_record[start..start + len]`, reassembling across records
    /// via [`PostHandshakeReasm`] (RFC 8446 §5.1). NewSessionTicket bodies are
    /// skipped (kept for CDN interop); KeyUpdate is acted on (§4.6.3); any other
    /// type fails so it can't silently desync the AEAD. A KeyUpdate changes
    /// keys, so nothing may follow its final byte in that record.
    fn feed_post_handshake(&mut self, start: usize, len: usize) -> Result<(), HandshakeError> {
        let mut i = 0usize;
        loop {
            // Drain a NewSessionTicket body skip carried over from a prior
            // record. 24-bit lengths ⇒ skip arithmetic stays in `u32`.
            if self.ph.skip_remaining > 0 {
                let n = self.ph.skip_remaining.min((len - i) as u32);
                self.ph.skip_remaining -= n;
                i += n as usize;
                if self.ph.skip_remaining > 0 {
                    return Ok(()); // record exhausted mid-skip
                }
            }
            while (self.ph.stage_len as usize) < 4 && i < len {
                self.ph.stage[self.ph.stage_len as usize] = self.scratch.recv_record[start + i];
                self.ph.stage_len += 1;
                i += 1;
            }
            if (self.ph.stage_len as usize) < 4 {
                return Ok(()); // header incomplete; carry over to the next record
            }
            let msg_type = self.ph.stage[0];
            // 24-bit length; keep as `u32` so it can't truncate on 16-bit usize.
            let body_len =
                u32::from_be_bytes([0, self.ph.stage[1], self.ph.stage[2], self.ph.stage[3]]);
            match msg_type {
                HS_NEW_SESSION_TICKET => {
                    self.ph.stage_len = 0;
                    let n = body_len.min((len - i) as u32);
                    i += n as usize;
                    if n < body_len {
                        self.ph.skip_remaining = body_len - n;
                        return Ok(());
                    }
                    // Body fully consumed; loop for the next coalesced message.
                }
                HS_KEY_UPDATE => {
                    if body_len != 1 {
                        return Err(HandshakeError::MalformedKeyUpdate);
                    }
                    // `update_requested` is staged at index 4.
                    while (self.ph.stage_len as usize) < PH_STAGE_MAX && i < len {
                        self.ph.stage[self.ph.stage_len as usize] =
                            self.scratch.recv_record[start + i];
                        self.ph.stage_len += 1;
                        i += 1;
                    }
                    if (self.ph.stage_len as usize) < PH_STAGE_MAX {
                        return Ok(()); // body byte not here yet; carry over
                    }
                    // The key change means nothing may follow in this record.
                    if i != len {
                        return Err(HandshakeError::MalformedKeyUpdate);
                    }
                    let update_requested = match self.ph.stage[4] {
                        0 => false,
                        1 => true,
                        _ => return Err(HandshakeError::MalformedKeyUpdate),
                    };
                    self.ph.stage_len = 0;
                    return self.process_key_update(update_requested);
                }
                _ => return Err(HandshakeError::PostHandshakeNotSupported),
            }
        }
    }

    /// Act on a server `KeyUpdate` (RFC 8446 §4.6.3): rotate our receive
    /// keys for the peer's next record, and when `update_requested` is set,
    /// queue our own `KeyUpdate(update_requested=0)` — encrypted under the
    /// current send keys — then rotate our send keys. The queued record is
    /// picked up by `step()`'s `Send` branch. Only reached in the data phase
    /// (the dispatch decrypted through a live `AppData` connection).
    fn process_key_update(&mut self, update_requested: bool) -> Result<(), HandshakeError> {
        match &mut self.state {
            #[cfg(feature = "cipher-aes")]
            EngineState::AppAes(conn) => conn.apply_recv_key_update(),
            #[cfg(feature = "chacha20")]
            EngineState::AppChaCha(conn) => conn.apply_recv_key_update(),
            _ => {
                return Err(HandshakeError::Internal(
                    InternalError::HandshakeStepWrongState,
                ));
            }
        }
        .map_err(HandshakeError::Connection)?;

        if !update_requested {
            return Ok(());
        }

        let scratch = &mut *self.scratch;
        let record_len = match &mut self.state {
            #[cfg(feature = "cipher-aes")]
            EngineState::AppAes(conn) => {
                let n = conn
                    .encrypt_key_update(false, &mut scratch.send_record)
                    .map_err(HandshakeError::Connection)?
                    .len();
                conn.apply_send_key_update()
                    .map_err(HandshakeError::Connection)?;
                n
            }
            #[cfg(feature = "chacha20")]
            EngineState::AppChaCha(conn) => {
                let n = conn
                    .encrypt_key_update(false, &mut scratch.send_record)
                    .map_err(HandshakeError::Connection)?
                    .len();
                conn.apply_send_key_update()
                    .map_err(HandshakeError::Connection)?;
                n
            }
            _ => {
                return Err(HandshakeError::Internal(
                    InternalError::HandshakeStepWrongState,
                ));
            }
        };
        self.send_pending_len = record_len;
        self.send_acked = 0;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Public lifecycle — wrapper-facing API
    // ------------------------------------------------------------------

    /// Free tail of `recv_record` for the wrapper's `Recv` event.
    /// Returns `&mut []` while plaintext is parked (I3).
    pub(crate) fn recv_buffer(&mut self) -> &mut [u8] {
        if self.recv.plaintext_parked() {
            return &mut [];
        }
        &mut self.scratch.recv_record[self.recv.filled..]
    }

    /// Acknowledge `n` bytes written into `recv_buffer()`. `advance(n > 0)`
    /// while plaintext is parked errors with `AdvanceWhileParked` (I3).
    pub(crate) fn advance(&mut self, n: usize) -> Result<(), HandshakeError> {
        if n == 0 {
            return Ok(());
        }
        if self.recv.plaintext_parked() {
            return Err(HandshakeError::Internal(InternalError::AdvanceWhileParked));
        }
        let new_filled = self
            .recv
            .filled
            .checked_add(n)
            .ok_or(HandshakeError::AdvanceTooLarge)?;
        if new_filled > self.scratch.recv_record.len() {
            return Err(HandshakeError::AdvanceTooLarge);
        }
        self.recv.filled = new_filled;
        Ok(())
    }

    /// Drain parked plaintext into `out`; returns `min(parked, out.len())`.
    pub(crate) fn read_app(&mut self, out: &mut [u8]) -> usize {
        let parked = self.recv.plain_end - self.recv.plain_start;
        let n = parked.min(out.len());
        if n == 0 {
            return 0;
        }
        let src_start = self.recv.plain_start;
        out[..n].copy_from_slice(&self.scratch.recv_record[src_start..src_start + n]);
        self.recv.plain_start += n;
        n
    }

    /// Encrypt up to `send_chunk_limit()` bytes into a single
    /// `application_data` record; returns plaintext bytes consumed.
    pub(crate) fn write_app(&mut self, plaintext: &[u8]) -> Result<usize, super::WriteAppError> {
        if self.closed {
            return Err(super::WriteAppError::Closed);
        }
        if self.is_send_pending() {
            return Err(super::WriteAppError::Busy);
        }
        if !self.state.in_data_phase() {
            return Err(super::WriteAppError::NotReady);
        }

        let max_chunk = self.send_chunk_limit();
        let chunk_len = plaintext.len().min(max_chunk);
        if chunk_len == 0 {
            return Ok(0);
        }

        let scratch = &mut *self.scratch;
        let record_len = match &mut self.state {
            #[cfg(feature = "cipher-aes")]
            EngineState::AppAes(conn) => conn
                .encrypt_record(
                    &plaintext[..chunk_len],
                    CT_APPLICATION_DATA,
                    &mut scratch.send_record,
                )
                .map_err(|e| super::WriteAppError::Other(HandshakeError::Connection(e)))?
                .len(),
            #[cfg(feature = "chacha20")]
            EngineState::AppChaCha(conn) => conn
                .encrypt_record(
                    &plaintext[..chunk_len],
                    CT_APPLICATION_DATA,
                    &mut scratch.send_record,
                )
                .map_err(|e| super::WriteAppError::Other(HandshakeError::Connection(e)))?
                .len(),
            _ => return Err(super::WriteAppError::NotReady),
        };

        self.send_pending_len = record_len;
        self.send_acked = 0;
        Ok(chunk_len)
    }

    /// Acknowledge `n` transmitted bytes from `send_bytes()`. Clears
    /// the CF gate so `HandshakeDone` can fire once the record drains.
    pub(crate) fn mark_sent(&mut self, n: usize) -> Result<(), HandshakeError> {
        let new_acked = self
            .send_acked
            .checked_add(n)
            .ok_or(HandshakeError::Internal(InternalError::MarkSentTooLarge))?;
        if new_acked > self.send_pending_len {
            return Err(HandshakeError::Internal(InternalError::MarkSentTooLarge));
        }
        self.send_acked = new_acked;
        if self.send_acked == self.send_pending_len {
            self.send_pending_len = 0;
            self.send_acked = 0;
            if self.handshake_finished_pending_ack {
                self.handshake_finished_pending_ack = false;
            }
        }
        Ok(())
    }

    /// Force terminal state after a transport mid-record write failure;
    /// a wrapper retry would resend duplicate bytes and desync AEAD.
    pub(crate) fn mark_terminal(&mut self) {
        self.state = EngineState::Closed;
        self.closed = true;
        self.send_pending_len = 0;
        self.send_acked = 0;
        self.handshake_finished_pending_ack = false;
        self.pending_handshake_done = false;
    }

    /// Queue `close_notify` and flip to closed. Idempotent. Returns
    /// `Busy` if a Send is pending. Pre-handshake close just flips the flag.
    pub(crate) fn close(&mut self) -> Result<(), HandshakeError> {
        if self.closed {
            return Ok(());
        }
        if self.is_send_pending() {
            return Err(HandshakeError::Busy);
        }
        if !self.state.in_data_phase() {
            self.closed = true;
            return Ok(());
        }

        let scratch = &mut *self.scratch;
        let record_len = match &mut self.state {
            #[cfg(feature = "cipher-aes")]
            EngineState::AppAes(conn) => conn
                .encrypt_record(&CLOSE_NOTIFY_ALERT, CT_ALERT, &mut scratch.send_record)
                .map_err(HandshakeError::Connection)?
                .len(),
            #[cfg(feature = "chacha20")]
            EngineState::AppChaCha(conn) => conn
                .encrypt_record(&CLOSE_NOTIFY_ALERT, CT_ALERT, &mut scratch.send_record)
                .map_err(HandshakeError::Connection)?
                .len(),
            // Unreachable via `in_data_phase()`; return Internal
            // rather than panic on wire-influenced state.
            _ => {
                return Err(HandshakeError::Internal(
                    InternalError::HandshakeStepWrongState,
                ));
            }
        };

        self.send_pending_len = record_len;
        self.send_acked = 0;
        self.closed = true;
        Ok(())
    }

    /// Per-chunk plaintext cap: min of peer RSL, local SEND buffer,
    /// and proto max (each minus the 1-byte inner content type).
    fn send_chunk_limit(&self) -> usize {
        let peer = (self.peer_recv_limit.get() as usize).saturating_sub(1);
        let local = SEND.saturating_sub(RECORD_OVERHEAD + 1);
        let proto = (PROTO_MAX_INNER_PLAINTEXT as usize).saturating_sub(1);
        peer.min(local).min(proto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientParams, DefaultConfig, DefaultScratch};

    /// `RecvState` compaction-eligibility (invariant I6): drained, with the
    /// record cursor advanced past 0. Over the private cursor state, so it
    /// lives here rather than as a method on the production type.
    fn needs_compaction(r: &RecvState) -> bool {
        !r.plaintext_parked() && r.next_record > 0
    }

    // RecvState

    #[test]
    fn recv_state_default_has_no_parked_plaintext() {
        let r = RecvState::new();
        assert!(!r.plaintext_parked());
        assert!(!needs_compaction(&r));
    }

    #[test]
    fn recv_state_plaintext_parked_only_when_range_nonempty() {
        let mut r = RecvState::new();
        r.plain_start = 0;
        r.plain_end = 0;
        assert!(!r.plaintext_parked());
        r.plain_end = 10;
        assert!(r.plaintext_parked());
        r.plain_start = 10;
        assert!(!r.plaintext_parked());
    }

    #[test]
    fn recv_state_needs_compaction_fires_only_post_drain_with_advanced_cursor() {
        let mut r = RecvState::new();
        // Not parked, next_record == 0 → false.
        assert!(!needs_compaction(&r));
        // Parked → false (I6 only fires post-drain).
        r.plain_end = 10;
        r.next_record = 20;
        assert!(!needs_compaction(&r));
        // Drained but next_record > 0 → true.
        r.plain_end = 0;
        assert!(needs_compaction(&r));
    }

    // ---------------------------------------------------------------------
    // Construction helpers
    // ---------------------------------------------------------------------

    /// Build an engine in `Closed` state — the lightest possible
    /// construction. Sufficient for any test that only exercises the
    /// scratch / cursor / flag fields and doesn't dispatch through a
    /// live typestate.
    fn closed_engine(
        scratch: &mut DefaultScratch,
    ) -> TlsEngine<'_, DefaultConfig, 16384, 16645, 4096, 8> {
        TlsEngine::new(
            scratch,
            EngineState::Closed,
            RecordSizeLimit::from_clamped(16384),
            RecordSizeLimit::from_clamped(16384),
            [0u8; 32],
        )
    }

    // Reused-scratch reconnect: `new` must drop a previous connection's flight
    // so it can't be folded into the next transcript (would fail CertVerify).
    #[test]
    fn new_clears_a_stale_reassembler() {
        let mut scratch = DefaultScratch::new();
        scratch
            .reassembler
            .push_content(&[0x42; 64])
            .expect("seed a stale flight");
        assert!(
            !scratch.reassembler.is_empty(),
            "precondition: stale flight"
        );
        let e = closed_engine(&mut scratch);
        assert!(
            e.scratch.reassembler.is_empty(),
            "TlsEngine::new must start each handshake with an empty reassembler",
        );
    }

    // advance / recv_buffer

    #[test]
    fn advance_zero_is_noop_regardless_of_state() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        assert!(e.advance(0).is_ok());
        e.recv.plain_end = 10;
        // Parked + advance(0) still Ok.
        assert!(e.advance(0).is_ok());
    }

    #[test]
    fn advance_while_parked_returns_internal_error() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        e.recv.plain_end = 10;
        let err = e.advance(1).unwrap_err();
        assert!(matches!(
            err,
            HandshakeError::Internal(InternalError::AdvanceWhileParked)
        ));
    }

    #[test]
    fn advance_overflow_returns_advance_too_large() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        let err = e.advance(usize::MAX).unwrap_err();
        assert!(matches!(err, HandshakeError::AdvanceTooLarge));
    }

    #[test]
    fn advance_past_capacity_returns_advance_too_large() {
        let mut scratch = DefaultScratch::new();
        let cap = scratch.recv_record.len();
        let mut e = closed_engine(&mut scratch);
        let err = e.advance(cap + 1).unwrap_err();
        assert!(matches!(err, HandshakeError::AdvanceTooLarge));
    }

    #[test]
    fn recv_buffer_empty_while_parked() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        e.recv.plain_end = 10;
        assert!(e.recv_buffer().is_empty());
    }

    // mark_sent

    #[test]
    fn mark_sent_overflow_returns_internal_error() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        e.send_pending_len = 10;
        let err = e.mark_sent(11).unwrap_err();
        assert!(matches!(
            err,
            HandshakeError::Internal(InternalError::MarkSentTooLarge)
        ));
    }

    #[test]
    fn mark_sent_full_drain_resets_both_cursors() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        e.send_pending_len = 42;
        e.send_acked = 10;
        assert!(e.mark_sent(32).is_ok());
        assert_eq!(e.send_pending_len, 0);
        assert_eq!(e.send_acked, 0);
    }

    #[test]
    fn mark_sent_full_drain_clears_handshake_finished_gate() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        e.send_pending_len = 10;
        e.handshake_finished_pending_ack = true;
        e.pending_handshake_done = true;
        assert!(e.mark_sent(10).is_ok());
        assert!(!e.handshake_finished_pending_ack);
        // pending_handshake_done is left for step_handshake to consume.
        assert!(e.pending_handshake_done);
    }

    #[test]
    fn mark_sent_partial_does_not_reset_cursors() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        e.send_pending_len = 42;
        assert!(e.mark_sent(10).is_ok());
        assert_eq!(e.send_acked, 10);
        assert_eq!(e.send_pending_len, 42);
    }

    // mark_terminal

    #[test]
    fn mark_terminal_clears_all_lifecycle_flags() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        e.send_pending_len = 42;
        e.send_acked = 10;
        e.handshake_finished_pending_ack = true;
        e.pending_handshake_done = true;
        e.closed = false;
        e.mark_terminal();
        assert_eq!(e.send_pending_len, 0);
        assert_eq!(e.send_acked, 0);
        assert!(!e.handshake_finished_pending_ack);
        assert!(!e.pending_handshake_done);
        assert!(e.closed);
        assert!(matches!(e.state, EngineState::Closed));
    }

    // ---------------------------------------------------------------------
    // Event-priority ladders. Compact buffer reuse makes the ordering easy to
    // regress, so assert it directly: with several conditions live at once,
    // the higher-priority event must win.
    // ---------------------------------------------------------------------

    /// Handshake phase: `Send > HandshakeDone > AppData > Closed > Recv`.
    #[test]
    fn step_handshake_event_priority_ladder() {
        struct Case {
            name: &'static str,
            send_pending: usize,
            handshake_done: bool,
            finished_ack_pending: bool,
            parked: bool,
            closed: bool,
            expect: EngineEvent,
        }
        let cases = [
            Case {
                name: "send outranks all",
                send_pending: 5,
                handshake_done: true,
                finished_ack_pending: false,
                parked: true,
                closed: true,
                expect: EngineEvent::Send(5),
            },
            Case {
                name: "handshake-done outranks appdata/closed",
                send_pending: 0,
                handshake_done: true,
                finished_ack_pending: false,
                parked: true,
                closed: true,
                expect: EngineEvent::HandshakeDone,
            },
            Case {
                name: "handshake-done gated while finished ack pending",
                send_pending: 0,
                handshake_done: true,
                finished_ack_pending: true,
                parked: true,
                closed: false,
                expect: EngineEvent::AppData,
            },
            Case {
                name: "appdata outranks closed",
                send_pending: 0,
                handshake_done: false,
                finished_ack_pending: false,
                parked: true,
                closed: true,
                expect: EngineEvent::AppData,
            },
            Case {
                name: "closed outranks recv",
                send_pending: 0,
                handshake_done: false,
                finished_ack_pending: false,
                parked: false,
                closed: true,
                expect: EngineEvent::Closed,
            },
            Case {
                name: "recv when idle",
                send_pending: 0,
                handshake_done: false,
                finished_ack_pending: false,
                parked: false,
                closed: false,
                expect: EngineEvent::Recv,
            },
        ];
        let params = ClientParams::self_signed("priority.test");
        for c in cases {
            let mut scratch = DefaultScratch::new();
            let mut e = closed_engine(&mut scratch);
            e.closed = c.closed;
            e.send_pending_len = c.send_pending;
            e.pending_handshake_done = c.handshake_done;
            e.handshake_finished_pending_ack = c.finished_ack_pending;
            if c.parked {
                e.recv.plain_end = 10;
            }
            assert_eq!(e.step_handshake(&params).unwrap(), c.expect, "{}", c.name);
        }
    }

    /// Data phase: same ladder minus `HandshakeDone`.
    #[test]
    fn step_data_event_priority_ladder() {
        struct Case {
            name: &'static str,
            send_pending: usize,
            parked: bool,
            closed: bool,
            expect: EngineEvent,
        }
        let cases = [
            Case {
                name: "send outranks all",
                send_pending: 7,
                parked: true,
                closed: true,
                expect: EngineEvent::Send(7),
            },
            Case {
                name: "appdata outranks closed",
                send_pending: 0,
                parked: true,
                closed: true,
                expect: EngineEvent::AppData,
            },
            Case {
                name: "closed outranks recv",
                send_pending: 0,
                parked: false,
                closed: true,
                expect: EngineEvent::Closed,
            },
            Case {
                name: "recv when idle",
                send_pending: 0,
                parked: false,
                closed: false,
                expect: EngineEvent::Recv,
            },
        ];
        for c in cases {
            let mut scratch = DefaultScratch::new();
            let mut e = closed_engine(&mut scratch);
            e.closed = c.closed;
            e.send_pending_len = c.send_pending;
            if c.parked {
                e.recv.plain_end = 10;
            }
            assert_eq!(e.step().unwrap(), c.expect, "{}", c.name);
        }
    }

    // handle_inner_content — NewSessionTicket walker

    /// Place a single handshake message header + payload at `recv_record[offset]`.
    /// Layout: `msg_type | uint24 length | payload[0..length]`.
    fn write_hs_msg(
        scratch: &mut DefaultScratch,
        offset: usize,
        msg_type: u8,
        payload: &[u8],
    ) -> usize {
        let len = payload.len();
        assert!(len < (1 << 24));
        scratch.recv_record[offset] = msg_type;
        scratch.recv_record[offset + 1] = ((len >> 16) & 0xff) as u8;
        scratch.recv_record[offset + 2] = ((len >> 8) & 0xff) as u8;
        scratch.recv_record[offset + 3] = (len & 0xff) as u8;
        scratch.recv_record[offset + 4..offset + 4 + len].copy_from_slice(payload);
        4 + len
    }

    #[test]
    fn handle_handshake_single_nst_skipped() {
        let mut scratch = DefaultScratch::new();
        let len = write_hs_msg(&mut scratch, 0, 4, &[0xaau8; 16]);
        let mut e = closed_engine(&mut scratch);
        assert!(e.handle_inner_content(0, len, CT_HANDSHAKE).is_ok());
    }

    #[test]
    fn handle_handshake_two_coalesced_nsts_both_skipped() {
        let mut scratch = DefaultScratch::new();
        let l1 = write_hs_msg(&mut scratch, 0, 4, &[0x11u8; 8]);
        let l2 = write_hs_msg(&mut scratch, l1, 4, &[0x22u8; 12]);
        let mut e = closed_engine(&mut scratch);
        assert!(e.handle_inner_content(0, l1 + l2, CT_HANDSHAKE).is_ok());
    }

    #[test]
    fn handle_handshake_key_update_not_last_rejected() {
        // A KeyUpdate changes keys, so it MUST be the final message in its
        // record (RFC 8446 §5.1). [KeyUpdate][NewSessionTicket] is malformed
        // and rejected before any key rotation runs.
        let mut scratch = DefaultScratch::new();
        let l1 = write_hs_msg(&mut scratch, 0, 24, &[0u8; 1]);
        let l2 = write_hs_msg(&mut scratch, l1, 4, &[0xaau8; 12]);
        let mut e = closed_engine(&mut scratch);
        let err = e
            .handle_inner_content(0, l1 + l2, CT_HANDSHAKE)
            .unwrap_err();
        assert!(matches!(err, HandshakeError::MalformedKeyUpdate));
    }

    #[test]
    fn handle_handshake_certificate_request_rejected() {
        let mut scratch = DefaultScratch::new();
        let len = write_hs_msg(&mut scratch, 0, 13, &[0u8; 8]);
        let mut e = closed_engine(&mut scratch);
        let err = e.handle_inner_content(0, len, CT_HANDSHAKE).unwrap_err();
        assert!(matches!(err, HandshakeError::PostHandshakeNotSupported));
    }

    #[test]
    fn handle_handshake_partial_header_is_buffered_then_completed() {
        // A handshake header split across two records is staged, not rejected
        // (RFC 8446 §5.1). Record 1 carries 2 bytes of an NST header.
        let mut scratch = DefaultScratch::new();
        scratch.recv_record[0] = HS_NEW_SESSION_TICKET;
        scratch.recv_record[1] = 0x00;
        let mut e = closed_engine(&mut scratch);
        assert!(e.handle_inner_content(0, 2, CT_HANDSHAKE).is_ok());
        assert_eq!(e.ph.stage_len, 2, "partial header buffered across records");

        // Record 2: the remaining header bytes (`len = 0`) complete the NST.
        e.scratch.recv_record[0] = 0x00;
        e.scratch.recv_record[1] = 0x00;
        assert!(e.handle_inner_content(0, 2, CT_HANDSHAKE).is_ok());
        assert_eq!(e.ph.stage_len, 0, "NST consumed; staging cleared");
    }

    #[test]
    fn handle_handshake_nst_body_spanning_records_is_skipped() {
        // An NST whose body overruns its record is skipped across records via
        // the carry-over counter, not rejected. Record 1: header (10-byte body)
        // + 4 body bytes.
        let mut scratch = DefaultScratch::new();
        scratch.recv_record[..4].copy_from_slice(&[HS_NEW_SESSION_TICKET, 0x00, 0x00, 0x0a]);
        let mut e = closed_engine(&mut scratch);
        assert!(e.handle_inner_content(0, 8, CT_HANDSHAKE).is_ok());
        assert_eq!(e.ph.skip_remaining, 6, "remaining NST body to skip");

        // Record 2: the final 6 body bytes drain the skip.
        assert!(e.handle_inner_content(0, 6, CT_HANDSHAKE).is_ok());
        assert_eq!(e.ph.skip_remaining, 0);
        assert_eq!(e.ph.stage_len, 0);
    }

    #[test]
    fn handle_handshake_fragmented_key_update_illegal_flag_rejected() {
        // KeyUpdate validation still fires once the message is reassembled:
        // record 1 carries the 4-byte header, record 2 an illegal flag (2).
        let mut scratch = DefaultScratch::new();
        scratch.recv_record[..4].copy_from_slice(&[HS_KEY_UPDATE, 0x00, 0x00, 0x01]);
        let mut e = closed_engine(&mut scratch);
        assert!(e.handle_inner_content(0, 4, CT_HANDSHAKE).is_ok());
        assert_eq!(e.ph.stage_len, 4);

        e.scratch.recv_record[0] = 0x02; // update_requested = 2 (illegal)
        assert!(matches!(
            e.handle_inner_content(0, 1, CT_HANDSHAKE).unwrap_err(),
            HandshakeError::MalformedKeyUpdate
        ));
    }

    #[test]
    fn handle_handshake_interleaved_record_mid_reassembly_rejected() {
        // RFC 8446 §5.1: app data / alert may not appear between fragments of a
        // split post-handshake message. Stage a partial header, then feed an
        // application_data record — it must be rejected, not parked.
        let mut scratch = DefaultScratch::new();
        scratch.recv_record[0] = HS_NEW_SESSION_TICKET;
        let mut e = closed_engine(&mut scratch);
        assert!(e.handle_inner_content(0, 2, CT_HANDSHAKE).is_ok());
        assert!(e.ph.in_progress());
        assert!(matches!(
            e.handle_inner_content(5, 10, CT_APPLICATION_DATA)
                .unwrap_err(),
            HandshakeError::InterleavedPostHandshake
        ));
        // A mid-skip NST body behaves the same.
        let mut scratch2 = DefaultScratch::new();
        scratch2.recv_record[..4].copy_from_slice(&[HS_NEW_SESSION_TICKET, 0x00, 0x00, 0x0a]);
        let mut e2 = closed_engine(&mut scratch2);
        assert!(e2.handle_inner_content(0, 4, CT_HANDSHAKE).is_ok());
        assert_eq!(e2.ph.skip_remaining, 10);
        assert!(matches!(
            e2.handle_inner_content(5, 2, CT_ALERT).unwrap_err(),
            HandshakeError::InterleavedPostHandshake
        ));
    }

    #[test]
    fn handle_handshake_zero_length_record_ok() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        assert!(e.handle_inner_content(0, 0, CT_HANDSHAKE).is_ok());
    }

    // handle_inner_content — application_data + alert

    #[test]
    fn handle_application_data_parks_plaintext() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        assert!(e.handle_inner_content(5, 100, CT_APPLICATION_DATA).is_ok());
        assert_eq!(e.recv.plain_start, 5);
        assert_eq!(e.recv.plain_end, 105);
    }

    #[test]
    fn handle_application_data_zero_length_is_silent_noop() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        assert!(e.handle_inner_content(5, 0, CT_APPLICATION_DATA).is_ok());
        assert_eq!(e.recv.plain_start, 0);
        assert_eq!(e.recv.plain_end, 0);
    }

    #[test]
    fn handle_alert_close_notify_sets_closed_returns_ok() {
        let mut scratch = DefaultScratch::new();
        scratch.recv_record[0] = 1; // level = warning
        scratch.recv_record[1] = 0; // description = close_notify
        let mut e = closed_engine(&mut scratch);
        e.closed = false;
        assert!(e.handle_inner_content(0, 2, CT_ALERT).is_ok());
        assert!(e.closed);
    }

    #[test]
    fn handle_alert_fatal_returns_alert_error() {
        let mut scratch = DefaultScratch::new();
        scratch.recv_record[0] = 2; // level = fatal
        scratch.recv_record[1] = 40; // description = handshake_failure
        let mut e = closed_engine(&mut scratch);
        let err = e.handle_inner_content(0, 2, CT_ALERT).unwrap_err();
        assert!(matches!(
            err,
            HandshakeError::Connection(ConnectionError::Alert {
                level: 2,
                description: 40,
            })
        ));
    }

    #[test]
    fn handle_alert_truncated_returns_decrypt_truncated() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        let err = e.handle_inner_content(0, 1, CT_ALERT).unwrap_err();
        assert!(matches!(
            err,
            HandshakeError::Connection(ConnectionError::Decrypt(
                crate::aead::DecryptError::Truncated
            ))
        ));
    }

    #[test]
    fn handle_unknown_inner_content_type_rejected() {
        let mut scratch = DefaultScratch::new();
        let mut e = closed_engine(&mut scratch);
        let err = e.handle_inner_content(0, 4, 0xff).unwrap_err();
        assert!(matches!(
            err,
            HandshakeError::Connection(ConnectionError::UnknownContentType(0xff))
        ));
    }

    // Live AppAes engine: white-box tests that build a `TlsConnection`
    // straight from captured app secrets (bypassing the handshake) to drive
    // the app-data state machine in isolation. AES-128-GCM, so cipher-aes.
    #[cfg(feature = "cipher-aes")]
    mod replay {
        use super::*;
        use crate::aead::Aes128GcmSha256;
        use crate::backends::RustCrypto;
        use crate::client::WriteAppError;
        use crate::connection::AppData;
        use crate::newtype::Secret;

        fn app_engine(
            scratch: &mut DefaultScratch,
        ) -> TlsEngine<'_, DefaultConfig, 16384, 16645, 4096, 8> {
            let c_ap_ts = Secret::from([0x42u8; 32]);
            let s_ap_ts = Secret::from([0x43u8; 32]);
            let conn = TlsConnection::<AppData<Aes128GcmSha256>, RustCrypto>::from_app_secrets(
                c_ap_ts, s_ap_ts, 0, 0,
            )
            .unwrap();
            TlsEngine::new(
                scratch,
                EngineState::AppAes(conn),
                RecordSizeLimit::from_clamped(16384),
                RecordSizeLimit::from_clamped(16384),
                [0u8; 32],
            )
        }

        #[test]
        fn write_app_returns_closed_when_engine_terminal() {
            let mut scratch = DefaultScratch::new();
            let mut e = app_engine(&mut scratch);
            e.closed = true;
            assert!(matches!(e.write_app(b"hi"), Err(WriteAppError::Closed)));
        }

        #[test]
        fn write_app_returns_busy_when_send_pending() {
            let mut scratch = DefaultScratch::new();
            let mut e = app_engine(&mut scratch);
            e.send_pending_len = 16;
            assert!(matches!(e.write_app(b"hi"), Err(WriteAppError::Busy)));
        }

        #[test]
        fn write_app_returns_zero_on_empty_plaintext() {
            let mut scratch = DefaultScratch::new();
            let mut e = app_engine(&mut scratch);
            assert_eq!(e.write_app(b""), Ok(0));
            assert_eq!(e.send_pending_len, 0);
        }

        #[test]
        fn write_app_queues_encrypted_record() {
            let mut scratch = DefaultScratch::new();
            let mut e = app_engine(&mut scratch);
            let n = e.write_app(b"hello").unwrap();
            assert_eq!(n, 5);
            assert_eq!(e.send_pending_len, 5 + 5 + 1 + 16);
            assert!(e.is_send_pending());
            assert_eq!(e.send_bytes().len(), e.send_pending_len);
            // First byte is the outer content type — must be application_data.
            assert_eq!(e.send_bytes()[0], CT_APPLICATION_DATA);
        }

        #[test]
        fn close_queues_encrypted_close_notify() {
            let mut scratch = DefaultScratch::new();
            let mut e = app_engine(&mut scratch);
            assert!(e.close().is_ok());
            assert_eq!(e.send_pending_len, 2 + 1 + 16 + 5);
            assert!(e.closed);
            // Outer record type is application_data (close_notify wrapped).
            assert_eq!(e.send_bytes()[0], CT_APPLICATION_DATA);
        }

        #[test]
        fn close_is_idempotent_after_first_call() {
            let mut scratch = DefaultScratch::new();
            let mut e = app_engine(&mut scratch);
            assert!(e.close().is_ok());
            let first_pending = e.send_pending_len;
            assert!(e.close().is_ok());
            assert_eq!(e.send_pending_len, first_pending);
        }

        #[test]
        fn close_returns_busy_when_send_pending() {
            let mut scratch = DefaultScratch::new();
            let mut e = app_engine(&mut scratch);
            e.send_pending_len = 16;
            let err = e.close().unwrap_err();
            assert!(matches!(err, HandshakeError::Busy));
        }
    }

    // Round-trip KeyUpdate against a mirror server. Uses the test-only
    // `AppData::decrypt_record`, gated to the AES-only build like the rest of
    // the byte-exact fixtures.
    #[cfg(all(
        feature = "cipher-aes",
        not(feature = "chacha20"),
        not(feature = "rsa")
    ))]
    mod key_update {
        use super::*;
        use crate::aead::Aes128GcmSha256;
        use crate::backends::RustCrypto;
        use crate::connection::AppData;
        use crate::newtype::Secret;

        fn app_engine(
            scratch: &mut DefaultScratch,
        ) -> TlsEngine<'_, DefaultConfig, 16384, 16645, 4096, 8> {
            let conn = TlsConnection::<AppData<Aes128GcmSha256>, RustCrypto>::from_app_secrets(
                Secret::from([0x42u8; 32]),
                Secret::from([0x43u8; 32]),
                0,
                0,
            )
            .unwrap();
            TlsEngine::new(
                scratch,
                EngineState::AppAes(conn),
                RecordSizeLimit::from_clamped(16384),
                RecordSizeLimit::from_clamped(16384),
                [0u8; 32],
            )
        }

        /// The `app_engine` client uses c_ap=[0x42], s_ap=[0x43]; the mirror
        /// server swaps them so records cross-decrypt.
        fn mirror_server() -> TlsConnection<AppData<Aes128GcmSha256>, RustCrypto> {
            TlsConnection::<AppData<Aes128GcmSha256>, RustCrypto>::from_app_secrets(
                Secret::from([0x43u8; 32]),
                Secret::from([0x42u8; 32]),
                0,
                0,
            )
            .unwrap()
        }

        fn feed(e: &mut TlsEngine<'_, DefaultConfig, 16384, 16645, 4096, 8>, bytes: &[u8]) {
            let buf = e.recv_buffer();
            buf[..bytes.len()].copy_from_slice(bytes);
            e.advance(bytes.len()).unwrap();
        }

        /// A server KeyUpdate(update_requested=1) drives the engine to rotate
        /// its receive keys, emit its own KeyUpdate(0), and rotate its send
        /// keys — after which both directions cross-decrypt (RFC 8446 §4.6.3).
        #[test]
        fn engine_answers_server_key_update_and_rotates_both_directions() {
            let mut scratch = DefaultScratch::new();
            let mut e = app_engine(&mut scratch);
            let mut server = mirror_server();

            let mut sbuf = [0u8; 64];
            let kn = server.encrypt_key_update(true, &mut sbuf).unwrap().len();
            let mut ku = [0u8; 64];
            ku[..kn].copy_from_slice(&sbuf[..kn]);
            server.apply_send_key_update().unwrap();

            feed(&mut e, &ku[..kn]);

            let resp_len = match e.step().unwrap() {
                EngineEvent::Send(n) => n,
                other => panic!("expected Send, got {other:?}"),
            };
            let mut resp = [0u8; 64];
            resp[..resp_len].copy_from_slice(&e.send_bytes()[..resp_len]);
            e.mark_sent(resp_len).unwrap();

            // Server reads our KeyUpdate(0) under its *old* receive keys, then
            // rotates them.
            let mut spt = [0u8; 64];
            let (content, ct) = server.decrypt_record(&resp[..resp_len], &mut spt).unwrap();
            assert_eq!(ct, CT_HANDSHAKE);
            assert_eq!(content, &[HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x00]);
            server.apply_recv_key_update().unwrap();

            // Server app record under its rotated send keys decrypts through
            // the engine's rotated receive keys.
            let mut abuf = [0u8; 96];
            let an = server
                .encrypt_record(b"rotated payload", CT_APPLICATION_DATA, &mut abuf)
                .unwrap()
                .len();
            feed(&mut e, &abuf[..an]);
            assert!(matches!(e.step().unwrap(), EngineEvent::AppData));
            let mut out = [0u8; 96];
            let got = e.read_app(&mut out);
            assert_eq!(&out[..got], b"rotated payload");
        }

        /// A KeyUpdate(update_requested=0) is rotated silently — no response
        /// queued — and the next server record decrypts under rotated keys.
        #[test]
        fn engine_rotates_on_unrequested_key_update_without_responding() {
            let mut scratch = DefaultScratch::new();
            let mut e = app_engine(&mut scratch);
            let mut server = mirror_server();

            let mut sbuf = [0u8; 64];
            let kn = server.encrypt_key_update(false, &mut sbuf).unwrap().len();
            let mut ku = [0u8; 64];
            ku[..kn].copy_from_slice(&sbuf[..kn]);
            server.apply_send_key_update().unwrap();

            feed(&mut e, &ku[..kn]);
            // No KeyUpdate flag set ⇒ no response queued ⇒ step consumes the
            // record and asks for more input.
            assert!(matches!(e.step().unwrap(), EngineEvent::Recv));
            assert!(!e.is_send_pending());

            let mut abuf = [0u8; 96];
            let an = server
                .encrypt_record(b"quiet rotation", CT_APPLICATION_DATA, &mut abuf)
                .unwrap()
                .len();
            feed(&mut e, &abuf[..an]);
            assert!(matches!(e.step().unwrap(), EngineEvent::AppData));
            let mut out = [0u8; 96];
            let got = e.read_app(&mut out);
            assert_eq!(&out[..got], b"quiet rotation");
        }

        #[test]
        fn engine_rejects_key_update_with_illegal_flag() {
            let mut scratch = DefaultScratch::new();
            let mut e = app_engine(&mut scratch);
            let mut server = mirror_server();

            // update_requested = 2 is illegal (RFC 8446 §4.6.3 allows 0/1).
            let mut sbuf = [0u8; 64];
            let n = server
                .encrypt_record(
                    &[HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x02],
                    CT_HANDSHAKE,
                    &mut sbuf,
                )
                .unwrap()
                .len();
            let mut rec = [0u8; 64];
            rec[..n].copy_from_slice(&sbuf[..n]);
            feed(&mut e, &rec[..n]);
            assert!(matches!(
                e.step().unwrap_err(),
                HandshakeError::MalformedKeyUpdate
            ));
        }

        /// Encrypt the 5-byte KeyUpdate message as two records split at byte 3,
        /// both under the server's current (gen-0) send keys, then rotate the
        /// server's send keys. Returns the two record byte vecs.
        fn fragmented_key_update(
            server: &mut TlsConnection<AppData<Aes128GcmSha256>, RustCrypto>,
            flag: u8,
        ) -> (Vec<u8>, Vec<u8>) {
            let msg = [HS_KEY_UPDATE, 0x00, 0x00, 0x01, flag];
            let mut b1 = [0u8; 32];
            let r1 = server
                .encrypt_record(&msg[..3], CT_HANDSHAKE, &mut b1)
                .unwrap();
            let rec1 = r1.to_vec();
            let mut b2 = [0u8; 32];
            let r2 = server
                .encrypt_record(&msg[3..], CT_HANDSHAKE, &mut b2)
                .unwrap();
            let rec2 = r2.to_vec();
            server.apply_send_key_update().unwrap();
            (rec1, rec2)
        }

        /// A KeyUpdate(update_requested=1) split across two records reassembles,
        /// rotates receive keys, queues our KeyUpdate(0), and rotates send keys.
        #[test]
        fn engine_reassembles_fragmented_key_update_requesting_update() {
            let mut scratch = DefaultScratch::new();
            let mut e = app_engine(&mut scratch);
            let mut server = mirror_server();
            let (rec1, rec2) = fragmented_key_update(&mut server, 1);

            // First fragment: message incomplete ⇒ no Send, engine wants more.
            feed(&mut e, &rec1);
            assert!(matches!(e.step().unwrap(), EngineEvent::Recv));
            assert!(!e.is_send_pending());

            // Second fragment completes it ⇒ rotate recv + queue our KeyUpdate(0).
            feed(&mut e, &rec2);
            let resp_len = match e.step().unwrap() {
                EngineEvent::Send(n) => n,
                other => panic!("expected Send, got {other:?}"),
            };
            let mut resp = [0u8; 32];
            resp[..resp_len].copy_from_slice(&e.send_bytes()[..resp_len]);
            e.mark_sent(resp_len).unwrap();

            // Our response decrypts under the server's old receive keys.
            let mut server_rx = mirror_server();
            let mut spt = [0u8; 32];
            let (content, ct) = server_rx
                .decrypt_record(&resp[..resp_len], &mut spt)
                .unwrap();
            assert_eq!(ct, CT_HANDSHAKE);
            assert_eq!(content, &[HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x00]);

            // Post-update server app data decrypts under the engine's rotated keys.
            let mut abuf = [0u8; 64];
            let an = server
                .encrypt_record(b"after frag update", CT_APPLICATION_DATA, &mut abuf)
                .unwrap()
                .len();
            feed(&mut e, &abuf[..an]);
            assert!(matches!(e.step().unwrap(), EngineEvent::AppData));
            let mut out = [0u8; 64];
            let got = e.read_app(&mut out);
            assert_eq!(&out[..got], b"after frag update");
        }

        /// A KeyUpdate(update_requested=0) split across two records reassembles
        /// and rotates receive keys silently — no response.
        #[test]
        fn engine_reassembles_fragmented_key_update_not_requesting() {
            let mut scratch = DefaultScratch::new();
            let mut e = app_engine(&mut scratch);
            let mut server = mirror_server();
            let (rec1, rec2) = fragmented_key_update(&mut server, 0);

            feed(&mut e, &rec1);
            assert!(matches!(e.step().unwrap(), EngineEvent::Recv));
            feed(&mut e, &rec2);
            assert!(matches!(e.step().unwrap(), EngineEvent::Recv));
            assert!(!e.is_send_pending());

            let mut abuf = [0u8; 64];
            let an = server
                .encrypt_record(b"quiet frag rotation", CT_APPLICATION_DATA, &mut abuf)
                .unwrap()
                .len();
            feed(&mut e, &abuf[..an]);
            assert!(matches!(e.step().unwrap(), EngineEvent::AppData));
            let mut out = [0u8; 64];
            let got = e.read_app(&mut out);
            assert_eq!(&out[..got], b"quiet frag rotation");
        }
    }
}
