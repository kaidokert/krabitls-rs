//! Deterministic test infrastructure. `SeededRng` mirrors Python
//! `tls_fixture` seed-mode entropy byte-for-byte; `CannedTransport`
//! replays captured server flights.
//!
//! Unpublished sibling crate: `SeededRng` implements
//! [`rand_core::TryCryptoRng`] for the facade's `connect()` bound but is a
//! fixed, seed-derived stream — never use it outside fixture replay.
#![no_std]

use krabitls::client::Transport;
use sha2::{Digest, Sha256};

/// Pre-image domain separator. Matches
/// `tls_fixture/tls13.py::derive_bytes`.
const DERIVE_DOMAIN: &[u8] = b"tls_fixture\0";

/// Maximum entropy bytes the facade draws per `connect()`: 32 for
/// `client_random`, 32 for the X25519 private key, then the ML-KEM-768 keygen
/// `d` (32) and `z` (32) that an `mlkem` build draws for the X25519MLKEM768
/// key_share. Derived unconditionally — a non-`mlkem` client just never reads
/// past byte 64 — so the helper needs no cipher/KEM feature of its own.
const ENTROPY_TOTAL: usize = 128;

/// Deterministic entropy source mirroring the Python fixture's seed-mode
/// RNG so the facade's `client_random` + X25519 private key match Python's
/// bytes byte-for-byte at the same seed.
#[derive(Debug, Clone)]
pub struct SeededRng {
    bytes: [u8; ENTROPY_TOTAL],
    pos: usize,
}

impl SeededRng {
    /// Pre-compute the stream in the order the facade's `connect()` draws it:
    /// `client_random` (32 B), X25519 private key (32 B), and under `mlkem` the
    /// ML-KEM-768 keygen `d` (32 B) then `z` (32 B). Per-chunk derivation is
    /// `SHA-256("tls_fixture\0" || seed_be8 || \0 || label || \0 || counter_be4)`,
    /// concatenated until 32 B per label.
    pub fn new(seed: u64) -> Self {
        let mut bytes = [0u8; ENTROPY_TOTAL];
        derive_bytes_into(seed, b"client_random", &mut bytes[0..32]);
        derive_bytes_into(seed, b"client_x25519", &mut bytes[32..64]);
        // No Python `tls_fixture` counterpart — these labels exist only so the
        // ML-KEM-768 keygen draw is deterministic across capture and replay.
        derive_bytes_into(seed, b"client_mlkem_d", &mut bytes[64..96]);
        derive_bytes_into(seed, b"client_mlkem_z", &mut bytes[96..128]);
        Self { bytes, pos: 0 }
    }

    /// Reset stream position.
    pub fn rewind(&mut self) {
        self.pos = 0;
    }
}

/// `try_fill_bytes` requested more bytes than the precomputed stream holds.
/// Indicates a test draws more entropy than the facade's `connect()` shape
/// (`client_random` + X25519 priv, plus the ML-KEM keygen `d`/`z` under `mlkem`).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct EntropyExhausted;

impl core::fmt::Display for EntropyExhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SeededRng precomputed stream exhausted")
    }
}

impl core::error::Error for EntropyExhausted {}

impl rand_core::TryRng for SeededRng {
    type Error = EntropyExhausted;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let want = self.pos.saturating_add(dst.len());
        if want > self.bytes.len() {
            return Err(EntropyExhausted);
        }
        dst.copy_from_slice(&self.bytes[self.pos..want]);
        self.pos = want;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for SeededRng {}

/// Python `derive_bytes(seed, label, length)` ported.
fn derive_bytes_into(seed: u64, label: &[u8], dst: &mut [u8]) {
    let mut counter: u32 = 0;
    let mut offset = 0;
    while offset < dst.len() {
        let mut h = Sha256::new();
        h.update(DERIVE_DOMAIN);
        h.update(seed.to_be_bytes());
        h.update(b"\0");
        h.update(label);
        h.update(b"\0");
        h.update(counter.to_be_bytes());
        let digest = h.finalize();
        let take = (dst.len() - offset).min(32);
        dst[offset..offset + take].copy_from_slice(&digest[..take]);
        offset += take;
        counter += 1;
    }
}

/// In-memory [`Transport`] for replaying canned server bytes through the
/// facade. `TX` caps the total bytes the facade may send; overflow
/// returns [`CannedError::TxOverflow`].
#[derive(Debug)]
pub struct CannedTransport<'r, const TX: usize> {
    server_bytes: &'r [u8],
    rx_pos: usize,
    captured_tx: [u8; TX],
    tx_pos: usize,
}

impl<'r, const TX: usize> CannedTransport<'r, TX> {
    /// New transport over `server_bytes` (read side); empty capture buffer.
    pub fn new(server_bytes: &'r [u8]) -> Self {
        Self {
            server_bytes,
            rx_pos: 0,
            captured_tx: [0u8; TX],
            tx_pos: 0,
        }
    }

    /// Slice of bytes the facade has written so far.
    pub fn captured_tx(&self) -> &[u8] {
        &self.captured_tx[..self.tx_pos]
    }

    /// Number of canned server bytes consumed so far.
    pub fn rx_consumed(&self) -> usize {
        self.rx_pos
    }

    /// Number of canned server bytes remaining.
    pub fn rx_remaining(&self) -> usize {
        self.server_bytes.len() - self.rx_pos
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CannedError {
    /// `write_all` exceeded the `TX` cap.
    TxOverflow,
}

impl core::fmt::Display for CannedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TxOverflow => f.write_str("CannedTransport tx capacity exceeded"),
        }
    }
}

impl core::error::Error for CannedError {}

impl<const TX: usize> Transport for CannedTransport<'_, TX> {
    type Error = CannedError;

    /// Returns `Ok(0)` once the canned stream is exhausted; the facade's
    /// drive loop maps that to
    /// [`ConnectError::UnexpectedEof`](krabitls::client::ConnectError::UnexpectedEof).
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let remaining = self.server_bytes.len() - self.rx_pos;
        if remaining == 0 {
            return Ok(0);
        }
        let take = remaining.min(buf.len());
        buf[..take].copy_from_slice(&self.server_bytes[self.rx_pos..self.rx_pos + take]);
        self.rx_pos += take;
        Ok(take)
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        let new_pos = self
            .tx_pos
            .checked_add(buf.len())
            .ok_or(CannedError::TxOverflow)?;
        if new_pos > TX {
            return Err(CannedError::TxOverflow);
        }
        self.captured_tx[self.tx_pos..new_pos].copy_from_slice(buf);
        self.tx_pos = new_pos;
        Ok(())
    }
}

// ============================================================================
// Known-answer tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::TryRng;

    /// `client_random` from `tls_fixture/state/client.json` at seed 0.
    const SEED_0_CLIENT_RANDOM: [u8; 32] = [
        0xed, 0xe5, 0x7b, 0xa2, 0x43, 0x3a, 0xd5, 0xa3, 0x4d, 0x05, 0x50, 0x3a, 0xfe, 0x4f, 0xc2,
        0x89, 0xdf, 0xd9, 0xe9, 0x53, 0x57, 0xd8, 0x16, 0x36, 0x80, 0x24, 0xe7, 0x3f, 0xbf, 0xa6,
        0xfa, 0xf5,
    ];
    /// `x25519_priv` from `tls_fixture/state/client.json` at seed 0.
    const SEED_0_X25519_PRIV: [u8; 32] = [
        0xac, 0xe1, 0xc2, 0x3b, 0x24, 0xdf, 0xad, 0x58, 0xc5, 0x4c, 0xcf, 0x4c, 0x1f, 0xe8, 0xdf,
        0xe8, 0x5e, 0x76, 0x0e, 0x02, 0x3b, 0x6c, 0xb6, 0x02, 0x2f, 0x70, 0x0f, 0x34, 0xde, 0x4c,
        0x28, 0x28,
    ];

    #[test]
    fn seeded_rng_seed_0_matches_python_known_answer() {
        let mut rng = SeededRng::new(0);
        let mut client_random = [0u8; 32];
        let mut x25519_priv = [0u8; 32];
        rng.try_fill_bytes(&mut client_random).unwrap();
        rng.try_fill_bytes(&mut x25519_priv).unwrap();
        assert_eq!(
            client_random, SEED_0_CLIENT_RANDOM,
            "client_random must match tls_fixture seed-0 derivation",
        );
        assert_eq!(
            x25519_priv, SEED_0_X25519_PRIV,
            "x25519_priv must match tls_fixture seed-0 derivation",
        );
    }

    #[test]
    fn seeded_rng_rewind_restarts_stream() {
        let mut rng = SeededRng::new(0);
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        rng.try_fill_bytes(&mut first).unwrap();
        rng.rewind();
        rng.try_fill_bytes(&mut second).unwrap();
        assert_eq!(first, second);
    }

    // Regen expected bytes: `derive_bytes(0, b'multi_block_kat', 64).hex()`
    // from a reference Python run.
    #[test]
    fn derive_bytes_multi_block_matches_python_known_answer() {
        let mut buf = [0u8; 64];
        derive_bytes_into(0, b"multi_block_kat", &mut buf);
        let expected: [u8; 64] = [
            0xd9, 0x13, 0x74, 0xdf, 0x64, 0xd6, 0x6f, 0xe8, 0x42, 0x99, 0x2d, 0xbb, 0x09, 0x32,
            0x70, 0xc8, 0x4a, 0x55, 0xf3, 0xf5, 0xbc, 0xf7, 0x6b, 0x2a, 0x13, 0x92, 0xe8, 0xb9,
            0x99, 0x10, 0x44, 0x99, 0x43, 0x3c, 0x03, 0x3d, 0x63, 0x12, 0x38, 0x4f, 0x73, 0x0e,
            0xfb, 0xaa, 0x03, 0x15, 0x7e, 0xe5, 0xbf, 0xe7, 0x6d, 0xe3, 0x9c, 0xcb, 0xbc, 0xa2,
            0xf0, 0x47, 0xf6, 0xd1, 0x00, 0x83, 0x9b, 0x2b,
        ];
        assert_eq!(buf, expected, "multi-block derive_bytes must match Python");
        // Bytes 32..64 are the second counter-step block; if the loop
        // mis-increments the counter or mis-frames the digest, this is
        // where it surfaces.
        assert_ne!(
            buf[..32],
            buf[32..],
            "second counter step must produce different bytes",
        );
    }

    #[test]
    fn seeded_rng_overdraw_returns_err() {
        let mut rng = SeededRng::new(0);
        let mut buf = [0u8; ENTROPY_TOTAL];
        rng.try_fill_bytes(&mut buf).unwrap();
        // Stream exhausted; any further draw must surface as Err, not zero-fill.
        let mut tail = [0u8; 1];
        assert_eq!(rng.try_fill_bytes(&mut tail), Err(EntropyExhausted));
    }

    #[test]
    fn seeded_rng_different_seeds_diverge() {
        let mut a = SeededRng::new(0);
        let mut b = SeededRng::new(1);
        let mut ba = [0u8; 32];
        let mut bb = [0u8; 32];
        a.try_fill_bytes(&mut ba).unwrap();
        b.try_fill_bytes(&mut bb).unwrap();
        assert_ne!(ba, bb, "seed change must perturb the stream");
    }

    #[test]
    fn canned_transport_serves_then_eof() {
        let server = [1u8, 2, 3, 4, 5];
        let mut t = CannedTransport::<256>::new(&server);
        let mut buf = [0u8; 10];
        assert_eq!(Transport::read(&mut t, &mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], &server);
        assert_eq!(Transport::read(&mut t, &mut buf).unwrap(), 0);
    }

    #[test]
    fn canned_transport_partial_reads_advance_cursor() {
        let server = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut t = CannedTransport::<256>::new(&server);
        let mut buf = [0u8; 3];
        assert_eq!(Transport::read(&mut t, &mut buf).unwrap(), 3);
        assert_eq!(&buf, &[1, 2, 3]);
        assert_eq!(Transport::read(&mut t, &mut buf).unwrap(), 3);
        assert_eq!(&buf, &[4, 5, 6]);
        assert_eq!(t.rx_remaining(), 2);
    }

    #[test]
    fn canned_transport_captures_writes() {
        let mut t = CannedTransport::<256>::new(&[]);
        Transport::write_all(&mut t, &[1u8, 2, 3]).unwrap();
        Transport::write_all(&mut t, &[4u8, 5]).unwrap();
        assert_eq!(t.captured_tx(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn canned_transport_write_overflow_rejects() {
        let mut t = CannedTransport::<4>::new(&[]);
        Transport::write_all(&mut t, &[1u8, 2]).unwrap();
        assert_eq!(
            Transport::write_all(&mut t, &[3u8, 4, 5]),
            Err(CannedError::TxOverflow),
        );
        // Partial state preserved: the first 2 bytes are still there.
        assert_eq!(t.captured_tx(), &[1, 2]);
    }
}
