//! DTLS 1.3 ACK records (RFC 9147 §7): the list of record numbers a peer has
//! received, letting the other side stop retransmitting an acknowledged flight.
//!
//! The ACK body is `RecordNumber record_numbers<0..2^16-1>` where each
//! `RecordNumber` is `epoch(u64) ‖ sequence_number(u64)`. It rides a record with
//! content type [`crate::consts::CT_ACK`].

#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub(crate) enum AckError {
    #[error("output buffer too small for the ACK")]
    BufferTooSmall,
    #[error("too many record numbers for one ACK")]
    TooMany,
    #[error("ACK body malformed")]
    Malformed,
}

/// One acknowledged record on the wire: its epoch and sequence number.
pub(crate) const RECORD_NUMBER_LEN: usize = 16;

/// Records one bitmap ACK carries at most — the width of the received-record
/// bitmap ([`write_ack_bitmap`]). 128 = `MAX_FLIGHT_MSGS × MAX_MSG_FRAGS`, the
/// most records a conforming handshake flight can fragment into, so every record
/// the flight reassembler accepts is acknowledgeable.
pub(crate) const MAX_ACK_RECORDS: usize = u128::BITS as usize;

/// Largest ACK body [`write_ack_bitmap`] can produce.
pub(crate) const MAX_ACK_BODY_LEN: usize = 2 + MAX_ACK_RECORDS * RECORD_NUMBER_LEN;

/// Serialize an ACK body into `out`, returning its length. `records` are the
/// `(epoch, sequence_number)` pairs being acknowledged.
pub(crate) fn write_ack(records: &[(u64, u64)], out: &mut [u8]) -> Result<usize, AckError> {
    let list_len = records
        .len()
        .checked_mul(RECORD_NUMBER_LEN)
        .ok_or(AckError::TooMany)?;
    if list_len > u16::MAX as usize {
        return Err(AckError::TooMany);
    }
    let total = 2 + list_len;
    if out.len() < total {
        return Err(AckError::BufferTooSmall);
    }
    out[..2].copy_from_slice(&(list_len as u16).to_be_bytes());
    let mut p = 2;
    for &(epoch, seq) in records {
        out[p..p + 8].copy_from_slice(&epoch.to_be_bytes());
        out[p + 8..p + 16].copy_from_slice(&seq.to_be_bytes());
        p += RECORD_NUMBER_LEN;
    }
    Ok(total)
}

/// Serialize an ACK body from a received-record bitmap: bit `i` of `seqs` set
/// means sequence number `i` at `epoch` was received. Records are emitted in
/// ascending sequence order. A bitmap deduplicates retransmits for free and
/// bounds the ACK to the 64 lowest sequence numbers of the epoch.
pub(crate) fn write_ack_bitmap(epoch: u64, seqs: u128, out: &mut [u8]) -> Result<usize, AckError> {
    let list_len = seqs.count_ones() as usize * RECORD_NUMBER_LEN;
    let total = 2 + list_len;
    if out.len() < total {
        return Err(AckError::BufferTooSmall);
    }
    out[..2].copy_from_slice(&(list_len as u16).to_be_bytes());
    let mut p = 2;
    let mut bits = seqs;
    while bits != 0 {
        let seq = bits.trailing_zeros() as u64;
        bits &= bits - 1;
        out[p..p + 8].copy_from_slice(&epoch.to_be_bytes());
        out[p + 8..p + 16].copy_from_slice(&seq.to_be_bytes());
        p += RECORD_NUMBER_LEN;
    }
    Ok(total)
}

/// Iterate the `(epoch, sequence_number)` pairs of a received ACK body.
pub(crate) fn parse_ack(body: &[u8]) -> Result<AckRecords<'_>, AckError> {
    let len_bytes = body.get(..2).ok_or(AckError::Malformed)?;
    let list_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
    let entries = body.get(2..2 + list_len).ok_or(AckError::Malformed)?;
    if !entries.len().is_multiple_of(RECORD_NUMBER_LEN) {
        return Err(AckError::Malformed);
    }
    Ok(AckRecords { entries, pos: 0 })
}

pub(crate) struct AckRecords<'a> {
    entries: &'a [u8],
    pos: usize,
}

impl Iterator for AckRecords<'_> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<(u64, u64)> {
        let chunk = self.entries.get(self.pos..self.pos + RECORD_NUMBER_LEN)?;
        self.pos += RECORD_NUMBER_LEN;
        // `chunk` is exactly 16 bytes, so both conversions succeed; `.ok()?`
        // keeps that infallible without an `unwrap`.
        let epoch = u64::from_be_bytes(chunk.get(..8)?.try_into().ok()?);
        let seq = u64::from_be_bytes(chunk.get(8..16)?.try_into().ok()?);
        Some((epoch, seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_matches_the_wire_layout() {
        let mut out = [0u8; 64];
        let n = write_ack(&[(2, 0), (2, 1)], &mut out).unwrap();
        assert_eq!(
            &out[..n],
            &[
                0x00, 0x20, // record_numbers length = 2 * 16
                0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, // (epoch 2, seq 0)
                0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, // (epoch 2, seq 1)
            ]
        );
    }

    #[test]
    fn empty_ack_is_a_bare_zero_length() {
        let mut out = [0u8; 8];
        let n = write_ack(&[], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x00, 0x00]);
        assert_eq!(parse_ack(&out[..n]).unwrap().count(), 0);
    }

    #[test]
    fn bitmap_emits_set_seqs_in_order_and_dedups() {
        // Bits 0, 1, 3 set (a retransmit of an already-seen seq is just the same
        // bit) → three records, ascending, no duplicates.
        let mut out = [0u8; MAX_ACK_BODY_LEN];
        let n = write_ack_bitmap(2, 0b1011, &mut out).unwrap();
        let parsed: heapless::Vec<(u64, u64), 8> = parse_ack(&out[..n]).unwrap().collect();
        assert_eq!(&parsed[..], &[(2, 0), (2, 1), (2, 3)]);
    }

    #[test]
    fn bitmap_emits_the_top_bit() {
        // The highest bit of the u128 window is record 127.
        let mut out = [0u8; MAX_ACK_BODY_LEN];
        let n = write_ack_bitmap(2, 1u128 << 127, &mut out).unwrap();
        let parsed: heapless::Vec<(u64, u64), 4> = parse_ack(&out[..n]).unwrap().collect();
        assert_eq!(&parsed[..], &[(2, 127)]);
    }

    #[test]
    fn bitmap_empty_is_a_bare_zero_length() {
        let mut out = [0u8; 8];
        let n = write_ack_bitmap(2, 0, &mut out).unwrap();
        assert_eq!(&out[..n], &[0x00, 0x00]);
    }

    #[test]
    fn round_trips() {
        let records = [(2u64, 0u64), (2, 1), (3, 7)];
        let mut out = [0u8; 64];
        let n = write_ack(&records, &mut out).unwrap();
        let parsed: heapless::Vec<(u64, u64), 8> = parse_ack(&out[..n]).unwrap().collect();
        assert_eq!(&parsed[..], &records);
    }

    #[test]
    fn rejects_truncated_and_misaligned() {
        assert_eq!(parse_ack(&[0x00]).err(), Some(AckError::Malformed));
        // Claims 16 bytes of records but only 8 present.
        assert_eq!(
            parse_ack(&[0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 1]).err(),
            Some(AckError::Malformed)
        );
        // Length not a multiple of 16.
        assert_eq!(
            parse_ack(&[0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 1]).err(),
            Some(AckError::Malformed)
        );
    }

    #[test]
    fn buffer_too_small_is_reported() {
        let mut out = [0u8; 4];
        assert_eq!(
            write_ack(&[(2, 0)], &mut out),
            Err(AckError::BufferTooSmall)
        );
    }
}
