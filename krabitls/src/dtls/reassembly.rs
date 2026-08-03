//! DTLS 1.3 handshake-message reassembly (RFC 9147 §5.5).
//!
//! A handshake message larger than the path MTU is split across several records,
//! each carrying a `fragment_offset`/`fragment_length` slice of the same
//! `message_seq` (the 12-byte DTLS handshake header, [`super::framing`]). Records
//! can arrive out of order, be duplicated, overlap, or be retransmitted, so the
//! receiver must track which byte ranges of each message it has and only surface
//! a message once `[0, length)` is fully covered.
//!
//! The message bodies live in a caller-supplied arena (no allocation here); this
//! structure holds only the per-message metadata and the received-range set. It
//! is generic in the message and fragment-per-message caps so a constrained
//! target can size it down.

use heapless::Vec;

#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub(crate) enum ReasmError {
    #[error("more concurrent handshake messages than the reassembler holds")]
    TooManyMessages,
    #[error("a message fragmented into more disjoint pieces than tracked")]
    TooManyFragments,
    #[error("reassembly arena is full")]
    ArenaFull,
    #[error("fragment extends past the message length")]
    BadFragment,
    #[error("fragment disagrees with an earlier one on message type or length")]
    Inconsistent,
}

struct Slot<const MAX_FRAGS: usize> {
    seq: u16,
    msg_type: u8,
    len: usize,
    /// Start of this message's body in the caller arena.
    off: usize,
    /// Received byte ranges within `[0, len)`, kept sorted and merged.
    ranges: Vec<(u32, u32), MAX_FRAGS>,
}

impl<const MAX_FRAGS: usize> Slot<MAX_FRAGS> {
    fn is_complete(&self) -> bool {
        matches!(self.ranges.first(), Some(&(0, end)) if end as usize == self.len)
            && self.ranges.len() == 1
    }

    /// Merge `[start, end)` into the range set, coalescing overlaps and
    /// adjacencies so a contiguously-arriving message collapses to one interval.
    fn add_range(&mut self, start: u32, end: u32) -> Result<(), ReasmError> {
        if start >= end {
            return Ok(());
        }
        let (mut lo, mut hi) = (start, end);
        let mut merged: Vec<(u32, u32), MAX_FRAGS> = Vec::new();
        let mut placed = false;
        for &(s, e) in &self.ranges {
            if e < lo {
                merged
                    .push((s, e))
                    .map_err(|_| ReasmError::TooManyFragments)?;
            } else if hi < s {
                if !placed {
                    merged
                        .push((lo, hi))
                        .map_err(|_| ReasmError::TooManyFragments)?;
                    placed = true;
                }
                merged
                    .push((s, e))
                    .map_err(|_| ReasmError::TooManyFragments)?;
            } else {
                // Overlapping or adjacent (`e == lo` / `hi == s`): absorb.
                lo = lo.min(s);
                hi = hi.max(e);
            }
        }
        if !placed {
            merged
                .push((lo, hi))
                .map_err(|_| ReasmError::TooManyFragments)?;
        }
        self.ranges = merged;
        Ok(())
    }
}

pub(crate) struct Reassembler<const MAX_MSGS: usize, const MAX_FRAGS: usize> {
    slots: Vec<Slot<MAX_FRAGS>, MAX_MSGS>,
    /// Bump high-water mark into the caller arena.
    used: usize,
}

impl<const MAX_MSGS: usize, const MAX_FRAGS: usize> Reassembler<MAX_MSGS, MAX_FRAGS> {
    pub(crate) fn new() -> Self {
        Self {
            slots: Vec::new(),
            used: 0,
        }
    }

    /// Insert one fragment. `arena` stores the message bodies; a message's region
    /// is bump-allocated on first sight of its `seq`. Duplicate/overlapping
    /// fragments are idempotent.
    pub(crate) fn push(
        &mut self,
        arena: &mut [u8],
        msg_type: u8,
        seq: u16,
        msg_len: usize,
        frag_off: usize,
        frag: &[u8],
    ) -> Result<(), ReasmError> {
        let frag_end = frag_off
            .checked_add(frag.len())
            .ok_or(ReasmError::BadFragment)?;
        if frag_end > msg_len {
            return Err(ReasmError::BadFragment);
        }

        let idx = match self.slots.iter().position(|s| s.seq == seq) {
            Some(i) => {
                if self.slots[i].msg_type != msg_type || self.slots[i].len != msg_len {
                    return Err(ReasmError::Inconsistent);
                }
                i
            }
            None => {
                let off = self.used;
                let new_used = off.checked_add(msg_len).ok_or(ReasmError::ArenaFull)?;
                if new_used > arena.len() {
                    return Err(ReasmError::ArenaFull);
                }
                self.slots
                    .push(Slot {
                        seq,
                        msg_type,
                        len: msg_len,
                        off,
                        ranges: Vec::new(),
                    })
                    .map_err(|_| ReasmError::TooManyMessages)?;
                self.used = new_used;
                self.slots.len() - 1
            }
        };

        let off = self.slots[idx].off;
        arena[off + frag_off..off + frag_end].copy_from_slice(frag);
        self.slots[idx].add_range(frag_off as u32, frag_end as u32)
    }

    /// Whether a `finished_type` message has fully arrived and every message from
    /// `base_seq` (the flight's first `message_seq` — one past ServerHello) up to
    /// it is present and complete — i.e. the whole flight has been received with
    /// no gaps. `base_seq` is supplied by the caller rather than inferred from the
    /// slots, so a Finished that arrives before the earlier messages is not
    /// mistaken for a complete flight.
    pub(crate) fn flight_complete(&self, base_seq: u16, finished_type: u8) -> bool {
        let Some(fin) = self
            .slots
            .iter()
            .find(|s| s.msg_type == finished_type && s.is_complete())
        else {
            return false;
        };
        if fin.seq < base_seq {
            return false;
        }
        (base_seq..=fin.seq).all(|seq| self.slots.iter().any(|s| s.seq == seq && s.is_complete()))
    }

    /// Serialize the assembled messages into `out` in ascending `message_seq`
    /// order, each as `msg_type ‖ u24 length ‖ body` (the 4-byte-header transcript
    /// form). Returns the written length. `arena` is the same body storage passed
    /// to [`push`](Self::push).
    pub(crate) fn serialize_flight(
        &self,
        arena: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ReasmError> {
        // Visit slots by ascending seq without allocating: repeatedly pick the
        // smallest seq greater than the last emitted.
        let mut written = 0usize;
        let mut prev: Option<u16> = None;
        loop {
            let next = self
                .slots
                .iter()
                .filter(|s| prev.is_none_or(|p| s.seq > p))
                .min_by_key(|s| s.seq);
            let Some(slot) = next else { break };
            prev = Some(slot.seq);
            if !slot.is_complete() {
                continue;
            }
            let hdr = [
                slot.msg_type,
                (slot.len >> 16) as u8,
                (slot.len >> 8) as u8,
                slot.len as u8,
            ];
            let end = written
                .checked_add(4 + slot.len)
                .ok_or(ReasmError::ArenaFull)?;
            if end > out.len() {
                return Err(ReasmError::ArenaFull);
            }
            out[written..written + 4].copy_from_slice(&hdr);
            out[written + 4..end].copy_from_slice(&arena[slot.off..slot.off + slot.len]);
            written = end;
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type R = Reassembler<8, 16>;

    /// Push three 2-byte fragments of one 6-byte message in the given offset
    /// order and assert it completes with the expected body.
    fn assemble_in(order: &[usize]) -> ([u8; 32], usize) {
        let mut arena = [0u8; 32];
        let mut r = R::new();
        let full = [0xA0, 0xA1, 0xB0, 0xB1, 0xC0, 0xC1];
        for &o in order {
            r.push(&mut arena, 11, 5, 6, o, &full[o..o + 2]).unwrap();
        }
        assert!(r.flight_complete(5, 11));
        let mut out = [0u8; 32];
        let n = r.serialize_flight(&arena, &mut out).unwrap();
        (out, n)
    }

    fn body(out: &[u8; 32], n: usize) -> std::vec::Vec<u8> {
        // out = [type, u24 len, body...]; strip the 4-byte header.
        out[4..n].to_vec()
    }

    #[test]
    fn in_order_fragments_reassemble() {
        let (out, n) = assemble_in(&[0, 2, 4]);
        assert_eq!(body(&out, n), [0xA0, 0xA1, 0xB0, 0xB1, 0xC0, 0xC1]);
        assert_eq!(&out[..4], &[11, 0, 0, 6]);
    }

    #[test]
    fn reversed_fragments_reassemble() {
        let (out, n) = assemble_in(&[4, 2, 0]);
        assert_eq!(body(&out, n), [0xA0, 0xA1, 0xB0, 0xB1, 0xC0, 0xC1]);
    }

    #[test]
    fn duplicated_fragments_are_idempotent() {
        let mut arena = [0u8; 32];
        let mut r = R::new();
        r.push(&mut arena, 11, 5, 6, 0, &[1, 2]).unwrap();
        r.push(&mut arena, 11, 5, 6, 0, &[1, 2]).unwrap(); // exact dup
        assert!(!r.flight_complete(5, 11));
        r.push(&mut arena, 11, 5, 6, 2, &[3, 4]).unwrap();
        r.push(&mut arena, 11, 5, 6, 4, &[5, 6]).unwrap();
        assert!(r.flight_complete(5, 11));
    }

    #[test]
    fn overlapping_fragments_merge() {
        let mut arena = [0u8; 32];
        let mut r = R::new();
        // [0,4) then [2,6) overlap on [2,4) → covers [0,6).
        r.push(&mut arena, 11, 5, 6, 0, &[1, 2, 3, 4]).unwrap();
        r.push(&mut arena, 11, 5, 6, 2, &[3, 4, 5, 6]).unwrap();
        assert!(r.flight_complete(5, 11));
    }

    #[test]
    fn gap_then_fill_completes() {
        let (out, n) = assemble_in(&[0, 4, 2]);
        assert_eq!(body(&out, n), [0xA0, 0xA1, 0xB0, 0xB1, 0xC0, 0xC1]);
    }

    #[test]
    fn multi_message_flight_out_of_order_serializes_in_seq_order() {
        let mut arena = [0u8; 64];
        let mut r = R::new();
        // Finished (seq 6) arrives before EncryptedExtensions (seq 5).
        r.push(&mut arena, 20, 6, 3, 0, &[0xF0, 0xF1, 0xF2])
            .unwrap();
        assert!(!r.flight_complete(5, 20), "EE (seq 5) still missing");
        r.push(&mut arena, 8, 5, 2, 0, &[0xE0, 0xE1]).unwrap();
        assert!(r.flight_complete(5, 20));

        let mut out = [0u8; 64];
        let n = r.serialize_flight(&arena, &mut out).unwrap();
        // EE first (seq 5), then Finished (seq 6).
        assert_eq!(
            &out[..n],
            &[8, 0, 0, 2, 0xE0, 0xE1, 20, 0, 0, 3, 0xF0, 0xF1, 0xF2]
        );
    }

    #[test]
    fn rejects_fragment_past_message_length() {
        let mut arena = [0u8; 32];
        let mut r = R::new();
        assert_eq!(
            r.push(&mut arena, 11, 5, 4, 2, &[1, 2, 3]),
            Err(ReasmError::BadFragment)
        );
    }

    #[test]
    fn rejects_inconsistent_length() {
        let mut arena = [0u8; 32];
        let mut r = R::new();
        r.push(&mut arena, 11, 5, 6, 0, &[1, 2]).unwrap();
        assert_eq!(
            r.push(&mut arena, 11, 5, 8, 2, &[3, 4]),
            Err(ReasmError::Inconsistent)
        );
    }

    #[test]
    fn arena_full_is_reported() {
        let mut arena = [0u8; 4];
        let mut r = R::new();
        assert_eq!(
            r.push(&mut arena, 11, 5, 8, 0, &[1, 2]),
            Err(ReasmError::ArenaFull)
        );
    }
}
