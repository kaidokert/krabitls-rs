//! Per-epoch anti-replay window (RFC 9147 §4.5.1): a sliding bitmap over the
//! most recently seen record sequence numbers, rejecting duplicates and records
//! older than the window.
//!
//! Reconstruction and enforcement are separate concerns: the record layer
//! reconstructs a full sequence number to open a record; this window then
//! decides whether that number is acceptable.

/// A 64-entry sliding window. `highest` is the largest accepted sequence number
/// (its bit is the top of the window); `bitmap` bit `i` marks
/// `highest - i` as seen.
pub(crate) struct ReplayWindow {
    highest: u64,
    seen_any: bool,
    bitmap: u64,
}

const WINDOW: u64 = 64;

impl ReplayWindow {
    pub(crate) const fn new() -> Self {
        Self {
            highest: 0,
            seen_any: false,
            bitmap: 0,
        }
    }

    /// Whether `seq` would be accepted (not a duplicate, not below the window)
    /// without recording it. `mark` still has to run once the record
    /// authenticates.
    pub(crate) fn accepts(&self, seq: u64) -> bool {
        if !self.seen_any || seq > self.highest {
            return true;
        }
        let delta = self.highest - seq;
        if delta >= WINDOW {
            return false;
        }
        self.bitmap & (1u64 << delta) == 0
    }

    /// Record `seq` as seen, sliding the window forward if it is the new high.
    /// Only call after the record's AEAD tag verifies (RFC 9147 §4.5.1).
    pub(crate) fn mark(&mut self, seq: u64) {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = seq;
            self.bitmap = 1;
            return;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= WINDOW {
                0
            } else {
                self.bitmap << shift
            };
            self.bitmap |= 1;
            self.highest = seq;
        } else {
            let delta = self.highest - seq;
            if delta < WINDOW {
                self.bitmap |= 1u64 << delta;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_window_accepts_anything_then_first_mark_anchors() {
        let mut w = ReplayWindow::new();
        assert!(w.accepts(0));
        assert!(w.accepts(5000));
        w.mark(10);
        assert!(!w.accepts(10), "the just-marked seq is now a duplicate");
        assert!(w.accepts(11));
    }

    #[test]
    fn rejects_duplicate_and_too_old() {
        let mut w = ReplayWindow::new();
        w.mark(100);
        w.mark(101);
        w.mark(103);
        assert!(!w.accepts(100));
        assert!(!w.accepts(103));
        assert!(w.accepts(102), "a gap inside the window is still open");
        w.mark(102);
        assert!(!w.accepts(102));
        // 103 is highest; 103 - 64 = 39 falls out of the window.
        assert!(!w.accepts(39));
        assert!(w.accepts(40));
    }

    #[test]
    fn large_jump_clears_the_window() {
        let mut w = ReplayWindow::new();
        w.mark(1);
        w.mark(2);
        w.mark(1000);
        assert!(!w.accepts(1000));
        // Everything more than a window below 1000 is rejected; 1 and 2 are gone.
        assert!(!w.accepts(1));
        assert!(w.accepts(999));
    }
}
