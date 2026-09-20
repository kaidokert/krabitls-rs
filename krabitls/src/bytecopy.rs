//! Byte-addressed copies for small fixed-size fields.
//!
//! A `copy_from_slice` / `extend_from_slice` whose source length is known at
//! compile time is lowered to one wide store — a 2-byte copy becomes a single
//! `strh` — because the ARMv7-M target declares unaligned access supported. The
//! destination offset is usually a runtime value (a cursor into a record
//! buffer), so that store lands on an odd address roughly half the time, which
//! faults on M-class parts that trap unaligned access; Cortex-M7 traps by
//! default. Writing a byte at a time emits the same bytes and cannot be merged
//! back into a wide store, because the offset's alignment is not provable.
//!
//! Only statically-sized copies need this. A runtime-length copy already goes
//! through `memcpy`, which aligns its own accesses.

/// Copy `src` into `dst`, one byte at a time.
///
/// Copies `src.len()` bytes and does nothing when `dst` is shorter, where
/// `copy_from_slice` would panic; every caller slices `dst` to the exact width
/// first, so the lengths match by construction.
pub(crate) fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    if src.len() > dst.len() {
        return;
    }
    let mut i = 0;
    while i < src.len() {
        dst[i] = src[i];
        i += 1;
    }
}

/// Append `bytes` to `out`, one byte at a time.
pub(crate) fn push_bytes<const N: usize>(
    out: &mut heapless::Vec<u8, N>,
    bytes: &[u8],
) -> Result<(), heapless::CapacityError> {
    for &byte in bytes {
        out.push(byte)
            .map_err(|_| heapless::CapacityError::default())?;
    }
    Ok(())
}
