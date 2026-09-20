//! Byte-addressed copies for fields whose length is known at compile time:
//! those lower to one wide store, which faults at an odd destination offset on
//! M-class parts that trap unaligned access.
//!
//! `#[inline(never)]` is what makes that work. Inlined into a caller that knows
//! the length, LLVM folds the loop straight back into the store being avoided.

/// Copies nothing on a width mismatch, where `copy_from_slice` would panic.
#[inline(never)]
pub(crate) fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    if src.len() > dst.len() {
        return;
    }
    let mut i = 0;
    while i < src.len() {
        dst[i] = src[i];
        i += 1;
    }
}

#[inline(never)]
pub(crate) fn push_bytes<const N: usize>(
    out: &mut heapless::Vec<u8, N>,
    bytes: &[u8],
) -> Result<(), heapless::CapacityError> {
    for &byte in bytes {
        // `CapacityError`'s constructor is private.
        out.push(byte)
            .map_err(|_| heapless::CapacityError::default())?;
    }
    Ok(())
}
