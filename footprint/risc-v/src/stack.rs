//! Stack high-water-mark instrumentation. Paint the unused region of the
//! stack with `0xAA`, then count how far the pattern was overwritten to
//! estimate peak live usage.
//!
//! riscv-rt's link.x exposes both ends of the stack output section as
//! linker symbols (`_estack` = bottom, `_stack_start` = top), so we use
//! those to bound the paint. We record the upper bound in a static so
//! `check_stack_high_water_mark` doesn't scan past it into the unpainted
//! live-frame area (those bytes are uninitialized as far as the abstract
//! machine is concerned).

use core::sync::atomic::{AtomicUsize, Ordering};

unsafe extern "C" {
    static _stack_start: u32;
    static _estack: u32;
}

/// Upper bound (exclusive) of the region painted by `paint_stack_inner`,
/// recorded so `check_stack_high_water_mark_inner` doesn't scan past it
/// into the unpainted live-frame area. 0 means "paint hasn't run yet".
static PAINT_END: AtomicUsize = AtomicUsize::new(0);

const SAFE_ZONE_BYTES: usize = 256;

#[inline(always)]
pub fn paint_stack() {
    paint_stack_inner::<SAFE_ZONE_BYTES>();
}

#[inline(always)]
pub fn check_stack_high_water_mark() -> usize {
    check_stack_high_water_mark_inner::<SAFE_ZONE_BYTES>()
}

pub fn paint_stack_inner<const SAFE: usize>() {
    unsafe {
        let stack_bottom = &raw const _estack as *mut u8;
        let safe_stack_bottom = stack_bottom.add(SAFE);

        // Read the live SP and stop the paint a margin below it, so we never
        // overwrite the active stack frame (which can be large under LTO).
        let mut sp: usize;
        core::arch::asm!("mv {}, sp", out(reg) sp, options(nomem, nostack));
        let live_limit = (sp as *mut u8).sub(SAFE);

        let paint_end = if (live_limit as usize) < (safe_stack_bottom as usize) {
            safe_stack_bottom
        } else {
            live_limit
        };

        let bytes_to_write = (paint_end as usize).saturating_sub(safe_stack_bottom as usize);
        if bytes_to_write > 0 {
            core::ptr::write_bytes(safe_stack_bottom, 0xAA, bytes_to_write);
        }
        PAINT_END.store(paint_end as usize, Ordering::Relaxed);
    }
}

pub fn check_stack_high_water_mark_inner<const SAFE: usize>() -> usize {
    unsafe {
        let stack_top = &raw const _stack_start as *mut u8;
        let stack_bottom = &raw const _estack as *mut u8;
        let safe_stack_bottom = stack_bottom.add(SAFE);
        // Bound the scan by what paint actually touched — reading past
        // `paint_end` would touch unpainted (uninitialized) stack bytes,
        // and stale 0xAA from prior runs would falsely extend the scan.
        let paint_end = PAINT_END.load(Ordering::Relaxed) as *mut u8;

        let mut current = safe_stack_bottom;
        while current < paint_end && *current == 0xAA {
            current = current.add(1);
        }

        // `stack_top` and `current` are derived from different linker
        // symbols (different abstract allocations), so `offset_from` would
        // be UB. Subtract as `usize` instead.
        (stack_top as usize) - (current as usize)
    }
}
