// portable-atomic so thumbv6m (no native 32-bit atomics) builds.
use portable_atomic::{AtomicUsize, Ordering};

unsafe extern "C" {
    static _stack_start: u32;
    // cortex-m-rt's bss end symbol. We can't paint below this without
    // clobbering static / static-mut data — including the cortex_m crate's
    // "peripherals taken" flag and other framework state.
    static __ebss: u32;
}

// Upper bound (exclusive) of the region painted by `paint_stack_inner`,
// recorded so `check_stack_high_water_mark_inner` doesn't scan past it
// into the unpainted live-frame area (which would be UB — those bytes
// are uninitialized as far as the abstract machine is concerned).
// 0 means "paint hasn't run yet".
static PAINT_END: AtomicUsize = AtomicUsize::new(0);

/// Margin between the painted region and:
///   - the bottom of RAM (keeps `.bss` / `.data` out of the paint)
///   - the live stack pointer at paint time (keeps the caller's frame intact)
///
/// With this read-SP-then-paint approach we don't need to budget for fat
/// LTO-inlined frames in a constant; 256 is just an over-the-shoulder margin.
const SAFE_ZONE_BYTES: usize = 256;

#[inline(always)]
pub fn paint_stack() {
    paint_stack_inner::<SAFE_ZONE_BYTES>();
}

#[inline(always)]
pub fn check_stack_high_water_mark() -> usize {
    check_stack_high_water_mark_inner::<SAFE_ZONE_BYTES>()
}

/// Lower bound of the paint region: just above the `.bss` end, with the
/// usual SAFE margin. Painting below `__ebss` would clobber static / static-
/// mut data (including the cortex_m crate's "peripherals taken" flag, which
/// shows up as a `Peripherals::take().unwrap()` panic on the *next* attempt
/// to claim them). Examples with no static-mut data happen to leave that
/// flag at its initialized value even when overwritten with 0xAA (the flag
/// is checked as a non-zero bit), which is why this only surfaces under
/// examples that have large static buffers.
unsafe fn safe_stack_end<const SAFE: usize>() -> *mut u8 {
    let ebss = &raw const __ebss as *mut u8;
    unsafe { ebss.add(SAFE) }
}

pub fn paint_stack_inner<const SAFE: usize>() {
    unsafe {
        let safe_stack_end = safe_stack_end::<SAFE>();

        // Read the live SP and stop the paint a margin below it, so we never
        // overwrite the active stack frame (which can be large under LTO).
        let mut sp: usize;
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
        let live_limit = (sp as *mut u8).sub(SAFE);

        let paint_end = if (live_limit as usize) < (safe_stack_end as usize) {
            safe_stack_end
        } else {
            live_limit
        };

        let bytes_to_write = (paint_end as usize).saturating_sub(safe_stack_end as usize);
        if bytes_to_write > 0 {
            core::ptr::write_bytes(safe_stack_end, 0xAA, bytes_to_write);
        }
        PAINT_END.store(paint_end as usize, Ordering::Relaxed);
    }
}

pub fn check_stack_high_water_mark_inner<const SAFE: usize>() -> usize {
    unsafe {
        // `&raw const _stack_start` avoids constructing a `&u32` to the
        // address one-past-the-end of RAM (UB — refs must point to valid,
        // initialized, dereferenceable memory).
        let stack_start = &raw const _stack_start as *mut u8;
        let safe_stack_end = safe_stack_end::<SAFE>();
        // Bound the scan by what paint actually touched — reading past
        // `paint_end` would touch unpainted (uninitialized) stack bytes.
        let paint_end = PAINT_END.load(Ordering::Relaxed) as *mut u8;

        let mut current = safe_stack_end;
        while current < paint_end && *current == 0xAA {
            current = current.add(1);
        }

        // `stack_start` and `current` are derived from different linker
        // symbols (different abstract allocations), so `offset_from` would
        // be UB. Subtract as `usize` instead.
        (stack_start as usize) - (current as usize)
    }
}
