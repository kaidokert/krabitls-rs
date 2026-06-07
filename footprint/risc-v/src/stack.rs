//! Stack high-water-mark instrumentation. Paint the unused region of the
//! stack with `0xAA`, then count how far the pattern was overwritten to
//! estimate peak live usage. riscv-rt's link.x exposes both ends of the
//! stack output section as linker symbols (`_estack` = bottom,
//! `_stack_start` = top), so we use those to bound the paint and avoid
//! clobbering `.data` / `.bss` (which on QEMU `virt` share the same DRAM
//! region as the stack).

unsafe extern "C" {
    static _stack_start: u32;
    static _estack: u32;
}

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
        let stack_top = &_stack_start as *const u32 as *mut u8;
        let stack_bottom = &_estack as *const u32 as *mut u8;
        let safe_stack_bottom = stack_bottom.add(SAFE);

        let mut sp: usize;
        core::arch::asm!("mv {}, sp", out(reg) sp, options(nomem, nostack));
        let live_limit = (sp as *mut u8).sub(SAFE);

        let paint_end = if (live_limit as usize) < (safe_stack_bottom as usize) {
            safe_stack_bottom
        } else if (live_limit as usize) > (stack_top as usize) {
            stack_top
        } else {
            live_limit
        };

        let bytes_to_write = (paint_end as usize).saturating_sub(safe_stack_bottom as usize);
        if bytes_to_write > 0 {
            core::ptr::write_bytes(safe_stack_bottom, 0xAA, bytes_to_write);
        }
    }
}

pub fn check_stack_high_water_mark_inner<const SAFE: usize>() -> usize {
    unsafe {
        let stack_top = &_stack_start as *const u32 as *mut u8;
        let stack_bottom = &_estack as *const u32 as *mut u8;
        let safe_stack_bottom = stack_bottom.add(SAFE);

        let mut current = safe_stack_bottom;
        while current < stack_top && *current == 0xAA {
            current = current.offset(1);
        }

        stack_top.offset_from(current) as usize
    }
}
