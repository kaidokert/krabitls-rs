#![no_std]

//! RISC-V test harness for the krabitls footprint demos. Owns only the
//! target-specific bits — cycle counter (`mcycle`), stack painter, panic
//! handler, semihosted ACCEPT/REJECT reporter. The handshake bodies and
//! captured fixtures live in the shared [`footprint_handshakes`] crate.

use riscv_semihosting::{debug, hprintln};

pub mod cyclecount;
pub mod stack;

use cyclecount::CycleCounter;
use stack::{check_stack_high_water_mark, paint_stack};

pub fn target_arch_name() -> &'static str {
    "riscv32imac"
}

pub fn test_fixture(testable: fn() -> bool, name: &str) -> ! {
    // paint_stack MUST be the first call — anything (even hprintln) inlined ahead
    // of it inflates test_fixture's frame past the 256-byte safe zone and paint
    // ends up clobbering live stack.
    paint_stack();
    let counter = CycleCounter::new();
    let result = testable();
    let elapsed_kcycles = counter.elapsed() / 1000;
    let stack = check_stack_high_water_mark();
    if result {
        hprintln!("{} ACCEPT", name);
    } else {
        hprintln!("{} REJECT", name);
    }
    hprintln!(
        "METRIC stack:{} kcycles:{} target:{} name:{}",
        stack,
        elapsed_kcycles,
        target_arch_name(),
        name,
    );
    if result {
        debug::exit(debug::EXIT_SUCCESS);
    } else {
        debug::exit(debug::EXIT_FAILURE);
    }
    // EXIT semihosting calls return on some QEMU builds; loop just in case.
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    hprintln!("PANIC: {}", info);
    debug::exit(debug::EXIT_FAILURE);
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}
