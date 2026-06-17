#![no_std]

//! Cortex-M test harness for the krabitls footprint demos. Owns only the
//! target-specific bits — cycle counter, stack painter, panic + semihosted
//! ACCEPT/REJECT reporter. The handshake bodies and captured fixtures live
//! in the shared [`footprint_handshakes`] crate so the risc-v target builds
//! the same code.

use cortex_m_semihosting::{debug, hprintln};

pub mod cyclecount;
pub mod stack;

use cyclecount::CycleCounter;
use stack::{check_stack_high_water_mark, paint_stack};

pub fn target_arch_name() -> &'static str {
    #[cfg(thumbv6m)]
    {
        "thumbv6m"
    }
    #[cfg(thumbv7m)]
    {
        "thumbv7m"
    }
    #[cfg(thumbv7em)]
    {
        "thumbv7em"
    }
    #[cfg(not(any(thumbv6m, thumbv7m, thumbv7em)))]
    {
        compile_error!(
            "footprint_cortex_m only targets thumbv6m-none-eabi / thumbv7m-none-eabi / thumbv7em-none-eabi; see .cargo/config.toml"
        )
    }
}

pub fn test_fixture(testable: fn() -> bool, name: &str) {
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
}

/// Custom panic handler: drops the `core::fmt` chain `panic-semihosting`
/// would otherwise pull in (~3 KiB) and exits QEMU with EXIT_FAILURE so CI
/// surfaces panics rather than hanging. Panic-info text is silent.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    debug::exit(debug::EXIT_FAILURE);
    loop {
        cortex_m::asm::nop();
    }
}
