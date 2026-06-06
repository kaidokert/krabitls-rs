#![no_std]

//! Cortex-M test harness for krabitls examples. Each example file
//! (`examples/krabitls*.rs`) is self-contained — owns its own captured
//! fixture, walker, and baseline stub — and shares only the cycle
//! counter + stack painter + semihosted ACCEPT/REJECT reporter exported
//! from this crate.

use core::cell::RefCell;
use cortex_m_semihosting::{debug, hprintln};
use critical_section::Mutex;

pub mod cyclecount;
pub mod stack;

/// Re-export `hex_decode` from krabitls so example files can decode their
/// captured `*.hex` fixtures without picking a fresh import path.
pub use krabitls::hex_decode;

/// Per-record decrypt scratch. Sized to fit the largest TLS record body
/// the M3 examples replay (RSA-2048 captured server flight runs ~6.3 KiB).
pub const RECORD_BUF_CAP: usize = 8 * 1024;

/// Flight-accumulator scratch.
pub const FLIGHT_BUF_CAP: usize = 8 * 1024;

/// Scratch buffers live in `.bss`, not on the stack, so the footprint-suite
/// stack delta isolates the crypto + protocol cost without a fictional
/// "buffer discount." Accessed through [`with_buffers`].
static RECORD_BUF: Mutex<RefCell<Option<[u8; RECORD_BUF_CAP]>>> =
    Mutex::new(RefCell::new(Some([0u8; RECORD_BUF_CAP])));
static FLIGHT_BUF: Mutex<RefCell<Option<[u8; FLIGHT_BUF_CAP]>>> =
    Mutex::new(RefCell::new(Some([0u8; FLIGHT_BUF_CAP])));

/// Lend out the static scratch buffers under a critical section. The TLS
/// handshake runs entirely inside the closure; the buffers never land on
/// the stack.
pub fn with_buffers<R>(
    f: impl FnOnce(&mut [u8; RECORD_BUF_CAP], &mut [u8; FLIGHT_BUF_CAP]) -> R,
) -> R {
    critical_section::with(|cs| {
        let mut record = RECORD_BUF.borrow(cs).borrow_mut();
        let mut flight = FLIGHT_BUF.borrow(cs).borrow_mut();
        let record_ref = record.as_mut().expect("RECORD_BUF taken");
        let flight_ref = flight.as_mut().expect("FLIGHT_BUF taken");
        f(record_ref, flight_ref)
    })
}

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
            "cortex_m_demo only targets thumbv6m-none-eabi / thumbv7m-none-eabi / thumbv7em-none-eabi; see .cargo/config.toml"
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

use panic_semihosting as _;
