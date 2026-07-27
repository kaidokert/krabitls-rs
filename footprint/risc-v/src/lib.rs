#![no_std]

//! RISC-V test harness for the krabitls footprint demos. Measurement and
//! reporting come from `krabi-caliper`; this crate retains semihosting,
//! termination, and panic policy. The handshake bodies and captured fixtures
//! live in the shared [`footprint_handshakes`] crate.

use krabi_caliper::report::{Field, TextReporter};
use krabi_caliper::risc_v::{FootprintConfig, run_footprint};
use riscv_semihosting::debug;

pub fn target_arch_name() -> &'static str {
    "riscv32imac"
}

pub fn test_fixture(testable: fn() -> bool, name: &str) -> ! {
    let fields = [Field::token("architecture", target_arch_name())];
    let result = unsafe {
        run_footprint::<256, _>(
            || {
                TextReporter::new(
                    riscv_semihosting::hio::hstdout().expect("failed to open semihosting stdout"),
                )
            },
            FootprintConfig::new(name, &fields),
            testable,
        )
    };
    match result {
        Ok(true) => debug::exit(debug::EXIT_SUCCESS),
        Ok(false) => {
            riscv_semihosting::hprintln!("MEASUREMENT FAILED");
            debug::exit(debug::EXIT_FAILURE);
        }
        Err(krabi_caliper::FootprintError::Stack(_)) => {
            riscv_semihosting::hprintln!("MEASUREMENT ERROR: invalid stack bounds");
            debug::exit(debug::EXIT_FAILURE);
        }
        Err(krabi_caliper::FootprintError::Reporter(_)) => {
            riscv_semihosting::hprintln!("MEASUREMENT ERROR: reporter failed");
            debug::exit(debug::EXIT_FAILURE);
        }
        Err(krabi_caliper::FootprintError::CounterUnavailable) => {
            riscv_semihosting::hprintln!("MEASUREMENT ERROR: counter unavailable");
            debug::exit(debug::EXIT_FAILURE);
        }
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
    riscv_semihosting::hprintln!("PANIC: {}", info);
    debug::exit(debug::EXIT_FAILURE);
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}
