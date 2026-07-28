#![no_std]

//! Cortex-M test harness for the krabitls footprint demos. Measurement and
//! reporting come from `krabi-caliper`; this crate retains target termination
//! and panic policy. The handshake bodies and captured fixtures live in the
//! shared [`footprint_handshakes`] crate so the RISC-V target builds the same
//! code.

use cortex_m_semihosting::debug;
use krabi_caliper::cortex_m::{FootprintConfig, run_footprint};
use krabi_caliper::report::Field;

krabi_caliper::cortex_m_systick_overflow_handler!();

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
    let fields = [Field::token("architecture", target_arch_name())];
    let result = unsafe {
        run_footprint::<256, _>(
            || {
                krabi_caliper::protocol::semihosting::init()
                    .expect("failed to open semihosting stdout")
            },
            FootprintConfig::new(name, &fields),
            testable,
        )
    };
    match result {
        Ok(true) => debug::exit(debug::EXIT_SUCCESS),
        Ok(false) => {
            cortex_m_semihosting::hprintln!("MEASUREMENT FAILED");
            debug::exit(debug::EXIT_FAILURE);
        }
        Err(krabi_caliper::FootprintError::CounterUnavailable) => {
            cortex_m_semihosting::hprintln!("MEASUREMENT ERROR: counter unavailable");
            debug::exit(debug::EXIT_FAILURE);
        }
        Err(krabi_caliper::FootprintError::Stack(_)) => {
            cortex_m_semihosting::hprintln!("MEASUREMENT ERROR: invalid stack bounds");
            debug::exit(debug::EXIT_FAILURE);
        }
        Err(krabi_caliper::FootprintError::Reporter(_)) => {
            cortex_m_semihosting::hprintln!("MEASUREMENT ERROR: reporter failed");
            debug::exit(debug::EXIT_FAILURE);
        }
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
