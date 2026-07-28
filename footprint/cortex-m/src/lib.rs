#![no_std]

//! Cortex-M test harness for the krabitls footprint demos. Measurement and
//! reporting come from `krabi-caliper`; this crate retains target termination
//! and panic policy. The handshake bodies and captured fixtures live in the
//! shared [`footprint_handshakes`] crate so the RISC-V target builds the same
//! code.

#[cfg(not(feature = "jtrace-f407"))]
use cortex_m_semihosting::debug;
use krabi_caliper::cortex_m::{FootprintConfig, run_footprint};
#[cfg(feature = "jtrace-f407")]
use krabi_caliper::protocol::rtt;
use krabi_caliper::report::Field;
#[cfg(feature = "jtrace-f407")]
use stm32f4xx_hal::{pac, prelude::*};

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
    #[cfg(feature = "jtrace-f407")]
    let frequency_hz = {
        let device = pac::Peripherals::take().expect("device peripherals already taken");
        let clocks = device.RCC.constrain().cfgr.sysclk(30.MHz()).freeze();
        clocks.hclk().raw() as u64
    };
    let fields = [Field::token("architecture", target_arch_name())];
    let config = FootprintConfig::new(name, &fields).enable_dwt(cfg!(feature = "jtrace-f407"));
    #[cfg(feature = "jtrace-f407")]
    let config = config.frequency_hz(frequency_hz);
    let result = unsafe {
        run_footprint::<256, _>(
            || krabi_caliper::cortex_m_reporter!("jtrace-f407"),
            config,
            testable,
        )
    };
    match result {
        Ok(true) => measurement_success(),
        Ok(false) => measurement_failure("workload returned false"),
        Err(krabi_caliper::FootprintError::CounterUnavailable) => {
            measurement_failure("counter unavailable");
        }
        Err(krabi_caliper::FootprintError::Stack(_)) => {
            measurement_failure("invalid stack bounds");
        }
        Err(krabi_caliper::FootprintError::Reporter(_)) => {
            measurement_failure("reporter failed");
        }
    }
}

fn measurement_success() {
    #[cfg(not(feature = "jtrace-f407"))]
    debug::exit(debug::EXIT_SUCCESS);
}

fn measurement_failure(message: &str) -> ! {
    #[cfg(feature = "jtrace-f407")]
    rtt::print(format_args!("MEASUREMENT ERROR: {message}\n"));
    #[cfg(not(feature = "jtrace-f407"))]
    {
        cortex_m_semihosting::hprintln!("MEASUREMENT ERROR: {}", message);
        debug::exit(debug::EXIT_FAILURE);
    }
    krabi_caliper::cortex_m::park()
}

/// Custom panic handler: drops the `core::fmt` chain `panic-semihosting`
/// would otherwise pull in (~3 KiB) and exits QEMU with EXIT_FAILURE so CI
/// surfaces panics rather than hanging. Panic-info text is silent.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    #[cfg(feature = "jtrace-f407")]
    rtt::print(format_args!("PANIC: {_info}\n"));
    #[cfg(not(feature = "jtrace-f407"))]
    debug::exit(debug::EXIT_FAILURE);
    loop {
        cortex_m::asm::nop();
    }
}
