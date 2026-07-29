#![no_main]
#![no_std]

//! Wall-clock timing of the TLS 1.3 handshake on the STM32F407 at 168 MHz,
//! reported in seconds via krabi-caliper's `PairedSuite` (`EM_SUMMARY`).
//!
//! Two fixtures: server-certificate-only vs mutual-TLS (client certificate).
//! A handshake has no constant-time A/B secret pair, so each is fed as both
//! sides of the paired suite with the spread gate opened wide — the suite is
//! used purely to harvest per-fixture timing, not to render a CT verdict. The
//! server-vs-mTLS delta is the cost of client-certificate auth.

use cortex_m_rt::entry;
use krabi_caliper::Unit;
use krabi_caliper::cortex_m::DwtMeasurementPlatform;
use krabi_caliper::protocol::rtt::{init_ct_compatible, print};
use krabi_caliper::report::Field;
use krabi_caliper::suite::{PairedSuite, PairedSuiteConfig, PairedSuiteFields};
use stm32f4xx_hal::pac;
use stm32f4xx_hal::prelude::*;

// Must be even — the paired runner splits it into A/B pairs (odd → OddSampleCapacity).
const TRIALS: usize = 4;
const HCLK_HZ: u64 = 168_000_000;
// Timing harness, not a CT verdict: open the spread gate so ordinary
// trial-to-trial jitter (µs on a multi-hundred-ms op) never fails the fixture.
const SPREAD_UNLIMITED: u64 = u64::MAX;

fn server_cert_handshake(_: &()) -> bool {
    footprint_handshakes::run_aes_ed25519_facade_on_stack().is_ok()
}

fn mtls_handshake(_: &()) -> bool {
    footprint_handshakes::run_aes_ed25519_mtls_facade_on_stack().is_ok()
}

fn stop() -> ! {
    loop {
        cortex_m::asm::nop();
    }
}

#[entry]
fn main() -> ! {
    let mut reporter = init_ct_compatible();
    let mut core = cortex_m::Peripherals::take().unwrap();
    let dp = pac::Peripherals::take().unwrap();

    // F407 rated max; HSI-sourced PLL (HAL sets flash wait states). `sysclk ==
    // hclk`; reported time is ±1% on HSI, but the server-vs-mTLS delta is
    // clock-exact.
    let _clocks = dp.RCC.constrain().cfgr.sysclk(168.MHz()).freeze();

    let mut platform =
        DwtMeasurementPlatform::enable(&mut core.DCB, &mut core.DWT, Some(HCLK_HZ)).unwrap();

    let run_fields = [
        Field::token("clock_profile", "hsi-pll-168mhz"),
        Field::u64("hclk_hz", HCLK_HZ),
        Field::u64("trials", TRIALS as u64),
    ];
    let mut suite = PairedSuite::<_, _, TRIALS>::start(
        &mut platform,
        &mut reporter,
        PairedSuiteConfig {
            suite: "krabitls-handshake",
            target: "cortex-m4f",
            board: Some("j-trace-stm32f407vg"),
            unit: Unit::CoreCycles,
            frequency_hz: Some(HCLK_HZ),
            warmup_blocks: 1,
            batches: 1,
            positive_max_spread: SPREAD_UNLIMITED,
            positive_require_overlap: false,
            fields: PairedSuiteFields {
                run: &run_fields,
                fixture: &[],
                summary: &[],
            },
        },
    )
    .unwrap();

    suite
        .positive("aes-ed25519-server-cert", &(), &(), server_cert_handshake)
        .unwrap();
    suite
        .positive("aes-ed25519-mtls", &(), &(), mtls_handshake)
        .unwrap();

    suite.finish().unwrap();
    stop();
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(format_args!("PANIC: {}\n", info));
    stop();
}
