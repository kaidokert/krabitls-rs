#![no_main]
#![no_std]

//! Cortex-M footprint example: facade driving a full TLS 1.3
//! handshake (`DefaultStream::connect`) against the seed-0 canned
//! fixtures.

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_aes_ed25519_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_aes_ed25519_facade().is_ok(),
        "krabitls_facade",
    );
    loop {
        cortex_m::asm::nop();
    }
}
