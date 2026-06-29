#![no_main]
#![no_std]

//! Cortex-M footprint example: AES-128-GCM-SHA256 + X25519MLKEM768 hybrid KEX
//! + ML-DSA-44 server cert. Drives the full TLS 1.3 facade
//! (`DefaultStream::connect`) against the seed-0 canned fixtures.

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_mlkem_mldsa_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_mlkem_mldsa_facade().is_ok(),
        "krabitls_mlkem_mldsa",
    );
    loop {
        cortex_m::asm::nop();
    }
}
