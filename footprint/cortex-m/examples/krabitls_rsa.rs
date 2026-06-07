#![no_main]
#![no_std]

//! Cortex-M footprint example: AES-128-GCM-SHA256 + RSA-2048-PSS. Replays
//! a captured TLS 1.3 handshake from a local openssl s_server.

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_aes_rsa2048(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_aes_rsa2048().is_ok(),
        "krabitls_rsa",
    );
    loop {
        cortex_m::asm::nop();
    }
}
