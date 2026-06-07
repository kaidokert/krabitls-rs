#![no_main]
#![no_std]

//! Cortex-M footprint example: ChaCha20-Poly1305-SHA256 + Ed25519. Replays
//! a captured TLS 1.3 handshake from a local openssl s_server.

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_chacha_ed25519(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_chacha_ed25519().is_ok(),
        "krabitls_chacha",
    );
    loop {
        cortex_m::asm::nop();
    }
}
