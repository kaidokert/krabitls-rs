#![no_main]
#![no_std]

//! Cortex-M footprint example: AES-128-GCM-SHA256 + secp256r1 (P-256) ECDHE KEX
//! + Ed25519 server cert. Drives the full TLS 1.3 facade
//! (`DefaultStream::connect`) against the seed-0 canned fixtures, linking the
//! classical P-256 ephemeral key-generation and ECDH shared-secret path.

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_p256_ed25519_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_p256_ed25519_facade().is_ok(),
        "krabitls_p256",
    );
    loop {
        cortex_m::asm::nop();
    }
}
