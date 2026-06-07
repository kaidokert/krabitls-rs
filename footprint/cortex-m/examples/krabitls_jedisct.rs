#![no_main]
#![no_std]

//! Cortex-M footprint example: same handshake as `krabitls` but with the
//! HKDF/SHA-256 backend swapped to jedisct1's `hmac-sha256` crate.

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_aes_ed25519_jedisct(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_aes_ed25519_jedisct().is_ok(),
        "krabitls_jedisct",
    );
    loop {
        cortex_m::asm::nop();
    }
}
