#![no_main]
#![no_std]

//! Cortex-M footprint example: same facade handshake as `krabitls` but
//! with the HKDF/SHA-256 backend swapped to jedisct1's `hmac-sha256`
//! crate. Drives `JedisctStream::connect` against the AES + Ed25519
//! seed-0 fixtures (wire bytes are HKDF-impl-independent).

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_aes_ed25519_jedisct_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_aes_ed25519_jedisct_facade().is_ok(),
        "krabitls_jedisct",
    );
    loop {
        cortex_m::asm::nop();
    }
}
