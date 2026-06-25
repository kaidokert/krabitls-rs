#![no_main]
#![no_std]

//! Same AES-128-GCM + Ed25519 facade as `krabitls`, but with a `Clocked`
//! strategy so the cert validity-window check is exercised. `.text` minus the
//! `krabitls` (NoClock) build = the opt-in cost of validity.

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_aes_ed25519_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_aes_ed25519_facade_clocked().is_ok(),
        "krabitls_validity",
    );
    loop {
        cortex_m::asm::nop();
    }
}
