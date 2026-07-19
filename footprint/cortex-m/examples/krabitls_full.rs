#![no_main]
#![no_std]

//! Cortex-M footprint probe: fully-featured verify surface in one binary —
//! Ed25519 + RSA (U1024 & U2048) + ECDSA (P-256 & P-384) + ML-DSA verify all
//! linked via the runtime cert-verify dispatch. Measures `.text` of the whole
//! monomorphization set (per-role CAP vs unified CAP=64). Build-only.

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || true,
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_full_stack(),
        "krabitls_full",
    );
    loop {
        cortex_m::asm::nop();
    }
}
