#![no_main]
#![no_std]

//! Cortex-M footprint example: ChaCha20-Poly1305 + X25519MLKEM768 hybrid KEX
//! + ML-DSA-44 server cert — the leanest full post-quantum TLS 1.3 handshake.
//! Drives `DefaultStream::connect` against the seed-0 canned fixtures.

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_chacha_mlkem_mldsa_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_chacha_mlkem_mldsa_facade().is_ok(),
        "krabitls_chacha_mlkem_mldsa",
    );
    loop {
        cortex_m::asm::nop();
    }
}
