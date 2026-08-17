#![no_main]
#![no_std]

//! Cortex-M footprint example: AES-128-GCM-SHA256 + X25519 KEX + a deep ECDSA-P256
//! intermediate chain validated by the `PinnedRoots` strategy
//! (server sends leaf + 8 intermediates, root omitted; client anchors on a
//! stored root cert). Replays the seed-0 canned fixtures.

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_aes_ecdsa_chain(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_aes_ecdsa_chain_facade().is_ok(),
        "krabitls_chain",
    );
    loop {
        cortex_m::asm::nop();
    }
}
