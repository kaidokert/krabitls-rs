#![no_main]
#![no_std]

//! RISC-V footprint example: ChaCha20-Poly1305-SHA256 + Ed25519.

#[riscv_rt::entry]
fn main() -> ! {
    footprint_riscv::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_chacha_ed25519(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_chacha_ed25519().is_ok(),
        "krabitls_chacha",
    );
}
