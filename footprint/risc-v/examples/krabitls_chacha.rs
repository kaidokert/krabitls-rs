#![no_main]
#![no_std]

//! RISC-V footprint example: ChaCha20-Poly1305-SHA256 + Ed25519. Drives
//! the full TLS 1.3 facade against the chacha seed-0 canned fixtures.
//! Build with `--no-default-features --features chacha20,cert-der,canned-replay`
//! so AES is genuinely absent from `.text`.

#[riscv_rt::entry]
fn main() -> ! {
    footprint_riscv::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_chacha_ed25519_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_chacha_ed25519_facade().is_ok(),
        "krabitls_chacha",
    );
}
