#![no_main]
#![no_std]

//! RISC-V footprint example: AES-128-GCM-SHA256 + RSA-2048-PSS. Drives
//! the full TLS 1.3 facade against the seed-0 canned RSA fixtures.

#[riscv_rt::entry]
fn main() -> ! {
    footprint_riscv::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_aes_rsa2048_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_aes_rsa2048_facade().is_ok(),
        "krabitls_rsa",
    );
}
