#![no_main]
#![no_std]

//! RISC-V footprint example: AES-128-GCM-SHA256 + X25519 KEX + ECDSA-P256
//! server cert. Drives the full TLS 1.3 facade (`DefaultStream::connect`)
//! against the seed-0 canned fixtures.

#[riscv_rt::entry]
fn main() -> ! {
    footprint_riscv::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_aes_ecdsa_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_aes_ecdsa_facade().is_ok(),
        "krabitls_ecdsa",
    );
}
