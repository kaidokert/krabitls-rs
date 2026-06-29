#![no_main]
#![no_std]

//! RISC-V footprint example: AES-128-GCM-SHA256 + X25519MLKEM768 hybrid KEX
//! + ML-DSA-44 server cert. Drives the full TLS 1.3 facade
//! (`DefaultStream::connect`) against the seed-0 canned fixtures.

#[riscv_rt::entry]
fn main() -> ! {
    footprint_riscv::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_mlkem_mldsa_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_mlkem_mldsa_facade().is_ok(),
        "krabitls_mlkem_mldsa",
    );
}
