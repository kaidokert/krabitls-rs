#![no_main]
#![no_std]

//! RISC-V footprint example: AES-128-GCM-SHA256 + X25519MLKEM768 hybrid KEX
//! + Ed25519. Drives the full TLS 1.3 facade (`DefaultStream::connect`)
//! against the seed-0 canned fixtures.

#[riscv_rt::entry]
fn main() -> ! {
    footprint_riscv::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_mlkem_ed25519_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_mlkem_ed25519_facade().is_ok(),
        "krabitls_mlkem",
    );
}
