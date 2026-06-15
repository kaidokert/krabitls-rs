#![no_main]
#![no_std]

//! RISC-V footprint example: facade driving a full TLS 1.3 handshake
//! (`DefaultStream::connect`) against the seed-0 canned fixtures.

#[riscv_rt::entry]
fn main() -> ! {
    footprint_riscv::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_aes_ed25519_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_aes_ed25519_facade().is_ok(),
        "krabitls_facade",
    );
}
