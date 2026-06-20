#![no_main]
#![no_std]

//! RISC-V footprint example: AES-128-GCM-SHA256 + Ed25519 with the
//! HKDF/SHA-256 backend swapped to jedisct1's `hmac-sha256`. Drives
//! the full facade.

#[riscv_rt::entry]
fn main() -> ! {
    footprint_riscv::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_aes_ed25519_jedisct_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_aes_ed25519_jedisct_facade().is_ok(),
        "krabitls_jedisct",
    );
}
