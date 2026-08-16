#![no_main]
#![no_std]

//! RISC-V footprint example: AES-128-GCM-SHA256 + secp256r1 (P-256) ECDHE KEX +
//! ECDSA-P256 server cert (a fully coherent all-P-256 handshake). Drives the
//! full TLS 1.3 facade (`DefaultStream::connect`) against the seed-0 canned
//! fixtures, linking the classical P-256 ephemeral key-generation and ECDH
//! shared-secret path together with the ECDSA-P256 certificate verify.

#[riscv_rt::entry]
fn main() -> ! {
    footprint_riscv::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_p256_ecdsa_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_p256_ecdsa_facade().is_ok(),
        "krabitls_p256",
    );
}
