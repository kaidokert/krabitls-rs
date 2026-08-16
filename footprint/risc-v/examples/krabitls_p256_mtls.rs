#![no_main]
#![no_std]

//! RISC-V footprint example: AES-128-GCM-SHA256 + secp256r1 (P-256) ECDHE KEX +
//! ECDSA-P256 server cert AND ECDSA-P256 client certificate (a fully coherent
//! all-P-256 mutual TLS). Drives the full TLS 1.3 facade
//! (`DefaultStream::connect`) against the seed-0 canned fixtures, linking the
//! P-256 ephemeral-ECDH path together with the client-auth ECDSA-P256
//! CertificateVerify sign — the client-authenticated P-256 stack cost.

#[riscv_rt::entry]
fn main() -> ! {
    footprint_riscv::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_p256_mtls_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_p256_mtls_facade().is_ok(),
        "krabitls_p256_mtls",
    );
}
