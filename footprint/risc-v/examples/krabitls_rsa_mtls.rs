#![no_main]
#![no_std]

//! RISC-V footprint example: AES-128-GCM-SHA256 + X25519 KEX + Ed25519 server
//! cert + RSA-2048-PSS client certificate (mutual TLS). Drives the full TLS 1.3
//! facade (`DefaultStream::connect`) against the seed-0 canned fixtures,
//! answering the server's CertificateRequest with an RSA-PSS CertificateVerify
//! — the RSA client-auth signing stack cost.

#[riscv_rt::entry]
fn main() -> ! {
    footprint_riscv::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_rsa_mtls_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_rsa_mtls_facade().is_ok(),
        "krabitls_rsa_mtls",
    );
}
