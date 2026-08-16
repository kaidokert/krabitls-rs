#![no_main]
#![no_std]

//! Cortex-M footprint example: AES-128-GCM-SHA256 + X25519 KEX + RSA-2048 server
//! cert AND RSA-2048-PSS client certificate (mutual TLS). Both server-auth (RSA
//! verify) and client-auth (RSA sign) run RSA-2048, so this isolates the cost of
//! an all-RSA mutual handshake. Drives the full TLS 1.3 facade
//! (`DefaultStream::connect`) against the seed-0 canned fixtures, answering the
//! server's CertificateRequest with an RSA-PSS CertificateVerify.

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_rsa_mtls_srv_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_rsa_mtls_srv_facade().is_ok(),
        "krabitls_rsa_mtls_srv",
    );
    loop {
        cortex_m::asm::nop();
    }
}
