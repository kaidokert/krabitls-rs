#![no_main]
#![no_std]

//! Cortex-M footprint example: AES-128-GCM-SHA256 + X25519 KEX + Ed25519 server
//! cert AND Ed25519 client certificate (mutual TLS). Drives the full TLS 1.3
//! facade (`DefaultStream::connect`) against the seed-0 canned fixtures,
//! answering the server's CertificateRequest with an Ed25519 CertificateVerify
//! — the client-auth signing stack cost.

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_ed25519_mtls_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_ed25519_mtls_facade().is_ok(),
        "krabitls_ed25519_mtls",
    );
    loop {
        cortex_m::asm::nop();
    }
}
