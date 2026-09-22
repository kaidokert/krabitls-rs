#![no_main]
#![no_std]

//! Cortex-M footprint example: AES-128-GCM-SHA256 + Ed25519 with **mutual
//! TLS** (client certificate). Drives the full facade
//! (`DefaultStream::connect` with a client-auth signer) against the seed-0
//! mTLS canned fixtures. Versus `krabitls` (server-cert-only), this adds the
//! client's Certificate + CertificateVerify (an Ed25519 sign).

use cortex_m_rt::entry;

#[cfg(feature = "jtrace-f407")]
fn run_handshake() -> bool {
    footprint_handshakes::run_aes_ed25519_mtls_facade_on_stack().is_ok()
}

#[cfg(not(feature = "jtrace-f407"))]
fn run_handshake() -> bool {
    footprint_handshakes::run_aes_ed25519_mtls_facade().is_ok()
}

#[entry]
fn main() -> ! {
    footprint_cortex_m::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_aes_ed25519_mtls_facade(),
        #[cfg(not(feature = "baseline"))]
        run_handshake,
        "krabitls-mtls",
    );
    loop {
        cortex_m::asm::nop();
    }
}
