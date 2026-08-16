#![no_main]
#![no_std]

//! RISC-V footprint example: ChaCha20-Poly1305-SHA256 + X25519 KEX + Ed25519
//! server cert AND Ed25519 client certificate (mutual TLS). Drives the full TLS
//! 1.3 facade against the seed-0 canned fixtures, answering the server's
//! CertificateRequest with an Ed25519 CertificateVerify — the client-auth
//! signing stack cost on the ChaCha cipher. Build with `--no-default-features
//! --features chacha20,client-auth,canned-replay` so AES is absent from `.text`.

#[riscv_rt::entry]
fn main() -> ! {
    footprint_riscv::test_fixture(
        #[cfg(feature = "baseline")]
        || footprint_handshakes::baseline_chacha_mtls_facade(),
        #[cfg(not(feature = "baseline"))]
        || footprint_handshakes::run_chacha_mtls_facade().is_ok(),
        "krabitls_chacha_mtls",
    );
}
