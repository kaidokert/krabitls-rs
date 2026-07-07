use super::*;
#[cfg(feature = "chacha20")]
use crate::aead::ChaCha20Poly1305Sha256;
use crate::aead::DecryptError;
use crate::aead::tests::NoCipher;
use crate::aead::tests::{decrypt_record, encrypt_record};
#[cfg(feature = "jedisct")]
use crate::backends::JedisctCrypto;
use crate::backends::RustCrypto;
use crate::hkdf::{HkdfLabelError, TranscriptError, TranscriptHash, traffic_keys};
use crate::newtype::tests::AeadKey;
#[cfg(feature = "chacha20")]
use crate::newtype::tests::AeadKey32;
use crate::newtype::{AeadIv, Secret, TranscriptDigest, ZeroBuf};
use crate::server_flight::tests::extract_cert_der;
use crate::server_flight::{FlightError, extract_chain};
use crate::traits::{CertView, HkdfSha256};
use embedded_io::SliceWriteError;

impl ClientHelloOptions<'_> {
    /// Legacy default: no `record_size_limit`, no SNI, default suite list.
    pub(crate) const fn legacy() -> Self {
        Self {
            hostname: None,
            record_size_limit: None,
            suites: SuiteList::Default,
            #[cfg(feature = "mlkem")]
            mlkem_ek: None,
        }
    }
}

// Captured from tls_fixture/packets/001_c2s_ClientHello.bin (seed 0).
const FIXTURE_RANDOM: [u8; 32] = [
    0xed, 0xe5, 0x7b, 0xa2, 0x43, 0x3a, 0xd5, 0xa3, 0x4d, 0x05, 0x50, 0x3a, 0xfe, 0x4f, 0xc2, 0x89,
    0xdf, 0xd9, 0xe9, 0x53, 0x57, 0xd8, 0x16, 0x36, 0x80, 0x24, 0xe7, 0x3f, 0xbf, 0xa6, 0xfa, 0xf5,
];
const FIXTURE_X25519_PUB: [u8; 32] = [
    0x82, 0x46, 0xe7, 0x35, 0x8f, 0x0a, 0xf7, 0xf3, 0x31, 0x7d, 0xca, 0xf6, 0x88, 0xd0, 0x34, 0xc9,
    0x5d, 0x5a, 0x2b, 0x54, 0xbf, 0x66, 0xc8, 0x95, 0x0e, 0xb8, 0x7a, 0x5f, 0x47, 0x93, 0x96, 0x0d,
];
/// Seed-0 ed25519-mode ClientHello from the Python fixture
/// (`packets/001_c2s_ClientHello.bin`), **149 bytes**.
///
/// Advertises **both** the RFC 6066 SNI extension
/// (server_name "tls-fixture.local") and the RFC 8449
/// `record_size_limit` extension (value 16385). Extension order
/// matches the Rust facade's wire emission: supported_versions →
/// supported_groups → signature_algorithms → server_name →
/// record_size_limit → key_share. The Python `tls_fixture` emits
/// this shape by default; the typestate API's
/// `ClientHelloOptions::legacy()` does **not**, so byte-identity
/// testing requires explicit `hostname: Some(...)` +
/// `record_size_limit: Some(16385)` opts.
const FIXTURE_CLIENT_HELLO: [u8; 149] = [
    0x16, 0x03, 0x03, 0x00, 0x90, 0x01, 0x00, 0x00, 0x8c, 0x03, 0x03, 0xed, 0xe5, 0x7b, 0xa2, 0x43,
    0x3a, 0xd5, 0xa3, 0x4d, 0x05, 0x50, 0x3a, 0xfe, 0x4f, 0xc2, 0x89, 0xdf, 0xd9, 0xe9, 0x53, 0x57,
    0xd8, 0x16, 0x36, 0x80, 0x24, 0xe7, 0x3f, 0xbf, 0xa6, 0xfa, 0xf5, 0x00, 0x00, 0x02, 0x13, 0x01,
    0x01, 0x00, 0x00, 0x61, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0a, 0x00, 0x04, 0x00,
    0x02, 0x00, 0x1d, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07, 0x00, 0x00, 0x00, 0x16, 0x00,
    0x14, 0x00, 0x00, 0x11, 0x74, 0x6c, 0x73, 0x2d, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0x2e,
    0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00,
    0x24, 0x00, 0x1d, 0x00, 0x20, 0x82, 0x46, 0xe7, 0x35, 0x8f, 0x0a, 0xf7, 0xf3, 0x31, 0x7d, 0xca,
    0xf6, 0x88, 0xd0, 0x34, 0xc9, 0x5d, 0x5a, 0x2b, 0x54, 0xbf, 0x66, 0xc8, 0x95, 0x0e, 0xb8, 0x7a,
    0x5f, 0x47, 0x93, 0x96, 0x0d,
];

/// Helper: write into a fresh buffer through `&mut &mut [u8]`. Returns the
/// borrowed slice as it stands after writing so we can confirm how many
/// bytes were consumed.
#[cfg(not(feature = "mlkem"))]
fn write_into(buf: &mut [u8]) -> Result<&mut [u8], ClientHelloError<SliceWriteError>> {
    let mut cursor: &mut [u8] = buf;
    write_client_hello_with(
        &mut cursor,
        &FIXTURE_RANDOM,
        &FIXTURE_X25519_PUB,
        &ClientHelloOptions::legacy(),
    )?;
    Ok(cursor)
}

// Byte-identity against the seed-0 Python fixture only holds when our CH
// advertises ed25519 alone with AES-128-GCM only. With `feature = "rsa"`
// we also advertise rsa_pss_rsae_sha256; with `feature = "chacha20"` we
// also advertise CHACHA20_POLY1305_SHA256 — either changes the CH bytes.
#[cfg(all(
    not(feature = "rsa"),
    not(feature = "chacha20"),
    not(feature = "mldsa"),
    not(feature = "mlkem")
))]
#[test]
fn matches_python_fixture() {
    // Python tls_fixture defaults to record_size_limit=16385
    // so the byte-identity test must pass the matching opts. The
    // `legacy()` path (no RSL) is covered by
    // `exact_sized_buffer_works_legacy` for length + writer plumbing
    // without byte-identity.
    let mut buf = [0u8; 256];
    let mut cursor: &mut [u8] = &mut buf;
    let opts = ClientHelloOptions {
        hostname: Some(b"tls-fixture.local"),
        record_size_limit: Some(16385),
        ..ClientHelloOptions::legacy()
    };
    let n =
        write_client_hello_with(&mut cursor, &FIXTURE_RANDOM, &FIXTURE_X25519_PUB, &opts).unwrap();
    assert_eq!(n, FIXTURE_CLIENT_HELLO.len());
    assert_eq!(&buf[..n], &FIXTURE_CLIENT_HELLO);
}

#[cfg(all(
    not(feature = "rsa"),
    not(feature = "chacha20"),
    not(feature = "mldsa"),
    not(feature = "mlkem")
))]
#[test]
fn exact_sized_buffer_works_legacy() {
    let mut buf = [0u8; CLIENT_HELLO_LEN];
    let leftover = write_into(&mut buf).unwrap();
    assert!(
        leftover.is_empty(),
        "should fully consume a tightly-sized buffer"
    );
    // Length-only check on the legacy (no-RSL) writer path. Byte-identity
    // against the Python fixture lives in `matches_python_fixture`.
    assert_eq!(buf.len(), CLIENT_HELLO_LEN);
}

#[cfg(not(feature = "mlkem"))]
#[test]
fn rejects_small_buffer() {
    let mut buf = [0u8; CLIENT_HELLO_LEN - 1];
    let err = write_into(&mut buf).unwrap_err();
    assert_eq!(err, ClientHelloError::Write(SliceWriteError::Full));
}

#[test]
fn rejects_oversize_hostname() {
    // hostname.len() > u16::MAX → HostnameTooLong.
    let huge = vec![b'a'; (u16::MAX as usize) + 1];
    let mut buf = [0u8; 256];
    let mut cursor: &mut [u8] = &mut buf;
    let err = write_client_hello_with(
        &mut cursor,
        &FIXTURE_RANDOM,
        &FIXTURE_X25519_PUB,
        &ClientHelloOptions {
            hostname: Some(&huge),
            ..ClientHelloOptions::legacy()
        },
    )
    .unwrap_err();
    assert_eq!(err, ClientHelloError::HostnameTooLong);
}

#[test]
fn rejects_oversize_record() {
    // hostname fits in u16 but pushes total record past 2^14 → MessageTooLong.
    let big = vec![b'a'; 16500];
    let mut buf = [0u8; 128];
    let mut cursor: &mut [u8] = &mut buf;
    let err = write_client_hello_with(
        &mut cursor,
        &FIXTURE_RANDOM,
        &FIXTURE_X25519_PUB,
        &ClientHelloOptions {
            hostname: Some(&big),
            ..ClientHelloOptions::legacy()
        },
    )
    .unwrap_err();
    assert_eq!(err, ClientHelloError::MessageTooLong);
}

// body_len is computed in usize before the cap check so a near-u16::MAX
// hostname surfaces as MessageTooLong instead of wrapping a u16 and
// either panicking in debug or emitting wrapped length fields in release.
#[test]
fn rejects_hostname_near_u16_max_without_wrap() {
    let host = vec![b'a'; 65500];
    let mut buf = [0u8; 256];
    let mut cursor: &mut [u8] = &mut buf;
    let err = write_client_hello_with(
        &mut cursor,
        &FIXTURE_RANDOM,
        &FIXTURE_X25519_PUB,
        &ClientHelloOptions {
            hostname: Some(&host),
            ..ClientHelloOptions::legacy()
        },
    )
    .unwrap_err();
    assert_eq!(err, ClientHelloError::MessageTooLong);
}

#[cfg(not(feature = "mlkem"))]
#[test]
fn rejects_record_size_limit_out_of_rfc8449_range() {
    // RFC 8449 §4: valid range is [64, 2^14 + 1] = [64, 16385].
    let mut buf = [0u8; 512];
    for rsl in [0u16, 1, 63, 16386, u16::MAX] {
        let mut cursor: &mut [u8] = &mut buf;
        let err = write_client_hello_with(
            &mut cursor,
            &FIXTURE_RANDOM,
            &FIXTURE_X25519_PUB,
            &ClientHelloOptions {
                record_size_limit: Some(rsl),
                ..ClientHelloOptions::legacy()
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            ClientHelloError::RecordSizeLimitOutOfRange,
            "rsl={rsl} must reject"
        );
    }
    for rsl in [64u16, 16385] {
        let mut cursor: &mut [u8] = &mut buf;
        write_client_hello_with(
            &mut cursor,
            &FIXTURE_RANDOM,
            &FIXTURE_X25519_PUB,
            &ClientHelloOptions {
                record_size_limit: Some(rsl),
                ..ClientHelloOptions::legacy()
            },
        )
        .unwrap_or_else(|_| panic!("rsl={rsl} must accept"));
    }
}

#[test]
fn client_hello_len_with_agrees_with_legacy_for_default_opts() {
    for host_len in [None, Some(0), Some(1), Some(64), Some(255), Some(8192)] {
        let legacy = client_hello_len(host_len);
        let host_bytes;
        let hostname: Option<&[u8]> = match host_len {
            None => None,
            Some(n) => {
                host_bytes = vec![b'x'; n];
                Some(host_bytes.leak())
            }
        };
        let opts = ClientHelloOptions {
            hostname,
            record_size_limit: None,
            suites: SuiteList::Default,
            #[cfg(feature = "mlkem")]
            mlkem_ek: None,
        };
        assert_eq!(
            client_hello_len_with(&opts),
            legacy,
            "host_len={host_len:?}"
        );
    }
}

#[test]
fn client_hello_len_with_accounts_for_record_size_limit() {
    let base = client_hello_len_with(&ClientHelloOptions::legacy());
    let with_rsl = client_hello_len_with(&ClientHelloOptions {
        record_size_limit: Some(16385),
        ..ClientHelloOptions::legacy()
    });
    assert_eq!(with_rsl, base + 6);
}

#[cfg(not(feature = "mlkem"))]
#[test]
fn writer_emits_exactly_client_hello_len_with_bytes() {
    for opts in [
        ClientHelloOptions::legacy(),
        ClientHelloOptions {
            record_size_limit: Some(16385),
            ..ClientHelloOptions::legacy()
        },
        ClientHelloOptions {
            hostname: Some(b"example.com"),
            ..ClientHelloOptions::legacy()
        },
        ClientHelloOptions {
            hostname: Some(b"example.com"),
            record_size_limit: Some(4096),
            ..ClientHelloOptions::legacy()
        },
    ] {
        let expected = client_hello_len_with(&opts);
        let mut buf = [0u8; 512];
        let mut cursor: &mut [u8] = &mut buf;
        let n = write_client_hello_with(&mut cursor, &FIXTURE_RANDOM, &FIXTURE_X25519_PUB, &opts)
            .unwrap();
        assert_eq!(n, expected, "opts={opts:?}");
    }
}

// The signature_algorithms list is key_share-independent; gated off `mlkem` so
// `legacy()` opts (no ML-KEM ek) drive the writer. Covered by non-`mlkem` mldsa
// combos.
#[cfg(all(feature = "mldsa", not(feature = "mlkem")))]
#[test]
fn client_hello_advertises_mldsa_schemes() {
    let random = [0x11u8; 32];
    let x25519 = [0x22u8; 32];
    let opts = ClientHelloOptions::legacy();
    let mut buf = [0u8; 512];
    let mut cursor: &mut [u8] = &mut buf;
    let n = write_client_hello_with(&mut cursor, &random, &x25519, &opts).unwrap();
    let ch = &buf[..n];

    // The exact `supported_signature_algorithms` list in RFC 8446 order:
    // ed25519, rsa_pss when enabled, then mldsa44/65/87.
    #[cfg(feature = "rsa")]
    const SCHEMES: &[u8] = &[0x08, 0x07, 0x08, 0x04, 0x09, 0x04, 0x09, 0x05, 0x09, 0x06];
    #[cfg(not(feature = "rsa"))]
    const SCHEMES: &[u8] = &[0x08, 0x07, 0x09, 0x04, 0x09, 0x05, 0x09, 0x06];
    assert_eq!(SCHEMES.len(), 2 * SIG_SCHEME_COUNT as usize);

    // Match the list together with its 2-byte length prefix, so the assertion
    // pins ordering and rejects any extra/duplicate/missing scheme.
    let mut needle = [0u8; 2 + 10];
    needle[..2].copy_from_slice(&(SCHEMES.len() as u16).to_be_bytes());
    needle[2..2 + SCHEMES.len()].copy_from_slice(SCHEMES);
    let needle = &needle[..2 + SCHEMES.len()];

    assert_eq!(
        ch.windows(needle.len()).filter(|w| *w == needle).count(),
        1,
        "ClientHello must advertise exactly the expected signature_algorithms list"
    );
}

/// End-to-end against real openssl-produced ML-DSA certificates: the active
/// `CertParser` parses the DER, and krabipqc verifies the self-signature
/// openssl wrote — a cross-implementation check of OID classification, SPKI/TBS
/// extraction, and the pure-ML-DSA verify path. `DerCert` is a feature alias,
/// so this runs the `der`-crate backend with `cert-der` and the in-tree TLV
/// walker without it (both covered by the feature-powerset CI).
#[cfg(feature = "mldsa")]
mod real_mldsa_certs {
    use super::*;
    use crate::backends::DerCert;
    use crate::backends::mldsa_verify::{MlDsaSig, MlDsaVerifierKey};
    use crate::traits::CertParser;
    use signature::Verifier;

    macro_rules! real_cert_test {
        ($name:ident, $file:literal, $der_len:expr, $pk_len:expr, $sig_len:expr) => {
            #[test]
            fn $name() {
                const DER: [u8; $der_len] =
                    crate::hex_decode(include_str!(concat!("../../testdata/certs/", $file)));
                let der: &[u8] = &DER;
                let CertView::MlDsa {
                    tbs,
                    signature,
                    pubkey,
                    san,
                    ..
                } = <DerCert as CertParser>::parse(der).expect("parse real ML-DSA cert")
                else {
                    panic!("real ML-DSA cert did not parse as CertView::MlDsa");
                };
                assert_eq!(pubkey.len(), $pk_len);
                assert_eq!(signature.len(), $sig_len);
                assert!(san.is_some(), "the cert's SubjectAltName must be parsed");

                let vk = MlDsaVerifierKey::new(pubkey).expect("build verifier from leaf pubkey");
                vk.verify(tbs, &MlDsaSig(signature))
                    .expect("openssl's self-signature must verify under krabipqc");
            }
        };
    }

    real_cert_test!(mldsa44, "mldsa44_selfsigned.hex", 4012, 1312, 2420);
    real_cert_test!(mldsa65, "mldsa65_selfsigned.hex", 5541, 1952, 3309);
    real_cert_test!(mldsa87, "mldsa87_selfsigned.hex", 7499, 2592, 4627);
}

#[test]
fn error_types_display() {
    // Round-trip Display through `format!` to catch any breakage in the
    // trait impls. `std` is available under cfg(test) so `format!` works.
    let e: Write24Error<SliceWriteError> = Write24Error::Overflow;
    assert!(format!("{e}").contains("24"));
    let e: ClientHelloError<SliceWriteError> = ClientHelloError::HostnameTooLong;
    assert!(format!("{e}").contains("hostname"));
    let e: ClientHelloError<SliceWriteError> = ClientHelloError::IntegerOverflow;
    assert!(format!("{e}").to_lowercase().contains("overflow"));
}

#[test]
fn write_u24_rejects_overflow() {
    // Not reachable from `write_client_hello` (body_len is u16-typed); the
    // trait method must reject any u32 that doesn't fit in 3 bytes.
    let mut buf = [0u8; 3];
    let mut cursor: &mut [u8] = &mut buf;
    let err = cursor.write_u24(0x100_0000).unwrap_err();
    assert_eq!(err, Write24Error::Overflow);

    let mut cursor: &mut [u8] = &mut buf;
    cursor.write_u24(0xFF_FFFF).unwrap();
    assert_eq!(buf, [0xff, 0xff, 0xff]);
}

#[cfg(not(feature = "mlkem"))]
#[test]
fn random_appears_at_correct_offset() {
    let mut random = [0u8; 32];
    for (i, b) in random.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut buf = [0u8; CLIENT_HELLO_LEN];
    let mut cursor: &mut [u8] = &mut buf;
    write_client_hello_with(
        &mut cursor,
        &random,
        &FIXTURE_X25519_PUB,
        &ClientHelloOptions::legacy(),
    )
    .unwrap();
    assert_eq!(&buf[11..11 + 32], &random);
}

#[cfg(not(feature = "mlkem"))]
#[test]
fn x25519_pub_appears_at_correct_offset() {
    let mut pub_key = [0u8; 32];
    for (i, b) in pub_key.iter_mut().enumerate() {
        *b = (0x80 + i) as u8;
    }
    let mut buf = [0u8; CLIENT_HELLO_LEN];
    let mut cursor: &mut [u8] = &mut buf;
    write_client_hello_with(
        &mut cursor,
        &FIXTURE_RANDOM,
        &pub_key,
        &ClientHelloOptions::legacy(),
    )
    .unwrap();
    assert_eq!(&buf[CLIENT_HELLO_LEN - 32..], &pub_key);
}

// Captured from tls_fixture/packets/002_s2c_ServerHello.bin (seed 0).
const FIXTURE_SERVER_HELLO: [u8; 95] = [
    0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0x64, 0x1c, 0x5b, 0xd9, 0x34,
    0xab, 0xe1, 0xc5, 0x98, 0xa9, 0xc9, 0x61, 0xf7, 0xcb, 0x1e, 0x06, 0x28, 0x0b, 0x4a, 0x5e, 0x88,
    0x0c, 0x1c, 0x19, 0xd2, 0xfe, 0x9e, 0xef, 0x33, 0x48, 0x0c, 0xae, 0x00, 0x13, 0x01, 0x00, 0x00,
    0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x60,
    0x4d, 0x7a, 0x17, 0x18, 0x38, 0xbd, 0xa2, 0x15, 0xd2, 0xb5, 0x4a, 0x24, 0xfb, 0x7d, 0x3a, 0x88,
    0x8d, 0xa5, 0xac, 0x36, 0x72, 0x72, 0x6d, 0x20, 0x06, 0x44, 0x04, 0xf7, 0x06, 0xdb, 0x7e,
];
const SH_CIPHER_SUITE_OFFSET: usize = 44;

#[cfg(not(feature = "mlkem"))]
const FIXTURE_SERVER_RANDOM: [u8; 32] = [
    0x64, 0x1c, 0x5b, 0xd9, 0x34, 0xab, 0xe1, 0xc5, 0x98, 0xa9, 0xc9, 0x61, 0xf7, 0xcb, 0x1e, 0x06,
    0x28, 0x0b, 0x4a, 0x5e, 0x88, 0x0c, 0x1c, 0x19, 0xd2, 0xfe, 0x9e, 0xef, 0x33, 0x48, 0x0c, 0xae,
];
#[cfg(not(feature = "mlkem"))]
const FIXTURE_SERVER_X25519: [u8; 32] = [
    0x60, 0x4d, 0x7a, 0x17, 0x18, 0x38, 0xbd, 0xa2, 0x15, 0xd2, 0xb5, 0x4a, 0x24, 0xfb, 0x7d, 0x3a,
    0x88, 0x8d, 0xa5, 0xac, 0x36, 0x72, 0x72, 0x6d, 0x20, 0x06, 0x44, 0x04, 0xf7, 0x06, 0xdb, 0x7e,
];

#[cfg(not(feature = "mlkem"))]
#[test]
fn parses_python_fixture_server_hello() {
    let v = parse_server_hello(&FIXTURE_SERVER_HELLO).unwrap();
    assert_eq!(v.random, &FIXTURE_SERVER_RANDOM);
    assert_eq!(v.session_id_echo, &[][..]);
    assert_eq!(v.cipher_suite, CIPHER_AES_128_GCM_SHA256);
    assert_eq!(v.selected_version, TLS_1_3);
    assert_eq!(v.x25519_share, &FIXTURE_SERVER_X25519);
}

#[test]
fn truncated_buffer_rejected() {
    let truncated = &FIXTURE_SERVER_HELLO[..FIXTURE_SERVER_HELLO.len() - 1];
    let err = parse_server_hello(truncated).unwrap_err();
    assert!(matches!(err, ParseError::Truncated));
}

#[test]
fn wrong_content_type_rejected() {
    let mut bad = FIXTURE_SERVER_HELLO;
    bad[0] = 23;
    assert_eq!(
        parse_server_hello(&bad),
        Err(ParseError::UnexpectedContentType(23)),
    );
}

#[test]
fn wrong_handshake_type_rejected() {
    let mut bad = FIXTURE_SERVER_HELLO;
    bad[5] = 1;
    assert_eq!(
        parse_server_hello(&bad),
        Err(ParseError::UnexpectedHandshakeType(1)),
    );
}

// Full-parse success path needs the x25519-shaped fixture key_share; under
// `mlkem` the parser expects the hybrid X25519MLKEM768 share instead.
#[cfg(all(feature = "chacha20", not(feature = "mlkem")))]
#[test]
fn server_hello_chacha20_accepted() {
    let mut sh = FIXTURE_SERVER_HELLO;
    sh[SH_CIPHER_SUITE_OFFSET] = 0x13;
    sh[SH_CIPHER_SUITE_OFFSET + 1] = 0x03;
    let v = parse_server_hello(&sh).unwrap();
    assert_eq!(v.cipher_suite, CIPHER_CHACHA20_POLY1305_SHA256);
}

#[cfg(not(feature = "chacha20"))]
#[test]
fn server_hello_chacha20_rejected_without_feature() {
    let mut sh = FIXTURE_SERVER_HELLO;
    sh[SH_CIPHER_SUITE_OFFSET] = 0x13;
    sh[SH_CIPHER_SUITE_OFFSET + 1] = 0x03;
    assert_eq!(
        parse_server_hello(&sh),
        Err(ParseError::UnsupportedCipherSuite(0x1303)),
    );
}

#[test]
fn wrong_cipher_suite_rejected() {
    let mut bad = FIXTURE_SERVER_HELLO;
    // TLS_AES_256_GCM_SHA384 is not in our profile.
    bad[SH_CIPHER_SUITE_OFFSET] = 0x13;
    bad[SH_CIPHER_SUITE_OFFSET + 1] = 0x02;
    assert_eq!(
        parse_server_hello(&bad),
        Err(ParseError::UnsupportedCipherSuite(0x1302)),
    );
}

#[test]
fn trailing_bytes_after_record_rejected() {
    let mut padded = [0u8; FIXTURE_SERVER_HELLO.len() + 1];
    padded[..FIXTURE_SERVER_HELLO.len()].copy_from_slice(&FIXTURE_SERVER_HELLO);
    assert_eq!(parse_server_hello(&padded), Err(ParseError::TrailingBytes));
}

#[test]
fn hello_retry_request_rejected() {
    let mut bad = FIXTURE_SERVER_HELLO;
    bad[11..43].copy_from_slice(&HRR_RANDOM);
    assert_eq!(
        parse_server_hello(&bad),
        Err(ParseError::HelloRetryRequested)
    );
}

#[test]
fn downgrade_marker_rejected() {
    let mut bad = FIXTURE_SERVER_HELLO;
    bad[35..43].copy_from_slice(&DOWNGRADE_TLS12);
    assert_eq!(parse_server_hello(&bad), Err(ParseError::DowngradeDetected));

    bad[35..43].copy_from_slice(&DOWNGRADE_TLS11_OR_BELOW);
    assert_eq!(parse_server_hello(&bad), Err(ParseError::DowngradeDetected));
}

#[test]
fn non_empty_session_id_echo_rejected() {
    let mut buf = [0u8; FIXTURE_SERVER_HELLO.len() + 1];
    buf[..43].copy_from_slice(&FIXTURE_SERVER_HELLO[..43]);
    buf[43] = 0x01;
    buf[44] = 0xab;
    buf[45..].copy_from_slice(&FIXTURE_SERVER_HELLO[44..]);
    buf[3..5].copy_from_slice(&[0x00, 0x5b]);
    buf[6..9].copy_from_slice(&[0x00, 0x00, 0x57]);

    assert_eq!(
        parse_server_hello(&buf),
        Err(ParseError::UnexpectedSessionIdEcho),
    );
}

#[cfg(not(feature = "mlkem"))]
#[test]
fn unknown_extension_rejected() {
    let mut buf = [0u8; FIXTURE_SERVER_HELLO.len() + 7];
    buf[..FIXTURE_SERVER_HELLO.len()].copy_from_slice(&FIXTURE_SERVER_HELLO);
    buf[FIXTURE_SERVER_HELLO.len()..].copy_from_slice(&[0x00, 0xff, 0x00, 0x03, 0xaa, 0xbb, 0xcc]);
    buf[3..5].copy_from_slice(&[0x00, 0x61]);
    buf[6..9].copy_from_slice(&[0x00, 0x00, 0x5d]);
    buf[47..49].copy_from_slice(&[0x00, 0x35]);

    assert_eq!(
        parse_server_hello(&buf),
        Err(ParseError::UnknownExtension(0x00ff)),
    );
}

#[cfg(not(feature = "mlkem"))]
#[test]
fn duplicate_extension_rejected() {
    let mut buf = [0u8; FIXTURE_SERVER_HELLO.len() + 6];
    buf[..FIXTURE_SERVER_HELLO.len()].copy_from_slice(&FIXTURE_SERVER_HELLO);
    buf[FIXTURE_SERVER_HELLO.len()..].copy_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    buf[3..5].copy_from_slice(&[0x00, 0x60]);
    buf[6..9].copy_from_slice(&[0x00, 0x00, 0x5c]);
    buf[47..49].copy_from_slice(&[0x00, 0x34]);

    assert_eq!(
        parse_server_hello(&buf),
        Err(ParseError::DuplicateExtension(EXT_SUPPORTED_VERSIONS)),
    );
}

//
// Two angles: RFC 8448 §3 publishes intermediate values for a full TLS 1.3
// handshake (well-known, not derived from our fixture), and we also pin
// against the tls_fixture seed-0 derivation chain so a backend swap can be
// caught here before it ever reaches the QEMU demo.

// RFC 8448 / fixture constants are kept as raw `[u8; N]` (const-
// friendly) and wrapped into the secret-bearing newtypes at use
// site via small helpers, because `Zeroizing::new` isn't `const fn`.

/// RFC 8448 §3: `HKDF-Extract(salt=00..00, IKM=00..00)` → no-PSK early secret.
const RFC8448_EARLY_SECRET_BYTES: [u8; 32] = [
    0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
    0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60, 0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a,
];
fn make_rfc8448_early_secret() -> Secret {
    Secret::new(ZeroBuf::<32>::new(RFC8448_EARLY_SECRET_BYTES))
}
/// RFC 8448 §3: `Derive-Secret(EarlySecret, "derived", "")`.
/// The empty-string transcript hash is `SHA-256("")`.
const RFC8448_DERIVED_FROM_EARLY_BYTES: [u8; 32] = [
    0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97,
    0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba,
];
/// `SHA-256("")` — the empty-transcript hash, used by `Derive-Secret(., "derived", "")`.
const EMPTY_SHA256: TranscriptDigest = TranscriptDigest::new([
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
]);

/// `tls_fixture` seed-0: handshake_secret computed from the recorded X25519 DHE.
const FIXTURE_DHE: [u8; 32] = [
    0xd6, 0xe8, 0x68, 0xc2, 0x71, 0xfa, 0x06, 0x2a, 0x48, 0xab, 0x2a, 0xcc, 0x32, 0xfe, 0x98, 0x58,
    0x0d, 0x48, 0x77, 0x00, 0x91, 0x1f, 0x47, 0xad, 0x94, 0xcb, 0xb3, 0xb5, 0x35, 0x58, 0xea, 0x51,
];
const FIXTURE_HANDSHAKE_SECRET_BYTES: [u8; 32] = [
    0x67, 0x4c, 0x4a, 0x90, 0x69, 0x17, 0x0e, 0xcd, 0x7a, 0xc6, 0x92, 0x5e, 0x96, 0x22, 0x49, 0xa2,
    0xa8, 0x6d, 0x22, 0x50, 0xc1, 0x2f, 0x21, 0x7a, 0x2c, 0x2a, 0x28, 0x3c, 0x64, 0xbf, 0x28, 0x7f,
];

#[test]
fn rfc8448_early_secret() {
    let zeros = [0u8; 32];
    let prk = Secret::new(RustCrypto::extract(&zeros, &zeros));
    assert_eq!(prk.as_bytes(), &RFC8448_EARLY_SECRET_BYTES);
}

#[test]
fn rfc8448_derived_from_early() {
    let derived =
        derive_secret::<RustCrypto>(&make_rfc8448_early_secret(), b"derived", &EMPTY_SHA256)
            .unwrap();
    assert_eq!(derived.as_bytes(), &RFC8448_DERIVED_FROM_EARLY_BYTES);
}

#[test]
fn hkdf_expand_label_rejects_oversized_public_inputs() {
    let secret = [0u8; 32];
    let mut out = [0u8; 32];
    let long = [0u8; 256];
    assert_eq!(
        hkdf_expand_label::<RustCrypto>(&secret, &long, &[], &mut out),
        Err(HkdfLabelError::LabelTooLong)
    );
    assert_eq!(
        hkdf_expand_label::<RustCrypto>(&secret, b"ok", &long, &mut out),
        Err(HkdfLabelError::ContextTooLong)
    );
    let too_big_for_scratch = [0u8; 58];
    assert_eq!(
        hkdf_expand_label::<RustCrypto>(&secret, &too_big_for_scratch, &[], &mut out),
        Err(HkdfLabelError::EncodedTooLong)
    );
    // out.len() > 255 * 32: backend rejects → Expand variant.
    let mut huge_out = vec![0u8; 8200];
    assert_eq!(
        hkdf_expand_label::<RustCrypto>(&secret, b"ok", b"", &mut huge_out),
        Err(HkdfLabelError::Expand(
            traits::HkdfExpandError::OutputTooLong
        ))
    );
}

#[test]
fn fixture_handshake_secret() {
    let derived =
        derive_secret::<RustCrypto>(&make_rfc8448_early_secret(), b"derived", &EMPTY_SHA256)
            .unwrap();
    let hs = Secret::new(RustCrypto::extract(derived.as_bytes(), &FIXTURE_DHE));
    assert_eq!(hs.as_bytes(), &FIXTURE_HANDSHAKE_SECRET_BYTES);
}

/// tls_fixture seed-0 client X25519 private (from state/client.json).
const FIXTURE_CLIENT_X25519_PRIV: [u8; 32] = [
    0xac, 0xe1, 0xc2, 0x3b, 0x24, 0xdf, 0xad, 0x58, 0xc5, 0x4c, 0xcf, 0x4c, 0x1f, 0xe8, 0xdf, 0xe8,
    0x5e, 0x76, 0x0e, 0x02, 0x3b, 0x6c, 0xb6, 0x02, 0x2f, 0x70, 0x0f, 0x34, 0xde, 0x4c, 0x28, 0x28,
];
const FIXTURE_SERVER_X25519_PUB_2: [u8; 32] = [
    0x60, 0x4d, 0x7a, 0x17, 0x18, 0x38, 0xbd, 0xa2, 0x15, 0xd2, 0xb5, 0x4a, 0x24, 0xfb, 0x7d, 0x3a,
    0x88, 0x8d, 0xa5, 0xac, 0x36, 0x72, 0x72, 0x6d, 0x20, 0x06, 0x44, 0x04, 0xf7, 0x06, 0xdb, 0x7e,
];
/// SHA-256(ClientHello_handshake_msg || ServerHello_handshake_msg) at
/// seed 0. CH carries SNI + RSL; cert carries SAN.
const FIXTURE_TRANSCRIPT_HASH_CH_SH: TranscriptDigest = TranscriptDigest::new([
    0xa8, 0xc5, 0x43, 0x11, 0x16, 0x98, 0x90, 0x0f, 0x4a, 0x5f, 0x43, 0xeb, 0x51, 0x0d, 0xe6, 0x3f,
    0xb5, 0x47, 0xd9, 0xbd, 0x5a, 0x50, 0x6b, 0x68, 0xe1, 0x7d, 0x70, 0xb1, 0x7a, 0x8e, 0xae, 0x74,
]);
/// Server handshake traffic secret. From tls_fixture/state/client.json `s_hs_ts`.
const FIXTURE_S_HS_TRAFFIC_SECRET_BYTES: [u8; 32] = [
    0x03, 0xab, 0xb1, 0x1c, 0x49, 0xde, 0x80, 0x93, 0xb3, 0x78, 0x60, 0x9b, 0x5b, 0x0a, 0xb4, 0xab,
    0x40, 0x8b, 0x7e, 0xe2, 0x23, 0xb4, 0x59, 0xef, 0x63, 0x14, 0xbb, 0x1b, 0xae, 0xa1, 0x3d, 0xea,
];
fn make_fixture_s_hs_traffic_secret() -> Secret {
    Secret::new(ZeroBuf::<32>::new(FIXTURE_S_HS_TRAFFIC_SECRET_BYTES))
}
/// Client handshake traffic secret. From tls_fixture/state/client.json `c_hs_ts`.
const FIXTURE_C_HS_TRAFFIC_SECRET_BYTES: [u8; 32] = [
    0xbb, 0xe1, 0xcb, 0x05, 0x42, 0x4c, 0x27, 0xe7, 0x0d, 0x7e, 0xf5, 0x7c, 0x6f, 0x96, 0xd8, 0x3f,
    0x44, 0x8a, 0x7d, 0xa0, 0xd0, 0x15, 0x3b, 0xa6, 0x64, 0xfe, 0xe6, 0x05, 0xb4, 0x00, 0x30, 0x01,
];

#[test]
fn transcript_update_record_rejects_too_short() {
    let mut t = TranscriptHash::<RustCrypto>::new();
    // < 5 bytes can't even hold a TLS record header.
    assert_eq!(
        t.update_record(&[0x16, 0x03, 0x03]),
        Err(TranscriptError::RecordTooShort)
    );
    assert_eq!(t.update_record(&[]), Err(TranscriptError::RecordTooShort));
}

#[test]
fn transcript_update_record_strips_5_byte_header() {
    let mut a = TranscriptHash::<RustCrypto>::new();
    a.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
    a.update_record(&FIXTURE_SERVER_HELLO).unwrap();

    let mut b = TranscriptHash::<RustCrypto>::new();
    b.update(&FIXTURE_CLIENT_HELLO[5..]);
    b.update(&FIXTURE_SERVER_HELLO[5..]);

    assert_eq!(a.snapshot(), b.snapshot());
}

#[test]
fn transcript_update_record_honors_declared_length() {
    // A buffered-read scenario: caller's slice holds the full record
    // followed by an extra trailing byte (start of the next record).
    // The transcript must hash ONLY the declared `length` bytes,
    // otherwise it silently diverges from the peer's transcript and
    // every downstream MAC/derivation fails.
    let mut record_plus_tail = [0u8; 5 + 4 + 1];
    record_plus_tail[0] = consts::CT_HANDSHAKE;
    record_plus_tail[1..3].copy_from_slice(&consts::LEGACY_VERSION.to_be_bytes());
    record_plus_tail[3..5].copy_from_slice(&4u16.to_be_bytes());
    record_plus_tail[5..9].copy_from_slice(b"abcd");
    record_plus_tail[9] = 0xFF;

    let mut a = TranscriptHash::<RustCrypto>::new();
    a.update_record(&record_plus_tail).unwrap();

    let mut b = TranscriptHash::<RustCrypto>::new();
    b.update(b"abcd");

    assert_eq!(
        a.snapshot(),
        b.snapshot(),
        "trailing 0xFF must NOT be hashed"
    );
}

#[test]
fn transcript_update_record_rejects_short_body() {
    let mut record = [0u8; 5 + 10];
    record[0] = consts::CT_HANDSHAKE;
    record[1..3].copy_from_slice(&consts::LEGACY_VERSION.to_be_bytes());
    record[3..5].copy_from_slice(&100u16.to_be_bytes());
    let mut t = TranscriptHash::<RustCrypto>::new();
    assert_eq!(
        t.update_record(&record),
        Err(TranscriptError::RecordTooShort)
    );
}

#[test]
fn fixture_transcript_hash_ch_sh() {
    // TranscriptHash strips the 5-byte TLS record header internally and
    // hashes the handshake-message body — RFC 8446 §4.4.1.
    let mut t = TranscriptHash::<RustCrypto>::new();
    t.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
    t.update_record(&FIXTURE_SERVER_HELLO).unwrap();
    assert_eq!(t.snapshot(), FIXTURE_TRANSCRIPT_HASH_CH_SH);
}

#[test]
fn fixture_dhe_via_x25519() {
    type T = fixed_bigint::FixedUInt<u32, 16, const_num_traits::Ct>;
    let dhe =
        ed25519_heapless::x25519::<T>(&FIXTURE_CLIENT_X25519_PRIV, &FIXTURE_SERVER_X25519_PUB_2);
    assert_eq!(dhe, FIXTURE_DHE);
}

#[test]
fn fixture_s_hs_traffic_secret_full_chain() {
    type T = fixed_bigint::FixedUInt<u32, 16, const_num_traits::Ct>;
    let dhe =
        ed25519_heapless::x25519::<T>(&FIXTURE_CLIENT_X25519_PRIV, &FIXTURE_SERVER_X25519_PUB_2);
    let hs = handshake_secret::<RustCrypto>(&dhe).unwrap();
    assert_eq!(hs.as_bytes(), &FIXTURE_HANDSHAKE_SECRET_BYTES);
    let th = {
        let mut t = TranscriptHash::<RustCrypto>::new();
        t.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
        t.update_record(&FIXTURE_SERVER_HELLO).unwrap();
        t.snapshot()
    };
    let (c_ts, s_ts) = handshake_traffic_secrets::<RustCrypto>(&hs, &th).unwrap();
    assert_eq!(c_ts.as_bytes(), &FIXTURE_C_HS_TRAFFIC_SECRET_BYTES);
    assert_eq!(s_ts.as_bytes(), &FIXTURE_S_HS_TRAFFIC_SECRET_BYTES);
}

/// HKDF-Expand-Label(s_hs_ts, "key"/"iv", ""). All AEAD keys/IVs
/// below derive from the regenerated
/// traffic secrets above.
const FIXTURE_S_HS_KEY_BYTES: [u8; 16] = [
    0xca, 0xf7, 0xdb, 0x48, 0x88, 0xeb, 0x19, 0x16, 0x1b, 0x2f, 0x90, 0x8d, 0x9d, 0xc5, 0x87, 0x44,
];
const FIXTURE_S_HS_IV_BYTES: [u8; 12] = [
    0x96, 0xaa, 0x3a, 0x44, 0xd8, 0x1f, 0x1b, 0x6b, 0xc2, 0x13, 0x31, 0xd7,
];

#[test]
fn fixture_traffic_keys_match() {
    let (k, iv) = traffic_keys::<RustCrypto, 16>(&make_fixture_s_hs_traffic_secret()).unwrap();
    let key = AeadKey::new(k);
    assert_eq!(key.as_bytes(), &FIXTURE_S_HS_KEY_BYTES);
    assert_eq!(iv.as_bytes(), &FIXTURE_S_HS_IV_BYTES);
}

#[test]
fn aead_nonce_xors_low_8_bytes() {
    // RFC 8446 §5.3: nonce = iv XOR (seq left-padded to iv_len).
    let iv = AeadIv::new(ZeroBuf::<12>::new([0u8; 12]));
    // seq = 1 should set last byte to 1
    assert_eq!(*aead_nonce(&iv, 1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    // seq = 0x0102030405060708 should occupy bytes 4..12
    assert_eq!(
        *aead_nonce(&iv, 0x0102030405060708),
        [0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    );
}

/// packets/003_s2c_ServerFlight_encrypted.hex (415 bytes, decoded at
/// compile time). Cert carries SAN matching `tls-fixture.local`.
const FIXTURE_PACKET_3: [u8; 415] = crate::hex_decode(include_str!(
    "../../testdata/packets/003_s2c_ServerFlight_encrypted.hex"
));

#[test]
fn decrypt_record_rejects_trailing_bytes() {
    // Two valid records glued together — caller MUST pass exactly one.
    // TrailingBytes is checked BEFORE the AEAD call so the cipher
    // never runs. Use NoCipher so the test is cipher-feature-agnostic.
    let key = ZeroBuf::<16>::new([0u8; 16]);
    let iv = AeadIv::new(ZeroBuf::<12>::new([0u8; 12]));
    let mut extra = [0u8; 416];
    extra[..415].copy_from_slice(&FIXTURE_PACKET_3);
    extra[415] = 0xAB; // one stray byte past the declared record body
    let mut buf = [0u8; 416];
    let err = decrypt_record::<NoCipher>(&extra, &key, &iv, 0, &mut buf).unwrap_err();
    assert_eq!(err, DecryptError::TrailingBytes);
}

#[cfg(feature = "jedisct")]
#[test]
fn jedisct_matches_rustcrypto() {
    // HKDF is fully spec-determined, so both backends must produce identical
    // outputs on the same inputs. Easy parity property-style test.
    for ikm in &[&[0u8; 32][..], b"abc"[..].as_ref(), &FIXTURE_DHE[..]] {
        let rc = RustCrypto::extract(&[0u8; 32], ikm);
        let jd = JedisctCrypto::extract(&[0u8; 32], ikm);
        assert_eq!(&*rc, &*jd, "extract diverged for ikm len={}", ikm.len());
    }
    // Mid-length expand.
    let prk: [u8; 32] = [0x42; 32];
    for out_len in [16usize, 32, 48] {
        let mut rc = [0u8; 48];
        let mut jd = [0u8; 48];
        RustCrypto::expand(&prk, b"test info", &mut rc[..out_len]).unwrap();
        JedisctCrypto::expand(&prk, b"test info", &mut jd[..out_len]).unwrap();
        assert_eq!(rc, jd, "expand diverged at len={out_len}");
    }
    // Full TLS 1.3 chain through to s_hs_traffic_secret must match.
    type Bn = fixed_bigint::FixedUInt<u32, 16, const_num_traits::Ct>;
    let dhe =
        ed25519_heapless::x25519::<Bn>(&FIXTURE_CLIENT_X25519_PRIV, &FIXTURE_SERVER_X25519_PUB_2);
    let rc_hs = handshake_secret::<RustCrypto>(&dhe).unwrap();
    let jd_hs = handshake_secret::<JedisctCrypto>(&dhe).unwrap();
    assert_eq!(rc_hs, jd_hs);
    let th = {
        let mut t = TranscriptHash::<RustCrypto>::new();
        t.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
        t.update_record(&FIXTURE_SERVER_HELLO).unwrap();
        t.snapshot()
    };
    let rc_ts = handshake_traffic_secrets::<RustCrypto>(&rc_hs, &th).unwrap();
    let jd_ts = handshake_traffic_secrets::<JedisctCrypto>(&jd_hs, &th).unwrap();
    assert_eq!(rc_ts, jd_ts);
}

#[test]
fn encrypt_record_rejects_oversize_plaintext() {
    // Content large enough that inner_plaintext + tag exceeds
    // TLSCiphertext.length cap (2^14 + 256). Out buffer size doesn't
    // matter — RecordTooLarge fires before BufferTooSmall. Size check
    // runs before the AEAD call; NoCipher keeps the test cipher-agnostic.
    let big = vec![0u8; (1 << 14) + 256];
    let mut out = [0u8; 1];
    let err = encrypt_record::<NoCipher>(
        &big,
        consts::CT_APPLICATION_DATA,
        &ZeroBuf::<16>::new([0u8; 16]),
        &AeadIv::new(ZeroBuf::<12>::new([0u8; 12])),
        0,
        &mut out,
    )
    .unwrap_err();
    assert_eq!(err, aead::EncryptError::RecordTooLarge);
}

#[cfg(feature = "chacha20")]
#[test]
fn chacha20_encrypt_decrypt_round_trip() {
    let key = AeadKey32::new(ZeroBuf::<32>::new([0x11; 32]));
    let iv = AeadIv::new(ZeroBuf::<12>::new([0x22; 12]));
    let plaintext = b"hello world";
    let mut record_buf = [0u8; 64];
    let record = encrypt_record::<ChaCha20Poly1305Sha256>(
        plaintext,
        consts::CT_APPLICATION_DATA,
        key.as_zeroizing(),
        &iv,
        7,
        &mut record_buf,
    )
    .unwrap();
    let record_owned = record.to_vec();
    let mut pt_buf = [0u8; 64];
    let inner = decrypt_record::<ChaCha20Poly1305Sha256>(
        &record_owned,
        key.as_zeroizing(),
        &iv,
        7,
        &mut pt_buf,
    )
    .unwrap();
    let (content, content_type) = aead::split_inner_plaintext(inner).unwrap();
    assert_eq!(content, plaintext);
    assert_eq!(content_type, consts::CT_APPLICATION_DATA);
}

#[test]
fn encrypt_record_rejects_plaintext_just_over_14k() {
    // RFC 8446 §5.1: TLSPlaintext.length max is 2^14. Content of
    // 2^14 + 1 bytes fits the §5.2 ciphertext cap (2^14 + 256) once
    // the AEAD tag + content_type are added, but violates the §5.1
    // plaintext cap — must surface as RecordTooLarge. NoCipher keeps
    // the test cipher-agnostic.
    let just_over = vec![0u8; (1 << 14) + 1];
    let mut out = vec![0u8; (1 << 14) + 256 + 5];
    let err = encrypt_record::<NoCipher>(
        &just_over,
        consts::CT_APPLICATION_DATA,
        &ZeroBuf::<16>::new([0u8; 16]),
        &AeadIv::new(ZeroBuf::<12>::new([0u8; 12])),
        0,
        &mut out,
    )
    .unwrap_err();
    assert_eq!(err, aead::EncryptError::RecordTooLarge);
}

#[test]
fn split_inner_plaintext_rejects_over_14k() {
    // Build a synthetic inner: 2^14 + 1 bytes of content, then the
    // content_type byte, no padding. §5.1 / §5.4 require content
    // (post-padding-strip) <= 2^14.
    let mut inner = vec![0xABu8; (1 << 14) + 2];
    let last = inner.len() - 1;
    inner[last] = consts::CT_APPLICATION_DATA;
    let err = split_inner_plaintext(&inner).unwrap_err();
    assert_eq!(err, aead::DecryptError::RecordTooLarge);
}

#[test]
fn split_inner_plaintext_accepts_exactly_14k() {
    // 2^14 content bytes + 1 content_type byte = boundary case.
    let mut inner = vec![0xCDu8; (1 << 14) + 1];
    let last = inner.len() - 1;
    inner[last] = consts::CT_APPLICATION_DATA;
    let (content, ct) = split_inner_plaintext(&inner).unwrap();
    assert_eq!(content.len(), 1 << 14);
    assert_eq!(ct, consts::CT_APPLICATION_DATA);
}

#[test]
fn certificate_verify_rejects_trailing_bytes() {
    // Synthetic CV body = u16(scheme) || u16(64) || 64 sig bytes || one trailing byte.
    let mut body = [0u8; 4 + 64 + 1];
    body[0..2].copy_from_slice(&consts::SIG_SCHEME_ED25519.to_be_bytes());
    body[2..4].copy_from_slice(&64u16.to_be_bytes());
    // sig bytes default 0 — verification would fail, but the trailing-bytes
    // check fires before any crypto.
    body[4 + 64] = 0xCC;
    // Synthetic CertView::Ed25519 with zero pubkey/signature; the trailing-
    // bytes check fires before any crypto.
    const ZERO_PUB: [u8; 32] = [0u8; 32];
    const ZERO_SIG: [u8; 64] = [0u8; 64];
    let view = CertView::Ed25519 {
        tbs: &[],
        signature: &ZERO_SIG,
        pubkey: &ZERO_PUB,
        san: None,
        validity_der: &[],
    };
    let th = TranscriptDigest::new([0u8; 32]);
    let err = server_flight::tests::verify_certificate_verify::<RustCrypto, RustCrypto>(
        &view, &th, &body,
    )
    .unwrap_err();
    assert_eq!(err, FlightError::TrailingBytes);
}

#[test]
fn extract_cert_der_returns_leaf_from_chain() {
    // Two cert entries in the list; extract_cert_der returns the FIRST.
    let mut body = [0u8; 1 + 3 + 20];
    body[0] = 0;
    body[3] = 20;
    body[6] = 5;
    body[7..12].copy_from_slice(&[1, 2, 3, 4, 5]);
    body[16] = 5;
    body[17..22].copy_from_slice(&[6, 7, 8, 9, 10]);
    let leaf = extract_cert_der(&body).expect("first cert");
    assert_eq!(leaf, &[1, 2, 3, 4, 5]);
}

fn make_cert_body(n: usize) -> Vec<u8> {
    let entry_size = 3 + 1 + 2;
    let list_len = (n * entry_size) as u32;
    let mut body = Vec::with_capacity(4 + n * entry_size);
    body.push(0);
    body.extend_from_slice(&list_len.to_be_bytes()[1..4]);
    for i in 0..n {
        body.extend_from_slice(&[0, 0, 1]);
        body.push((i + 1) as u8);
        body.extend_from_slice(&[0, 0]);
    }
    body
}

#[test]
fn extract_chain_returns_all_entries() {
    let body = make_cert_body(3);
    let chain = extract_chain::<8>(&body).expect("chain parses");
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0], &[1u8][..]);
    assert_eq!(chain[1], &[2u8][..]);
    assert_eq!(chain[2], &[3u8][..]);
}

#[test]
fn extract_chain_rejects_overflow() {
    let body = make_cert_body(3);
    let err = extract_chain::<2>(&body).expect_err("must reject overflow");
    assert_eq!(err, FlightError::CertChainTooLong);
}

// All cipher-aes-dependent fixtures, helpers, and tests, gated once on the
// module. (The seed-0 wire fixtures + RecordKeys schedule are AES-128-GCM.)
#[cfg(feature = "cipher-aes")]
mod cipher_aes {
    use super::*;
    use crate::aead::Aes128GcmSha256;

    use crate::backends::DerCert;

    #[cfg(all(feature = "rsa", not(feature = "rsa_pss_only")))]
    use crate::backends::RsaVerifierKey;

    use crate::client_flight::CLIENT_FINISHED_LEN;

    use crate::server_flight::parse_server_flight;

    use crate::traits::verify_strategy::PreparedVerifier;

    use crate::traits::{CertParseError, CertParser, Ed25519VerifierProvider};

    /// Ed25519 pubkey in the seed-0 self-signed leaf cert. Same constant
    /// as in connection.rs::tests; hoisted here so the verify-helper
    /// can stay test-module-level.
    const FIXTURE_LEAF_ED25519_PUB: [u8; 32] = [
        0x9d, 0xfe, 0x2a, 0xb0, 0x3e, 0x35, 0x70, 0x4b, 0x9c, 0xfb, 0x93, 0xb6, 0x03, 0xa6, 0x61,
        0x18, 0x82, 0x17, 0xa6, 0xb5, 0xfd, 0x6a, 0x1f, 0x75, 0xe6, 0x16, 0x1a, 0x39, 0xe0, 0x53,
        0x4c, 0x3f,
    ];

    fn fixture_prepared_ed25519<E: Ed25519VerifierProvider>() -> PreparedVerifier<E, RustCrypto> {
        PreparedVerifier::ed25519(E::prepare_ed25519(&FIXTURE_LEAF_ED25519_PUB))
    }

    fn fixture_leaf_ed25519() -> CertView<'static> {
        CertView::Ed25519 {
            tbs: &[],
            signature: &[0u8; 64],
            pubkey: &FIXTURE_LEAF_ED25519_PUB,
            san: None,
            validity_der: &[],
        }
    }

    #[cfg(feature = "chacha20")]
    #[test]
    fn client_hello_len_with_aes_only_shrinks_by_two_bytes_under_chacha20() {
        let default = client_hello_len_with(&ClientHelloOptions::legacy());
        let aes_only = client_hello_len_with(&ClientHelloOptions {
            suites: SuiteList::AesOnly,
            ..ClientHelloOptions::legacy()
        });
        assert_eq!(aes_only + 2, default);
    }

    /// First 32 bytes of the decrypted TLSInnerPlaintext of packet 003. Begins:
    ///   0x08 0x00 0x00 0x02 0x00 0x00       EncryptedExtensions (empty)
    ///   0x0b 0x00 0x00 0xf0 ...             Certificate (msg_type=11, len=0x0000f0)
    /// First 32 bytes of the SF plaintext.
    const FIXTURE_PACKET_3_PLAINTEXT_HEAD: [u8; 32] = [
        0x08, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x13, 0x00, 0x00, 0x01, 0x0f, 0x00,
        0x01, 0x0a, 0x30, 0x82, 0x01, 0x06, 0x30, 0x81, 0xb9, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
        0x01, 0x01,
    ];

    /// Wrap the seed-0 server handshake AEAD key bytes into an `AeadKey`.
    /// `AeadKey::new` takes a `ZeroBuf<16>` (= `Zeroizing<[u8; 16]>`) which
    /// isn't const-constructible, so we wrap at the call site.
    fn make_fixture_s_hs_key() -> AeadKey {
        AeadKey::new(ZeroBuf::<16>::new(FIXTURE_S_HS_KEY_BYTES))
    }

    fn make_fixture_s_hs_iv() -> AeadIv {
        AeadIv::new(ZeroBuf::<12>::new(FIXTURE_S_HS_IV_BYTES))
    }

    /// Stub Ed25519VerifierProvider backend that always rejects. Swapping it
    /// in at the `E` generic must flip verify results even with identical
    /// cert / signature bytes.
    struct AlwaysReject;

    struct AlwaysRejectVerifier;

    impl signature::Verifier<[u8; 64]> for AlwaysRejectVerifier {
        fn verify(&self, _: &[u8], _: &[u8; 64]) -> Result<(), signature::Error> {
            Err(signature::Error::new())
        }
    }

    impl crate::traits::verify_strategy::VerifierKeyMaterial<[u8; 32]> for AlwaysRejectVerifier {
        fn matches(&self, _: [u8; 32]) -> subtle::Choice {
            subtle::Choice::from(0)
        }
    }

    impl crate::traits::Ed25519VerifierProvider for AlwaysReject {
        type Verifier = AlwaysRejectVerifier;
        fn prepare_ed25519(_: &[u8; 32]) -> Self::Verifier {
            AlwaysRejectVerifier
        }
    }

    #[test]
    fn ed25519_verify_trait_propagates_to_cert_self_sig() {
        // Same fixture cert that passes with RustCrypto. Plugging in
        // AlwaysReject must flip the result to CertSelfSignatureInvalid.
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let cert_der = &buf[..len];
        let err =
            verify_self_signed_cert::<DerCert, AlwaysReject, RustCrypto>(cert_der).unwrap_err();
        assert_eq!(err, FlightError::CertSelfSignatureInvalid);
    }

    /// Locate every occurrence of the Ed25519 OID DER byte sequence
    /// (`06 03 2B 65 70`) in a cert. In a self-signed Ed25519 cert there are
    /// exactly three, in this byte order:
    /// 1. `TBSCertificate.signature` AlgorithmIdentifier
    /// 2. `SubjectPublicKeyInfo.algorithm` AlgorithmIdentifier
    /// 3. outer `Certificate.signatureAlgorithm` AlgorithmIdentifier
    fn find_ed25519_oid_positions(cert_der: &[u8]) -> [usize; 3] {
        const ED25519_OID_BYTES: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
        let mut positions = [0usize; 3];
        let mut count = 0;
        let mut i = 0;
        while i + ED25519_OID_BYTES.len() <= cert_der.len() {
            if &cert_der[i..i + ED25519_OID_BYTES.len()] == ED25519_OID_BYTES {
                assert!(count < 3, "more than 3 Ed25519-OID occurrences in cert");
                positions[count] = i;
                count += 1;
            }
            i += 1;
        }
        assert_eq!(count, 3, "expected 3 Ed25519-OID occurrences in cert");
        positions
    }

    /// Decrypt server flight, walk to the cert SEQUENCE, return its DER bytes
    /// copied into a stack buffer the caller can mutate.
    fn fixture_cert_der_copy(buf: &mut [u8]) -> usize {
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut pt_buf = [0u8; 400];
        let pt = decrypt_record::<Aes128GcmSha256>(
            &FIXTURE_PACKET_3,
            key.as_zeroizing(),
            &iv,
            0,
            &mut pt_buf,
        )
        .unwrap();
        let (content, _) = split_inner_plaintext(pt).unwrap();
        let flight = parse_server_flight(content).unwrap();
        let cert_der = extract_cert_der(flight.cert_body).unwrap();
        buf[..cert_der.len()].copy_from_slice(cert_der);
        cert_der.len()
    }

    #[test]
    fn cert_rejects_wrong_outer_signature_algorithm_oid_via_symmetry() {
        // Flip only the outer signatureAlgorithm OID. TBS.signature still
        // claims Ed25519, so the RFC 5280 §4.1.1.2 symmetry check is what
        // catches the mismatch — the parser leaves outer OIDs uninterpreted
        // since issuer-signed leaves routinely carry unknown ones.
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let positions = find_ed25519_oid_positions(&buf[..len]);
        buf[positions[2] + 4] ^= 0x01; // outer signatureAlgorithm OID
        let err = <DerCert as CertParser>::parse(&buf[..len]).unwrap_err();
        assert_eq!(err, CertParseError::SignatureAlgorithmMismatch);
    }

    #[test]
    fn cert_rejects_wrong_spki_algorithm_oid() {
        // Outer + symmetry pass; only the SPKI's algorithm OID is mangled.
        // The SPKI is what we dispatch on, so an unknown OID there is
        // `WrongAlgorithmOid` directly.
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let positions = find_ed25519_oid_positions(&buf[..len]);
        buf[positions[1] + 4] ^= 0x01; // SPKI algorithm OID
        let err = <DerCert as CertParser>::parse(&buf[..len]).unwrap_err();
        assert_eq!(err, CertParseError::WrongAlgorithmOid);
    }

    #[test]
    fn cert_with_unknown_outer_sig_algo_still_parses_if_spki_known() {
        // SPKI stays valid Ed25519. The parser must accept — outer sig algo
        // describes the *issuer*'s signature, which for real leaves routinely
        // isn't anything we recognize. Dispatch is on SPKI.
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let positions = find_ed25519_oid_positions(&buf[..len]);
        // Same byte in TBS and outer keeps the symmetry check passing.
        buf[positions[0] + 4] ^= 0x01;
        buf[positions[2] + 4] ^= 0x01;
        let view = <DerCert as CertParser>::parse(&buf[..len]).expect("parse must succeed");
        assert!(matches!(view, CertView::Ed25519 { .. }));
    }

    #[test]
    fn cert_rejects_inner_outer_signature_alg_mismatch() {
        // Flip only the TBS.signature OID. Outer OID still claims Ed25519,
        // so symmetry check fires (TBS.signature bytes now differ from
        // Certificate.signatureAlgorithm).
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let positions = find_ed25519_oid_positions(&buf[..len]);
        buf[positions[0] + 4] ^= 0x01; // TBS.signature OID
        let err = <DerCert as CertParser>::parse(&buf[..len]).unwrap_err();
        assert_eq!(err, CertParseError::SignatureAlgorithmMismatch);
    }

    #[test]
    fn cert_rejects_unsupported_version() {
        // v1 encoded explicitly is malformed per DER, but the parser must
        // surface a clear rejection rather than silent acceptance.
        const V3_VERSION_BYTES: &[u8] = &[0xA0, 0x03, 0x02, 0x01, 0x02];
        let mut buf = [0u8; 512];
        let len = fixture_cert_der_copy(&mut buf);
        let pos = buf[..len]
            .windows(V3_VERSION_BYTES.len())
            .position(|w| w == V3_VERSION_BYTES)
            .expect("v3 version field");
        buf[pos + 4] = 0x00; // claim v1
        let err = <DerCert as CertParser>::parse(&buf[..len]).unwrap_err();
        assert_eq!(err, CertParseError::UnsupportedCertVersion);
    }

    /// packets/005_c2s_AppData_send_0.hex (52 bytes) — first client app-data record.
    const FIXTURE_PACKET_5: [u8; 52] = crate::hex_decode(include_str!(
        "../../testdata/packets/005_c2s_AppData_send_0.hex"
    ));

    /// packets/006_s2c_AppData_reply_0.hex (48 bytes) — first server app-data record.
    const FIXTURE_PACKET_6: [u8; 48] = crate::hex_decode(include_str!(
        "../../testdata/packets/006_s2c_AppData_reply_0.hex"
    ));

    /// Plaintext the fixture's `cli.py --send` sent.
    const PACKET_5_PLAINTEXT: &[u8] = b"hello from the embedded client";

    /// Plaintext the fixture's `serv.py --reply` sent — includes a UTF-8 em-dash
    /// (`\xe2\x80\x94`) which exercises non-ASCII handling.
    const PACKET_6_PLAINTEXT: &[u8] = b"hello back \xe2\x80\x94 server here";

    /// `((key, iv), (key, iv))` for `(c_ap, s_ap)` AEAD streams.
    type ApAeadKeys = (AeadKey, AeadIv);

    fn make_fixture_handshake_secret() -> Secret {
        Secret::new(ZeroBuf::<32>::new(FIXTURE_HANDSHAKE_SECRET_BYTES))
    }

    fn make_fixture_c_hs_traffic_secret() -> Secret {
        Secret::new(ZeroBuf::<32>::new(FIXTURE_C_HS_TRAFFIC_SECRET_BYTES))
    }

    /// Derive the application traffic secrets the same way the demo runs, then
    /// peel off `(c_ap_key, c_ap_iv)` and `(s_ap_key, s_ap_iv)`.
    fn application_keys() -> (ApAeadKeys, ApAeadKeys) {
        let key = make_fixture_s_hs_key();
        let iv = make_fixture_s_hs_iv();
        let mut pt_buf = [0u8; 400];
        let pt = decrypt_record::<Aes128GcmSha256>(
            &FIXTURE_PACKET_3,
            key.as_zeroizing(),
            &iv,
            0,
            &mut pt_buf,
        )
        .unwrap();
        let (content, _) = split_inner_plaintext(pt).unwrap();
        let mut transcript = TranscriptHash::<RustCrypto>::new();
        transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
        transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
        verify_server_flight::<RustCrypto, RustCrypto, RustCrypto>(
            &mut transcript,
            content,
            &make_fixture_s_hs_traffic_secret(),
            &fixture_prepared_ed25519::<RustCrypto>(),
            &fixture_leaf_ed25519(),
        )
        .unwrap();
        let ms = master_secret::<RustCrypto>(&make_fixture_handshake_secret()).unwrap();
        let (c_ap_ts, s_ap_ts) =
            application_traffic_secrets::<RustCrypto>(&ms, &transcript.snapshot()).unwrap();
        let aes_keys = |secret: &Secret| {
            let (k, iv) = traffic_keys::<RustCrypto, 16>(secret).unwrap();
            (AeadKey::new(k), iv)
        };
        (aes_keys(&c_ap_ts), aes_keys(&s_ap_ts))
    }

    /// packets/004_c2s_ClientFinished_encrypted.hex (58 bytes).
    const FIXTURE_PACKET_4: [u8; 58] = crate::hex_decode(include_str!(
        "../../testdata/packets/004_c2s_ClientFinished_encrypted.hex"
    ));

    /// Fixture-bound AES tests: each test decrypts or encrypts a
    /// captured wire fixture generated with AES-128-GCM, so the
    /// cipher choice is intrinsic.
    mod aes_tests {
        use super::*;

        #[test]
        fn fixture_packet_3_decrypts() {
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut buf,
            )
            .expect("decrypt_record");
            assert_eq!(pt.len(), 394);
            assert_eq!(&pt[..32], &FIXTURE_PACKET_3_PLAINTEXT_HEAD);

            let (content, content_type) = split_inner_plaintext(pt).expect("split inner plaintext");
            assert_eq!(content_type, consts::CT_HANDSHAKE);
            assert_eq!(&content[..6], &[0x08, 0x00, 0x00, 0x02, 0x00, 0x00]);
        }

        #[test]
        fn fixture_packet_3_decrypts_full_chain() {
            type Bn = fixed_bigint::FixedUInt<u32, 16, const_num_traits::Ct>;
            let dhe = ed25519_heapless::x25519::<Bn>(
                &FIXTURE_CLIENT_X25519_PRIV,
                &FIXTURE_SERVER_X25519_PUB_2,
            );
            let hs = handshake_secret::<RustCrypto>(&dhe).unwrap();
            let th = {
                let mut t = TranscriptHash::<RustCrypto>::new();
                t.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
                t.update_record(&FIXTURE_SERVER_HELLO).unwrap();
                t.snapshot()
            };
            let (_c_ts, s_ts) = handshake_traffic_secrets::<RustCrypto>(&hs, &th).unwrap();
            let (k, iv) = traffic_keys::<RustCrypto, 16>(&s_ts).unwrap();
            let key = AeadKey::new(k);

            let mut buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut buf,
            )
            .unwrap();
            let (content, content_type) = split_inner_plaintext(pt).unwrap();
            assert_eq!(content_type, consts::CT_HANDSHAKE);
            assert_eq!(&content[..6], &[0x08, 0x00, 0x00, 0x02, 0x00, 0x00]);
        }

        #[test]
        fn fixture_packet_3_server_flight_verifies() {
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut buf,
            )
            .unwrap();
            let (content, _ct) = split_inner_plaintext(pt).unwrap();

            let flight = parse_server_flight(content).expect("parse_server_flight");

            assert_eq!(flight.ee_body, &[0x00, 0x00][..]);

            let cert_der = extract_cert_der(flight.cert_body).expect("extract_cert_der");
            let cert_view = <DerCert as CertParser>::parse(cert_der).expect("parse cert");
            const EXPECTED_SERVER_ID_PUB: [u8; 32] = [
                0x9d, 0xfe, 0x2a, 0xb0, 0x3e, 0x35, 0x70, 0x4b, 0x9c, 0xfb, 0x93, 0xb6, 0x03, 0xa6,
                0x61, 0x18, 0x82, 0x17, 0xa6, 0xb5, 0xfd, 0x6a, 0x1f, 0x75, 0xe6, 0x16, 0x1a, 0x39,
                0xe0, 0x53, 0x4c, 0x3f,
            ];
            match cert_view {
                CertView::Ed25519 { pubkey, .. } => assert_eq!(pubkey, &EXPECTED_SERVER_ID_PUB),
                #[cfg(any(feature = "rsa", feature = "mldsa"))]
                _ => panic!("fixture cert is Ed25519"),
            }

            let view = verify_self_signed_cert::<DerCert, RustCrypto, RustCrypto>(cert_der)
                .expect("cert self-sig");
            let pk = match view {
                CertView::Ed25519 { pubkey, .. } => *pubkey,
                #[cfg(any(feature = "rsa", feature = "mldsa"))]
                _ => panic!("fixture cert is Ed25519"),
            };
            assert_eq!(pk, EXPECTED_SERVER_ID_PUB);

            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            let result = verify_server_flight::<RustCrypto, RustCrypto, RustCrypto>(
                &mut transcript,
                content,
                &make_fixture_s_hs_traffic_secret(),
                &fixture_prepared_ed25519::<RustCrypto>(),
                &fixture_leaf_ed25519(),
            )
            .expect("verify_server_flight");
            assert_eq!(
                result.server_pubkey.as_ed25519(),
                Some(EXPECTED_SERVER_ID_PUB)
            );
        }

        #[test]
        fn ed25519_verify_trait_propagates_to_certificate_verify() {
            // Swap the backend on the prepared verifier — AlwaysReject's
            // `verify` returns Err, so CV must fail with
            // `CertVerifyInvalid`. Confirms `E` flows through to the
            // CV-check path.
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut pt_buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut pt_buf,
            )
            .unwrap();
            let (content, _) = split_inner_plaintext(pt).unwrap();
            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            let err = verify_server_flight::<RustCrypto, AlwaysReject, RustCrypto>(
                &mut transcript,
                content,
                &make_fixture_s_hs_traffic_secret(),
                &fixture_prepared_ed25519::<AlwaysReject>(),
                &fixture_leaf_ed25519(),
            )
            .unwrap_err();
            assert_eq!(err, FlightError::CertVerifyInvalid);
        }

        #[test]
        fn fixture_bad_finished_rejected() {
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut buf,
            )
            .unwrap();
            let (content, _) = split_inner_plaintext(pt).unwrap();

            let mut tampered = [0u8; 400];
            tampered[..content.len()].copy_from_slice(content);
            let last = content.len() - 1;
            tampered[last] ^= 0xFF;

            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            let err = verify_server_flight::<RustCrypto, RustCrypto, RustCrypto>(
                &mut transcript,
                &tampered[..content.len()],
                &make_fixture_s_hs_traffic_secret(),
                &fixture_prepared_ed25519::<RustCrypto>(),
                &fixture_leaf_ed25519(),
            )
            .unwrap_err();
            assert_eq!(err, FlightError::FinishedMacInvalid);
        }

        #[test]
        fn fixture_packet_5_encrypts_byte_identical() {
            let ((c_key, c_iv), _) = application_keys();
            // Regenerated from the c_ap_ts under the RSL-bearing CH transcript
            // with SAN-bearing cert.
            assert_eq!(
                c_key.as_bytes(),
                &[
                    0xe6, 0xfc, 0x45, 0x60, 0x91, 0x90, 0x27, 0x4e, 0x6f, 0xda, 0xae, 0x67, 0xc3,
                    0x06, 0x2f, 0xb0,
                ]
            );
            assert_eq!(
                c_iv.as_bytes(),
                &[
                    0x6f, 0x04, 0xf5, 0xff, 0x3d, 0x43, 0x2a, 0x54, 0x4b, 0xa1, 0x4c, 0xef,
                ]
            );

            let mut out = [0u8; 80];
            let record = encrypt_record::<Aes128GcmSha256>(
                PACKET_5_PLAINTEXT,
                consts::CT_APPLICATION_DATA,
                c_key.as_zeroizing(),
                &c_iv,
                0,
                &mut out,
            )
            .unwrap();
            assert_eq!(record, &FIXTURE_PACKET_5[..]);
        }

        #[test]
        fn fixture_packet_6_decrypts_to_expected_plaintext() {
            let (_, (s_key, s_iv)) = application_keys();
            let mut pt = [0u8; 64];
            let inner = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_6,
                s_key.as_zeroizing(),
                &s_iv,
                0,
                &mut pt,
            )
            .expect("decrypt packet 6");
            let (content, ct) = split_inner_plaintext(inner).unwrap();
            assert_eq!(ct, consts::CT_APPLICATION_DATA);
            assert_eq!(content, PACKET_6_PLAINTEXT);
        }

        #[test]
        fn fixture_client_finished_matches() {
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut pt_buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut pt_buf,
            )
            .unwrap();
            let (content, _ct) = split_inner_plaintext(pt).unwrap();
            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            verify_server_flight::<RustCrypto, RustCrypto, RustCrypto>(
                &mut transcript,
                content,
                &make_fixture_s_hs_traffic_secret(),
                &fixture_prepared_ed25519::<RustCrypto>(),
                &fixture_leaf_ed25519(),
            )
            .unwrap();

            let mut out = [0u8; 64];
            let record = RecordKeys::<Aes128GcmSha256>::build_client_finished::<RustCrypto>(
                &make_fixture_c_hs_traffic_secret(),
                &transcript.snapshot(),
                0,
                &mut out,
            )
            .unwrap();
            assert_eq!(record.len(), CLIENT_FINISHED_LEN);
            assert_eq!(record, &FIXTURE_PACKET_4[..]);
        }

        #[test]
        fn fixture_application_traffic_secrets_match() {
            let ms = master_secret::<RustCrypto>(&make_fixture_handshake_secret()).unwrap();
            // App secrets are keyed on the transcript hash through *server* Finished.
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut pt_buf = [0u8; 400];
            let pt = decrypt_record::<Aes128GcmSha256>(
                &FIXTURE_PACKET_3,
                key.as_zeroizing(),
                &iv,
                0,
                &mut pt_buf,
            )
            .unwrap();
            let (content, _) = split_inner_plaintext(pt).unwrap();
            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_SERVER_HELLO).unwrap();
            verify_server_flight::<RustCrypto, RustCrypto, RustCrypto>(
                &mut transcript,
                content,
                &make_fixture_s_hs_traffic_secret(),
                &fixture_prepared_ed25519::<RustCrypto>(),
                &fixture_leaf_ed25519(),
            )
            .unwrap();

            let (c_ap, s_ap) =
                application_traffic_secrets::<RustCrypto>(&ms, &transcript.snapshot()).unwrap();

            // From tls_fixture/state/client.json `c_ap_ts` / `s_ap_ts` at seed 0.
            const FIXTURE_C_AP_BYTES: [u8; 32] = [
                0x54, 0x1a, 0xd5, 0xfc, 0xef, 0x9e, 0x66, 0x5f, 0x2b, 0x1b, 0xdb, 0x37, 0xfc, 0x05,
                0xd6, 0xcf, 0x94, 0x8f, 0x4a, 0x10, 0xda, 0x18, 0xe0, 0x9f, 0x57, 0x10, 0x48, 0x5b,
                0xf4, 0xf6, 0x64, 0x88,
            ];
            const FIXTURE_S_AP_BYTES: [u8; 32] = [
                0xa1, 0x04, 0xee, 0xae, 0xe6, 0xfa, 0x92, 0x7c, 0x2a, 0x64, 0xbd, 0x79, 0x86, 0xcb,
                0xac, 0xeb, 0x40, 0xa1, 0x69, 0xcf, 0x3a, 0xfb, 0x8c, 0xa0, 0x1a, 0x67, 0x13, 0xdb,
                0xa7, 0x04, 0xb5, 0x65,
            ];
            assert_eq!(c_ap.as_bytes(), &FIXTURE_C_AP_BYTES);
            assert_eq!(s_ap.as_bytes(), &FIXTURE_S_AP_BYTES);
        }

        #[test]
        fn bad_tag_returns_aead_failed() {
            let key = make_fixture_s_hs_key();
            let iv = make_fixture_s_hs_iv();
            let mut tampered = [0u8; 415];
            tampered.copy_from_slice(&FIXTURE_PACKET_3);
            let last = tampered.len() - 1;
            tampered[last] ^= 0xFF; // corrupt the auth tag
            let mut buf = [0u8; 400];
            // Pre-fill with a sentinel; the function should overwrite the
            // ciphertext window with zeroes on AEAD failure.
            buf.fill(0xAA);
            let err =
                decrypt_record::<Aes128GcmSha256>(&tampered, key.as_zeroizing(), &iv, 0, &mut buf)
                    .unwrap_err();
            assert_eq!(err, DecryptError::AeadFailed);

            // The bytes in the ciphertext window (record body minus 16-byte tag)
            // must be zeroed — RFC says callers MUST NOT use the buffer on
            // error, and we defensively zero it. Bytes outside that window
            // (anything beyond ct_len) are left alone, since `decrypt_record`
            // is documented to write only the `[..ct_len]` prefix.
            let body_len = u16::from_be_bytes([tampered[3], tampered[4]]) as usize;
            let ct_len = body_len - 16;
            assert!(
                buf[..ct_len].iter().all(|&b| b == 0),
                "ciphertext window must be zeroed on AeadFailed"
            );
            assert!(
                buf[ct_len..].iter().all(|&b| b == 0xAA),
                "bytes past ct_len must be untouched"
            );
        }
    }

    #[cfg(all(feature = "rsa", not(feature = "rsa_pss_only")))]
    mod rsa_tests {
        use super::*;

        /// RSA fixture, c→s ClientHello.
        const FIXTURE_RSA_CLIENT_HELLO: [u8; 151] = crate::hex_decode(include_str!(
            "../../testdata/packets_rsa/001_c2s_ClientHello.hex"
        ));
        /// RSA fixture, s→c ServerHello.
        const FIXTURE_RSA_SERVER_HELLO: [u8; 95] = crate::hex_decode(include_str!(
            "../../testdata/packets_rsa/002_s2c_ServerHello.hex"
        ));
        /// RSA fixture, encrypted server flight (dominated by the
        /// 2048-bit RSA cert + 256-byte RSA-PSS signature).
        const FIXTURE_RSA_PACKET_3: [u8; 1362] = crate::hex_decode(include_str!(
            "../../testdata/packets_rsa/003_s2c_ServerFlight_encrypted.hex"
        ));

        /// Server handshake traffic secret for the RSA fixture, recovered from
        /// the capture server's `SSLKEYLOG` (`SERVER_HANDSHAKE_TRAFFIC_SECRET`
        /// for the seed-0 client_random).
        const FIXTURE_RSA_S_HS_TRAFFIC_SECRET_BYTES: [u8; 32] = [
            0xb4, 0x09, 0xa4, 0x3e, 0xa8, 0xd5, 0x9a, 0x22, 0x87, 0x31, 0x36, 0x5b, 0x09, 0x15,
            0xaf, 0x59, 0xe8, 0xc2, 0xc9, 0xfb, 0x00, 0xa5, 0xc3, 0x36, 0x25, 0xe9, 0x30, 0xae,
            0x2b, 0x97, 0x9b, 0x15,
        ];

        fn s_hs_traffic_secret() -> Secret {
            Secret::new(ZeroBuf::<32>::new(FIXTURE_RSA_S_HS_TRAFFIC_SECRET_BYTES))
        }

        /// The capture server fragments the flight across several records;
        /// decrypt each (seq 0, 1, …) and concatenate the inner handshake
        /// plaintext. Fails fast on a truncated or under-consumed fixture.
        fn decrypt_rsa_flight() -> Vec<u8> {
            let s_hs_ts = s_hs_traffic_secret();
            let (k, iv) = traffic_keys::<RustCrypto, 16>(&s_hs_ts).expect("traffic_keys");
            let key = AeadKey::new(k);
            let mut flight = Vec::new();
            let mut remaining = &FIXTURE_RSA_PACKET_3[..];
            let mut seq = 0u64;
            while remaining.len() >= 5 {
                let rec_len = 5 + u16::from_be_bytes([remaining[3], remaining[4]]) as usize;
                let (rec, rest) = remaining
                    .split_at_checked(rec_len)
                    .expect("truncated TLS record in RSA fixture");
                let mut pt_buf = [0u8; 1024];
                let pt = decrypt_record::<Aes128GcmSha256>(
                    rec,
                    key.as_zeroizing(),
                    &iv,
                    seq,
                    &mut pt_buf,
                )
                .expect("decrypt packets_rsa/003 record");
                let (content, ct) = split_inner_plaintext(pt).unwrap();
                assert_eq!(ct, consts::CT_HANDSHAKE);
                flight.extend_from_slice(content);
                remaining = rest;
                seq += 1;
            }
            assert!(remaining.is_empty(), "trailing bytes left in RSA fixture");
            flight
        }

        #[test]
        fn fixture_rsa_server_flight_verifies() {
            let s_hs_ts = s_hs_traffic_secret();
            let content = decrypt_rsa_flight();
            let content = content.as_slice();

            // Build the RSA prepared verifier directly from the leaf.
            let flight_pre = parse_server_flight(content).expect("parse_server_flight");
            let leaf_der = extract_cert_der(flight_pre.cert_body).expect("extract_cert_der");
            let leaf_view = <DerCert as CertParser>::parse(leaf_der).expect("parse RSA leaf");
            let prepared = match &leaf_view {
                CertView::Rsa {
                    modulus, exponent, ..
                } => PreparedVerifier::Rsa(
                    <RustCrypto as crate::traits::RsaVerifierProvider>::prepare_rsa(
                        modulus, *exponent,
                    )
                    .expect("prepare_rsa"),
                ),
                _ => panic!("fixture is RSA"),
            };

            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&FIXTURE_RSA_CLIENT_HELLO).unwrap();
            transcript.update_record(&FIXTURE_RSA_SERVER_HELLO).unwrap();
            verify_server_flight::<RustCrypto, RustCrypto, RustCrypto>(
                &mut transcript,
                content,
                &s_hs_ts,
                &prepared,
                &leaf_view,
            )
            .expect("verify RSA server flight");
        }

        #[test]
        fn rsa_verify_rejects_wrong_signature_length() {
            // `FixedUInt::from_be_bytes` requires an exact-length slice; the
            // RSA verify APIs must guard against wrong-length input and
            // return `RsaVerifyError` instead of panicking.
            let modulus_2048 = [0xFFu8; 256];
            let exponent: u32 = 65537;
            let vk = RsaVerifierKey::new(&modulus_2048, exponent).expect("vk");
            let short_sig = [0u8; 200];
            assert!(vk.verify_pkcs1v15_sha256(b"msg", &short_sig).is_err());
            assert!(vk.verify_pss_sha256(b"msg", &short_sig).is_err());
        }

        #[test]
        fn fixture_rsa_cert_parses_as_rsa_view() {
            let flight_buf = decrypt_rsa_flight();
            let flight = parse_server_flight(&flight_buf).unwrap();
            let cert_der = extract_cert_der(flight.cert_body).unwrap();
            let view = <DerCert as CertParser>::parse(cert_der).expect("RSA cert parses");
            match view {
                CertView::Rsa {
                    modulus, exponent, ..
                } => {
                    assert_eq!(modulus.len(), 256, "RSA-2048 modulus is 256 bytes");
                    assert_eq!(exponent, 65537, "fixture priv uses e=65537");
                }
                _ => panic!("expected CertView::Rsa, got {:?}", view),
            }
        }
    }
}

/// X25519MLKEM768 hybrid key-exchange wiring: the ClientHello key_share framing
/// and the ServerHello key_share split. The combined-secret derivation is
/// validated end-to-end against a real server in the canned-handshake follow-up.
#[cfg(feature = "mlkem")]
mod mlkem_keyshare {
    use super::*;
    use crate::backends::mlkem::{MLKEM768_CT_BYTES, MLKEM768_EK_BYTES};

    #[test]
    fn client_hello_advertises_x25519mlkem768_key_share() {
        let random = [0x11u8; 32];
        let x25519_pub = [0x22u8; 32];
        let ek = [0x33u8; MLKEM768_EK_BYTES];
        let opts = ClientHelloOptions {
            hostname: None,
            record_size_limit: None,
            suites: SuiteList::Default,
            mlkem_ek: Some(&ek),
        };
        let mut buf = [0u8; 2048];
        let mut cursor: &mut [u8] = &mut buf;
        let n = write_client_hello_with(&mut cursor, &random, &x25519_pub, &opts).unwrap();
        let ch = &buf[..n];

        // key_share entry: group(0x11EC) || key_len(1216) || ek || x25519_pub.
        let mut needle = Vec::new();
        needle.extend_from_slice(&NAMED_GROUP_X25519MLKEM768.to_be_bytes());
        needle.extend_from_slice(&(1216u16).to_be_bytes());
        needle.extend_from_slice(&ek);
        needle.extend_from_slice(&x25519_pub);
        assert_eq!(
            ch.windows(needle.len())
                .filter(|w| *w == needle.as_slice())
                .count(),
            1,
            "ClientHello must carry exactly one X25519MLKEM768 key_share (ML-KEM ek first)"
        );
        // supported_groups advertises only the hybrid group.
        assert!(
            !ch.windows(2).any(|w| w == NAMED_GROUP_X25519.to_be_bytes()),
            "must not advertise plain X25519 under mlkem"
        );
    }

    /// The 1216-byte hybrid key_share resizes the ClientHello; this is the only
    /// direct guard that `CLIENT_HELLO_LEN` still tracks the writer exactly (and
    /// that one byte short is rejected) under `mlkem`.
    #[test]
    fn client_hello_fits_exact_buffer_and_rejects_short() {
        let random = [0x11u8; 32];
        let x25519_pub = [0x22u8; 32];
        let ek = [0x33u8; MLKEM768_EK_BYTES];
        let opts = ClientHelloOptions {
            hostname: None,
            record_size_limit: None,
            suites: SuiteList::Default,
            mlkem_ek: Some(&ek),
        };

        let mut exact = [0u8; CLIENT_HELLO_LEN];
        let mut cursor: &mut [u8] = &mut exact;
        write_client_hello_with(&mut cursor, &random, &x25519_pub, &opts).unwrap();
        assert!(cursor.is_empty(), "must fully consume CLIENT_HELLO_LEN");

        let mut short = [0u8; CLIENT_HELLO_LEN - 1];
        let mut cursor: &mut [u8] = &mut short;
        let err = write_client_hello_with(&mut cursor, &random, &x25519_pub, &opts).unwrap_err();
        assert_eq!(err, ClientHelloError::Write(SliceWriteError::Full));
    }

    /// Build a complete ServerHello record with a hybrid key_share = ct || x25519.
    fn hybrid_server_hello(ct: &[u8; MLKEM768_CT_BYTES], x25519: &[u8; 32]) -> Vec<u8> {
        let mut ext = Vec::new();
        // supported_versions (TLS 1.3)
        ext.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.extend_from_slice(&TLS_1_3.to_be_bytes());
        // key_share: group || key (ct || x25519)
        let mut key = Vec::new();
        key.extend_from_slice(ct);
        key.extend_from_slice(x25519);
        ext.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        ext.extend_from_slice(&((2 + 2 + key.len()) as u16).to_be_bytes()); // ext_data
        ext.extend_from_slice(&NAMED_GROUP_X25519MLKEM768.to_be_bytes());
        ext.extend_from_slice(&(key.len() as u16).to_be_bytes());
        ext.extend_from_slice(&key);

        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
        hs_body.extend_from_slice(&[0x42u8; 32]); // random (not HRR/downgrade)
        hs_body.push(0); // empty session_id echo
        hs_body.extend_from_slice(&CIPHER_AES_128_GCM_SHA256.to_be_bytes());
        hs_body.push(0); // compression
        hs_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&ext);

        let mut record_body = Vec::new();
        record_body.push(HS_SERVER_HELLO);
        let l = hs_body.len() as u32;
        record_body.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        record_body.extend_from_slice(&hs_body);

        let mut record = Vec::new();
        record.push(CT_HANDSHAKE);
        record.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
        record.extend_from_slice(&(record_body.len() as u16).to_be_bytes());
        record.extend_from_slice(&record_body);
        record
    }

    #[test]
    fn parse_splits_hybrid_server_key_share() {
        let ct = [0xAAu8; MLKEM768_CT_BYTES];
        let x25519 = [0xBBu8; 32];
        let sh = hybrid_server_hello(&ct, &x25519);
        let v = parse_server_hello(&sh).expect("parse hybrid ServerHello");
        assert_eq!(
            v.mlkem_ct, &ct,
            "ML-KEM ciphertext is the leading 1088 bytes"
        );
        assert_eq!(
            v.x25519_share, &x25519,
            "X25519 share is the trailing 32 bytes"
        );
    }

    #[test]
    fn parse_rejects_short_hybrid_key_share() {
        // The hybrid group carrying only a 32-byte key (no room for the ML-KEM
        // ciphertext) must fail the ct||x25519 split.
        let short = {
            let mut ext = Vec::new();
            ext.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
            ext.extend_from_slice(&2u16.to_be_bytes());
            ext.extend_from_slice(&TLS_1_3.to_be_bytes());
            ext.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
            ext.extend_from_slice(&(2u16 + 2 + 32).to_be_bytes());
            ext.extend_from_slice(&NAMED_GROUP_X25519MLKEM768.to_be_bytes());
            ext.extend_from_slice(&32u16.to_be_bytes());
            ext.extend_from_slice(&[0u8; 32]);
            let mut hb = Vec::new();
            hb.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
            hb.extend_from_slice(&[0x42u8; 32]);
            hb.push(0);
            hb.extend_from_slice(&CIPHER_AES_128_GCM_SHA256.to_be_bytes());
            hb.push(0);
            hb.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            hb.extend_from_slice(&ext);
            let mut rb = vec![HS_SERVER_HELLO];
            let l = hb.len() as u32;
            rb.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
            rb.extend_from_slice(&hb);
            let mut r = vec![CT_HANDSHAKE];
            r.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
            r.extend_from_slice(&(rb.len() as u16).to_be_bytes());
            r.extend_from_slice(&rb);
            r
        };
        assert_eq!(parse_server_hello(&short), Err(ParseError::BadKeyShare));
    }
}
