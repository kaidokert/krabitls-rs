#[cfg(any(
    all(not(feature = "rsa"), not(feature = "chacha20")),
    all(feature = "cipher-aes", feature = "chacha20", not(feature = "mlkem"))
))]
use super::*;
#[cfg(any(
    all(
        not(feature = "rsa"),
        not(feature = "chacha20"),
        not(feature = "mldsa"),
        not(feature = "ecdsa"),
        not(feature = "mlkem")
    ),
    all(feature = "cipher-aes", feature = "chacha20", not(feature = "mlkem"))
))]
use crate::backends::RustCrypto;

// Seed-0 fixtures duplicated from `lib.rs` — keep in sync.
#[cfg(any(
    all(
        not(feature = "rsa"),
        not(feature = "chacha20"),
        not(feature = "mldsa"),
        not(feature = "ecdsa"),
        not(feature = "mlkem")
    ),
    all(feature = "cipher-aes", feature = "chacha20", not(feature = "mlkem"))
))]
const FIXTURE_RANDOM: [u8; 32] = [
    0xed, 0xe5, 0x7b, 0xa2, 0x43, 0x3a, 0xd5, 0xa3, 0x4d, 0x05, 0x50, 0x3a, 0xfe, 0x4f, 0xc2, 0x89,
    0xdf, 0xd9, 0xe9, 0x53, 0x57, 0xd8, 0x16, 0x36, 0x80, 0x24, 0xe7, 0x3f, 0xbf, 0xa6, 0xfa, 0xf5,
];
#[cfg(any(
    all(
        not(feature = "rsa"),
        not(feature = "chacha20"),
        not(feature = "mldsa"),
        not(feature = "ecdsa"),
        not(feature = "mlkem")
    ),
    all(feature = "cipher-aes", feature = "chacha20", not(feature = "mlkem"))
))]
const FIXTURE_X25519_PUB: [u8; 32] = [
    0x82, 0x46, 0xe7, 0x35, 0x8f, 0x0a, 0xf7, 0xf3, 0x31, 0x7d, 0xca, 0xf6, 0x88, 0xd0, 0x34, 0xc9,
    0x5d, 0x5a, 0x2b, 0x54, 0xbf, 0x66, 0xc8, 0x95, 0x0e, 0xb8, 0x7a, 0x5f, 0x47, 0x93, 0x96, 0x0d,
];
#[cfg(any(
    all(
        not(feature = "rsa"),
        not(feature = "chacha20"),
        not(feature = "mldsa"),
        not(feature = "ecdsa"),
        not(feature = "mlkem")
    ),
    all(feature = "cipher-aes", feature = "chacha20", not(feature = "mlkem"))
))]
const FIXTURE_CLIENT_X25519_PRIV: [u8; 32] = [
    0xac, 0xe1, 0xc2, 0x3b, 0x24, 0xdf, 0xad, 0x58, 0xc5, 0x4c, 0xcf, 0x4c, 0x1f, 0xe8, 0xdf, 0xe8,
    0x5e, 0x76, 0x0e, 0x02, 0x3b, 0x6c, 0xb6, 0x02, 0x2f, 0x70, 0x0f, 0x34, 0xde, 0x4c, 0x28, 0x28,
];

// The cipher-suite narrowing is key_share-independent; gated off `mlkem` so the
// struct-literal `ClientHelloOptions` / two-arg `new()` stay valid (both gain an
// ML-KEM field/param under `mlkem`). Covered by the non-`mlkem` matrix.
#[cfg(all(feature = "cipher-aes", feature = "chacha20", not(feature = "mlkem")))]
#[test]
fn write_client_hello_with_aes_only_narrows_cipher_suites() {
    let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
    let conn_default: TlsConnection<Init, RustCrypto> =
        TlsConnection::new(FIXTURE_RANDOM, priv_zb.clone());
    let mut out_default = [0u8; 256];
    let (written_default, _) = conn_default
        .write_client_hello_to_slice_with(
            &mut out_default[..],
            &FIXTURE_X25519_PUB,
            &crate::ClientHelloOptions::legacy(),
        )
        .expect("default");

    let conn_aes: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
    let mut out_aes = [0u8; 256];
    let aes_opts = crate::ClientHelloOptions {
        hostname: None,
        record_size_limit: None,
        session_id: None,
        alpn: None,
        suites: crate::SuiteList::AesOnly,
    };
    let (written_aes, _) = conn_aes
        .write_client_hello_to_slice_with(&mut out_aes[..], &FIXTURE_X25519_PUB, &aes_opts)
        .expect("aes-only");

    assert_eq!(written_aes + 2, written_default);
    let aes_bytes = &out_aes[..written_aes];
    assert!(
        !aes_bytes.windows(2).any(|w| w == [0x13, 0x03]),
        "AES-only CH still advertises ChaCha suite",
    );
    assert!(
        aes_bytes.windows(2).any(|w| w == [0x13, 0x01]),
        "AES-only CH missing AES suite",
    );
}

// Tests asserting byte-exact AES-128-GCM / Ed25519 fixtures. Grouped under
// one gate (the seed-0 wire bytes only match an AES+Ed25519, no-RSA build).
#[cfg(all(
    not(feature = "rsa"),
    not(feature = "chacha20"),
    not(feature = "mldsa"),
    not(feature = "ecdsa"),
    not(feature = "mlkem")
))]
mod aes_only {
    use super::*;
    use crate::aead::Aes128GcmSha256;
    use crate::consts::{CT_APPLICATION_DATA, CT_HANDSHAKE, HS_KEY_UPDATE};
    use crate::reassembler::ServerFlightReassembler;

    /// Matches `testdata/packets/001_c2s_ClientHello.hex` (RFC 8449 RSL=16385).
    const FIXTURE_CLIENT_HELLO: [u8; 149] = [
        0x16, 0x03, 0x03, 0x00, 0x90, 0x01, 0x00, 0x00, 0x8c, 0x03, 0x03, 0xed, 0xe5, 0x7b, 0xa2,
        0x43, 0x3a, 0xd5, 0xa3, 0x4d, 0x05, 0x50, 0x3a, 0xfe, 0x4f, 0xc2, 0x89, 0xdf, 0xd9, 0xe9,
        0x53, 0x57, 0xd8, 0x16, 0x36, 0x80, 0x24, 0xe7, 0x3f, 0xbf, 0xa6, 0xfa, 0xf5, 0x00, 0x00,
        0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x61, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
        0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07,
        0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x00, 0x00, 0x11, 0x74, 0x6c, 0x73, 0x2d, 0x66, 0x69,
        0x78, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x1c, 0x00, 0x02,
        0x40, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x82, 0x46, 0xe7,
        0x35, 0x8f, 0x0a, 0xf7, 0xf3, 0x31, 0x7d, 0xca, 0xf6, 0x88, 0xd0, 0x34, 0xc9, 0x5d, 0x5a,
        0x2b, 0x54, 0xbf, 0x66, 0xc8, 0x95, 0x0e, 0xb8, 0x7a, 0x5f, 0x47, 0x93, 0x96, 0x0d,
    ];

    /// Matches `FIXTURE_CLIENT_HELLO`: RSL=16385, SNI=`tls-fixture.local`.
    fn fixture_opts() -> crate::ClientHelloOptions<'static> {
        crate::ClientHelloOptions {
            hostname: Some(b"tls-fixture.local"),
            record_size_limit: Some(16385),
            session_id: None,
            alpn: None,
            suites: crate::SuiteList::Default,
        }
    }

    const FIXTURE_SERVER_HELLO: [u8; 95] = [
        0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0x64, 0x1c, 0x5b, 0xd9,
        0x34, 0xab, 0xe1, 0xc5, 0x98, 0xa9, 0xc9, 0x61, 0xf7, 0xcb, 0x1e, 0x06, 0x28, 0x0b, 0x4a,
        0x5e, 0x88, 0x0c, 0x1c, 0x19, 0xd2, 0xfe, 0x9e, 0xef, 0x33, 0x48, 0x0c, 0xae, 0x00, 0x13,
        0x01, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00,
        0x1d, 0x00, 0x20, 0x60, 0x4d, 0x7a, 0x17, 0x18, 0x38, 0xbd, 0xa2, 0x15, 0xd2, 0xb5, 0x4a,
        0x24, 0xfb, 0x7d, 0x3a, 0x88, 0x8d, 0xa5, 0xac, 0x36, 0x72, 0x72, 0x6d, 0x20, 0x06, 0x44,
        0x04, 0xf7, 0x06, 0xdb, 0x7e,
    ];

    /// One 415-byte AEAD record carrying the full seed-0 server flight.
    const FIXTURE_PACKET_3: [u8; 415] = crate::hex_decode(include_str!(
        "../../../testdata/packets/003_s2c_ServerFlight_encrypted.hex"
    ));

    /// Ed25519 pubkey in the seed-0 self-signed cert.
    const EXPECTED_SERVER_ID_PUB: [u8; 32] = [
        0x9d, 0xfe, 0x2a, 0xb0, 0x3e, 0x35, 0x70, 0x4b, 0x9c, 0xfb, 0x93, 0xb6, 0x03, 0xa6, 0x61,
        0x18, 0x82, 0x17, 0xa6, 0xb5, 0xfd, 0x6a, 0x1f, 0x75, 0xe6, 0x16, 0x1a, 0x39, 0xe0, 0x53,
        0x4c, 0x3f,
    ];

    fn fixture_prepared() -> PreparedVerifier<RustCrypto, RustCrypto> {
        PreparedVerifier::ed25519(<RustCrypto as Ed25519VerifierProvider>::prepare_ed25519(
            &EXPECTED_SERVER_ID_PUB,
        ))
    }

    fn fixture_leaf_view() -> CertView<'static> {
        CertView::Ed25519 {
            tbs: &[],
            signature: &[0u8; 64],
            pubkey: &EXPECTED_SERVER_ID_PUB,
            san: None,
            validity_der: &[],
        }
    }

    /// Seed-0 client Finished, 58 B (= [`CLIENT_FINISHED_LEN`]).
    const FIXTURE_PACKET_4: [u8; 58] = crate::hex_decode(include_str!(
        "../../../testdata/packets/004_c2s_ClientFinished_encrypted.hex"
    ));

    /// First c->s app-data record under seed-0 c_ap.
    const FIXTURE_PACKET_5: [u8; 52] = crate::hex_decode(include_str!(
        "../../../testdata/packets/005_c2s_AppData_send_0.hex"
    ));

    /// First s->c app-data record under seed-0 s_ap.
    const FIXTURE_PACKET_6: [u8; 48] = crate::hex_decode(include_str!(
        "../../../testdata/packets/006_s2c_AppData_reply_0.hex"
    ));

    const PACKET_5_PLAINTEXT: &[u8] = b"hello from the embedded client";

    const PACKET_6_PLAINTEXT: &[u8] = b"hello back \xe2\x80\x94 server here";

    #[test]
    fn write_client_hello_with_legacy_opts_emits_no_rsl_extension() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out = [0u8; 256];
        let (written, _next) = conn
            .write_client_hello_to_slice_with(
                &mut out[..],
                &FIXTURE_X25519_PUB,
                &crate::ClientHelloOptions::legacy(),
            )
            .expect("write_client_hello_to_slice_with");
        assert_eq!(written, crate::CLIENT_HELLO_LEN);
        // RSL extension type bytes (0x00 0x1c) must be absent.
        let needle = [0x00u8, 0x1c];
        let haystack = &out[..written];
        assert!(
            !haystack.windows(2).any(|w| w == needle),
            "legacy opts unexpectedly emitted the RSL extension type bytes",
        );
    }

    #[test]
    fn write_client_hello_with_record_size_limit_extension_present() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out = [0u8; 256];
        let opts = crate::ClientHelloOptions {
            hostname: None,
            record_size_limit: Some(8192),
            session_id: None,
            alpn: None,
            suites: crate::SuiteList::Default,
        };
        let (written, _next) = conn
            .write_client_hello_to_slice_with(&mut out[..], &FIXTURE_X25519_PUB, &opts)
            .expect("write_client_hello_to_slice_with");
        // +6 vs legacy = 4-byte ext header + 2-byte u16 value.
        assert_eq!(written, crate::CLIENT_HELLO_LEN + 6);
        // 8192 = 0x2000.
        let needle = [0x00, 0x1c, 0x00, 0x02, 0x20, 0x00];
        let haystack = &out[..written];
        assert!(
            haystack.windows(needle.len()).any(|w| w == needle),
            "record_size_limit extension bytes not found",
        );
    }

    #[test]
    fn init_writes_byte_identical_client_hello() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        const BUF_LEN: usize = 256;
        let mut out = [0u8; BUF_LEN];
        let written = {
            let mut cursor: &mut [u8] = &mut out[..];
            let _conn = conn
                .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
                .expect("write_client_hello_with");
            BUF_LEN - cursor.len()
        };
        assert_eq!(written, FIXTURE_CLIENT_HELLO.len());
        assert_eq!(&out[..written], &FIXTURE_CLIENT_HELLO);
    }

    #[test]
    fn read_server_hello_lands_on_aes_variant() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();

        let negotiated = conn.read_server_hello(&FIXTURE_SERVER_HELLO).unwrap();
        match negotiated {
            #[cfg(feature = "cipher-aes")]
            NegotiatedSuite::Aes128Gcm(_) => {}
            #[allow(unreachable_patterns)]
            _ => panic!("expected AES-128-GCM variant"),
        }
    }

    /// Splice `echo` into the fixture ServerHello as its `legacy_session_id_echo`
    /// (the fixture's own is empty), fixing the record + handshake length
    /// prefixes so the rest of the message stays valid.
    fn server_hello_echoing(echo: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(FIXTURE_SERVER_HELLO.len() + echo.len());
        out.extend_from_slice(&FIXTURE_SERVER_HELLO[..43]);
        out.push(echo.len() as u8);
        out.extend_from_slice(echo);
        out.extend_from_slice(&FIXTURE_SERVER_HELLO[44..]);
        let rec_len = (out.len() - 5) as u16;
        out[3..5].copy_from_slice(&rec_len.to_be_bytes());
        let hs_len = (out.len() - 9) as u32;
        out[6..9].copy_from_slice(&hs_len.to_be_bytes()[1..]);
        out
    }

    fn write_ch_then_read_sh(
        session_id: Option<&[u8; 32]>,
        sh: &[u8],
    ) -> Result<NegotiatedSuite<RustCrypto>, ConnectionError> {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let opts = crate::ClientHelloOptions {
            session_id,
            ..fixture_opts()
        };
        let mut out = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &opts)
            .unwrap();
        conn.read_server_hello(sh)
    }

    #[test]
    fn client_hello_carries_32_byte_session_id_when_enabled() {
        const ID: [u8; 32] = [0x5a; 32];
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let opts = crate::ClientHelloOptions {
            session_id: Some(&ID),
            ..fixture_opts()
        };
        let mut out = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out[..];
        conn.write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &opts)
            .unwrap();
        // record(5) + hs header(4) + legacy_version(2) + random(32) => the
        // session_id length byte sits at offset 43, its 32 bytes at 44..76.
        assert_eq!(out[43], 32);
        assert_eq!(&out[44..76], &ID);
    }

    #[test]
    fn client_hello_carries_alpn_extension() {
        const PROTOS: [&[u8]; 1] = [b"h2"];
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let opts = crate::ClientHelloOptions {
            alpn: Some(&PROTOS),
            ..fixture_opts()
        };
        let mut out = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out[..];
        conn.write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &opts)
            .unwrap();
        let n = 256 - cursor.len();
        // ext type 0x0010 | ext_data_len 0x0005 | list_len 0x0003 | name_len
        // 0x02 | "h2".
        let needle = b"\x00\x10\x00\x05\x00\x03\x02h2";
        assert!(
            out[..n].windows(needle.len()).any(|w| w == needle),
            "ALPN extension not found on the wire",
        );
    }

    #[test]
    fn server_hello_matching_session_id_echo_accepted() {
        let id = [0xab; 32];
        let sh = server_hello_echoing(&id);
        let negotiated = write_ch_then_read_sh(Some(&id), &sh).expect("matching echo accepted");
        match negotiated {
            #[cfg(feature = "cipher-aes")]
            NegotiatedSuite::Aes128Gcm(_) => {}
            #[allow(unreachable_patterns)]
            _ => panic!("expected AES-128-GCM variant"),
        }
    }

    #[test]
    fn server_hello_mismatched_session_id_echo_rejected() {
        let sent = [0xab; 32];
        let sh = server_hello_echoing(&[0xcd; 32]);
        assert!(matches!(
            write_ch_then_read_sh(Some(&sent), &sh),
            Err(ConnectionError::Parse(ParseError::UnexpectedSessionIdEcho)),
        ));
    }

    #[test]
    fn server_hello_empty_echo_rejected_when_we_sent_an_id() {
        // We sent 32 bytes; an empty echo (the fixture's own) must abort.
        assert!(matches!(
            write_ch_then_read_sh(Some(&[0xab; 32]), &FIXTURE_SERVER_HELLO),
            Err(ConnectionError::Parse(ParseError::UnexpectedSessionIdEcho)),
        ));
    }

    #[test]
    fn server_hello_nonempty_echo_rejected_when_we_sent_none() {
        // Guards the default (empty-id) profile: we sent an empty id, so any
        // non-empty echo means the ServerHello isn't ours.
        let sh = server_hello_echoing(&[0xab; 1]);
        assert!(matches!(
            write_ch_then_read_sh(None, &sh),
            Err(ConnectionError::Parse(ParseError::UnexpectedSessionIdEcho)),
        ));
    }

    #[test]
    fn feed_server_record_and_finalize_smoke() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let mut conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();

        let mut reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut scratch = [0u8; 400];
        let step = conn
            .feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .expect("feed_server_record");
        assert_eq!(step, FlightStep::Ready);

        let done = conn
            .finalize_server_flight::<512, RustCrypto, RustCrypto>(
                &reassembler,
                &fixture_prepared(),
                &fixture_leaf_view(),
            )
            .expect("finalize_server_flight");
        match &done.state.server_pubkey {
            ServerPubkeyOwned::Ed25519(pk) => assert_eq!(pk, &EXPECTED_SERVER_ID_PUB),
            #[cfg(feature = "rsa")]
            ServerPubkeyOwned::Rsa { .. } => panic!("expected Ed25519 pubkey"),
            #[cfg(feature = "mldsa")]
            ServerPubkeyOwned::MlDsa(_) => panic!("expected Ed25519 pubkey"),
            #[cfg(feature = "ecdsa")]
            ServerPubkeyOwned::EcdsaP256(_) | ServerPubkeyOwned::EcdsaP384(_) => {
                panic!("expected Ed25519 pubkey")
            }
        }
    }

    #[test]
    fn finalize_without_flight_is_incomplete() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();

        let reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let err = match conn.finalize_server_flight::<512, RustCrypto, RustCrypto>(
            &reassembler,
            &fixture_prepared(),
            &fixture_leaf_view(),
        ) {
            Ok(_) => panic!("expected IncompleteFlight"),
            Err(e) => e,
        };
        assert_eq!(err, ConnectionError::IncompleteFlight);
    }

    #[test]
    fn feed_server_record_skips_ccs_without_bumping_seq() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let mut conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();

        let mut reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut scratch = [0u8; 400];

        // Middlebox-compat CCS.
        let ccs_record = [0x14u8, 0x03, 0x03, 0x00, 0x01, 0x01];
        let step = conn
            .feed_server_record(&ccs_record, &mut reassembler, &mut scratch)
            .unwrap();
        assert_eq!(step, FlightStep::Pending);
        assert_eq!(conn.state.seq_in, 0);

        let step = conn
            .feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .unwrap();
        assert_eq!(step, FlightStep::Ready);
        assert_eq!(conn.state.seq_in, 1);
    }

    #[test]
    fn feed_server_record_inplace_matches_copying() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let mut conn_copy = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();
        let mut copy_reasm: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut scratch = [0u8; 400];
        let step_copy = conn_copy
            .feed_server_record(&FIXTURE_PACKET_3, &mut copy_reasm, &mut scratch)
            .unwrap();
        let seq_copy = conn_copy.state.seq_in;

        // Separate TlsConnection so we can compare seq_in.
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let mut conn_inplace = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();
        let mut inplace_reasm: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut record_buf = FIXTURE_PACKET_3;
        let step_inplace = conn_inplace
            .feed_server_record_inplace(&mut record_buf[..], &mut inplace_reasm)
            .unwrap();

        assert_eq!(step_copy, step_inplace);
        assert_eq!(seq_copy, conn_inplace.state.seq_in);
        assert_eq!(copy_reasm.flight_bytes(), inplace_reasm.flight_bytes());
    }

    #[test]
    fn feed_server_record_inplace_skips_ccs_without_bumping_seq() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let mut conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();

        let mut reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut ccs_record = [0x14u8, 0x03, 0x03, 0x00, 0x01, 0x01];
        let step = conn
            .feed_server_record_inplace(&mut ccs_record, &mut reassembler)
            .unwrap();
        assert_eq!(step, FlightStep::Pending);
        assert_eq!(conn.state.seq_in, 0);

        let mut flight = FIXTURE_PACKET_3;
        let step = conn
            .feed_server_record_inplace(&mut flight[..], &mut reassembler)
            .unwrap();
        assert_eq!(step, FlightStep::Ready);
        assert_eq!(conn.state.seq_in, 1);
    }

    #[test]
    fn finish_handshake_byte_identical_client_finished() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let mut conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();
        let mut reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut scratch = [0u8; 400];
        conn.feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .unwrap();
        let conn = conn
            .finalize_server_flight::<512, RustCrypto, RustCrypto>(
                &reassembler,
                &fixture_prepared(),
                &fixture_leaf_view(),
            )
            .unwrap();

        let mut fin_buf = [0u8; 64];
        let (fin_record, _conn) = conn.finish_handshake(&mut fin_buf).unwrap();
        assert_eq!(fin_record, &FIXTURE_PACKET_4[..]);
    }

    #[test]
    fn app_data_encrypt_record_byte_identical_packet_5() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut ch_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut ch_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let mut conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();
        let mut reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut scratch = [0u8; 400];
        conn.feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .unwrap();
        let conn = conn
            .finalize_server_flight::<512, RustCrypto, RustCrypto>(
                &reassembler,
                &fixture_prepared(),
                &fixture_leaf_view(),
            )
            .unwrap();

        let mut fin_buf = [0u8; 64];
        let (_fin, mut conn) = conn.finish_handshake(&mut fin_buf).unwrap();

        let mut rec_buf = [0u8; 80];
        let rec = conn
            .encrypt_record(PACKET_5_PLAINTEXT, CT_APPLICATION_DATA, &mut rec_buf)
            .unwrap();
        assert_eq!(rec, &FIXTURE_PACKET_5[..]);
        assert_eq!(conn.state.seq_out, 1);
    }

    #[test]
    fn app_data_decrypt_record_round_trips_packet_6() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut ch_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut ch_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let mut conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();
        let mut reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut scratch = [0u8; 400];
        conn.feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .unwrap();
        let conn = conn
            .finalize_server_flight::<512, RustCrypto, RustCrypto>(
                &reassembler,
                &fixture_prepared(),
                &fixture_leaf_view(),
            )
            .unwrap();

        // Pull pubkey before finish_handshake burns the borrow.
        assert!(matches!(conn.server_pubkey(), ServerPubkey::Ed25519(_, _)));

        let mut fin_buf = [0u8; 64];
        let (_fin, mut conn) = conn.finish_handshake(&mut fin_buf).unwrap();

        let mut pt = [0u8; 64];
        let (content, ct) = conn.decrypt_record(&FIXTURE_PACKET_6, &mut pt).unwrap();
        assert_eq!(ct, CT_APPLICATION_DATA);
        assert_eq!(content, PACKET_6_PLAINTEXT);
        assert_eq!(conn.state.seq_in, 1);
    }

    #[test]
    fn close_notify_emits_encrypted_alert_record() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut ch_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut ch_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();
        let mut conn = conn
            .read_server_hello(&FIXTURE_SERVER_HELLO)
            .unwrap()
            .assume_aes_128_gcm()
            .unwrap();
        let mut reassembler: ServerFlightReassembler<512> = ServerFlightReassembler::new();
        let mut scratch = [0u8; 400];
        conn.feed_server_record(&FIXTURE_PACKET_3, &mut reassembler, &mut scratch)
            .unwrap();
        let conn = conn
            .finalize_server_flight::<512, RustCrypto, RustCrypto>(
                &reassembler,
                &fixture_prepared(),
                &fixture_leaf_view(),
            )
            .unwrap();
        let mut fin_buf = [0u8; 64];
        let (_fin, conn) = conn.finish_handshake(&mut fin_buf).unwrap();

        let mut alert_buf = [0u8; 64];
        let alert = conn.close_notify(&mut alert_buf).unwrap();
        assert_eq!(alert[0], CT_APPLICATION_DATA);
        assert_eq!(&alert[1..3], &[0x03, 0x03]);
        let body_len = u16::from_be_bytes([alert[3], alert[4]]) as usize;
        assert_eq!(body_len, 2 + 1 + 16);
        assert_eq!(alert.len(), 5 + body_len);
    }

    #[test]
    fn assume_aes_succeeds_for_aes_handshake() {
        let priv_zb = ZeroBuf::<32>::new(FIXTURE_CLIENT_X25519_PRIV);
        let conn: TlsConnection<Init, RustCrypto> = TlsConnection::new(FIXTURE_RANDOM, priv_zb);
        let mut out_buf = [0u8; 256];
        let mut cursor: &mut [u8] = &mut out_buf[..];
        let conn = conn
            .write_client_hello_with(&mut cursor, &FIXTURE_X25519_PUB, &fixture_opts())
            .unwrap();

        let negotiated = conn.read_server_hello(&FIXTURE_SERVER_HELLO).unwrap();
        let _conn = negotiated
            .assume_aes_128_gcm()
            .expect("assume_aes_128_gcm should accept an AES handshake");
    }

    type AppConn = TlsConnection<AppData<Aes128GcmSha256>, RustCrypto>;

    fn app_secret(byte: u8) -> Secret {
        Secret::new(ZeroBuf::<32>::new([byte; 32]))
    }

    /// A client-auth flight larger than the peer's `record_size_limit`
    /// fragments across records (RFC 8446 §5.1), each capped at the RSL, and
    /// the fragments reassemble to the original plaintext; a large RSL emits a
    /// single record.
    #[test]
    fn encrypt_handshake_flight_fragments_to_peer_record_size_limit() {
        let keys =
            crate::aead::RecordKeys::<Aes128GcmSha256>::derive::<RustCrypto>(&app_secret(0x55))
                .unwrap();
        let plaintext: Vec<u8> = (0..200u32).map(|i| i as u8).collect();

        // Peer RSL 64 → each record's inner plaintext (data + content-type) ≤ 64.
        let mut out = [0u8; 1024];
        let blob = super::encrypt_handshake_flight(&keys, &plaintext, 64, &mut out)
            .unwrap()
            .to_vec();

        let mut recovered = Vec::new();
        let mut rest = &blob[..];
        let mut seq = 0u64;
        let mut records = 0;
        while !rest.is_empty() {
            let len = 5 + u16::from_be_bytes([rest[3], rest[4]]) as usize;
            let (rec, tail) = rest.split_at(len);
            let mut scratch = [0u8; 128];
            let inner = keys.decrypt_record(rec, seq, &mut scratch).unwrap();
            assert!(inner.len() <= 64, "inner plaintext must fit the peer RSL");
            let (data, ct) = split_inner_plaintext(inner).unwrap();
            assert_eq!(ct, CT_HANDSHAKE);
            recovered.extend_from_slice(data);
            rest = tail;
            seq += 1;
            records += 1;
        }
        assert!(records > 1, "a small RSL must fragment the flight");
        assert_eq!(recovered, plaintext, "fragments reassemble to the flight");

        // A large RSL emits a single record.
        let mut out2 = [0u8; 1024];
        let blob2 = super::encrypt_handshake_flight(&keys, &plaintext, 16385, &mut out2).unwrap();
        let len = 5 + u16::from_be_bytes([blob2[3], blob2[4]]) as usize;
        assert_eq!(len, blob2.len(), "a large RSL emits one record");
    }

    /// Build a client and its mirror server from two distinct app-traffic
    /// secrets: the server's send secret is the client's receive secret and
    /// vice versa, so records cross-decrypt.
    fn mirrored_pair() -> (AppConn, AppConn) {
        let client = AppConn::from_app_secrets(app_secret(0x11), app_secret(0x22), 0, 0).unwrap();
        let server = AppConn::from_app_secrets(app_secret(0x22), app_secret(0x11), 0, 0).unwrap();
        (client, server)
    }

    /// KeyUpdate rotates both directions: after the peer updates its send
    /// keys, records still cross-decrypt under the rotated secrets, and the
    /// sequence numbers reset (RFC 8446 §4.6.3).
    #[test]
    fn key_update_round_trips_both_directions() {
        let (mut client, mut server) = mirrored_pair();

        // Server → client KeyUpdate(update_requested=1), then server rotates
        // its own send keys.
        let mut sbuf = [0u8; 64];
        let n = server.encrypt_key_update(true, &mut sbuf).unwrap().len();
        let mut ku = [0u8; 64];
        ku[..n].copy_from_slice(&sbuf[..n]);
        server.apply_send_key_update().unwrap();

        // Client reads it under the *old* receive keys, then rotates.
        let mut pt = [0u8; 64];
        let (content, ct) = client.decrypt_record(&ku[..n], &mut pt).unwrap();
        assert_eq!(ct, CT_HANDSHAKE);
        assert_eq!(content, &[HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x01]);
        client.apply_recv_key_update().unwrap();

        // Server app record under its rotated send keys decrypts on the
        // client's rotated receive keys, at reset seq 0.
        let mut abuf = [0u8; 96];
        let an = server
            .encrypt_record(b"after the update", CT_APPLICATION_DATA, &mut abuf)
            .unwrap()
            .len();
        let mut arec = [0u8; 96];
        arec[..an].copy_from_slice(&abuf[..an]);
        let mut apt = [0u8; 96];
        let (content, ct) = client.decrypt_record(&arec[..an], &mut apt).unwrap();
        assert_eq!(ct, CT_APPLICATION_DATA);
        assert_eq!(content, b"after the update");
        assert_eq!(client.state.seq_in, 1);

        // Reverse direction: client → server KeyUpdate(0), client rotates send.
        let mut cbuf = [0u8; 64];
        let cn = client.encrypt_key_update(false, &mut cbuf).unwrap().len();
        let mut cku = [0u8; 64];
        cku[..cn].copy_from_slice(&cbuf[..cn]);
        client.apply_send_key_update().unwrap();

        let mut spt = [0u8; 64];
        let (content, ct) = server.decrypt_record(&cku[..cn], &mut spt).unwrap();
        assert_eq!(ct, CT_HANDSHAKE);
        assert_eq!(content, &[HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x00]);
        server.apply_recv_key_update().unwrap();

        let mut c2 = [0u8; 96];
        let c2n = client
            .encrypt_record(b"client after update", CT_APPLICATION_DATA, &mut c2)
            .unwrap()
            .len();
        let mut c2rec = [0u8; 96];
        c2rec[..c2n].copy_from_slice(&c2[..c2n]);
        let mut s2pt = [0u8; 96];
        let (content, ct) = server.decrypt_record(&c2rec[..c2n], &mut s2pt).unwrap();
        assert_eq!(ct, CT_APPLICATION_DATA);
        assert_eq!(content, b"client after update");
    }
}

#[cfg(all(
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "ecdsa"),
    not(feature = "mlkem")
))]
impl<S, H, M> TlsConnection<WaitServerFlight<S, M>, H>
where
    S: CipherSuite,
    H: HkdfSha256,
    M: HandshakeMode,
{
    /// CCS records skipped without bumping seq_in.
    // Test-only; the facade engine has its own record-feed path.
    pub fn feed_server_record<const N: usize>(
        &mut self,
        record: &[u8],
        reassembler: &mut ServerFlightReassembler<N>,
        scratch: &mut [u8],
    ) -> Result<FlightStep, ConnectionError> {
        feed_server_record_inner(
            record,
            &mut self.state.seq_in,
            reassembler,
            scratch,
            |r, s, b| self.state.s_hs_keys.decrypt_record(r, s, b),
        )
    }
}

// Only caller is `feed_server_record` below — same gate.
#[cfg(all(
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "ecdsa"),
    not(feature = "mlkem")
))]
fn feed_server_record_inner<const N: usize, F>(
    record: &[u8],
    seq_in: &mut u64,
    reassembler: &mut ServerFlightReassembler<N>,
    scratch: &mut [u8],
    decrypt: F,
) -> Result<FlightStep, ConnectionError>
where
    F: for<'a> FnOnce(&[u8], u64, &'a mut [u8]) -> Result<&'a [u8], DecryptError>,
{
    if record.is_empty() {
        return Err(ConnectionError::Decrypt(DecryptError::Truncated));
    }
    match record[0] {
        CT_CHANGE_CIPHER_SPEC => Ok(if reassembler.is_complete() {
            FlightStep::Ready
        } else {
            FlightStep::Pending
        }),
        CT_APPLICATION_DATA => {
            let inner = decrypt(record, *seq_in, scratch)?;
            let (content, inner_ct) = split_inner_plaintext(inner)?;
            if inner_ct != CT_HANDSHAKE {
                return Err(ConnectionError::Decrypt(
                    DecryptError::UnexpectedContentType(inner_ct),
                ));
            }
            reassembler.push_content(content)?;
            *seq_in += 1;
            Ok(if reassembler.is_complete() {
                FlightStep::Ready
            } else {
                FlightStep::Pending
            })
        }
        other => Err(ConnectionError::Decrypt(
            DecryptError::UnexpectedContentType(other),
        )),
    }
}

#[cfg(all(
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "ecdsa"),
    not(feature = "mlkem")
))]
impl ServerPubkeyOwned {
    pub(crate) fn as_view(&self) -> ServerPubkey<'_> {
        match self {
            Self::Ed25519(pk) => ServerPubkey::ed25519(*pk),
            #[cfg(feature = "rsa")]
            Self::Rsa { modulus, exponent } => ServerPubkey::Rsa {
                modulus: &modulus[..],
                exponent: *exponent,
            },
            #[cfg(feature = "mldsa")]
            Self::MlDsa(pk) => ServerPubkey::MlDsa(&pk[..]),
            #[cfg(feature = "ecdsa")]
            Self::EcdsaP256(pk) => ServerPubkey::EcdsaP256(&pk[..]),
            #[cfg(feature = "ecdsa")]
            Self::EcdsaP384(pk) => ServerPubkey::EcdsaP384(&pk[..]),
        }
    }
}

#[cfg(all(
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "ecdsa"),
    not(feature = "mlkem")
))]
impl<S, H, M> TlsConnection<ServerFlightDone<S, M>, H>
where
    S: CipherSuite,
    H: HkdfSha256,
    M: HandshakeMode,
{
    pub(crate) fn server_pubkey(&self) -> ServerPubkey<'_> {
        self.state.server_pubkey.as_view()
    }
}
