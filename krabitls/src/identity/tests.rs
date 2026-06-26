use super::*;
use subtle::ConstantTimeEq;

#[test]
fn exact_match() {
    assert!(dns_name_matches(b"example.com", b"example.com"));
}

#[test]
fn case_insensitive() {
    assert!(dns_name_matches(b"Example.COM", b"example.com"));
    assert!(dns_name_matches(b"example.com", b"EXAMPLE.com"));
}

#[test]
fn no_partial_suffix() {
    assert!(!dns_name_matches(b"example.com", b"foo.example.com"));
    assert!(!dns_name_matches(b"foo.example.com", b"example.com"));
}

#[test]
fn wildcard_matches_one_label() {
    assert!(dns_name_matches(b"*.example.com", b"foo.example.com"));
    assert!(dns_name_matches(b"*.example.com", b"FOO.example.com"));
}

#[test]
fn wildcard_rejects_two_labels() {
    assert!(!dns_name_matches(b"*.example.com", b"a.b.example.com"));
}

#[test]
fn wildcard_rejects_apex() {
    assert!(!dns_name_matches(b"*.example.com", b"example.com"));
}

#[test]
fn wildcard_rejects_empty_label() {
    assert!(!dns_name_matches(b"*.example.com", b".example.com"));
}

#[test]
fn wildcard_rejects_non_leftmost() {
    assert!(!dns_name_matches(b"foo.*.com", b"foo.bar.com"));
    assert!(!dns_name_matches(b"*foo.com", b"abcfoo.com"));
}

/// Encode one DER TLV: short-form length only (sufficient for the test
/// inputs we build here).
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 0x80);
    let mut v = vec![tag, value.len() as u8];
    v.extend_from_slice(value);
    v
}

#[test]
fn iterates_one_dns_name() {
    let san = tlv(0x82, b"example.com");
    let names: Vec<&[u8]> = san_dns_names(&san).map(|r| r.unwrap()).collect();
    assert_eq!(names, vec![&b"example.com"[..]]);
}

#[test]
fn iterates_multiple_dns_names() {
    let mut san = vec![];
    san.extend(tlv(0x82, b"example.com"));
    san.extend(tlv(0x82, b"www.example.com"));
    let names: Vec<&[u8]> = san_dns_names(&san).map(|r| r.unwrap()).collect();
    assert_eq!(names, vec![&b"example.com"[..], &b"www.example.com"[..]]);
}

#[test]
fn skips_non_dns_general_names() {
    let mut san = vec![];
    // rfc822Name [1]
    san.extend(tlv(0x81, b"foo@bar.com"));
    // dNSName [2]
    san.extend(tlv(0x82, b"example.com"));
    // uniformResourceIdentifier [6]
    san.extend(tlv(0x86, b"https://example.com"));
    let names: Vec<&[u8]> = san_dns_names(&san).map(|r| r.unwrap()).collect();
    assert_eq!(names, vec![&b"example.com"[..]]);
}

#[test]
fn truncated_san_reports_error() {
    let san = [0x82, 0x05, b'a', b'b']; // claims 5 bytes, only 2 present
    let r = san_dns_names(&san).next().unwrap();
    assert_eq!(r, Err(IdentityError::MalformedSan));
}

/// `ip-host` OFF must still reject IP-literal hostnames against
/// dNSName SAN entries — the shape detector is unconditional.
#[test]
fn verify_hostname_ip_literal_rejects_dns_fallback() {
    let dns_san = |s: &str| {
        let mut v = vec![0x82, s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        v
    };
    fn mk_view(san: &[u8]) -> CertView<'_> {
        CertView::Ed25519 {
            tbs: &[],
            signature: &[0u8; 64],
            pubkey: &[0u8; 32],
            san: Some(san),
            validity_der: &[],
        }
    }
    let san = dns_san("1.1.1.1");
    assert_eq!(
        verify_hostname(&mk_view(&san), "1.1.1.1"),
        Err(IdentityError::HostnameMismatch)
    );
    let san = dns_san("2001:db8::1");
    assert_eq!(
        verify_hostname(&mk_view(&san), "2001:db8::1"),
        Err(IdentityError::HostnameMismatch)
    );
    let san = dns_san("[2001:db8::1]");
    assert_eq!(
        verify_hostname(&mk_view(&san), "[2001:db8::1]"),
        Err(IdentityError::HostnameMismatch)
    );
    let san = dns_san("example.com");
    assert_eq!(verify_hostname(&mk_view(&san), "example.com"), Ok(()));
}

#[test]
fn ip_shape_detector() {
    assert!(looks_like_ip_literal("1.1.1.1"));
    assert!(looks_like_ip_literal("2001:db8::1"));
    assert!(looks_like_ip_literal("[2001:db8::1]"));
    assert!(looks_like_ip_literal("999.999.999.999")); // shape-only
    assert!(!looks_like_ip_literal("example.com"));
    assert!(!looks_like_ip_literal("a.b.c"));
    assert!(!looks_like_ip_literal(""));
    assert!(!looks_like_ip_literal("12345")); // no dot, no colon
}

fn ed25519_view(pubkey: &[u8; 32]) -> CertView<'_> {
    const SIG: [u8; 64] = [0u8; 64];
    CertView::Ed25519 {
        tbs: &[],
        signature: &SIG,
        pubkey,
        san: None,
        validity_der: &[],
    }
}

#[test]
fn pin_match_ed25519() {
    let pk = [0x42u8; 32];
    let view = ed25519_view(&pk);
    assert_eq!(
        verify_pinned_pubkey(&view, &PinnedPubkey::Ed25519(pk)),
        Ok(())
    );
}

#[test]
fn pin_mismatch_ed25519() {
    let pk = [0x42u8; 32];
    let other = [0x43u8; 32];
    let view = ed25519_view(&pk);
    assert_eq!(
        verify_pinned_pubkey(&view, &PinnedPubkey::Ed25519(other)),
        Err(IdentityError::PinMismatch)
    );
}

#[test]
fn pin_mismatch_ed25519_last_byte() {
    let pk = [0x42u8; 32];
    let mut other = pk;
    other[31] = 0x43;
    let view = ed25519_view(&pk);
    assert_eq!(
        verify_pinned_pubkey(&view, &PinnedPubkey::Ed25519(other)),
        Err(IdentityError::PinMismatch)
    );
}

#[test]
fn pin_algorithm_mismatch() {
    let pk = [0x42u8; 32];
    let view = ed25519_view(&pk);
    let pin = PinnedPubkey::_Phantom(core::marker::PhantomData);
    assert_eq!(
        verify_pinned_pubkey(&view, &pin),
        Err(IdentityError::PinAlgorithmMismatch)
    );
}

#[cfg(feature = "ip-host")]
mod ip_host_tests {
    use super::super::ip_host::san_ip_addresses;
    use super::super::*;
    use super::tlv;
    use crate::traits::cert::CertView;

    fn ed25519_view_with_san(san: &[u8]) -> CertView<'_> {
        CertView::Ed25519 {
            tbs: &[],
            signature: &[0u8; 64],
            pubkey: &[0u8; 32],
            san: Some(san),
            validity_der: &[],
        }
    }

    #[test]
    fn san_ip_v4_iter() {
        let san = tlv(0x87, &[1, 1, 1, 1]);
        let ips: Vec<&[u8]> = san_ip_addresses(&san).map(|r| r.unwrap()).collect();
        assert_eq!(ips, vec![&[1, 1, 1, 1][..]]);
    }

    #[test]
    fn san_ip_v6_iter() {
        let v6 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4];
        let san = tlv(0x87, &v6);
        let ips: Vec<&[u8]> = san_ip_addresses(&san).map(|r| r.unwrap()).collect();
        assert_eq!(ips, vec![&v6[..]]);
    }

    #[test]
    fn san_ip_iter_skips_dns() {
        let mut san = vec![];
        san.extend(tlv(0x82, b"example.com"));
        san.extend(tlv(0x87, &[1, 1, 1, 1]));
        let ips: Vec<&[u8]> = san_ip_addresses(&san).map(|r| r.unwrap()).collect();
        assert_eq!(ips, vec![&[1, 1, 1, 1][..]]);
    }

    #[test]
    fn verify_hostname_ip_v4_match() {
        let san = tlv(0x87, &[1, 1, 1, 1]);
        let view = ed25519_view_with_san(&san);
        assert_eq!(verify_hostname(&view, "1.1.1.1"), Ok(()));
    }

    #[test]
    fn verify_hostname_ip_v4_mismatch() {
        let san = tlv(0x87, &[1, 1, 1, 1]);
        let view = ed25519_view_with_san(&san);
        assert_eq!(
            verify_hostname(&view, "1.2.3.4"),
            Err(IdentityError::HostnameMismatch)
        );
    }

    #[test]
    fn verify_hostname_ip_literal_skips_dns_match() {
        let san = tlv(0x82, b"1.1.1.1");
        let view = ed25519_view_with_san(&san);
        assert_eq!(
            verify_hostname(&view, "1.1.1.1"),
            Err(IdentityError::HostnameMismatch)
        );
    }

    #[test]
    fn verify_hostname_ip_v6_match() {
        let v6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let san = tlv(0x87, &v6);
        let view = ed25519_view_with_san(&san);
        assert_eq!(verify_hostname(&view, "2001:db8::1"), Ok(()));
    }

    #[test]
    fn verify_hostname_ip_v6_bracketed() {
        let v6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let san = tlv(0x87, &v6);
        let view = ed25519_view_with_san(&san);
        assert_eq!(verify_hostname(&view, "[2001:db8::1]"), Ok(()));
    }

    #[test]
    fn san_ip_wrong_length_is_malformed() {
        // tag 7 with a 5-byte payload — not 4 or 16
        let san = tlv(0x87, &[1, 2, 3, 4, 5]);
        let r = san_ip_addresses(&san).next().unwrap();
        assert_eq!(r, Err(IdentityError::MalformedSan));
    }
}

#[cfg(feature = "rsa")]
mod rsa_tests {
    use super::super::*;
    use super::verify_pinned_pubkey;
    use crate::traits::cert::CertView;

    #[test]
    fn pin_match_rsa() {
        let modulus = [0xAAu8; 256];
        let view = CertView::Rsa {
            tbs: &[],
            signature: &[],
            modulus: &modulus,
            exponent: 65537,
            san: None,
            validity_der: &[],
            outer_sig_alg: Some(crate::traits::cert::RsaCertSigAlg::PssSha256),
        };
        assert_eq!(
            verify_pinned_pubkey(
                &view,
                &PinnedPubkey::Rsa {
                    modulus: &modulus,
                    exponent: 65537
                }
            ),
            Ok(())
        );
    }

    #[test]
    fn pin_mismatch_rsa_modulus_last_byte() {
        let modulus = [0xAAu8; 256];
        let mut other = modulus;
        other[255] = 0xAB;
        let view = CertView::Rsa {
            tbs: &[],
            signature: &[],
            modulus: &modulus,
            exponent: 65537,
            san: None,
            validity_der: &[],
            outer_sig_alg: Some(crate::traits::cert::RsaCertSigAlg::PssSha256),
        };
        assert_eq!(
            verify_pinned_pubkey(
                &view,
                &PinnedPubkey::Rsa {
                    modulus: &other,
                    exponent: 65537
                }
            ),
            Err(IdentityError::PinMismatch)
        );
    }

    #[test]
    fn pin_mismatch_rsa_exponent() {
        let modulus = [0xAAu8; 256];
        let view = CertView::Rsa {
            tbs: &[],
            signature: &[],
            modulus: &modulus,
            exponent: 65537,
            san: None,
            validity_der: &[],
            outer_sig_alg: Some(crate::traits::cert::RsaCertSigAlg::PssSha256),
        };
        assert_eq!(
            verify_pinned_pubkey(
                &view,
                &PinnedPubkey::Rsa {
                    modulus: &modulus,
                    exponent: 3
                }
            ),
            Err(IdentityError::PinMismatch)
        );
    }

    #[test]
    fn pin_mismatch_rsa_modulus_length() {
        let modulus_2048 = [0xAAu8; 256];
        let modulus_1024 = [0xAAu8; 128];
        let view = CertView::Rsa {
            tbs: &[],
            signature: &[],
            modulus: &modulus_2048,
            exponent: 65537,
            san: None,
            validity_der: &[],
            outer_sig_alg: Some(crate::traits::cert::RsaCertSigAlg::PssSha256),
        };
        assert_eq!(
            verify_pinned_pubkey(
                &view,
                &PinnedPubkey::Rsa {
                    modulus: &modulus_1024,
                    exponent: 65537
                }
            ),
            Err(IdentityError::PinMismatch)
        );
    }
}

#[cfg(feature = "cert-der")]
mod validity_tests {
    use super::super::*;
    use crate::traits::cert::CertView;
    use crate::traits::time::TimeSource;
    use crate::traits::time::tests::FixedTime;

    /// 2030-01-15T00:00:00Z = 1894665600.
    const T_2030_01_15: u64 = 1894665600;
    /// 2024-06-15T12:34:56Z = 1718454896.
    const T_2024_06_15_LATE: u64 = 1718454896;

    /// Encode a `Validity SEQUENCE { UTCTime, UTCTime }` (short-form
    /// length only — total fits in 32 bytes).
    fn validity_der(not_before: &[u8], not_after: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0x17);
        body.push(not_before.len() as u8);
        body.extend_from_slice(not_before);
        body.push(0x17);
        body.push(not_after.len() as u8);
        body.extend_from_slice(not_after);
        let mut out = Vec::new();
        out.push(0x30); // SEQUENCE
        out.push(body.len() as u8);
        out.extend(body);
        out
    }

    fn cert_view_with_validity(validity_der: &[u8]) -> CertView<'_> {
        const SIG: [u8; 64] = [0u8; 64];
        const PK: [u8; 32] = [0u8; 32];
        CertView::Ed25519 {
            tbs: &[],
            signature: &SIG,
            pubkey: &PK,
            san: None,
            validity_der,
        }
    }

    #[test]
    fn validity_ok_in_window() {
        let der = validity_der(b"200115000000Z", b"300115000000Z");
        let view = cert_view_with_validity(&der);
        assert_eq!(
            verify_validity(&view, &FixedTime(T_2024_06_15_LATE)),
            Ok(())
        );
    }

    #[test]
    fn validity_not_yet_valid() {
        let der = validity_der(b"300115000000Z", b"400115000000Z");
        let view = cert_view_with_validity(&der);
        assert_eq!(
            verify_validity(&view, &FixedTime(T_2024_06_15_LATE)),
            Err(ValidityError::NotYetValid {
                not_before: T_2030_01_15,
                now: T_2024_06_15_LATE,
            })
        );
    }

    #[test]
    fn validity_expired() {
        let der = validity_der(b"100115000000Z", b"200115000000Z");
        let view = cert_view_with_validity(&der);
        assert!(matches!(
            verify_validity(&view, &FixedTime(T_2024_06_15_LATE)),
            Err(ValidityError::Expired { .. })
        ));
    }

    #[test]
    fn validity_malformed_der_rejected() {
        let der = [0xFF, 0xFF, 0xFF];
        let view = cert_view_with_validity(&der);
        assert_eq!(
            verify_validity(&view, &FixedTime(T_2024_06_15_LATE)),
            Err(ValidityError::Malformed)
        );
    }

    #[test]
    fn validity_rejects_trailing_fields_in_sequence() {
        // `Validity ::= SEQUENCE { notBefore Time, notAfter Time }` is
        // exactly two Time fields. Append a third TLV inside the SEQUENCE
        // (here: a NULL `0x05 0x00`) and confirm it's rejected rather
        // than silently accepted because the first two timestamps happen
        // to bracket `now`.
        let two_times = validity_der(b"200115000000Z", b"300115000000Z");
        // Pull out the inner SEQUENCE body, append the trailing TLV, and
        // re-wrap with a fixed SEQUENCE header. The two-Time body is
        // `two_times[2..]`; the SEQUENCE header is `0x30 <len>`.
        let inner = &two_times[2..];
        let mut body = Vec::from(inner);
        body.extend_from_slice(&[0x05, 0x00]); // trailing NULL
        let mut der = vec![0x30, body.len() as u8];
        der.extend(body);
        let view = cert_view_with_validity(&der);
        assert_eq!(
            verify_validity(&view, &FixedTime(T_2024_06_15_LATE)),
            Err(ValidityError::Malformed)
        );
    }

    #[test]
    fn fixed_time_is_a_timesource() {
        let t: &dyn TimeSource = &FixedTime(42);
        assert_eq!(t.now_unix_secs(), 42);
    }
}

/// Compare the cert's public key to a pinned reference. Used by
/// [`crate::backends::PinOrSelfSigned`] via [`PinnedPubkeyOwned`] in
/// production; the borrowed-pin form here is test-only.
fn verify_pinned_pubkey(
    cert_view: &CertView<'_>,
    pin: &PinnedPubkey<'_>,
) -> Result<(), IdentityError> {
    match (cert_view, pin) {
        (CertView::Ed25519 { pubkey, .. }, PinnedPubkey::Ed25519(expected)) => {
            if bool::from((**pubkey).ct_eq(expected)) {
                Ok(())
            } else {
                Err(IdentityError::PinMismatch)
            }
        }
        #[cfg(feature = "rsa")]
        (
            CertView::Rsa {
                modulus, exponent, ..
            },
            PinnedPubkey::Rsa {
                modulus: pm,
                exponent: pe,
            },
        ) => {
            // RSA key size is public; length mismatch can short-circuit
            // without breaking the CT contract.
            if modulus.len() != pm.len() {
                return Err(IdentityError::PinMismatch);
            }
            // `&` (not `&&`) — bitwise on `Choice`, both halves always run.
            if bool::from(modulus.ct_eq(pm) & exponent.ct_eq(pe)) {
                Ok(())
            } else {
                Err(IdentityError::PinMismatch)
            }
        }
        _ => Err(IdentityError::PinAlgorithmMismatch),
    }
}
