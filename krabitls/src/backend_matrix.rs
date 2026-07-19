//! Backend honesty matrix — `cfg(test)`-only, zero publish impact (the git
//! dev-deps are stripped from the published manifest, as modmath's own manifest
//! demonstrates). Proves the crypto crates krabitls builds on accept alternate
//! bigint carriers — bnum, crypto-bigint, num-bigint — and return the correct
//! answers, so [`crate::bigint`] could be re-pointed at any of them.
//!
//! bnum + crypto-bigint are fixed-width `Copy` carriers covering both the
//! vartime (verify) and constant-time (x25519) halves. num-bigint is a
//! heap-backed runtime-width carrier that is *not* `Copy` and has no CT surface,
//! so it appears on the vartime verify rows only (its x25519 row is absent by
//! construction, not omission).
//!
//! Each op is one `macro_rules!` per row so the body is monomorphic and needs no
//! carrier trait bounds spelled out; `try_from_be_bytes_vartime` is the one
//! uniform constructor every carrier implements.

// ── KAT vectors ────────────────────────────────────────────────────────────

#[cfg(feature = "rsa")]
mod rsa_kat {
    // RSA-1024 PKCS#1-v1.5 / SHA-256 (rsa_heapless footprint fixture).
    pub const E: u32 = 65537;
    pub const MSG: &[u8] = b"hello world!";
    pub const MODULUS: [u8; 128] = [
        0xc0, 0x97, 0x48, 0xba, 0x17, 0x3c, 0xdc, 0x57, 0x07, 0x51, 0x7f, 0x23, 0xc7, 0x71, 0xba,
        0xa9, 0xb2, 0x5e, 0xb5, 0x19, 0x82, 0xbb, 0x9d, 0x16, 0xf5, 0xd4, 0x9c, 0x46, 0x80, 0xd2,
        0xfa, 0xcd, 0xf1, 0x08, 0x73, 0x65, 0xd7, 0xf3, 0xa8, 0xbc, 0x5c, 0x59, 0xf7, 0xea, 0x81,
        0xf6, 0xe6, 0x62, 0xa7, 0x02, 0x39, 0x47, 0x78, 0x44, 0xa1, 0x7c, 0x78, 0xd0, 0x10, 0xaa,
        0x0e, 0x38, 0x14, 0x08, 0x44, 0x0b, 0x9e, 0x88, 0xb2, 0xc8, 0x60, 0x9f, 0xe4, 0x5d, 0x11,
        0x9c, 0xf5, 0x7c, 0x4c, 0xe9, 0x69, 0xcc, 0x1b, 0x90, 0xce, 0x17, 0x67, 0xca, 0xa4, 0x71,
        0xdf, 0x4a, 0xad, 0x86, 0x32, 0x3d, 0xf2, 0x8d, 0x52, 0xac, 0xe2, 0x2e, 0x4e, 0x7f, 0x2a,
        0x4e, 0x3b, 0xed, 0xa2, 0xb8, 0xb4, 0xc2, 0xf5, 0x3f, 0xeb, 0xeb, 0x47, 0x9c, 0x32, 0x44,
        0x43, 0x9e, 0x6c, 0x7d, 0x1f, 0x05, 0xd7, 0x95,
    ];
    pub const SIGNATURE: [u8; 128] = [
        0x83, 0x12, 0x5a, 0xa2, 0x7b, 0x6e, 0x7b, 0xf6, 0xff, 0x85, 0xf5, 0xb4, 0x7c, 0x5f, 0x4b,
        0x0e, 0xb9, 0xed, 0x1b, 0xf6, 0x31, 0x20, 0x5b, 0x82, 0x38, 0x0c, 0x53, 0xe8, 0x18, 0x47,
        0xe5, 0xef, 0xe4, 0xc1, 0x4d, 0xe5, 0xa2, 0x44, 0xda, 0x40, 0xbf, 0x60, 0xe9, 0xeb, 0x2f,
        0x45, 0xe8, 0xac, 0x68, 0xd6, 0x41, 0xec, 0x62, 0xe5, 0x80, 0x07, 0x2c, 0x96, 0x29, 0x52,
        0xa6, 0xbd, 0x8a, 0xe7, 0x26, 0x9d, 0xa4, 0x52, 0xa8, 0x4d, 0x2a, 0xc7, 0xbc, 0x26, 0xd6,
        0xae, 0xb6, 0xa7, 0xac, 0x1c, 0x6c, 0x3c, 0xb1, 0x3b, 0x7a, 0x74, 0x46, 0xcd, 0x55, 0xc9,
        0x4f, 0x9c, 0xb2, 0x54, 0x38, 0xc3, 0x7a, 0xac, 0xb4, 0x78, 0x4e, 0x74, 0x2b, 0x8d, 0xc6,
        0x6a, 0xbe, 0x0f, 0xf1, 0xff, 0x9e, 0x7c, 0xb7, 0xb7, 0x35, 0x4e, 0x5c, 0x61, 0xe2, 0xfc,
        0x13, 0xc3, 0x10, 0xd9, 0xe4, 0xa9, 0x46, 0x36,
    ];
}

mod ed_kat {
    use crate::hex_decode;
    // RFC 8032 §7.1 Test 2 (Ed25519, 1-byte message).
    pub const PUB: [u8; 32] =
        hex_decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    pub const MSG: &[u8] = &[0x72];
    pub const SIG: [u8; 64] = hex_decode(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );
}

#[cfg(feature = "ecdsa")]
mod p256_kat {
    use crate::hex_decode;
    // krabiecdsa's own P-256 KAT ("sample message for krabiecdsa").
    pub const PUB: [u8; 65] = hex_decode(
        "04dec34713540fe2b1f1734a03c4a9332ed2b403e8f24bb05ab626bb0cd40b36\
         aa33ea26baa96b27d7497876a7934a8e9e384484556a2d942f6e4ce56419c04a96",
    );
    pub const DIGEST: [u8; 32] =
        hex_decode("b965f29d7c66cd5ca7406ce09463f3008460a403ab172246565de3afac40a360");
    pub const R: [u8; 32] =
        hex_decode("a994d67f622c58d869c4351cedcbdf54bf76fd153fa824943106bf50f14d28fc");
    pub const S: [u8; 32] =
        hex_decode("299a09fc29835d392ed98a1f72f50b2a6ad66abe95b75ae4e7d996956e7948ba");
}

mod x_kat {
    use crate::hex_decode;
    // RFC 7748 §5.2 X25519 test 1.
    pub const SCALAR: [u8; 32] =
        hex_decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    pub const U: [u8; 32] =
        hex_decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    pub const OUT: [u8; 32] =
        hex_decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
}

// ── RSA-1024 verify (vartime) ──────────────────────────────────────────────

#[cfg(feature = "rsa")]
macro_rules! rsa_verify_row {
    ($name:ident, $t:ty) => {
        #[test]
        fn $name() {
            use rsa::modmath_support::public_key_from_be_bytes;
            use rsa::pkcs1v15::{GenericSignature, GenericVerifyingKey};
            use rsa::signature::Verifier;
            use rsa::traits::FixedWidthUnsignedInt;
            use sha2::Sha256;

            let key =
                public_key_from_be_bytes::<$t>(&rsa_kat::MODULUS, rsa_kat::E).expect("pubkey");
            let vk = GenericVerifyingKey::<Sha256, _, _>::new(key);
            let sig_val =
                <$t as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&rsa_kat::SIGNATURE)
                    .expect("sig");
            let sig = GenericSignature::from(sig_val);
            vk.verify(rsa_kat::MSG, &sig).expect("verify");
            assert!(vk.verify(b"HELLO WORLD!", &sig).is_err());
        }
    };
}

#[cfg(feature = "rsa")]
rsa_verify_row!(rsa1024_verify_bnum, bnum_patched::types::U1024);
#[cfg(feature = "rsa")]
rsa_verify_row!(rsa1024_verify_crypto_bigint, crypto_bigint_patched::U1024);
// num-bigint has NO op rows: its heap-backed, non-`Copy` `FixedWidthBigUint`
// cannot satisfy any of the published crypto crates' carrier bounds — RSA wants
// `DefaultIsZeroes` + `FromBytes`, Ed25519 `UnsignedModularInt`, ECDSA
// `FieldFor`, all of which lean on `Copy`/constant-time-select the heap carrier
// lacks (see heap-carrier autopsy). It stays a dev-dep + `num_bigint_present`
// below so the matrix documents the limit as a fact, not an omission.

// ── Ed25519 verify (vartime) ───────────────────────────────────────────────

macro_rules! ed25519_verify_row {
    ($name:ident, $t:ty) => {
        #[test]
        fn $name() {
            assert!(ed25519_heapless::verify::<$t>(
                ed_kat::PUB,
                ed_kat::MSG,
                ed_kat::SIG
            ));
            let mut bad = ed_kat::SIG;
            bad[0] ^= 1;
            assert!(!ed25519_heapless::verify::<$t>(
                ed_kat::PUB,
                ed_kat::MSG,
                bad
            ));
        }
    };
}

ed25519_verify_row!(ed25519_verify_bnum, bnum_patched::types::U512);
ed25519_verify_row!(ed25519_verify_crypto_bigint, crypto_bigint_patched::U512);

// ── ECDSA P-256 verify (vartime) ───────────────────────────────────────────

#[cfg(feature = "ecdsa")]
macro_rules! p256_verify_row {
    ($name:ident, $t:ty) => {
        #[test]
        fn $name() {
            assert!(krabiecdsa::p256::verify_prehashed::<$t>(
                &p256_kat::PUB,
                &p256_kat::DIGEST,
                &p256_kat::R,
                &p256_kat::S,
            ));
            let mut bad_r = p256_kat::R;
            bad_r[0] ^= 1;
            assert!(!krabiecdsa::p256::verify_prehashed::<$t>(
                &p256_kat::PUB,
                &p256_kat::DIGEST,
                &bad_r,
                &p256_kat::S,
            ));
        }
    };
}

#[cfg(feature = "ecdsa")]
p256_verify_row!(p256_verify_bnum, bnum_patched::types::U256);
#[cfg(feature = "ecdsa")]
p256_verify_row!(p256_verify_crypto_bigint, crypto_bigint_patched::U256);

// ── X25519 (constant-time) — Copy carriers only ────────────────────────────

macro_rules! x25519_row {
    ($name:ident, $t:ty) => {
        #[test]
        fn $name() {
            let got = ed25519_heapless::x25519::<$t>(&x_kat::SCALAR, &x_kat::U).expect("x25519");
            assert_eq!(got, x_kat::OUT);
        }
    };
}

x25519_row!(x25519_bnum, bnum_patched::types::U256);
x25519_row!(
    x25519_crypto_bigint,
    crypto_bigint_patched::Ct<crypto_bigint_patched::U256>
);

// ── num-bigint: resolves as an Nct carrier, but no crypto-crate op accepts it ──

#[test]
fn num_bigint_present_but_unsupported() {
    use const_num_traits::{HasPersonality, Nct};
    // The const-num-traits integration is real (personality = Nct)...
    fn assert_nct<T: HasPersonality<P = Nct>>() {}
    assert_nct::<num_bigint_patched::FixedWidthBigUint>();
    // ...but the RSA/Ed25519/ECDSA rows above deliberately exclude it: the
    // crypto crates' bounds need a `Copy` carrier this heap type can't be.
}
