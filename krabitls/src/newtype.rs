//! Newtypes for secret-bearing byte arrays and transcript digests.
//!
//! Secret-bearing types are not `Copy` and zeroize on drop so implicit moves do
//! not scatter key material silently.

/// Fixed-size byte buffer that wipes its contents on drop.
pub type ZeroBuf<const N: usize> = zeroize::Zeroizing<[u8; N]>;

macro_rules! secret_newtype {
    (
        $(#[$attr:meta])*
        $name:ident($n:literal)
    ) => {
        $(#[$attr])*
        #[repr(transparent)]
        #[derive(Clone, PartialEq, Eq, zeroize::Zeroize)]
        pub struct $name(ZeroBuf<$n>);

        impl $name {
            /// Wrap an existing zeroizing buffer.
            pub fn new(bytes: ZeroBuf<$n>) -> Self {
                Self(bytes)
            }

            /// Borrow the underlying bytes.
            // Not every secret-newtype instance exercises this accessor.
            #[allow(dead_code)]
            pub fn as_bytes(&self) -> &[u8; $n] {
                &*self.0
            }
        }

        impl AsRef<[u8; $n]> for $name {
            fn as_ref(&self) -> &[u8; $n] {
                &*self.0
            }
        }

        impl From<[u8; $n]> for $name {
            fn from(bytes: [u8; $n]) -> Self {
                Self(ZeroBuf::<$n>::new(bytes))
            }
        }
    };
}

secret_newtype! {
    /// 32-byte HKDF secret material. Not `Copy`; zeroes on drop.
    Secret(32)
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret([redacted; 32])")
    }
}

/// 32-byte SHA-256 transcript hash. Output of
/// [`crate::TranscriptHash::snapshot`]; input to HKDF-Expand-Label for
/// `*_traffic_secret` derivations and the Finished MAC.
///
/// Public protocol material — not secret — so it stays `Copy` and is
/// printable. Distinct from [`Secret`] at the type level even though
/// the byte shape matches.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TranscriptDigest(pub [u8; 32]);

impl TranscriptDigest {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8; 32]> for TranscriptDigest {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for TranscriptDigest {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for TranscriptDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("TranscriptDigest").field(&self.0).finish()
    }
}

secret_newtype! {
    /// 12-byte AEAD IV. Output of [`crate::traffic_keys`]; XOR'd with the
    /// big-endian record sequence number to produce the per-record nonce
    /// in [`crate::aead_nonce`]. Not `Copy`; zeroes on drop.
    AeadIv(12)
}

// The IV isn't a long-term secret on its own, but combined with the key
// it derives the per-record nonce. Treat as sensitive for the same
// reason: don't drop into logs via `{:?}`.
impl core::fmt::Debug for AeadIv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AeadIv([redacted; 12])")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate alloc;
    use super::*;
    use alloc::format;
    use zeroize::Zeroize;

    // Test-only key newtypes; production stores keys in `Zeroizing<S::KeyBytes>`.
    secret_newtype! {
        /// 16-byte AES-128-GCM key. Output of [`crate::traffic_keys`].
        /// Not `Copy`; zeroes on drop.
        AeadKey(16)
    }

    impl core::fmt::Debug for AeadKey {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("AeadKey([redacted; 16])")
        }
    }

    impl AeadKey {
        /// Borrow the underlying zeroizing buffer to feed the test record
        /// helpers, which take `&Zeroizing<S::KeyBytes>`.
        // Used by the cipher-aes record tests; dead in chacha-only builds.
        #[allow(dead_code)]
        pub(crate) fn as_zeroizing(&self) -> &ZeroBuf<16> {
            &self.0
        }
    }

    #[cfg(feature = "chacha20")]
    secret_newtype! {
        /// 32-byte ChaCha20-Poly1305 key. Parallel to [`AeadKey`].
        AeadKey32(32)
    }

    #[cfg(feature = "chacha20")]
    impl core::fmt::Debug for AeadKey32 {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("AeadKey32([redacted; 32])")
        }
    }

    #[cfg(feature = "chacha20")]
    impl AeadKey32 {
        // Used by the chacha record tests; dead when cipher-aes is also on
        // (those paths exercise AeadKey instead).
        #[allow(dead_code)]
        pub(crate) fn as_zeroizing(&self) -> &ZeroBuf<32> {
            &self.0
        }
    }

    #[test]
    fn newtype_round_trip() {
        let s = Secret::new(ZeroBuf::<32>::new([0x42; 32]));
        assert_eq!(s.as_bytes(), &[0x42; 32]);
        let key = AeadKey::new(ZeroBuf::<16>::new([0x11; 16]));
        assert_eq!(key.as_bytes(), &[0x11; 16]);
        let iv = AeadIv::new(ZeroBuf::<12>::new([0x22; 12]));
        assert_eq!(iv.as_bytes(), &[0x22; 12]);
        let td = TranscriptDigest::new([0x33; 32]);
        assert_eq!(td.as_bytes(), &[0x33; 32]);
    }

    #[test]
    fn from_array_round_trip() {
        let s = Secret::from([0x42; 32]);
        assert_eq!(s.as_bytes(), &[0x42; 32]);
        let key: AeadKey = [0x11; 16].into();
        assert_eq!(key.as_bytes(), &[0x11; 16]);
        let iv: AeadIv = [0x22; 12].into();
        assert_eq!(iv.as_bytes(), &[0x22; 12]);
    }

    #[test]
    fn secret_zeroizes() {
        let mut s = Secret::from([0x42; 32]);
        s.zeroize();
        assert_eq!(s.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn secret_debug_does_not_leak_bytes() {
        let s = Secret::new(ZeroBuf::<32>::new([0xAB; 32]));
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("171"), "Debug leaks decimal bytes: {dbg}");
        assert!(!dbg.contains("0xab"), "Debug leaks hex bytes: {dbg}");
        assert!(!dbg.contains("AB"), "Debug leaks hex bytes: {dbg}");
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn aead_key_debug_does_not_leak_bytes() {
        let k = AeadKey::new(ZeroBuf::<16>::new([0xCD; 16]));
        let dbg = format!("{k:?}");
        assert!(!dbg.contains("205"), "Debug leaks decimal bytes: {dbg}");
        assert!(!dbg.contains("CD"), "Debug leaks hex bytes: {dbg}");
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn aead_iv_debug_does_not_leak_bytes() {
        let iv = AeadIv::new(ZeroBuf::<12>::new([0xEF; 12]));
        let dbg = format!("{iv:?}");
        assert!(!dbg.contains("239"), "Debug leaks decimal bytes: {dbg}");
        assert!(!dbg.contains("EF"), "Debug leaks hex bytes: {dbg}");
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn transcript_digest_debug_prints_bytes() {
        let td = TranscriptDigest::new([0x11; 32]);
        let dbg = format!("{td:?}");
        assert!(dbg.contains("17") || dbg.contains("0x11"));
    }

    #[test]
    fn zero_buf_round_trip() {
        let mut buf = ZeroBuf::<16>::new([0u8; 16]);
        assert_eq!(*buf, [0u8; 16]);
        buf.copy_from_slice(&[0x42; 16]);
        assert_eq!(*buf, [0x42u8; 16]);
        let arr: [u8; 16] = *buf;
        assert_eq!(arr, [0x42u8; 16]);
    }
}
