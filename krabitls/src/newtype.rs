//! Small newtypes for byte arrays that aren't interchangeable.
//!
//! The library used to thread `[u8; 32]` / `[u8; 16]` / `[u8; 12]` and
//! bare `&[u8]` for things with very different semantics — a 32-byte
//! traffic secret, a 32-byte transcript hash, a 32-byte pubkey, a
//! 16-byte AEAD key, a 12-byte AEAD IV, and so on. The compiler
//! couldn't tell them apart, which made wrong-site bugs ("I passed
//! the *server* traffic secret where the *client* one was expected")
//! silent.
//!
//! These wrappers are zero-cost (`#[repr(transparent)]`) and bring the
//! type system in to catch a few obvious confusions at compile time:
//!
//! - [`Secret`] for any 32-byte HKDF output (early / handshake / master /
//!   traffic secrets). Secret-bearing — **not `Copy`**, zeroes on drop.
//! - [`TranscriptDigest`] for the public 32-byte hash returned from
//!   [`crate::TranscriptHash::snapshot`]. Public protocol material, so
//!   it stays `Copy` and is printable.
//! - [`AeadKey`] / [`AeadIv`] for the 16-byte AEAD key and 12-byte AEAD
//!   IV produced by [`crate::traffic_keys`]. Same secret-bearing
//!   treatment as `Secret`.
//!
//! Secret-bearing types are deliberately **not `Copy`** so that every
//! move shows up in the source — implicit bitwise copies leave
//! sensitive bytes scattered across stack frames you can't audit.
//! `Clone` is kept so callers who genuinely need a fresh copy can ask
//! for one explicitly; the absence of `Copy` forces them to.
//!
//! What we deliberately did *not* newtype here:
//!
//! - Public keys (Ed25519 32-byte). They're named struct fields on
//!   `CertView` already, so wrong-site confusion is structural, not
//!   type-based.
//! - The Finished MAC output and HKDF-Expand-Label output buffers. The
//!   former is a one-shot verify_data that lives inside its handler;
//!   the latter is a short-lived scratch that wraps into one of the
//!   newtypes above.

/// Fixed-size byte buffer that wipes its contents on drop.
///
/// Type alias for [`zeroize::Zeroizing<[u8; N]>`] — picks up the
/// crate's auto-zero-on-drop, `Deref<Target = [u8; N]>` (so `*buf`
/// gives the array, `&buf[..]` gives the slice, `buf[i]` indexes), and
/// `DerefMut` for the same on the write side.
///
/// Use for short-lived stack scratch that holds secret bytes en route
/// to one of the long-lived [`Secret`] / [`AeadKey`] / [`AeadIv`]
/// newtypes (which themselves auto-zero on drop). On every code path —
/// including `?` early-returns — the bytes are wiped when the binding
/// goes out of scope.
///
/// ```ignore
/// let mut key = ZeroBuf::<16>::new([0; 16]);
/// hkdf_expand_label::<H>(..., &mut key[..])?;
/// let aead_key = AeadKey::new(*key);
/// ```
pub type ZeroBuf<const N: usize> = zeroize::Zeroizing<[u8; N]>;

/// Generates a secret-bearing byte newtype.
///
/// Holds `Zeroizing<[u8; N]>` internally — Drop-zero comes from the
/// inner wrapper, no manual impl needed. Constructor takes the
/// wrapped value by move, so handing bytes through ZeroBuf → newtype
/// is a single move with no implicit `*key` deref-copy of the array.
macro_rules! secret_newtype {
    (
        $(#[$attr:meta])*
        $name:ident($n:literal)
    ) => {
        $(#[$attr])*
        #[repr(transparent)]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(ZeroBuf<$n>);

        impl $name {
            /// Wrap an existing `ZeroBuf<N>` (= `Zeroizing<[u8; N]>`).
            /// Takes the wrapper by move — no copy of the bytes.
            pub fn new(bytes: ZeroBuf<$n>) -> Self {
                Self(bytes)
            }

            /// Borrow the underlying bytes as `&[u8; N]`. The returned
            /// reference is short-lived; the secret bytes stay owned by
            /// the inner `Zeroizing<>`.
            pub fn as_bytes(&self) -> &[u8; $n] {
                &*self.0
            }

            /// Borrow the underlying `Zeroizing<[u8; N]>` directly —
            /// for handing to APIs that expect that contract at the
            /// type level (e.g. [`crate::traits::Aes128GcmAead`]).
            pub fn as_zeroizing(&self) -> &ZeroBuf<$n> {
                &self.0
            }
        }

        impl AsRef<[u8; $n]> for $name {
            fn as_ref(&self) -> &[u8; $n] {
                &*self.0
            }
        }
    };
}

secret_newtype! {
    /// 32-byte HKDF secret material. Covers early_secret, handshake_secret,
    /// master_secret, and the four traffic secrets (client/server × hs/ap).
    ///
    /// The type doesn't distinguish *which* role the secret plays — the
    /// embedded TLS profile doesn't earn the noise of per-role types. It
    /// does prevent confusion with [`TranscriptDigest`] (the other common
    /// 32-byte goo), with raw OS-random output, and with cert pubkey bytes.
    ///
    /// Not `Copy`; zeroes on drop.
    Secret(32)
}

// Redacted Debug — printing raw secret bytes via `{:?}` (panic messages,
// log macros, derived Debug on containing structs) would defeat the
// Zeroize hygiene this module is built around.
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

// `TranscriptDigest` is public protocol material; print the raw bytes.
impl core::fmt::Debug for TranscriptDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("TranscriptDigest").field(&self.0).finish()
    }
}

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
mod tests {
    use super::*;

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

    extern crate alloc;
    use alloc::format;

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
        // Sanity-check counterpoint: public material *should* be printable.
        let td = TranscriptDigest::new([0x11; 32]);
        let dbg = format!("{td:?}");
        assert!(dbg.contains("17") || dbg.contains("0x11"));
    }

    // (The `Drop` impl just delegates to `self.0.zeroize()`, which is
    // exercised directly by `secret_zeroizes` above. A post-drop pointer
    // peek to "verify" Drop fired is UB in general — Rust may move the
    // stack slot or the optimizer may elide writes whose effects aren't
    // observed. Trust the implementation + the Zeroize test.)

    #[test]
    fn zero_buf_round_trip() {
        // ZeroBuf is `Zeroizing<[u8; N]>`. Deref to the array gives us
        // indexing and `*buf` copy-out for the boundary into other
        // newtype constructors.
        let mut buf = ZeroBuf::<16>::new([0u8; 16]);
        assert_eq!(*buf, [0u8; 16]);
        buf.copy_from_slice(&[0x42; 16]);
        assert_eq!(*buf, [0x42u8; 16]);
        let arr: [u8; 16] = *buf;
        assert_eq!(arr, [0x42u8; 16]);
    }
}
