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
//!   traffic secrets). Implements [`zeroize::Zeroize`] so callers can wipe
//!   on drop via [`zeroize::Zeroizing`] without rewrapping.
//! - [`TranscriptDigest`] for the public 32-byte hash returned from
//!   [`crate::TranscriptHash::snapshot`]. Distinct from `Secret` because
//!   one is a secret, the other is a digest of public protocol bytes —
//!   passing one where the other was expected is a real foot-gun.
//! - [`AeadKey`] / [`AeadIv`] for the 16-byte AEAD key and 12-byte AEAD
//!   IV produced by [`crate::traffic_keys`]. Same reasoning.
//!
//! What we deliberately did *not* newtype here:
//!
//! - Public keys (Ed25519 32-byte, RSA modulus). They're named struct
//!   fields on `CertView` already, so wrong-site confusion is structural,
//!   not type-based.
//! - The Finished MAC output and HKDF-Expand-Label output buffers. Those
//!   are short-lived locals at call sites; no observed confusion problem.
//! - The DHE share fed into `handshake_secret`. It's a one-shot input
//!   from X25519 and used immediately; same logic.

use zeroize::Zeroize;

macro_rules! byte_array_newtype {
    (
        $(#[$attr:meta])*
        $name:ident($n:literal)
    ) => {
        $(#[$attr])*
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(pub [u8; $n]);

        impl $name {
            pub const fn new(bytes: [u8; $n]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $n] {
                &self.0
            }
        }

        impl AsRef<[u8; $n]> for $name {
            fn as_ref(&self) -> &[u8; $n] {
                &self.0
            }
        }

        impl From<[u8; $n]> for $name {
            fn from(bytes: [u8; $n]) -> Self {
                Self(bytes)
            }
        }
    };
}

byte_array_newtype! {
    /// 32-byte HKDF secret material. Covers early_secret, handshake_secret,
    /// master_secret, and the four traffic secrets (client/server × hs/ap).
    ///
    /// The type doesn't distinguish *which* role the secret plays — the
    /// embedded TLS profile doesn't earn the noise of per-role types. It
    /// does prevent confusion with [`TranscriptDigest`] (the other common
    /// 32-byte goo), with raw OS-random output, and with cert pubkey bytes.
    ///
    /// Implements [`Zeroize`] for hygiene; wrap in [`zeroize::Zeroizing`]
    /// when you want auto-clear on drop.
    Secret(32)
}

impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

byte_array_newtype! {
    /// 32-byte SHA-256 transcript hash. Output of
    /// [`crate::TranscriptHash::snapshot`]; input to HKDF-Expand-Label for
    /// `*_traffic_secret` derivations and the Finished MAC.
    ///
    /// Public protocol material — not secret — but byte-shape collides with
    /// [`Secret`], so they're separated at the type level.
    TranscriptDigest(32)
}

byte_array_newtype! {
    /// 16-byte AES-128-GCM key. Output of [`crate::traffic_keys`].
    AeadKey(16)
}

impl Zeroize for AeadKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

byte_array_newtype! {
    /// 12-byte AEAD IV. Output of [`crate::traffic_keys`]; XOR'd with the
    /// big-endian record sequence number to produce the per-record nonce
    /// in [`crate::aead_nonce`].
    AeadIv(12)
}

impl Zeroize for AeadIv {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newtype_round_trip() {
        let s = Secret::new([0x42; 32]);
        assert_eq!(s.as_bytes(), &[0x42; 32]);
        let key = AeadKey::from([0x11; 16]);
        assert_eq!(key.as_bytes(), &[0x11; 16]);
        let iv = AeadIv::from([0x22; 12]);
        assert_eq!(iv.as_bytes(), &[0x22; 12]);
        let td = TranscriptDigest::new([0x33; 32]);
        assert_eq!(td.as_bytes(), &[0x33; 32]);
    }

    #[test]
    fn secret_zeroizes() {
        let mut s = Secret::new([0x42; 32]);
        s.zeroize();
        assert_eq!(s.as_bytes(), &[0u8; 32]);
    }
}
