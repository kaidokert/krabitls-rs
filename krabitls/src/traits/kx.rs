//! Pluggable key-exchange backend, symmetric with [`AeadBackend`](crate::traits::AeadBackend)
//! and [`VerifierBackend`](crate::traits::VerifierBackend).
//!
//! A [`KxBackend`] names one [`KxGroup`] per TLS 1.3 named group the profile
//! can advertise. Each group is KEM/DH-shaped: [`KxGroup::generate`] draws an
//! ephemeral keypair and yields the wire `key_share`, [`KxGroup::derive`]
//! consumes the ephemeral secret against the server's share to produce the IKM.
//! The default [`RustCrypto`](crate::backends::RustCrypto) wiring delegates to
//! the bundled X25519 / P-256 / ML-KEM primitives.

use rand_core::TryCryptoRng;
use zeroize::{ZeroizeOnDrop, Zeroizing};

// Longest client `key_share` this build can emit — the largest enabled group's
// `CLIENT_SHARE_LEN`. X25519MLKEM768 (ML-KEM ek ‖ X25519 pub) dominates when
// present; otherwise P-256's SEC1 point (65) or X25519's 32. Mirrors the
// `KEY_SHARE_KEY_LEN` selection in the crate root.
#[cfg(feature = "mlkem")]
pub const MAX_CLIENT_SHARE_LEN: usize = crate::backends::mlkem::MLKEM768_EK_BYTES + 32;
#[cfg(all(not(feature = "mlkem"), feature = "p256-kx"))]
pub const MAX_CLIENT_SHARE_LEN: usize = crate::backends::ecdhe::P256_SHARE_BYTES;
#[cfg(all(not(feature = "mlkem"), not(feature = "p256-kx")))]
pub const MAX_CLIENT_SHARE_LEN: usize = 32;

/// Longest IKM a group derives: 64 for the X25519MLKEM768 hybrid (two 32-byte
/// secrets concatenated), 32 for the classical groups.
pub const MAX_SHARED_SECRET_LEN: usize = 64;

/// Fixed-capacity holder for a client `key_share`, sized to the largest group
/// this build can emit ([`MAX_CLIENT_SHARE_LEN`]). Filled by
/// [`KxGroup::generate`] and read by the ClientHello writer.
/// A [`ClientShareBuf::extend_from_slice`] would exceed [`MAX_CLIENT_SHARE_LEN`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("client key_share exceeds the maximum length")]
pub struct CapacityError;

#[derive(Clone)]
pub struct ClientShareBuf {
    buf: [u8; MAX_CLIENT_SHARE_LEN],
    len: usize,
}

impl ClientShareBuf {
    pub const fn new() -> Self {
        Self {
            buf: [0u8; MAX_CLIENT_SHARE_LEN],
            len: 0,
        }
    }

    /// Append `bytes`; `Err` if it would exceed [`MAX_CLIENT_SHARE_LEN`].
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), CapacityError> {
        let end = self.len.checked_add(bytes.len()).ok_or(CapacityError)?;
        if end > MAX_CLIENT_SHARE_LEN {
            return Err(CapacityError);
        }
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Default for ClientShareBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// Zeroize-on-drop holder for a derived IKM (32 or 64 bytes).
pub struct SharedSecretBuf {
    buf: Zeroizing<[u8; MAX_SHARED_SECRET_LEN]>,
    len: usize,
}

impl SharedSecretBuf {
    /// Copy `bytes` (its length clamped to [`MAX_SHARED_SECRET_LEN`]) into a
    /// fresh zeroizing holder.
    pub fn from_slice(bytes: &[u8]) -> Self {
        let len = bytes.len().min(MAX_SHARED_SECRET_LEN);
        let mut buf = Zeroizing::new([0u8; MAX_SHARED_SECRET_LEN]);
        buf[..len].copy_from_slice(&bytes[..len]);
        Self { buf, len }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// One TLS 1.3 key-exchange named group. Ephemeral-only: [`generate`](Self::generate)
/// hands back the `key_share` bytes and a secret held through the typestate;
/// [`derive`](Self::derive) consumes that secret (single-use, zeroize-on-drop)
/// against the server's share to yield the IKM.
pub trait KxGroup {
    /// `supported_groups` / `key_share` codepoint (e.g. `0x001d` X25519).
    const NAMED_GROUP: u16;
    /// Bytes written into the client `key_share` entry.
    const CLIENT_SHARE_LEN: usize;
    /// IKM length (32 for X25519 / P-256, 64 for the hybrid).
    const SHARED_SECRET_LEN: usize;

    /// Ephemeral private holder; moved (not copied) through the typestate and
    /// dropped in place on any handshake abort. The [`ZeroizeOnDrop`] bound keeps
    /// a backend from parking the raw scalar in a plain buffer that leaks on drop
    /// — the holder must clear the secret when it falls (e.g. wrap it in
    /// [`Zeroizing`], the pattern the bundled groups use).
    type Secret: ZeroizeOnDrop;
    type Error;

    fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self::Secret, ClientShareBuf), Self::Error>;

    /// Consume `secret` against the server's `key_share` and return the IKM.
    fn derive(secret: Self::Secret, server_share: &[u8]) -> Result<SharedSecretBuf, Self::Error>;
}

/// The single key-exchange backend a [`ClientConfig`](crate::client::ClientConfig)
/// threads: it names the concrete [`KxGroup`] for each named group the build can
/// advertise. Aggregates the groups the way [`AeadBackend`](crate::traits::AeadBackend)
/// aggregates the ciphers.
pub trait KxBackend {
    #[cfg(feature = "x25519-kx")]
    type X25519: KxGroup;
    #[cfg(feature = "p256-kx")]
    type P256: KxGroup;
    /// The X25519MLKEM768 hybrid as one composite group
    /// (draft-ietf-tls-ecdhe-mlkem).
    #[cfg(feature = "mlkem")]
    type X25519MlKem768: KxGroup;
}
