/// AEAD tag verification failed. RFC 8446 §5.2: tear down with `bad_record_mac`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AeadError;

/// The single AEAD backend a [`ClientConfig`](crate::client::ClientConfig)
/// threads: it names the concrete [`CipherSuite`](crate::aead::CipherSuite)
/// marker for each TLS 1.3 record cipher. The record core is generic over the
/// suite, so a hardware AEAD substitutes at the suite level rather than
/// touching the record layer. Aggregates the ciphers the way
/// [`VerifierBackend`](crate::traits::VerifierBackend) aggregates the signature
/// algorithms.
pub trait AeadBackend {
    #[cfg(feature = "cipher-aes")]
    type Aes: crate::aead::CipherSuite<KeyBytes = [u8; 16]>;
    #[cfg(feature = "chacha20")]
    type ChaCha: crate::aead::CipherSuite<KeyBytes = [u8; 32]>;
}
