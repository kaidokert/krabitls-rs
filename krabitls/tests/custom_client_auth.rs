//! Public-API proof for an external ECDSA client-auth signer.

#![cfg(feature = "client-auth-ecdsa")]

use krabitls::client::{ClientAuth, ClientAuthError, ClientSignature, MAX_CLIENT_SIG_LEN};
use krabitls_fixtures::SeededRng;
use rand_core::TryCryptoRng;

struct ExternalP256Signer;

impl<R: TryCryptoRng + ?Sized> ClientAuth<R> for ExternalP256Signer {
    fn cert_der(&self) -> &[u8] {
        b"external-leaf"
    }

    fn scheme(&self) -> u16 {
        0x0403
    }

    fn sign(
        &self,
        _content: &[u8],
        _rng: &mut R,
    ) -> Result<ClientSignature, ClientAuthError> {
        let mut signature = ClientSignature::new();
        signature
            .extend_from_slice(&[0x5a; 72])
            .map_err(|_| ClientAuthError)?;
        Ok(signature)
    }
}

#[test]
fn external_p256_signer_can_return_max_der_signature() {
    assert!(MAX_CLIENT_SIG_LEN >= 72);
    let mut rng = SeededRng::new(7);
    let signature = <ExternalP256Signer as ClientAuth<SeededRng>>::sign(
        &ExternalP256Signer,
        b"certificate verify",
        &mut rng,
    )
    .unwrap();
    assert_eq!(signature.len(), 72);
}
