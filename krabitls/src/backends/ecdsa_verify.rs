//! ECDSA (P-256, P-384) signature verification over `krabiecdsa`. Verify only;
//! the signature is public data, so the vartime `crate::bigint` carriers.
//!
//! TLS 1.3 CertificateVerify and X.509 certificate signatures carry ECDSA as a
//! DER `ECDSA-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`); `krabiecdsa`'s
//! `PrehashVerifier` wants fixed-width IEEE-P1363 `r || s`, so the DER decoder
//! here bridges the two before every verify.

use crate::bigint::{EcdsaP256Bn, EcdsaP384Bn};
use krabiecdsa::{p256, p384};
use signature::hazmat::PrehashVerifier;

/// Verification failure (kept opaque — surfaces upstream as a cert / CV error).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct EcdsaVerifyError;

fn take<'a>(p: &mut &'a [u8], n: usize) -> Result<&'a [u8], EcdsaVerifyError> {
    if p.len() < n {
        return Err(EcdsaVerifyError);
    }
    let (head, tail) = p.split_at(n);
    *p = tail;
    Ok(head)
}

fn read_tlv<'a>(p: &mut &'a [u8], tag: u8) -> Result<&'a [u8], EcdsaVerifyError> {
    if take(p, 1)?[0] != tag {
        return Err(EcdsaVerifyError);
    }
    let len = match take(p, 1)?[0] {
        n if n < 0x80 => n as usize,
        0x81 => take(p, 1)?[0] as usize,
        0x82 => {
            let b = take(p, 2)?;
            ((b[0] as usize) << 8) | b[1] as usize
        }
        _ => return Err(EcdsaVerifyError),
    };
    take(p, len)
}

/// Big-endian, left-pad a DER INTEGER value into `out`. `r`/`s` are positive:
/// a leading `0x00` is only the DER sign byte, and a set high bit without it is
/// a negative encoding (invalid here).
fn int_to_padded(v: &[u8], out: &mut [u8]) -> Result<(), EcdsaVerifyError> {
    if v.is_empty() || v[0] & 0x80 != 0 {
        return Err(EcdsaVerifyError);
    }
    let mut val = v;
    while val.len() > 1 && val[0] == 0 {
        val = &val[1..];
    }
    let start = out.len().checked_sub(val.len()).ok_or(EcdsaVerifyError)?;
    out.fill(0);
    out[start..].copy_from_slice(val);
    Ok(())
}

/// Decode `SEQUENCE { r, s }` into `out` (`2 * eb` bytes: `r || s`).
fn der_sig_to_p1363(der: &[u8], eb: usize, out: &mut [u8]) -> Result<(), EcdsaVerifyError> {
    let mut outer = der;
    let mut body = read_tlv(&mut outer, 0x30)?;
    if !outer.is_empty() {
        return Err(EcdsaVerifyError);
    }
    let r = read_tlv(&mut body, 0x02)?;
    let s = read_tlv(&mut body, 0x02)?;
    if !body.is_empty() {
        return Err(EcdsaVerifyError);
    }
    int_to_padded(r, &mut out[..eb])?;
    int_to_padded(s, &mut out[eb..])
}

/// Verify an ECDSA-P256 signature. `pubkey_sec1` is the 65-byte SEC1
/// uncompressed point (`0x04 || X || Y`), `prehash` the SHA-256 digest,
/// `der_sig` the DER `ECDSA-Sig-Value`.
pub fn verify_p256(
    pubkey_sec1: &[u8],
    prehash: &[u8],
    der_sig: &[u8],
) -> Result<(), EcdsaVerifyError> {
    if pubkey_sec1.len() != p256::PUBKEY_BYTES {
        return Err(EcdsaVerifyError);
    }
    let mut pk = [0u8; p256::PUBKEY_BYTES];
    pk.copy_from_slice(pubkey_sec1);
    let mut rs = [0u8; 64];
    der_sig_to_p1363(der_sig, 32, &mut rs)?;
    p256::VerifyingKey::<EcdsaP256Bn>::from_sec1_bytes(pk)
        .verify_prehash(prehash, &rs)
        .map_err(|_| EcdsaVerifyError)
}

/// Verify an ECDSA-P384 signature. `pubkey_sec1` is the 97-byte SEC1
/// uncompressed point, `prehash` the SHA-384 digest.
pub fn verify_p384(
    pubkey_sec1: &[u8],
    prehash: &[u8],
    der_sig: &[u8],
) -> Result<(), EcdsaVerifyError> {
    if pubkey_sec1.len() != p384::PUBKEY_BYTES {
        return Err(EcdsaVerifyError);
    }
    let mut pk = [0u8; p384::PUBKEY_BYTES];
    pk.copy_from_slice(pubkey_sec1);
    let mut rs = [0u8; 96];
    der_sig_to_p1363(der_sig, 48, &mut rs)?;
    p384::VerifyingKey::<EcdsaP384Bn>::from_sec1_bytes(pk)
        .verify_prehash(prehash, &rs)
        .map_err(|_| EcdsaVerifyError)
}

#[cfg(test)]
mod tests {
    use super::*;

    // openssl-generated KATs over the message "krabitls ecdsa probe".
    const P256_PK: [u8; 65] = crate::hex_decode(
        "0445ba1c589efbac5ca4228888374899a599e0d51cf7ea25bfdbe02c4febfe3af1\
         0ab74a6e67642c1569cf8f1365227f391fc5068c2efbea7f90c48f0f89a12c5e",
    );
    const P256_DIGEST: [u8; 32] =
        crate::hex_decode("458d269c6cfffcb9599d715e1c0afe6d1364efe9560879bc9571ab3828c55f00");
    const P256_SIG: [u8; 70] = crate::hex_decode(
        "304402200c5937bafa2a954ed5be58f3dd105e01d127a6271e55a1602a2e2a1c874\
         295a10220711f4d547895ff329e19ef0198a928e81ab9b0eeedf41fab03f9531b29\
         330df4",
    );

    const P384_PK: [u8; 97] = crate::hex_decode(
        "042771bc8da8486959e59d6e379d4af4e26e833bcd5025a0f0920b931497dda46d6\
         ceb4235c4d5f1a5b527bdc5d54281e52863c219702822e12a68b0beb0d505ed43a1\
         61f264bab74b52babfee01c72fb24a6a8c46d5fba40a5a9f4a6ecb75a4b8",
    );
    const P384_DIGEST: [u8; 48] = crate::hex_decode(
        "c1fc36fd42c1e680cb4417ee7a7defb3724138e2bd8046eaecfcabdfd8eca3f1d5e\
         d4bc05d157d6f53300e80e234371a",
    );
    const P384_SIG: [u8; 104] = crate::hex_decode(
        "30660231008f8812246f6bfcbc6155023e27928ae5f0742169337737632b5cee9e2\
         20e01e0406d3b35e9ec2d838871a2cbdfd4482202310099475723d07a21f57bbf55\
         73a1303631b0cec924a18aed52c152aa378eb0c8df0abc021169e202e76c30aebbc\
         041427a",
    );

    #[test]
    fn p256_kat_verifies() {
        assert!(verify_p256(&P256_PK, &P256_DIGEST, &P256_SIG).is_ok());
    }

    #[test]
    fn p256_tampered_digest_rejects() {
        let mut d = P256_DIGEST;
        d[0] ^= 1;
        assert!(verify_p256(&P256_PK, &d, &P256_SIG).is_err());
    }

    #[test]
    fn p256_tampered_sig_rejects() {
        let mut sig = P256_SIG;
        sig[10] ^= 1;
        assert!(verify_p256(&P256_PK, &P256_DIGEST, &sig).is_err());
    }

    #[test]
    fn p384_kat_verifies() {
        assert!(verify_p384(&P384_PK, &P384_DIGEST, &P384_SIG).is_ok());
    }

    #[test]
    fn p384_tampered_digest_rejects() {
        let mut d = P384_DIGEST;
        d[0] ^= 1;
        assert!(verify_p384(&P384_PK, &d, &P384_SIG).is_err());
    }

    #[test]
    fn malformed_der_rejects() {
        assert!(verify_p256(&P256_PK, &P256_DIGEST, &[0x30, 0x00]).is_err());
        assert!(verify_p256(&P256_PK, &P256_DIGEST, &[]).is_err());
    }
}
