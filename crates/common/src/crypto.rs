use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use ed25519_dalek::Signer;

/// Hash bytes with SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Deterministic encoding for signing: bincode over the struct.
pub fn enc<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(bincode::serialize(value)?)
}

/// Sign: sigma = Sign(sk, H(Enc(msg))).
pub fn sign_struct<T: serde::Serialize>(sk: &SigningKey, msg: &T) -> Result<[u8; 64]> {
    let bytes = enc(msg)?;
    let h = sha256(&bytes);
    let sig: Signature = sk.sign(&h);
    Ok(sig.to_bytes())
}

/// Verify: Verify(pk, H(Enc(msg)), sigma).
pub fn verify_struct<T: serde::Serialize>(pk: &VerifyingKey, msg: &T, sig_bytes: &[u8; 64]) -> Result<()> {
    let bytes = enc(msg)?;
    let h = sha256(&bytes);

    let sig = Signature::from_bytes(sig_bytes);
    pk.verify_strict(&h, &sig)
        .map_err(|e| anyhow!("signature verification failed: {e}"))
}

/// Parse verifying key from raw bytes.
pub fn verifying_key_from_bytes(pk: &[u8; 32]) -> Result<VerifyingKey> {
    Ok(VerifyingKey::from_bytes(pk)?)
}
