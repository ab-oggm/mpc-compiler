use anyhow::{anyhow, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use base64::Engine as _;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyKeysFile {
    /// 32-byte seed (ed25519 signing key)
    pub sk_seed_b64: String,
}

pub struct PartyKeys {
    pub sk: SigningKey,
    pub pk: VerifyingKey,
}

impl PartyKeys {
    pub fn load_or_create(path: &str) -> Result<Self> {
        let (sk, pk) = if let Ok(data) = fs::read_to_string(path) {
            let kf: PartyKeysFile = serde_json::from_str(&data)?;
            let seed = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, kf.sk_seed_b64)?;
            if seed.len() != 32 {
                return Err(anyhow!("party key seed must be 32 bytes"));
            }
            let mut seed32 = [0u8; 32];
            seed32.copy_from_slice(&seed);
            let sk = SigningKey::from_bytes(&seed32);
            let pk = sk.verifying_key();
            (sk, pk)
        } else {
            let sk = SigningKey::generate(&mut OsRng);
            let pk = sk.verifying_key();
            let seed32 = sk.to_bytes();
            let kf = PartyKeysFile {
                sk_seed_b64: base64::engine::general_purpose::STANDARD.encode(seed32),
            };
            fs::write(path, serde_json::to_string_pretty(&kf)?)?;
            (sk, pk)
        };
        Ok(Self { sk, pk })
    }
}
