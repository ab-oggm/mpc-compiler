use anyhow::{anyhow, Result};
use common::{
    crypto::{sign_struct, verify_struct, verifying_key_from_bytes, enc},
    merkle::{leaf_hash, merkle_root},
    types::{PartyRegistrationRecord, SignedRosterSnapshot, SnapshotMessage},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use base64::Engine as _;

#[derive(Debug)]
pub struct WatchtowerState {
    pub epoch: u64,
    pub log: Vec<PartyRegistrationRecord>, // 1-indexed conceptually
    pub last_seq: HashMap<u64, u64>,        // party_id -> last seq accepted
    pub sk_w: SigningKey,
    pub pk_w: VerifyingKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyFile {
    /// raw 32-byte signing key seed (ed25519)
    sk_seed_b64: String,
}

impl WatchtowerState {
    pub fn load_or_create(epoch: u64, key_file: &str) -> Result<Self> {
        let (sk_w, pk_w) = if let Ok(data) = fs::read_to_string(key_file) {
            let kf: KeyFile = serde_json::from_str(&data)?;
            let seed = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, kf.sk_seed_b64)?;
            if seed.len() != 32 {
                return Err(anyhow!("watchtower key seed must be 32 bytes"));
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
            let kf = KeyFile {
                sk_seed_b64: base64::engine::general_purpose::STANDARD.encode(seed32),
            };
            fs::write(key_file, serde_json::to_string_pretty(&kf)?)?;
            (sk, pk)
        };

        Ok(Self {
            epoch,
            log: Vec::new(),
            last_seq: HashMap::new(),
            sk_w,
            pk_w,
        })
    }

    pub fn watchtower_pubkey_bytes(&self) -> [u8; 32] {
        self.pk_w.to_bytes()
    }

    pub fn register(&mut self, prr: PartyRegistrationRecord) -> Result<SignedRosterSnapshot> {
        // Epoch must match
        if prr.msg.epoch != self.epoch {
            return Err(anyhow!(
                "epoch mismatch: watchtower epoch={}, got={}",
                self.epoch,
                prr.msg.epoch
            ));
        }

        // Verify party signature
        let pk_party = verifying_key_from_bytes(&prr.msg.pk_party)?;
        verify_struct(&pk_party, &prr.msg, &prr.sig_party)?;

        // Enforce seq monotonicity
        let pid = prr.msg.party_id;
        let seq = prr.msg.seq;
        if let Some(last) = self.last_seq.get(&pid) {
            if seq <= *last {
                return Err(anyhow!(
                    "seq must increase for party_id={pid}. last={last}, got={seq}"
                ));
            }
        }

        self.last_seq.insert(pid, seq);
        self.log.push(prr);

        Ok(self.snapshot()?)
    }

    pub fn snapshot(&self) -> Result<SignedRosterSnapshot> {
        let k = self.log.len() as u64;

        // Build Merkle root over leaf hashes of serialized PRRs
        let mut leaves = Vec::with_capacity(self.log.len());
        for prr in &self.log {
            let bytes = enc(prr)?;
            leaves.push(leaf_hash(&bytes));
        }
        let root = merkle_root(leaves);

        let msg = SnapshotMessage {
            epoch: self.epoch,
            log_len: k,
            merkle_root: root,
        };
        let sig_watchtower = sign_struct(&self.sk_w, &msg)?;

        Ok(SignedRosterSnapshot { msg, sig_watchtower })
    }

    pub fn entries(&self, from: u64, to: u64) -> Result<Vec<PartyRegistrationRecord>> {
        let k = self.log.len() as u64;
        if from == 0 || to == 0 || from > to {
            return Err(anyhow!("invalid range: from={from} to={to} (must be 1-indexed, from<=to)"));
        }
        if to > k {
            return Err(anyhow!("range out of bounds: to={to} > log_len={k}"));
        }
        // Convert to 0-indexed slice.
        let start = (from - 1) as usize;
        let end = to as usize;
        Ok(self.log[start..end].to_vec())
    }
}
