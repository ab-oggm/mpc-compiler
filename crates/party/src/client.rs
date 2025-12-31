use anyhow::{anyhow, Result};
use common::{
    crypto::{enc, verify_struct, verifying_key_from_bytes},
    merkle::{leaf_hash, merkle_root},
    types::{
        EntriesResponse, PartyRegistrationRecord, RegisterRequest, SnapshotResponse,
        SignedRosterSnapshot,
    },
};
use ed25519_dalek::VerifyingKey;

#[derive(Clone)]
pub struct WatchtowerClient {
    base: String,
    http: reqwest::Client,
}

impl WatchtowerClient {
    pub fn new(base: String) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn get_watchtower_pubkey_b64(&self) -> Result<String> {
        let url = format!("{}/watchtower_pubkey", self.base);
        let resp = self.http.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("watchtower_pubkey failed: {}", resp.status()));
        }
        Ok(resp.text().await?)
    }

    pub async fn register(&self, prr: PartyRegistrationRecord) -> Result<SignedRosterSnapshot> {
        let url = format!("{}/register", self.base);
        let resp = self
            .http
            .post(url)
            .json(&RegisterRequest { prr })
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("register failed: {} {}", resp.status(), resp.text().await?));
        }
        let sr: SnapshotResponse = resp.json().await?;
        Ok(sr.srs)
    }

    pub async fn snapshot(&self) -> Result<SignedRosterSnapshot> {
        let url = format!("{}/snapshot", self.base);
        let resp = self.http.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("snapshot failed: {}", resp.status()));
        }
        let sr: SnapshotResponse = resp.json().await?;
        Ok(sr.srs)
    }

    pub async fn entries(&self, from: u64, to: u64) -> Result<Vec<PartyRegistrationRecord>> {
        let url = format!("{}/entries?from={}&to={}", self.base, from, to);
        let resp = self.http.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("entries failed: {} {}", resp.status(), resp.text().await?));
        }
        let er: EntriesResponse = resp.json().await?;
        Ok(er.entries)
    }
}

/// Verify a watchtower snapshot signature and consistency with fetched PRRs (Merkle root).
pub fn verify_snapshot_and_log(
    pk_w: &VerifyingKey,
    srs: &SignedRosterSnapshot,
    full_log: &[PartyRegistrationRecord],
) -> Result<()> {
    // Verify watchtower signature on snapshot message
    verify_struct(pk_w, &srs.msg, &srs.sig_watchtower)?;

    // Verify log length
    let k = srs.msg.log_len as usize;
    if full_log.len() != k {
        return Err(anyhow!(
            "log length mismatch: snapshot log_len={} but fetched {} entries",
            k,
            full_log.len()
        ));
    }

    // Verify each PRR signature and build leaves
    let mut leaves = Vec::with_capacity(full_log.len());
    for prr in full_log {
        let pk_party = verifying_key_from_bytes(&prr.msg.pk_party)?;
        verify_struct(&pk_party, &prr.msg, &prr.sig_party)?;

        let bytes = enc(prr)?;
        leaves.push(leaf_hash(&bytes));
    }

    let root = merkle_root(leaves);
    if root != srs.msg.merkle_root {
        return Err(anyhow!(
            "merkle root mismatch: snapshot root != computed root"
        ));
    }
    Ok(())
}
