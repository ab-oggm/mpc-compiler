use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Party endpoint. Keep as a string for simplicity: "ip:port" or "host:port".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Endpoint {
    pub addr: String,
}

/// Party Registration *message* (what is signed by the party).
/// This is the canonical structure that is serialized (bincode) and signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationMessage {
    pub epoch: u64,
    pub party_id: u64,
    pub endpoint: Endpoint,
    /// Party public key (ed25519) in raw bytes (32 bytes).
    pub pk_party: [u8; 32],
    /// Monotonic per-party sequence within an epoch.
    pub seq: u64,
    /// Random 128-bit nonce for uniqueness/hygiene.
    pub nonce: [u8; 16],
}

/// Party Registration Record = message + party signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartyRegistrationRecord {
    pub msg: RegistrationMessage,
    /// Party signature over H(Enc(msg)).
    #[serde(with = "BigArray")]
    pub sig_party: [u8; 64],
}

/// Watchtower Snapshot *message* (what is signed by watchtower).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMessage {
    pub epoch: u64,
    pub log_len: u64,
    /// Merkle root committing to PRR log [1..log_len]
    pub merkle_root: [u8; 32],
}

/// Signed roster snapshot = snapshot message + watchtower signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRosterSnapshot {
    pub msg: SnapshotMessage,
    /// Watchtower signature over H(Enc(msg)).
    #[serde(with = "BigArray")]
    pub sig_watchtower: [u8; 64],
}

/// Request payload for /register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub prr: PartyRegistrationRecord,
}

/// Response payload for /register and /snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotResponse {
    pub srs: SignedRosterSnapshot,
}

/// Response payload for /entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntriesResponse {
    /// 1-indexed entries, returned in order.
    pub entries: Vec<PartyRegistrationRecord>,
}

/// Optional gossip payload (party-to-party) to detect watchtower equivocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipSnapshot {
    pub from_party_id: u64,
    pub srs: SignedRosterSnapshot,
}
