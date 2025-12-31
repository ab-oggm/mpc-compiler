use anyhow::Result;
use common::types::{PartyRegistrationRecord, SignedRosterSnapshot};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use base64::Engine as _;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterEntry {
    pub endpoint: String,
    pub pk_party_b64: String,
    pub seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyStateFile {
    pub epoch: u64,
    pub party_id: u64,

    /// Next seq to use if this party registers/updates again.
    pub next_seq: u64,

    /// Last seen watchtower snapshot.
    pub current_srs: Option<SignedRosterSnapshot>,

    /// Local cached log length.
    pub last_log_len: u64,

    /// Derived roster map: party_id -> latest entry (by seq).
    pub roster: HashMap<u64, RosterEntry>,

    /// For debugging: last fetched PRRs count.
    pub last_entries_count: usize,
}

impl PartyStateFile {
    pub fn new(epoch: u64, party_id: u64) -> Self {
        Self {
            epoch,
            party_id,
            next_seq: 1,
            current_srs: None,
            last_log_len: 0,
            roster: HashMap::new(),
            last_entries_count: 0,
        }
    }

    pub fn load_or_init(path: &str, epoch: u64, party_id: u64) -> Result<Self> {
        if let Ok(data) = fs::read_to_string(path) {
            let mut st: PartyStateFile = serde_json::from_str(&data)?;
            // If user changes epoch/party_id, reset the state to avoid confusion.
            if st.epoch != epoch || st.party_id != party_id {
                st = Self::new(epoch, party_id);
            }
            Ok(st)
        } else {
            Ok(Self::new(epoch, party_id))
        }
    }

    pub fn save(&self, path: &str) -> Result<()> {
        fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn apply_prrs(&mut self, prrs: &[PartyRegistrationRecord]) {
        for prr in prrs {
            let pid = prr.msg.party_id;
            let seq = prr.msg.seq;
            let endpoint = prr.msg.endpoint.addr.clone();
            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(prr.msg.pk_party);

            let should_update = match self.roster.get(&pid) {
                None => true,
                Some(existing) => seq > existing.seq,
            };

            if should_update {
                self.roster.insert(
                    pid,
                    RosterEntry {
                        endpoint,
                        pk_party_b64: pk_b64,
                        seq,
                    },
                );
            }
        }
        self.last_entries_count = prrs.len();
    }
}
