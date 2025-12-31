mod client;
mod gossip;
mod keys;
mod p2p;
mod state;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use common::crypto::sign_struct;
use common::types::{Endpoint, PartyRegistrationRecord, RegistrationMessage};
use ed25519_dalek::VerifyingKey;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashSet;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(name = "party")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Register this party with the watchtower (uses persisted next_seq from state file).
    Register {
        #[arg(long)]
        watchtower: String,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        party_id: u64,
        /// This party's externally reachable endpoint "ip:port"
        #[arg(long)]
        endpoint: String,
        /// Path to store/load party key seed.
        #[arg(long, default_value = "party_key.json")]
        key_file: String,
        /// Path to store/load party state.
        #[arg(long, default_value = "party_state.json")]
        state_file: String,
        /// Watchtower pubkey (base64). If omitted, fetched from /watchtower_pubkey (TOFU).
        #[arg(long)]
        watchtower_pubkey_b64: Option<String>,
    },

    /// Fetch latest roster from watchtower, verify signatures and merkle root.
    Sync {
        #[arg(long)]
        watchtower: String,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        party_id: u64,
        #[arg(long, default_value = "party_state.json")]
        state_file: String,
        /// Watchtower pubkey (base64). If omitted, fetched from /watchtower_pubkey (TOFU).
        #[arg(long)]
        watchtower_pubkey_b64: Option<String>,
    },

    /// A single command that:
    /// 1) starts a P2P listener on --endpoint,
    /// 2) registers/updates itself (seq persisted),
    /// 3) periodically syncs roster + connects to all peers and logs success.
    Run {
        #[arg(long)]
        watchtower: String,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        party_id: u64,
        /// This party's bind + advertised endpoint "ip:port"
        #[arg(long)]
        endpoint: String,
        /// How often to sync and attempt connections
        #[arg(long, default_value_t = 5)]
        interval_secs: u64,
        /// TCP connect timeout per peer (ms)
        #[arg(long, default_value_t = 500)]
        connect_timeout_ms: u64,
        #[arg(long, default_value = "party_key.json")]
        key_file: String,
        #[arg(long, default_value = "party_state.json")]
        state_file: String,
        /// Watchtower pubkey (base64). If omitted, fetched from /watchtower_pubkey (TOFU).
        #[arg(long)]
        watchtower_pubkey_b64: Option<String>,
    },

    /// Serve a gossip endpoint at --bind (separate from P2P), for equivocation detection.
    GossipServe {
        /// Bind address for this party's gossip server (e.g. 0.0.0.0:9001).
        #[arg(long)]
        bind: String,
        #[arg(long)]
        watchtower: String,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        party_id: u64,
        #[arg(long, default_value = "party_state.json")]
        state_file: String,
        /// Watchtower pubkey (base64). If omitted, fetched from /watchtower_pubkey (TOFU).
        #[arg(long)]
        watchtower_pubkey_b64: Option<String>,
    },

    /// Send your current snapshot to a peer's gossip endpoint (e.g. http://ip:port).
    GossipSend {
        #[arg(long)]
        peer: String,
        #[arg(long)]
        party_id: u64,
        #[arg(long, default_value = "party_state.json")]
        state_file: String,
    },

    /// Print current roster from local state.
    ShowRoster {
        #[arg(long, default_value = "party_state.json")]
        state_file: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let cli = Cli::parse();

    match cli.cmd {
        Command::Register {
            watchtower,
            epoch,
            party_id,
            endpoint,
            key_file,
            state_file,
            watchtower_pubkey_b64,
        } => {
            let wt = client::WatchtowerClient::new(watchtower);
            let pk_w = load_or_fetch_watchtower_pk(&wt, watchtower_pubkey_b64).await?;
            let keys = keys::PartyKeys::load_or_create(&key_file)?;
            let mut st = state::PartyStateFile::load_or_init(&state_file, epoch, party_id)?;

            register_self(&wt, &keys, &mut st, endpoint).await?;
            full_sync_and_verify(&wt, &pk_w, &mut st).await?;
            st.save(&state_file)?;

            info!("registered and synced. roster_size={}", st.roster.len());
        }

        Command::Sync {
            watchtower,
            epoch,
            party_id,
            state_file,
            watchtower_pubkey_b64,
        } => {
            let wt = client::WatchtowerClient::new(watchtower);
            let pk_w = load_or_fetch_watchtower_pk(&wt, watchtower_pubkey_b64).await?;
            let mut st = state::PartyStateFile::load_or_init(&state_file, epoch, party_id)?;
            full_sync_and_verify(&wt, &pk_w, &mut st).await?;
            st.save(&state_file)?;
            info!("synced. roster_size={}", st.roster.len());
        }

        Command::Run {
            watchtower,
            epoch,
            party_id,
            endpoint,
            interval_secs,
            connect_timeout_ms,
            key_file,
            state_file,
            watchtower_pubkey_b64,
        } => {
            let wt = client::WatchtowerClient::new(watchtower);
            let pk_w = load_or_fetch_watchtower_pk(&wt, watchtower_pubkey_b64).await?;
            let keys = keys::PartyKeys::load_or_create(&key_file)?;
            let mut st = state::PartyStateFile::load_or_init(&state_file, epoch, party_id)?;

            // Start P2P listener in background.
            let p2p_bind = endpoint.clone();
            tokio::spawn(async move {
                if let Err(e) = p2p::serve_p2p(&p2p_bind).await {
                    eprintln!("p2p server error: {e}");
                }
            });

            // Register/update self so others can find us.
            register_self(&wt, &keys, &mut st, endpoint).await?;
            full_sync_and_verify(&wt, &pk_w, &mut st).await?;
            st.save(&state_file)?;

            // Connectivity tracking: only log "connected to X" once per peer.
            let mut connected: HashSet<u64> = HashSet::new();

            loop {
                if let Err(e) = full_sync_and_verify(&wt, &pk_w, &mut st).await {
                    warn!("sync error: {}", e);
                } else {
                    // Attempt to connect to all peers (excluding self).
                    let my_id = st.party_id;
                    let peers: Vec<(u64, String)> = st
                        .roster
                        .iter()
                        .filter(|(pid, _)| **pid != my_id)
                        .map(|(pid, entry)| (*pid, entry.endpoint.clone()))
                        .collect();

                    for (pid, addr) in peers {
                        if connected.contains(&pid) {
                            continue;
                        }
                        match p2p::connect_and_handshake(&addr, my_id, connect_timeout_ms).await {
                            Ok(_) => {
                                connected.insert(pid);
                                info!("connected to party_id={} at {}", pid, addr);
                            }
                            Err(_) => {
                                // Not fatal; peer may not be up yet.
                            }
                        }
                    }

                    st.save(&state_file)?;
                    info!(
                        "ready-check: roster_size={}, connected_peers={}",
                        st.roster.len(),
                        connected.len()
                    );
                }

                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            }
        }

        Command::GossipServe {
            bind,
            watchtower,
            epoch,
            party_id,
            state_file,
            watchtower_pubkey_b64,
        } => {
            let wt = client::WatchtowerClient::new(watchtower);
            let pk_w = load_or_fetch_watchtower_pk(&wt, watchtower_pubkey_b64).await?;

            // Initialize gossip state with current snapshot if exists.
            let st = state::PartyStateFile::load_or_init(&state_file, epoch, party_id)?;
            let shared_last = std::sync::Arc::new(std::sync::Mutex::new(st.current_srs.clone()));

            let gs = gossip::GossipState {
                pk_w,
                last: shared_last,
            };

            let app = gossip::router(gs);
            let addr: std::net::SocketAddr = bind.parse()?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            info!("gossip server listening on {}", addr);
            axum::serve(listener, app).await?;
        }

        Command::GossipSend { peer, party_id, state_file } => {
            let st: state::PartyStateFile =
                serde_json::from_str(&std::fs::read_to_string(&state_file)?)?;
            let srs = st.current_srs.ok_or_else(|| anyhow!("no current_srs in state file"))?;
            gossip::send_gossip(&peer, party_id, srs).await?;
            info!("gossip sent to {}", peer);
        }

        Command::ShowRoster { state_file } => {
            let st: state::PartyStateFile =
                serde_json::from_str(&std::fs::read_to_string(&state_file)?)?;
            println!("epoch: {}", st.epoch);
            println!("party_id: {}", st.party_id);
            println!("next_seq: {}", st.next_seq);
            println!("last_log_len: {}", st.last_log_len);
            println!("roster (party_id -> endpoint, seq):");
            let mut keys: Vec<_> = st.roster.keys().cloned().collect();
            keys.sort();
            for pid in keys {
                let e = &st.roster[&pid];
                println!("  {} -> {}, seq={}", pid, e.endpoint, e.seq);
            }
        }
    }

    Ok(())
}

async fn register_self(
    wt: &client::WatchtowerClient,
    keys: &keys::PartyKeys,
    st: &mut state::PartyStateFile,
    endpoint: String,
) -> Result<()> {
    let seq = st.next_seq;

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let msg = RegistrationMessage {
        epoch: st.epoch,
        party_id: st.party_id,
        endpoint: Endpoint { addr: endpoint },
        pk_party: keys.pk.to_bytes(),
        seq,
        nonce,
    };

    let sig_party = sign_struct(&keys.sk, &msg)?;
    let prr = PartyRegistrationRecord { msg, sig_party };

    let srs = wt.register(prr).await?;
    st.current_srs = Some(srs);

    // Advance sequence for next re-register/update.
    st.next_seq = st.next_seq.saturating_add(1);
    Ok(())
}

async fn load_or_fetch_watchtower_pk(
    wt: &client::WatchtowerClient,
    provided_b64: Option<String>,
) -> Result<VerifyingKey> {
    let b64 = if let Some(v) = provided_b64 {
        v
    } else {
        // TOFU: fetch from watchtower. For production you'd pin it.
        wt.get_watchtower_pubkey_b64().await?
    };

    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)?;
    if bytes.len() != 32 {
        return Err(anyhow!("watchtower pubkey must be 32 bytes"));
    }
    let mut pk32 = [0u8; 32];
    pk32.copy_from_slice(&bytes);
    Ok(VerifyingKey::from_bytes(&pk32)?)
}

async fn full_sync_and_verify(
    wt: &client::WatchtowerClient,
    pk_w: &VerifyingKey,
    st: &mut state::PartyStateFile,
) -> Result<()> {
    let srs = wt.snapshot().await?;
    // Full fetch 1..log_len so we can recompute Merkle root and verify end-to-end.
    let k = srs.msg.log_len;
    let entries = if k == 0 { vec![] } else { wt.entries(1, k).await? };

    client::verify_snapshot_and_log(pk_w, &srs, &entries)?;

    st.current_srs = Some(srs);
    st.last_log_len = k;
    st.apply_prrs(&entries);
    Ok(())
}
