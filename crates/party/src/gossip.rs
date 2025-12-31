use anyhow::{anyhow, Result};
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use common::crypto::verify_struct;
use common::types::GossipSnapshot;
use ed25519_dalek::VerifyingKey;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct GossipState {
    pub pk_w: VerifyingKey,
    /// Store the last seen SRS (epoch, log_len, root). If conflicts arrive, we report.
    pub last: Arc<Mutex<Option<common::types::SignedRosterSnapshot>>>,
}

pub fn router(state: GossipState) -> Router {
    Router::new().route("/gossip", post(gossip)).with_state(state)
}

async fn gossip(State(st): State<GossipState>, Json(req): Json<GossipSnapshot>) -> impl IntoResponse {
    // Verify watchtower signature on received snapshot
    if let Err(e) = verify_struct(&st.pk_w, &req.srs.msg, &req.srs.sig_watchtower) {
        return (StatusCode::BAD_REQUEST, format!("invalid watchtower signature: {e}")).into_response();
    }

    let mut guard = st.last.lock().unwrap();
    if let Some(prev) = guard.as_ref() {
        // Equivocation detection: same epoch & log_len but different root
        if prev.msg.epoch == req.srs.msg.epoch
            && prev.msg.log_len == req.srs.msg.log_len
            && prev.msg.merkle_root != req.srs.msg.merkle_root
        {
            let msg = format!(
                "EQUIVOCATION DETECTED: epoch={}, log_len={}, prev_root!=new_root. \
                 Keep both signed snapshots as evidence.",
                prev.msg.epoch, prev.msg.log_len
            );
            return (StatusCode::CONFLICT, msg).into_response();
        }
    }

    // Update last seen
    *guard = Some(req.srs);

    (StatusCode::OK, "ok").into_response()
}

/// Client helper: send your SRS to a peer's gossip endpoint.
pub async fn send_gossip(peer_base: &str, from_party_id: u64, srs: common::types::SignedRosterSnapshot) -> Result<()> {
    let url = format!("{}/gossip", peer_base.trim_end_matches('/'));
    let http = reqwest::Client::new();
    let resp = http
        .post(url)
        .json(&common::types::GossipSnapshot { from_party_id, srs })
        .send()
        .await?;

    if !resp.status().is_success() && resp.status() != StatusCode::CONFLICT {
        return Err(anyhow!("gossip send failed: {} {}", resp.status(), resp.text().await?));
    }
    Ok(())
}
