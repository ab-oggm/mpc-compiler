use crate::state::WatchtowerState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use common::types::{EntriesResponse, RegisterRequest, SnapshotResponse};
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use base64::Engine as _;

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<Mutex<WatchtowerState>>,
}

#[derive(Debug, Deserialize)]
pub struct EntriesQuery {
    pub from: u64,
    pub to: u64,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/snapshot", get(snapshot))
        .route("/entries", get(entries))
        .route("/watchtower_pubkey", get(watchtower_pubkey))
        .with_state(state)
}

async fn register(State(st): State<AppState>, Json(req): Json<RegisterRequest>) -> impl IntoResponse {
    let mut guard = st.inner.lock().unwrap();
    match guard.register(req.prr) {
        Ok(srs) => (StatusCode::OK, Json(SnapshotResponse { srs })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn snapshot(State(st): State<AppState>) -> impl IntoResponse {
    let guard = st.inner.lock().unwrap();
    match guard.snapshot() {
        Ok(srs) => (StatusCode::OK, Json(SnapshotResponse { srs })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn entries(State(st): State<AppState>, Query(q): Query<EntriesQuery>) -> impl IntoResponse {
    let guard = st.inner.lock().unwrap();
    match guard.entries(q.from, q.to) {
        Ok(entries) => (StatusCode::OK, Json(EntriesResponse { entries })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn watchtower_pubkey(State(st): State<AppState>) -> impl IntoResponse {
    let guard = st.inner.lock().unwrap();
    let pk = guard.watchtower_pubkey_bytes();
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(pk);
    (StatusCode::OK, pk_b64)
}
