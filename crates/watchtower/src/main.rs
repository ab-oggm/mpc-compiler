mod api;
mod config;
mod state;

use crate::{api::AppState, config::Config, state::WatchtowerState};
use axum::Router;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower_http::trace::TraceLayer;
use tracing::info;
use base64::Engine as _;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    let cfg = Config::parse();

    let wt_state = WatchtowerState::load_or_create(cfg.epoch, &cfg.key_file)?;
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(wt_state.watchtower_pubkey_bytes());

    info!("Watchtower starting on {}", cfg.bind);
    info!("epoch = {}", cfg.epoch);
    info!("watchtower_pubkey_b64 = {}", pk_b64);

    let shared = AppState {
        inner: Arc::new(Mutex::new(wt_state)),
    };

    let app: Router = api::router(shared).layer(TraceLayer::new_for_http());

    let addr: SocketAddr = cfg.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
