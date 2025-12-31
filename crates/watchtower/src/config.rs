use clap::Parser;

#[derive(Debug, Parser)]
pub struct Config {
    /// Bind address for the watchtower HTTP server.
    #[arg(long, default_value = "0.0.0.0:7000")]
    pub bind: String,

    /// Epoch/session id.
    #[arg(long, default_value_t = 1)]
    pub epoch: u64,

    /// Watchtower key file path (JSON). Generated if missing.
    #[arg(long, default_value = "watchtower_key.json")]
    pub key_file: String,
}
