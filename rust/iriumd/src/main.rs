use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(name="iriumd", version, author="iriumlabs", about="Irium node daemon")]
struct Cli {
    /// Increase verbosity (-v, -vv)
    #[arg(short, long, global=true, action=clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the node services (placeholder)
    Start {
        #[arg(long, default_value="configs")]
        config_dir: String,
    },
    /// Load and verify the genesis header JSON
    CheckGenesis {
        #[arg(long, default_value="configs/genesis.header.json")]
        genesis: String,
    },
    /// P2P handshake placeholder
    P2pHandshake {
        #[arg(long, default_value="127.0.0.1:38291")]
        peer: String,
    },
}

#[derive(Deserialize, Debug)]
struct HeaderFields {
    version: u32,
    prev_hash: String,
    merkle_root: String,
    time: u64,
    bits: String,
    nonce: u32,
    hash: String,
}

#[derive(Deserialize, Debug)]
struct GenesisFile {
    height: u64,
    header: HeaderFields,
    transactions: Vec<String>,
}

fn init_tracing(verbosity: u8) {
    let level = match verbosity { 0 => "info", 1 => "debug", _ => "trace" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    fmt().with_env_filter(filter).with_target(false).init();
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.cmd {
        Commands::Start { config_dir } => {
            info!(%config_dir, "starting iriumd (placeholder)");
            // Placeholder: future work will start services and spawn listeners
            println!("iriumd start (config_dir={})", config_dir);
            Ok(())
        }
        Commands::CheckGenesis { genesis } => {
            let raw = fs::read_to_string(&genesis)
                .with_context(|| format!("reading {}", genesis))?;
            let parsed: GenesisFile = serde_json::from_str(&raw)
                .with_context(|| "parsing genesis header JSON")?;
            info!(height=%parsed.height, "loaded genesis header");

            // Recompute double-SHA256 header hash to confirm integrity
            let hdr = &parsed.header;
            let bits_u32 = u32::from_str_radix(hdr.bits.trim_start_matches("0x"), 16)
                .with_context(|| "parsing bits field as hex")?;
            let mut header_bytes = Vec::with_capacity(80);
            header_bytes.extend_from_slice(&hdr.version.to_le_bytes());
            let prev = hex::decode(&hdr.prev_hash)
                .with_context(|| "decoding prev_hash hex")?;
            let merkle = hex::decode(&hdr.merkle_root)
                .with_context(|| "decoding merkle_root hex")?;
            if prev.len() != 32 || merkle.len() != 32 {
                anyhow::bail!("prev_hash or merkle_root must be 32 bytes");
            }
            header_bytes.extend_from_slice(&prev.iter().rev().copied().collect::<Vec<u8>>());
            header_bytes.extend_from_slice(&merkle.iter().rev().copied().collect::<Vec<u8>>());
            header_bytes.extend_from_slice(&(hdr.time as u32).to_le_bytes());
            header_bytes.extend_from_slice(&bits_u32.to_le_bytes());
            header_bytes.extend_from_slice(&hdr.nonce.to_le_bytes());

            let first = Sha256::digest(&header_bytes);
            let second = Sha256::digest(&first);
            let mut derived = second.to_vec();
            derived.reverse();
            let derived_hex = hex::encode(derived);
            println!("derived header hash: {}", derived_hex);
            println!("file header hash   : {}", hdr.hash);
            println!("match: {}", derived_hex.eq_ignore_ascii_case(&hdr.hash));

            Ok(())
        }
        Commands::P2pHandshake { peer } => {
            warn!(%peer, "P2P handshake stub (no network I/O performed)");
            println!("P2P handshake stub for peer {}", peer);
            Ok(())
        }
    }
}
