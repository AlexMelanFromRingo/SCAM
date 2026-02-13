use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand, ValueEnum};
use scam_chain::{BlockSubmissionOutcome, ChainError, ChainRuntime};
use scam_consensus::{TxValidationError, UtxoSet, validate_and_apply_block};
use scam_core::{
    ChainConfig, ChainConfigError, DifficultyAlgorithm, Hash256, OutPoint, Target, Transaction,
    TxIn, TxOut, block_meets_pow, render_hash_bitmap_16x16,
};
use scam_miner::{BlockTemplate, mine_block};
use scam_p2p::{
    FramingConfig, GossipEngine, InventoryItem, LocalHandshake, PeerCandidate, TransportError,
    WireMessage, build_block_locator, client_handshake, read_message, request_blocks,
    request_headers, select_block_hashes_for_peer, select_headers_for_peer, select_outbound_peers,
    send_message, server_handshake,
};
use scam_rpc::{StatusResponse, TxResponse, header_to_block_response, to_pretty_json};
use scam_storage::{
    ChainArchive, ChainStateSnapshot, PeerAddressBook, PeerAddressRecord, StorageError,
    load_chain_archive_db, load_peer_book_db, load_snapshot, load_snapshot_db,
    save_chain_archive_db, save_peer_book_db, save_snapshot, save_snapshot_db,
};
use scam_stratum::{
    MiningJob, SUPPORTED_SV2_VERSION, SessionConfig as Sv2SessionConfig, SessionEvent, Sv2Message,
    Sv2Session, read_frame as read_sv2_frame, write_frame as write_sv2_frame,
};
use scam_wallet::{
    AddressError, DeriveKeyError, MnemonicError, QrError, RescanError, SchnorrError, WalletKey,
    WalletMnemonic, WalletVaultError, decrypt_wallet_vault, derive_wallet_key, derive_watched_keys,
    load_wallet_vault, new_encrypted_wallet_vault, new_mnemonic, parse_address, qr_for_payment_uri,
    rescan_blocks, save_wallet_vault, sign_digest, to_address, verify_digest,
};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(name = "scam-node")]
#[command(about = "SCAM full node bootstrap", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    // Backward-compatible flags: if no subcommand is passed, runs node bootstrap.
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    runtime_db: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    print_genesis: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    Node(NodeArgs),
    Status(StatusArgs),
    GetBlock(GetBlockArgs),
    GetTx(GetTxArgs),
    ConfigScaffold(ConfigScaffoldArgs),
    AddPeer(AddPeerArgs),
    HashVisual(HashVisualArgs),
    Wallet(WalletArgs),
    MineOnce(MineOnceArgs),
    ChainDemo(ChainDemoArgs),
    SyncDemo(SyncDemoArgs),
    NetDemo(NetDemoArgs),
    SyncPeer(SyncPeerArgs),
    SyncBook(SyncBookArgs),
    ReindexRuntime(ReindexRuntimeArgs),
    Soak(SoakArgs),
    ReorgDemo(ReorgDemoArgs),
    StratumServe(StratumServeArgs),
    RpcServe(RpcServeArgs),
    Snapshot(SnapshotArgs),
    P2pDemo,
}

#[derive(Debug, Args)]
struct NodeArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    runtime_db: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    print_genesis: bool,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    mine_blocks: u32,
    #[arg(long, default_value_t = 120)]
    interval_sec: u64,
    #[arg(long, default_value_t = 500_000)]
    max_nonce: u64,
    #[arg(long, default_value_t = true)]
    json: bool,
}

#[derive(Debug, Args)]
struct GetBlockArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    height: u64,
    #[arg(long, default_value_t = 120)]
    interval_sec: u64,
    #[arg(long, default_value_t = 500_000)]
    max_nonce: u64,
    #[arg(long, default_value_t = true)]
    json: bool,
}

#[derive(Debug, Args)]
struct GetTxArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    height: u64,
    #[arg(long)]
    tx_index: usize,
    #[arg(long, default_value_t = 120)]
    interval_sec: u64,
    #[arg(long, default_value_t = 500_000)]
    max_nonce: u64,
    #[arg(long, default_value_t = true)]
    json: bool,
}

#[derive(Debug, Args)]
struct ConfigScaffoldArgs {
    #[arg(long)]
    network_id: String,
    #[arg(long, default_value = "s")]
    hrp: String,
    #[arg(long, default_value_t = 120)]
    target_block_time_sec: u64,
    #[arg(long, default_value_t = 20)]
    difficulty_adjustment_window: u32,
    #[arg(long, value_enum, default_value_t = DifficultyAlgoArg::Windowed)]
    difficulty_algorithm: DifficultyAlgoArg,
    #[arg(long, default_value_t = 3_600)]
    asert_half_life_sec: u64,
    #[arg(long, default_value_t = 4.0)]
    difficulty_clamp_up: f64,
    #[arg(long, default_value_t = 0.25)]
    difficulty_clamp_down: f64,
    #[arg(long, default_value_t = 1_000_000)]
    max_block_size: u32,
    #[arg(long, default_value_t = 100_000)]
    max_tx_size: u32,
    #[arg(long, default_value_t = 50_000)]
    max_mempool_txs: u32,
    #[arg(long, default_value_t = 1_000)]
    min_relay_fee_per_kb: u64,
    #[arg(long, default_value_t = 5_000)]
    max_orphan_txs: u32,
    #[arg(long, default_value_t = 1_200)]
    orphan_ttl_sec: u64,
    #[arg(long, default_value_t = 2)]
    p2p_max_outbound_per_bucket: u32,
    #[arg(long = "dns-seed")]
    dns_seeds: Vec<String>,
    #[arg(long, default_value_t = 100)]
    coinbase_maturity: u32,
    #[arg(long, default_value_t = 5_000_000_000)]
    block_subsidy: u64,
    #[arg(long, default_value = "SCAM custom genesis block")]
    genesis_message: String,
    #[arg(long)]
    genesis_timestamp: Option<u64>,
    #[arg(
        long,
        default_value = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )]
    genesis_target: String,
    #[arg(long, default_value_t = 0)]
    genesis_nonce: u64,
    #[arg(long, default_value = "0000000000000000000000000000000000000000")]
    genesis_reward_key_hash20: String,
    #[arg(long, default_value = "config/custom.toml")]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct AddPeerArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    peer: String,
    #[arg(long, default_value = "data/peers")]
    peers_dir: PathBuf,
}

#[derive(Debug, Args)]
struct HashVisualArgs {
    #[arg(long)]
    hash_hex: String,
}

#[derive(Debug, Args)]
struct WalletArgs {
    #[command(subcommand)]
    command: WalletCommand,
}

#[derive(Debug, Args)]
struct MineOnceArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value_t = 50_000)]
    max_nonce: u64,
}

#[derive(Debug, Args)]
struct ChainDemoArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value_t = 25)]
    blocks: u32,
    #[arg(long, default_value_t = 200_000)]
    max_nonce: u64,
    #[arg(long, default_value_t = 30)]
    interval_sec: u64,
}

#[derive(Debug, Args)]
struct SyncDemoArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value_t = 5)]
    local_blocks: u32,
    #[arg(long, default_value_t = 25)]
    remote_blocks: u32,
    #[arg(long, default_value_t = 2000)]
    max_headers: usize,
    #[arg(long, default_value_t = 30)]
    interval_sec: u64,
    #[arg(long, default_value_t = 500_000)]
    max_nonce: u64,
}

#[derive(Debug, Args)]
struct NetDemoArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value_t = 5)]
    local_blocks: u32,
    #[arg(long, default_value_t = 25)]
    remote_blocks: u32,
    #[arg(long, default_value_t = 2000)]
    max_headers: usize,
    #[arg(long, default_value_t = 30)]
    interval_sec: u64,
    #[arg(long, default_value_t = 500_000)]
    max_nonce: u64,
}

#[derive(Debug, Args)]
struct SyncPeerArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    runtime_db: Option<PathBuf>,
    #[arg(long)]
    peer: String,
    #[arg(long, default_value_t = 16)]
    max_batches: u32,
}

#[derive(Debug, Args)]
struct SyncBookArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    runtime_db: Option<PathBuf>,
    #[arg(long, default_value = "data/peers")]
    peers_dir: PathBuf,
    #[arg(long, default_value_t = 8)]
    max_peers: usize,
    #[arg(long, default_value_t = 16)]
    max_batches_per_peer: u32,
    #[arg(long, default_value_t = 6 * 60 * 60)]
    rotate_after_sec: u64,
}

#[derive(Debug, Args)]
struct ReindexRuntimeArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    runtime_db: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct SoakArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    runtime_db: Option<PathBuf>,
    #[arg(long, default_value_t = 60)]
    rounds: u32,
    #[arg(long, default_value_t = 5)]
    blocks_per_round: u32,
    #[arg(long, default_value_t = 30)]
    interval_sec: u64,
    #[arg(long, default_value_t = 500_000)]
    max_nonce: u64,
    #[arg(long, default_value_t = 10)]
    persist_every_rounds: u32,
    #[arg(long, default_value_t = 0)]
    txs_per_round: u32,
    #[arg(long, default_value_t = 1_000)]
    tx_amount: u64,
    #[arg(long, default_value_t = 1)]
    tx_fee: u64,
    #[arg(long, default_value_t = 0)]
    sleep_per_round_sec: u64,
}

#[derive(Debug, Args)]
struct ReorgDemoArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value_t = 4)]
    main_blocks: u32,
    #[arg(long, default_value_t = 6)]
    fork_blocks: u32,
    #[arg(long, default_value_t = 1)]
    fork_from_height: u64,
    #[arg(long, default_value_t = 30)]
    main_interval_sec: u64,
    #[arg(long, default_value_t = 20)]
    fork_interval_sec: u64,
    #[arg(long, default_value_t = 500_000)]
    max_nonce: u64,
}

#[derive(Debug, Args)]
struct StratumServeArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    runtime_db: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:3347")]
    bind: String,
    #[arg(
        long,
        default_value = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )]
    share_target_hex: String,
    #[arg(long, default_value_t = 64)]
    max_jobs_per_channel: usize,
    #[arg(long, default_value_t = 1)]
    max_clients: u32,
}

#[derive(Debug, Args)]
struct RpcServeArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:18080")]
    bind: String,
    #[arg(long, default_value_t = 0)]
    mine_blocks: u32,
    #[arg(long, default_value_t = 120)]
    interval_sec: u64,
    #[arg(long, default_value_t = 500_000)]
    max_nonce: u64,
    #[arg(long, default_value_t = 0)]
    max_requests: u32,
}

#[derive(Debug, Args)]
struct SnapshotArgs {
    #[command(subcommand)]
    command: SnapshotCommand,
}

#[derive(Debug, Subcommand)]
enum SnapshotCommand {
    SaveGenesis {
        #[arg(long, value_enum, default_value_t = Network::Devnet)]
        network: Network,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = "data/chain.snapshot")]
        out: PathBuf,
    },
    SaveGenesisDb {
        #[arg(long, value_enum, default_value_t = Network::Devnet)]
        network: Network,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = "data/chain.redb")]
        out: PathBuf,
    },
    Show {
        #[arg(long)]
        path: PathBuf,
    },
    ShowDb {
        #[arg(long)]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum WalletCommand {
    New {
        #[arg(long, default_value_t = 12)]
        words: usize,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long, default_value = "sd")]
        hrp: String,
    },
    Address {
        #[arg(long)]
        mnemonic: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long, default_value = "sd")]
        hrp: String,
    },
    Restore {
        #[arg(long)]
        mnemonic: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long, default_value = "sd")]
        hrp: String,
    },
    SecureNew {
        #[arg(long, default_value_t = 12)]
        words: usize,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value = "data/wallets/default.vault.json")]
        out: PathBuf,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long, default_value = "sd")]
        hrp: String,
    },
    SecureRestore {
        #[arg(long)]
        mnemonic: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value = "data/wallets/default.vault.json")]
        out: PathBuf,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long, default_value = "sd")]
        hrp: String,
    },
    SecureAddress {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        password: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long, default_value = "sd")]
        hrp: String,
    },
    Rescan {
        #[arg(long, value_enum, default_value_t = Network::Devnet)]
        network: Network,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        mnemonic: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        start_index: u32,
        #[arg(long, default_value_t = 20)]
        end_index: u32,
        #[arg(long, default_value_t = 0)]
        mine_blocks: u32,
        #[arg(long, default_value_t = 120)]
        interval_sec: u64,
        #[arg(long, default_value_t = 500_000)]
        max_nonce: u64,
    },
    SecureRescan {
        #[arg(long, value_enum, default_value_t = Network::Devnet)]
        network: Network,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        password: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        start_index: u32,
        #[arg(long, default_value_t = 20)]
        end_index: u32,
        #[arg(long, default_value_t = 0)]
        mine_blocks: u32,
        #[arg(long, default_value_t = 120)]
        interval_sec: u64,
        #[arg(long, default_value_t = 500_000)]
        max_nonce: u64,
    },
    Balance {
        #[arg(long, value_enum, default_value_t = Network::Devnet)]
        network: Network,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        mnemonic: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long, default_value_t = 0)]
        mine_blocks: u32,
        #[arg(long, default_value_t = 120)]
        interval_sec: u64,
        #[arg(long, default_value_t = 500_000)]
        max_nonce: u64,
    },
    Send {
        #[arg(long, value_enum, default_value_t = Network::Devnet)]
        network: Network,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        mnemonic: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long)]
        to: String,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        amount: u64,
        #[arg(long, default_value_t = 1)]
        fee: u64,
        #[arg(long, default_value_t = 0)]
        mine_blocks: u32,
        #[arg(long, default_value_t = 120)]
        interval_sec: u64,
        #[arg(long, default_value_t = 500_000)]
        max_nonce: u64,
    },
    Decode {
        #[arg(long)]
        address: String,
    },
    Sign {
        #[arg(long)]
        mnemonic: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long)]
        digest_hex: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long, default_value = "sd")]
        hrp: String,
    },
    Verify {
        #[arg(long)]
        pubkey_hex: String,
        #[arg(long)]
        digest_hex: String,
        #[arg(long)]
        signature_hex: String,
    },
    Qr {
        #[arg(long)]
        address: String,
        #[arg(long)]
        amount: Option<u64>,
        #[arg(long)]
        label: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Network {
    Devnet,
    Testnet,
    Mainnet,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DifficultyAlgoArg {
    Windowed,
    Lwma,
    Asert,
}

impl From<DifficultyAlgoArg> for DifficultyAlgorithm {
    fn from(value: DifficultyAlgoArg) -> Self {
        match value {
            DifficultyAlgoArg::Windowed => DifficultyAlgorithm::Windowed,
            DifficultyAlgoArg::Lwma => DifficultyAlgorithm::Lwma,
            DifficultyAlgoArg::Asert => DifficultyAlgorithm::Asert,
        }
    }
}

impl Network {
    fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }
}

fn accepted_hrps_for_network(network: Network, configured_hrp: &str) -> Vec<String> {
    let mut out = vec![configured_hrp.to_owned()];
    let legacy_and_defaults: &[&str] = match network {
        Network::Devnet => &["sd", "scd"],
        Network::Testnet => &["st", "sct"],
        Network::Mainnet => &["s", "sc"],
    };
    for hrp in legacy_and_defaults {
        if !out.iter().any(|existing| existing == hrp) {
            out.push((*hrp).to_owned());
        }
    }
    out
}

#[derive(Debug, Error)]
enum NodeError {
    #[error("cannot read config from {path}: {source}")]
    ConfigRead {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot parse config from {path}: {source}")]
    ConfigParse {
        path: String,
        source: toml::de::Error,
    },
    #[error("invalid chain config: {0}")]
    InvalidConfig(#[from] ChainConfigError),
    #[error("block/tx validation failed: {0}")]
    Validation(#[from] TxValidationError),
    #[error("chain runtime error: {0}")]
    Chain(#[from] ChainError),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("mnemonic error: {0}")]
    Mnemonic(#[from] MnemonicError),
    #[error("key derivation error: {0}")]
    Derive(#[from] DeriveKeyError),
    #[error("address error: {0}")]
    Address(#[from] AddressError),
    #[error("schnorr error: {0}")]
    Schnorr(#[from] SchnorrError),
    #[error("stratum error: {0}")]
    Stratum(#[from] scam_stratum::StratumError),
    #[error("wallet rescan error: {0}")]
    Rescan(#[from] RescanError),
    #[error("qr error: {0}")]
    Qr(#[from] QrError),
    #[error("wallet vault error: {0}")]
    Vault(#[from] WalletVaultError),
    #[error("invalid hex in {field}: {source}")]
    InvalidHex {
        field: &'static str,
        source: hex::FromHexError,
    },
    #[error("{field} must be {expected} bytes, got {got}")]
    InvalidHexLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error(
        "insufficient spendable funds for amount+fee={needed} (spendable total: {spendable_total})"
    )]
    InsufficientFunds { needed: u64, spendable_total: u128 },
    #[error("{0}")]
    Runtime(String),
}

fn load_chain_config(path: &Path) -> Result<ChainConfig, NodeError> {
    let raw = fs::read_to_string(path).map_err(|source| NodeError::ConfigRead {
        path: path.display().to_string(),
        source,
    })?;
    let cfg: ChainConfig = toml::from_str(&raw).map_err(|source| NodeError::ConfigParse {
        path: path.display().to_string(),
        source,
    })?;
    cfg.validate()?;
    Ok(cfg)
}

fn default_runtime_db_path(network: Network) -> PathBuf {
    PathBuf::from(format!("data/{}.runtime.redb", network.as_str()))
}

fn runtime_to_archive(runtime: &ChainRuntime) -> Result<ChainArchive, NodeError> {
    let blocks_by_height = runtime.main_chain_blocks()?;
    Ok(ChainArchive {
        network_id: runtime.config().network_id.clone(),
        blocks_by_height,
    })
}

fn load_runtime_from_db_or_genesis(
    cfg: &ChainConfig,
    runtime_db_path: &Path,
) -> Result<(ChainRuntime, &'static str), NodeError> {
    if runtime_db_path.exists() {
        let archive = load_chain_archive_db(runtime_db_path)?;
        if archive.network_id != cfg.network_id {
            return Err(NodeError::Runtime(format!(
                "runtime db network mismatch: db='{}', config='{}'",
                archive.network_id, cfg.network_id
            )));
        }
        Ok((
            ChainRuntime::from_ordered_blocks(cfg.clone(), archive.blocks_by_height)?,
            "db",
        ))
    } else {
        Ok((ChainRuntime::from_config(cfg.clone())?, "genesis"))
    }
}

fn persist_runtime_db(runtime: &ChainRuntime, runtime_db_path: &Path) -> Result<(), NodeError> {
    let archive = runtime_to_archive(runtime)?;
    save_chain_archive_db(runtime_db_path, &archive)?;
    Ok(())
}

fn run_node(
    network: Network,
    config: Option<PathBuf>,
    runtime_db: Option<PathBuf>,
    print_genesis: bool,
) -> Result<(), NodeError> {
    let config_path =
        config.unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let runtime_db_path = runtime_db.unwrap_or_else(|| default_runtime_db_path(network));
    let (runtime, source) = load_runtime_from_db_or_genesis(&cfg, &runtime_db_path)?;
    persist_runtime_db(&runtime, &runtime_db_path)?;
    let genesis_hash = cfg.build_genesis_block()?.header.block_hash();

    println!("Project: SCAM (Smart Computing Alternative Money)");
    println!("Network: {}", cfg.network_id);
    println!("Config: {}", config_path.display());
    println!("Runtime DB: {}", runtime_db_path.display());
    println!("Runtime source: {}", source);
    println!("Genesis hash: {}", genesis_hash);
    println!("Tip height: {}", runtime.tip_height());
    println!("Tip hash: {}", runtime.tip_hash());
    println!("UTXO count: {}", runtime.utxo_len());
    println!("Chainwork: {}", runtime.cumulative_work().to_str_radix(10));
    println!("Block target: {}", runtime.tip_header().target);

    if print_genesis {
        let genesis = runtime
            .block_by_hash(&runtime.block_hashes()[0])
            .expect("genesis must exist");
        println!("{genesis:#?}");
    }
    Ok(())
}

fn build_runtime_for_query(
    network: Network,
    config: Option<PathBuf>,
    mine_blocks: u32,
    interval_sec: u64,
    max_nonce: u64,
    label_prefix: &'static str,
) -> Result<(ChainConfig, ChainRuntime), NodeError> {
    let config_path =
        config.unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let mut runtime = ChainRuntime::from_config(cfg.clone())?;
    if mine_blocks > 0 {
        let params = MiningLoopParams {
            count: mine_blocks,
            interval_sec,
            max_nonce,
            subsidy: cfg.block_subsidy,
            miner_key_hash: cfg.genesis_reward_key_hash20()?,
            label_prefix,
            print_each: false,
        };
        mine_blocks_on_runtime(&mut runtime, &params)?;
    }
    Ok((cfg, runtime))
}

fn decode_fixed_hex<const N: usize>(field: &'static str, raw: &str) -> Result<[u8; N], NodeError> {
    let normalized = raw.strip_prefix("0x").unwrap_or(raw);
    let decoded =
        hex::decode(normalized).map_err(|source| NodeError::InvalidHex { field, source })?;
    if decoded.len() != N {
        return Err(NodeError::InvalidHexLength {
            field,
            expected: N,
            got: decoded.len(),
        });
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn run_status(args: StatusArgs) -> Result<(), NodeError> {
    let (cfg, runtime) = build_runtime_for_query(
        args.network,
        args.config,
        args.mine_blocks,
        args.interval_sec,
        args.max_nonce,
        "status",
    )?;
    let payload = StatusResponse {
        network_id: cfg.network_id,
        tip_height: runtime.tip_height(),
        tip_hash: runtime.tip_hash().to_hex(),
        utxo_count: runtime.utxo_len(),
        cumulative_work: runtime.cumulative_work().to_str_radix(10),
    };

    if args.json {
        println!(
            "{}",
            to_pretty_json(&payload).map_err(|e| NodeError::Runtime(e.to_string()))?
        );
    } else {
        println!(
            "network={} tip_height={} tip_hash={} utxos={} chainwork={}",
            payload.network_id,
            payload.tip_height,
            payload.tip_hash,
            payload.utxo_count,
            payload.cumulative_work
        );
    }
    Ok(())
}

fn run_get_block(args: GetBlockArgs) -> Result<(), NodeError> {
    let mine_blocks = args.height as u32;
    let (_cfg, runtime) = build_runtime_for_query(
        args.network,
        args.config,
        mine_blocks,
        args.interval_sec,
        args.max_nonce,
        "get-block",
    )?;
    let Some(hash) = runtime.block_hash_at_height(args.height) else {
        return Err(NodeError::Runtime(format!(
            "height {} not found",
            args.height
        )));
    };
    let Some(block) = runtime.block_by_hash(&hash) else {
        return Err(NodeError::Runtime(format!("block {} not found", hash)));
    };

    let payload = header_to_block_response(args.height, &block.header, block.transactions.len());
    if args.json {
        println!(
            "{}",
            to_pretty_json(&payload).map_err(|e| NodeError::Runtime(e.to_string()))?
        );
    } else {
        println!(
            "height={} hash={} prev={} timestamp={} target={} txs={}",
            payload.height,
            payload.hash,
            payload.prev_hash,
            payload.timestamp,
            payload.target,
            payload.tx_count
        );
    }
    Ok(())
}

fn run_get_tx(args: GetTxArgs) -> Result<(), NodeError> {
    let mine_blocks = args.height as u32;
    let (_cfg, runtime) = build_runtime_for_query(
        args.network,
        args.config,
        mine_blocks,
        args.interval_sec,
        args.max_nonce,
        "get-tx",
    )?;
    let Some(hash) = runtime.block_hash_at_height(args.height) else {
        return Err(NodeError::Runtime(format!(
            "height {} not found",
            args.height
        )));
    };
    let Some(block) = runtime.block_by_hash(&hash) else {
        return Err(NodeError::Runtime(format!("block {} not found", hash)));
    };
    let Some(tx) = block.transactions.get(args.tx_index) else {
        return Err(NodeError::Runtime(format!(
            "tx index {} not found in block {}",
            args.tx_index, hash
        )));
    };
    let payload = TxResponse::from_tx(args.height, args.tx_index, tx);
    if args.json {
        println!(
            "{}",
            to_pretty_json(&payload).map_err(|e| NodeError::Runtime(e.to_string()))?
        );
    } else {
        println!(
            "height={} tx_index={} txid={} inputs={} outputs={}",
            payload.block_height,
            payload.tx_index,
            payload.txid,
            payload.input_count,
            payload.output_count
        );
    }
    Ok(())
}

fn run_config_scaffold(args: ConfigScaffoldArgs) -> Result<(), NodeError> {
    let genesis_timestamp = match args.genesis_timestamp {
        Some(ts) => ts,
        None => current_unix_sec()?,
    };
    let cfg = ChainConfig {
        network_id: args.network_id.clone(),
        target_block_time_sec: args.target_block_time_sec,
        difficulty_adjustment_window: args.difficulty_adjustment_window,
        difficulty_algorithm: args.difficulty_algorithm.into(),
        asert_half_life_sec: args.asert_half_life_sec,
        difficulty_clamp_up: args.difficulty_clamp_up,
        difficulty_clamp_down: args.difficulty_clamp_down,
        max_block_size: args.max_block_size,
        max_tx_size: args.max_tx_size,
        max_mempool_txs: args.max_mempool_txs,
        min_relay_fee_per_kb: args.min_relay_fee_per_kb,
        max_orphan_txs: args.max_orphan_txs,
        orphan_ttl_sec: args.orphan_ttl_sec,
        p2p_max_outbound_per_bucket: args.p2p_max_outbound_per_bucket,
        dns_seeds: args.dns_seeds.clone(),
        coinbase_maturity: args.coinbase_maturity,
        block_subsidy: args.block_subsidy,
        hrp: args.hrp.clone(),
        genesis_message: args.genesis_message.clone(),
        genesis_timestamp,
        genesis_target: args.genesis_target.clone(),
        genesis_nonce: args.genesis_nonce,
        genesis_reward_key_hash20: args.genesis_reward_key_hash20.clone(),
    };
    cfg.validate()?;
    let rendered = toml::to_string_pretty(&cfg)
        .map_err(|e| NodeError::Runtime(format!("cannot render config toml: {e}")))?;
    if let Some(parent) = args.out.parent() {
        fs::create_dir_all(parent).map_err(|e| NodeError::Runtime(e.to_string()))?;
    }
    fs::write(&args.out, rendered).map_err(|e| NodeError::Runtime(e.to_string()))?;

    let genesis_hash = cfg.build_genesis_block()?.header.block_hash();
    println!("Config scaffold written: {}", args.out.display());
    println!("Network: {}", cfg.network_id);
    println!("HRP: {}", cfg.hrp);
    println!(
        "Difficulty: {:?} (window={} half_life_sec={})",
        cfg.difficulty_algorithm, cfg.difficulty_adjustment_window, cfg.asert_half_life_sec
    );
    println!("Genesis timestamp: {}", cfg.genesis_timestamp);
    println!("Genesis hash: {}", genesis_hash);
    Ok(())
}

fn peer_book_paths(peers_dir: &Path, network_name: &str) -> (PathBuf, PathBuf) {
    (
        peers_dir.join(format!("{network_name}.redb")),
        peers_dir.join(format!("{network_name}.txt")),
    )
}

fn load_or_init_peer_book(
    network_name: &str,
    peers_db_path: &Path,
    legacy_txt_path: &Path,
) -> Result<PeerAddressBook, NodeError> {
    if peers_db_path.exists() {
        let loaded = load_peer_book_db(peers_db_path)?;
        if loaded.network_id != network_name {
            return Err(NodeError::Runtime(format!(
                "peer book network mismatch in {}: expected '{}', got '{}'",
                peers_db_path.display(),
                network_name,
                loaded.network_id
            )));
        }
        return Ok(loaded);
    }

    if legacy_txt_path.exists() {
        let mut peers = fs::read_to_string(legacy_txt_path)
            .map_err(|e| NodeError::Runtime(e.to_string()))?
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|address| PeerAddressRecord {
                address: address.to_owned(),
                last_seen_unix_sec: 0,
                ban_score: 0,
            })
            .collect::<Vec<_>>();
        peers.sort_by(|a, b| a.address.cmp(&b.address));
        peers.dedup_by(|a, b| a.address == b.address);
        return Ok(PeerAddressBook {
            network_id: network_name.to_owned(),
            peers,
        });
    }

    Ok(PeerAddressBook {
        network_id: network_name.to_owned(),
        peers: Vec::new(),
    })
}

fn current_unix_sec() -> Result<u64, NodeError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| NodeError::Runtime(format!("system clock error: {e}")))?;
    Ok(now.as_secs())
}

fn resolve_dns_seed(seed: &str) -> Vec<SocketAddr> {
    let raw = seed.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return vec![addr];
    }
    let with_port = if raw.contains(':') {
        raw.to_owned()
    } else {
        format!("{raw}:8333")
    };
    with_port
        .to_socket_addrs()
        .map(|iter| iter.collect::<Vec<_>>())
        .unwrap_or_default()
}

fn peer_diversity_bucket(addr: SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("v4-{}.{}", octets[0], octets[1])
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            format!("v6-{:x}:{:x}", seg[0], seg[1])
        }
    }
}

fn apply_bucket_cap(addrs: Vec<SocketAddr>, max_per_bucket: u32) -> Vec<SocketAddr> {
    if max_per_bucket == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(addrs.len());
    let mut counts = HashMap::<String, u32>::new();
    for addr in addrs {
        let key = peer_diversity_bucket(addr);
        let count = counts.entry(key).or_insert(0);
        if *count >= max_per_bucket {
            continue;
        }
        *count = count.saturating_add(1);
        out.push(addr);
    }
    out
}

fn run_add_peer(args: AddPeerArgs) -> Result<(), NodeError> {
    let network_name = args.network.as_str();
    let (peers_db_path, legacy_txt_path) = peer_book_paths(&args.peers_dir, network_name);
    if let Some(parent) = peers_db_path.parent() {
        fs::create_dir_all(parent).map_err(|e| NodeError::Runtime(e.to_string()))?;
    }

    let mut peer_book = load_or_init_peer_book(network_name, &peers_db_path, &legacy_txt_path)?;

    if !peer_book
        .peers
        .iter()
        .any(|entry| entry.address == args.peer)
    {
        peer_book.peers.push(PeerAddressRecord {
            address: args.peer.clone(),
            last_seen_unix_sec: 0,
            ban_score: 0,
        });
        peer_book.peers.sort_by(|a, b| a.address.cmp(&b.address));
        peer_book.peers.dedup_by(|a, b| a.address == b.address);
        save_peer_book_db(&peers_db_path, &peer_book)?;
        println!("Peer added for {}: {}", network_name, args.peer);
    } else {
        println!("Peer already exists for {}: {}", network_name, args.peer);
    }
    println!("Peer book: {}", peers_db_path.display());
    println!("Total peers: {}", peer_book.peers.len());
    Ok(())
}

fn run_hash_visual(args: HashVisualArgs) -> Result<(), NodeError> {
    let hash = Hash256::from_hex(&args.hash_hex)
        .map_err(|e| NodeError::Runtime(format!("bad hash: {e}")))?;
    let rendered = render_hash_bitmap_16x16(hash);
    println!("Hash: {}", hash.to_hex());
    println!("Legend: 1=white pixel, 0=black pixel");
    println!("{rendered}");
    Ok(())
}

fn run_wallet(command: WalletCommand) -> Result<(), NodeError> {
    fn key_hash20_from_pubkey(pubkey_compressed: [u8; 33]) -> [u8; 20] {
        scam_core::hash160_blake3(&pubkey_compressed)
    }

    fn derive_and_print_address(
        mnemonic_phrase: &str,
        passphrase: &str,
        account: u32,
        index: u32,
        hrp: &str,
    ) -> Result<(), NodeError> {
        let mnemonic = WalletMnemonic::parse(mnemonic_phrase)?;
        let seed = mnemonic.to_seed(passphrase);
        let key = derive_wallet_key(&seed, account, index)?;
        let address = to_address(hrp, key.pubkey_compressed())?;

        println!(
            "PubKey (compressed): {}",
            hex::encode(key.pubkey_compressed())
        );
        println!("Address: {address}");
        Ok(())
    }

    fn derive_and_print_address_from_vault(
        wallet_path: &Path,
        password: &str,
        account: u32,
        index: u32,
        hrp: &str,
    ) -> Result<(), NodeError> {
        let vault = load_wallet_vault(wallet_path)?;
        let secret = decrypt_wallet_vault(&vault, password)?;
        let seed = secret.mnemonic.to_seed(&secret.bip39_passphrase);
        let key = derive_wallet_key(&seed, account, index)?;
        let address = to_address(hrp, key.pubkey_compressed())?;

        println!("Wallet file: {}", wallet_path.display());
        println!(
            "PubKey (compressed): {}",
            hex::encode(key.pubkey_compressed())
        );
        println!("Address: {address}");
        Ok(())
    }

    fn run_rescan_for_seed(
        runtime: &ChainRuntime,
        seed: &[u8],
        account: u32,
        start_index: u32,
        end_index: u32,
    ) -> Result<(), NodeError> {
        let watched = derive_watched_keys(seed, account, start_index, end_index)?;
        let mut address_by_key = HashMap::<(u32, u32, [u8; 20]), String>::new();
        for key in &watched {
            let address = to_address(&runtime.config().hrp, key.pubkey_compressed)?;
            address_by_key.insert((key.account, key.index, key.key_hash20), address);
        }

        let blocks = (0..=runtime.tip_height()).filter_map(|height| {
            runtime
                .block_hash_at_height(height)
                .and_then(|hash| runtime.block_by_hash(&hash).map(|block| (height, block)))
        });
        let report = rescan_blocks(&watched, blocks, runtime.config().coinbase_maturity as u64);

        println!("Wallet rescan report:");
        println!("Network: {}", runtime.config().network_id);
        println!("Scanned blocks: {}", report.scanned_blocks);
        println!("Tip height: {}", report.tip_height);
        println!("Watched keys: {}", report.watched_keys);
        println!("Total received: {}", report.total_received);
        println!("Total spent: {}", report.total_spent);
        println!("Unspent total: {}", report.unspent_total);
        println!("Spendable total: {}", report.spendable_total);
        println!("Immature total: {}", report.immature_total);
        println!("Unspent outputs: {}", report.unspent_count);

        let non_empty_balances = report
            .balances
            .iter()
            .filter(|entry| entry.total > 0)
            .collect::<Vec<_>>();
        if non_empty_balances.is_empty() {
            println!("No funds found in watched derivation range.");
            return Ok(());
        }

        println!("Balances by derived address:");
        for balance in non_empty_balances {
            let key = (balance.account, balance.index, balance.key_hash20);
            let address = address_by_key
                .get(&key)
                .cloned()
                .unwrap_or_else(|| "<address-unavailable>".to_owned());
            println!(
                "{} [{}:{}] total={} spendable={} immature={} utxos={}",
                address,
                balance.account,
                balance.index,
                balance.total,
                balance.spendable,
                balance.immature,
                balance.unspent_count
            );
        }
        Ok(())
    }

    match command {
        WalletCommand::New {
            words,
            passphrase,
            account,
            index,
            hrp,
        } => {
            let mnemonic = new_mnemonic(words)?;
            let seed = mnemonic.to_seed(&passphrase);
            let key = derive_wallet_key(&seed, account, index)?;
            let address = to_address(&hrp, key.pubkey_compressed())?;

            println!("Mnemonic: {}", mnemonic.phrase());
            println!(
                "PubKey (compressed): {}",
                hex::encode(key.pubkey_compressed())
            );
            println!("Address: {address}");
        }
        WalletCommand::Address {
            mnemonic,
            passphrase,
            account,
            index,
            hrp,
        } => derive_and_print_address(&mnemonic, &passphrase, account, index, &hrp)?,
        WalletCommand::Restore {
            mnemonic,
            passphrase,
            account,
            index,
            hrp,
        } => derive_and_print_address(&mnemonic, &passphrase, account, index, &hrp)?,
        WalletCommand::SecureNew {
            words,
            passphrase,
            password,
            out,
            account,
            index,
            hrp,
        } => {
            let mnemonic = new_mnemonic(words)?;
            let vault = new_encrypted_wallet_vault(mnemonic.phrase(), &passphrase, &password)?;
            save_wallet_vault(&out, &vault)?;

            let seed = mnemonic.to_seed(&passphrase);
            let key = derive_wallet_key(&seed, account, index)?;
            let address = to_address(&hrp, key.pubkey_compressed())?;

            println!("Mnemonic (backup this offline): {}", mnemonic.phrase());
            println!("Wallet file: {}", out.display());
            println!(
                "PubKey (compressed): {}",
                hex::encode(key.pubkey_compressed())
            );
            println!("Address: {address}");
        }
        WalletCommand::SecureRestore {
            mnemonic,
            passphrase,
            password,
            out,
            account,
            index,
            hrp,
        } => {
            let parsed = WalletMnemonic::parse(&mnemonic)?;
            let vault = new_encrypted_wallet_vault(parsed.phrase(), &passphrase, &password)?;
            save_wallet_vault(&out, &vault)?;

            let seed = parsed.to_seed(&passphrase);
            let key = derive_wallet_key(&seed, account, index)?;
            let address = to_address(&hrp, key.pubkey_compressed())?;

            println!("Wallet restored and encrypted at rest.");
            println!("Wallet file: {}", out.display());
            println!(
                "PubKey (compressed): {}",
                hex::encode(key.pubkey_compressed())
            );
            println!("Address: {address}");
        }
        WalletCommand::SecureAddress {
            wallet,
            password,
            account,
            index,
            hrp,
        } => derive_and_print_address_from_vault(&wallet, &password, account, index, &hrp)?,
        WalletCommand::Rescan {
            network,
            config,
            mnemonic,
            passphrase,
            account,
            start_index,
            end_index,
            mine_blocks,
            interval_sec,
            max_nonce,
        } => {
            let (_cfg, runtime) = build_runtime_for_query(
                network,
                config,
                mine_blocks,
                interval_sec,
                max_nonce,
                "wallet-rescan",
            )?;
            let mnemonic = WalletMnemonic::parse(&mnemonic)?;
            let seed = mnemonic.to_seed(&passphrase);
            run_rescan_for_seed(&runtime, &seed, account, start_index, end_index)?;
        }
        WalletCommand::SecureRescan {
            network,
            config,
            wallet,
            password,
            account,
            start_index,
            end_index,
            mine_blocks,
            interval_sec,
            max_nonce,
        } => {
            let (_cfg, runtime) = build_runtime_for_query(
                network,
                config,
                mine_blocks,
                interval_sec,
                max_nonce,
                "wallet-secure-rescan",
            )?;
            let vault = load_wallet_vault(&wallet)?;
            let secret = decrypt_wallet_vault(&vault, &password)?;
            let seed = secret.mnemonic.to_seed(&secret.bip39_passphrase);
            run_rescan_for_seed(&runtime, &seed, account, start_index, end_index)?;
        }
        WalletCommand::Balance {
            network,
            config,
            mnemonic,
            passphrase,
            account,
            index,
            mine_blocks,
            interval_sec,
            max_nonce,
        } => {
            let (_cfg, runtime) = build_runtime_for_query(
                network,
                config,
                mine_blocks,
                interval_sec,
                max_nonce,
                "wallet-balance",
            )?;

            let mnemonic = WalletMnemonic::parse(&mnemonic)?;
            let seed = mnemonic.to_seed(&passphrase);
            let key = derive_wallet_key(&seed, account, index)?;
            let key_hash20 = key_hash20_from_pubkey(key.pubkey_compressed());

            let mut total: u128 = 0;
            let mut spendable: u128 = 0;
            let mut immature: u128 = 0;
            let mut utxo_count = 0usize;
            let mut spendable_count = 0usize;
            let mut immature_count = 0usize;

            let tip_height = runtime.tip_height();
            let coinbase_maturity = runtime.config().coinbase_maturity as u64;
            for utxo in runtime.utxo_set().values() {
                if utxo.key_hash20 != key_hash20 {
                    continue;
                }
                utxo_count += 1;
                total = total.saturating_add(utxo.value as u128);

                let is_immature_coinbase = utxo.is_coinbase
                    && tip_height < utxo.created_height.saturating_add(coinbase_maturity);
                if is_immature_coinbase {
                    immature_count += 1;
                    immature = immature.saturating_add(utxo.value as u128);
                } else {
                    spendable_count += 1;
                    spendable = spendable.saturating_add(utxo.value as u128);
                }
            }

            println!("Wallet balance:");
            println!("Tip height: {}", tip_height);
            println!("Address key hash20: {}", hex::encode(key_hash20));
            println!("UTXOs: {}", utxo_count);
            println!("Total: {}", total);
            println!("Spendable: {} ({} utxos)", spendable, spendable_count);
            println!("Immature: {} ({} utxos)", immature, immature_count);
        }
        WalletCommand::Send {
            network,
            config,
            mnemonic,
            passphrase,
            account,
            index,
            to,
            amount,
            fee,
            mine_blocks,
            interval_sec,
            max_nonce,
        } => {
            let (cfg, runtime) = build_runtime_for_query(
                network,
                config,
                mine_blocks,
                interval_sec,
                max_nonce,
                "wallet-send",
            )?;
            if amount == 0 {
                return Err(NodeError::Runtime(
                    "amount must be > 0 (zero-value outputs are invalid)".to_owned(),
                ));
            }
            let recipient = parse_address(&to)?;
            let accepted_hrps = accepted_hrps_for_network(network, &cfg.hrp);
            if !accepted_hrps.iter().any(|hrp| hrp == &recipient.hrp) {
                return Err(NodeError::Runtime(format!(
                    "address hrp '{}' is not valid for network '{}' (accepted: {})",
                    recipient.hrp,
                    cfg.network_id,
                    accepted_hrps.join(", ")
                )));
            }

            let mnemonic = WalletMnemonic::parse(&mnemonic)?;
            let seed = mnemonic.to_seed(&passphrase);
            let key = derive_wallet_key(&seed, account, index)?;
            let signed = build_signed_transfer_tx(
                &runtime,
                &cfg.network_id,
                &key,
                recipient.key_hash20,
                amount,
                fee,
            )?;

            println!("Transaction created and signed:");
            println!("Txid: {}", signed.tx.txid());
            println!("Input count: {}", signed.tx.inputs.len());
            for (idx, utxo) in signed.selected_inputs.iter().enumerate() {
                println!(
                    "Input #{idx}: {}:{} (value={})",
                    utxo.outpoint.txid, utxo.outpoint.vout, utxo.value
                );
            }
            println!("Input total: {}", signed.input_total);
            println!("To key-hash20: {}", hex::encode(recipient.key_hash20));
            println!("Amount: {}", amount);
            println!("Fee: {}", fee);
            println!("Change: {}", signed.change_value);
            println!("Self-transfer: {}", signed.is_self_transfer);
            println!("RawTx (hex): {}", hex::encode(signed.tx.encode_for_hash()));
        }
        WalletCommand::Decode { address } => {
            let decoded = parse_address(&address)?;
            println!("HRP: {}", decoded.hrp);
            println!("KeyHash20: {}", hex::encode(decoded.key_hash20));
        }
        WalletCommand::Sign {
            mnemonic,
            passphrase,
            digest_hex,
            account,
            index,
            hrp,
        } => {
            let mnemonic = WalletMnemonic::parse(&mnemonic)?;
            let digest = decode_fixed_hex::<32>("digest_hex", &digest_hex)?;
            let seed = mnemonic.to_seed(&passphrase);
            let key = derive_wallet_key(&seed, account, index)?;
            let signature = sign_digest(&key, digest)?;
            let address = to_address(&hrp, key.pubkey_compressed())?;

            println!(
                "PubKey (compressed): {}",
                hex::encode(key.pubkey_compressed())
            );
            println!("Address: {address}");
            println!("Signature (hex): {}", hex::encode(signature));
        }
        WalletCommand::Verify {
            pubkey_hex,
            digest_hex,
            signature_hex,
        } => {
            let pubkey = decode_fixed_hex::<33>("pubkey_hex", &pubkey_hex)?;
            let digest = decode_fixed_hex::<32>("digest_hex", &digest_hex)?;
            let signature = decode_fixed_hex::<64>("signature_hex", &signature_hex)?;
            let ok = verify_digest(digest, signature, pubkey)?;
            println!("Signature valid: {ok}");
        }
        WalletCommand::Qr {
            address,
            amount,
            label,
        } => {
            let ascii = qr_for_payment_uri(&address, amount, label.as_deref())?;
            println!("{ascii}");
        }
    }

    Ok(())
}

fn run_p2p_demo() -> Result<(), NodeError> {
    let mut engine = GossipEngine::new(256)
        .map_err(|e| NodeError::Runtime(format!("cannot create gossip engine: {e}")))?;
    engine.connect_peer(1);
    engine.connect_peer(2);
    engine.connect_peer(3);

    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: scam_core::hash::hash256(b"demo-prev"),
                vout: 0,
            },
            signature: vec![0u8; 64],
            pubkey_compressed: vec![2u8; 33],
            sequence: 0,
        }],
        outputs: vec![TxOut {
            value: 1,
            key_hash20: [9u8; 20],
        }],
        lock_time: 0,
    };

    let fanout = engine
        .on_message(1, WireMessage::Tx { tx })
        .map_err(|e| NodeError::Runtime(format!("gossip processing failed: {e}")))?;

    println!("P2P gossip demo:");
    println!("Incoming: peer #1 sent tx object");
    println!("Engine produced {} outbound messages", fanout.len());
    for outbound in fanout {
        println!(" -> to peer #{}: {:?}", outbound.peer_id, outbound.message);
    }
    println!("Pattern: inv/getdata/object relay with peer-level dedup");
    Ok(())
}

fn run_snapshot(command: SnapshotCommand) -> Result<(), NodeError> {
    match command {
        SnapshotCommand::SaveGenesis {
            network,
            config,
            out,
        } => {
            let config_path = config
                .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", network.as_str())));
            let cfg = load_chain_config(&config_path)?;
            let genesis = cfg.build_genesis_block()?;
            let genesis_hash = genesis.header.block_hash();

            let mut utxos = UtxoSet::new();
            validate_and_apply_block(
                &genesis,
                0,
                cfg.block_subsidy,
                cfg.coinbase_maturity as u64,
                cfg.network_id.as_bytes(),
                &mut utxos,
            )?;

            let snapshot = ChainStateSnapshot::from_utxo_set(
                cfg.network_id.clone(),
                0,
                genesis_hash,
                vec![genesis_hash],
                &utxos,
            );
            save_snapshot(&out, &snapshot)?;
            println!("Snapshot saved: {}", out.display());
            println!("Network: {}", snapshot.network_id);
            println!("Tip height: {}", snapshot.tip_height);
            println!("Tip hash: {}", snapshot.tip_hash);
            println!("UTXO count: {}", snapshot.utxos.len());
        }
        SnapshotCommand::SaveGenesisDb {
            network,
            config,
            out,
        } => {
            let config_path = config
                .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", network.as_str())));
            let cfg = load_chain_config(&config_path)?;
            let genesis = cfg.build_genesis_block()?;
            let genesis_hash = genesis.header.block_hash();

            let mut utxos = UtxoSet::new();
            validate_and_apply_block(
                &genesis,
                0,
                cfg.block_subsidy,
                cfg.coinbase_maturity as u64,
                cfg.network_id.as_bytes(),
                &mut utxos,
            )?;

            let snapshot = ChainStateSnapshot::from_utxo_set(
                cfg.network_id.clone(),
                0,
                genesis_hash,
                vec![genesis_hash],
                &utxos,
            );
            save_snapshot_db(&out, &snapshot)?;
            println!("Snapshot DB saved: {}", out.display());
            println!("Network: {}", snapshot.network_id);
            println!("Tip height: {}", snapshot.tip_height);
            println!("Tip hash: {}", snapshot.tip_hash);
            println!("UTXO count: {}", snapshot.utxos.len());
        }
        SnapshotCommand::Show { path } => {
            let snapshot = load_snapshot(&path)?;
            println!("Snapshot: {}", path.display());
            println!("Network: {}", snapshot.network_id);
            println!("Tip height: {}", snapshot.tip_height);
            println!("Tip hash: {}", snapshot.tip_hash);
            println!("Blocks tracked: {}", snapshot.block_hashes_by_height.len());
            println!("UTXO count: {}", snapshot.utxos.len());
        }
        SnapshotCommand::ShowDb { path } => {
            let snapshot = load_snapshot_db(&path)?;
            println!("Snapshot DB: {}", path.display());
            println!("Network: {}", snapshot.network_id);
            println!("Tip height: {}", snapshot.tip_height);
            println!("Tip hash: {}", snapshot.tip_hash);
            println!("Blocks tracked: {}", snapshot.block_hashes_by_height.len());
            println!("UTXO count: {}", snapshot.utxos.len());
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SpendableUtxo {
    outpoint: OutPoint,
    value: u64,
}

fn select_utxos_for_amount(
    candidates: &[SpendableUtxo],
    needed: u64,
) -> Option<(Vec<SpendableUtxo>, u64)> {
    if needed == 0 {
        return Some((Vec::new(), 0));
    }

    // Prefer a single input (smaller tx size) when possible.
    let single = candidates
        .iter()
        .filter(|utxo| utxo.value >= needed)
        .min_by(|a, b| {
            a.value
                .cmp(&b.value)
                .then_with(|| a.outpoint.txid.cmp(&b.outpoint.txid))
                .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
        })
        .cloned();
    if let Some(best) = single {
        return Some((vec![best.clone()], best.value));
    }

    // Fallback: accumulate largest-first until covered.
    let mut ordered = candidates.to_vec();
    ordered.sort_unstable_by(|a, b| {
        b.value
            .cmp(&a.value)
            .then_with(|| a.outpoint.txid.cmp(&b.outpoint.txid))
            .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
    });

    let mut selected = Vec::new();
    let mut total = 0u64;
    for utxo in ordered {
        if total >= needed {
            break;
        }
        total = total.saturating_add(utxo.value);
        selected.push(utxo);
    }

    if total >= needed {
        Some((selected, total))
    } else {
        None
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SignedTransferTx {
    tx: Transaction,
    selected_inputs: Vec<SpendableUtxo>,
    input_total: u64,
    change_value: u64,
    sender_key_hash20: [u8; 20],
    is_self_transfer: bool,
}

fn collect_spendable_utxos(
    runtime: &ChainRuntime,
    owner_key_hash20: [u8; 20],
) -> (Vec<SpendableUtxo>, u128) {
    let tip_height = runtime.tip_height();
    let coinbase_maturity = runtime.config().coinbase_maturity as u64;
    let mut spendable = Vec::<SpendableUtxo>::new();
    let mut spendable_total = 0u128;

    for (outpoint, utxo) in runtime.utxo_set() {
        if utxo.key_hash20 != owner_key_hash20 {
            continue;
        }
        let is_immature_coinbase =
            utxo.is_coinbase && tip_height < utxo.created_height.saturating_add(coinbase_maturity);
        if is_immature_coinbase {
            continue;
        }
        spendable_total = spendable_total.saturating_add(utxo.value as u128);
        spendable.push(SpendableUtxo {
            outpoint: outpoint.clone(),
            value: utxo.value,
        });
    }

    (spendable, spendable_total)
}

fn build_signed_transfer_tx(
    runtime: &ChainRuntime,
    network_id: &str,
    sender_key: &WalletKey,
    recipient_key_hash20: [u8; 20],
    amount: u64,
    fee: u64,
) -> Result<SignedTransferTx, NodeError> {
    if amount == 0 {
        return Err(NodeError::Runtime(
            "amount must be > 0 (zero-value outputs are invalid)".to_owned(),
        ));
    }

    let needed = amount
        .checked_add(fee)
        .ok_or_else(|| NodeError::Runtime("amount + fee overflow".to_owned()))?;
    let sender_pubkey = sender_key.pubkey_compressed();
    let sender_key_hash20 = scam_core::hash160_blake3(&sender_pubkey);
    let is_self_transfer = recipient_key_hash20 == sender_key_hash20;

    let (spendable, spendable_total) = collect_spendable_utxos(runtime, sender_key_hash20);
    let (selected, selected_total) =
        select_utxos_for_amount(&spendable, needed).ok_or(NodeError::InsufficientFunds {
            needed,
            spendable_total,
        })?;
    let change_value = selected_total.checked_sub(needed).ok_or_else(|| {
        NodeError::Runtime("selected UTXO total is smaller than needed amount".to_owned())
    })?;

    let mut tx = Transaction {
        version: 1,
        inputs: selected
            .iter()
            .map(|utxo| TxIn {
                prev_out: utxo.outpoint.clone(),
                signature: vec![],
                pubkey_compressed: sender_pubkey.to_vec(),
                sequence: 0,
            })
            .collect(),
        outputs: vec![TxOut {
            value: amount,
            key_hash20: recipient_key_hash20,
        }],
        lock_time: 0,
    };
    if change_value > 0 {
        tx.outputs.push(TxOut {
            value: change_value,
            key_hash20: sender_key_hash20,
        });
    }

    for input_index in 0..tx.inputs.len() {
        let digest = tx
            .signing_digest_with_chain_domain(input_index, network_id.as_bytes())
            .map_err(|e| NodeError::Runtime(format!("signing digest failed: {e}")))?;
        let signature = sign_digest(sender_key, digest.0)?;
        tx.inputs[input_index].signature = signature.to_vec();

        let sig_ok = verify_digest(digest.0, signature, sender_pubkey)?;
        if !sig_ok {
            return Err(NodeError::Runtime(format!(
                "internal signature self-check failed for input #{}",
                input_index
            )));
        }
    }

    Ok(SignedTransferTx {
        tx,
        selected_inputs: selected,
        input_total: selected_total,
        change_value,
        sender_key_hash20,
        is_self_transfer,
    })
}

fn build_coinbase_tx(tag: String, subsidy: u64, key_hash20: [u8; 20]) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint::coinbase(),
            signature: tag.into_bytes(),
            pubkey_compressed: vec![],
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: subsidy,
            key_hash20,
        }],
        lock_time: 0,
    }
}

#[derive(Clone)]
struct MiningLoopParams {
    count: u32,
    interval_sec: u64,
    max_nonce: u64,
    subsidy: u64,
    miner_key_hash: [u8; 20],
    label_prefix: &'static str,
    print_each: bool,
}

fn mine_block_with_transactions(
    runtime: &mut ChainRuntime,
    interval_sec: u64,
    max_nonce: u64,
    subsidy: u64,
    miner_key_hash: [u8; 20],
    coinbase_tag: String,
    mut transactions: Vec<Transaction>,
) -> Result<(Hash256, scam_core::Target, u128), NodeError> {
    let expected_target = runtime.expected_target_for_next_block()?;
    let timestamp = runtime.tip_header().timestamp.saturating_add(interval_sec);
    let mut block_txs = Vec::with_capacity(transactions.len() + 1);
    block_txs.push(build_coinbase_tx(coinbase_tag, subsidy, miner_key_hash));
    block_txs.append(&mut transactions);
    let template = BlockTemplate {
        version: 1,
        prev_block: runtime.tip_hash(),
        timestamp,
        target: expected_target,
        transactions: block_txs,
    };

    let Some(block) = mine_block(&template, max_nonce) else {
        return Err(NodeError::Runtime(format!(
            "cannot mine height {} in nonce range 0..={}",
            runtime.tip_height() + 1,
            max_nonce
        )));
    };

    let applied = runtime.apply_next_block(block)?;
    Ok((
        applied.block_hash,
        runtime.tip_header().target,
        applied.total_fees,
    ))
}

fn mine_blocks_on_runtime(
    runtime: &mut ChainRuntime,
    params: &MiningLoopParams,
) -> Result<(), NodeError> {
    for step in 1..=params.count {
        let (block_hash, target, total_fees) = mine_block_with_transactions(
            runtime,
            params.interval_sec,
            params.max_nonce,
            params.subsidy,
            params.miner_key_hash,
            format!("{}-{step}", params.label_prefix),
            Vec::new(),
        )?;
        if params.print_each {
            println!(
                "h={} hash={} target={} fees={}",
                runtime.tip_height(),
                block_hash,
                target,
                total_fees
            );
        }
    }
    Ok(())
}

fn run_mine_once(args: MineOnceArgs) -> Result<(), NodeError> {
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", args.network.as_str())));

    let cfg = load_chain_config(&config_path)?;
    let genesis = cfg.build_genesis_block()?;
    let mut utxos = UtxoSet::new();
    validate_and_apply_block(
        &genesis,
        0,
        cfg.block_subsidy,
        cfg.coinbase_maturity as u64,
        cfg.network_id.as_bytes(),
        &mut utxos,
    )?;

    let miner_key_hash = cfg.genesis_reward_key_hash20()?;
    let coinbase = build_coinbase_tx("mine-once".to_owned(), cfg.block_subsidy, miner_key_hash);
    let template = BlockTemplate {
        version: 1,
        prev_block: genesis.header.block_hash(),
        timestamp: genesis
            .header
            .timestamp
            .saturating_add(cfg.target_block_time_sec),
        target: genesis.header.target,
        transactions: vec![coinbase],
    };

    let Some(mined_block) = mine_block(&template, args.max_nonce) else {
        println!(
            "Mining failed: no nonce found in range 0..={}",
            args.max_nonce
        );
        return Ok(());
    };

    let summary = validate_and_apply_block(
        &mined_block,
        1,
        cfg.block_subsidy,
        cfg.coinbase_maturity as u64,
        cfg.network_id.as_bytes(),
        &mut utxos,
    )?;

    println!("Mine-once result:");
    println!("Config: {}", config_path.display());
    println!("Mined block hash: {}", mined_block.header.block_hash());
    println!("Nonce: {}", mined_block.header.nonce);
    println!("PoW valid: {}", block_meets_pow(&mined_block));
    println!("Applied: true");
    println!("UTXO size: {}", utxos.len());
    println!("Coinbase value: {}", summary.coinbase_value);
    Ok(())
}

fn run_chain_demo(args: ChainDemoArgs) -> Result<(), NodeError> {
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", args.network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let miner_key_hash = cfg.genesis_reward_key_hash20()?;
    let mut runtime = ChainRuntime::from_config(cfg.clone())?;

    println!("Chain demo start");
    println!("Network: {}", cfg.network_id);
    println!(
        "Start tip: h={} hash={}",
        runtime.tip_height(),
        runtime.tip_hash()
    );
    println!("Window: {}", cfg.difficulty_adjustment_window);
    println!("Interval sec per new block: {}", args.interval_sec);
    let params = MiningLoopParams {
        count: args.blocks,
        interval_sec: args.interval_sec,
        max_nonce: args.max_nonce,
        subsidy: cfg.block_subsidy,
        miner_key_hash,
        label_prefix: "chain-demo",
        print_each: true,
    };
    mine_blocks_on_runtime(&mut runtime, &params)?;

    println!(
        "Chain demo finished at h={} with utxos={}",
        runtime.tip_height(),
        runtime.utxo_len()
    );
    Ok(())
}

fn run_sync_demo(args: SyncDemoArgs) -> Result<(), NodeError> {
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", args.network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let miner_key_hash = cfg.genesis_reward_key_hash20()?;

    let mut local = ChainRuntime::from_config(cfg.clone())?;
    let mut remote = ChainRuntime::from_config(cfg.clone())?;
    let local_params = MiningLoopParams {
        count: args.local_blocks,
        interval_sec: args.interval_sec,
        max_nonce: args.max_nonce,
        subsidy: cfg.block_subsidy,
        miner_key_hash,
        label_prefix: "local",
        print_each: false,
    };
    let remote_params = MiningLoopParams {
        count: args.remote_blocks,
        interval_sec: args.interval_sec,
        max_nonce: args.max_nonce,
        subsidy: cfg.block_subsidy,
        miner_key_hash,
        label_prefix: "remote",
        print_each: false,
    };
    mine_blocks_on_runtime(&mut local, &local_params)?;
    mine_blocks_on_runtime(&mut remote, &remote_params)?;

    let locator = build_block_locator(local.block_hashes());
    let mut remote_headers = HashMap::new();
    for hash in remote.block_hashes() {
        if let Some(header) = remote.header_by_hash(hash) {
            remote_headers.insert(*hash, header.clone());
        }
    }

    let headers = select_headers_for_peer(
        remote.block_hashes(),
        &remote_headers,
        &locator,
        None,
        args.max_headers,
    );

    println!("Headers-first sync demo");
    println!(
        "Local tip: h={} hash={}",
        local.tip_height(),
        local.tip_hash()
    );
    println!(
        "Remote tip: h={} hash={}",
        remote.tip_height(),
        remote.tip_hash()
    );
    println!("Locator size sent by local peer: {}", locator.len());
    println!("Headers returned by remote peer: {}", headers.len());
    if let Some(first) = headers.first() {
        println!("First returned header prev: {}", first.prev_block);
    }
    if let Some(last) = headers.last() {
        println!("Last returned header hash: {}", last.block_hash());
    }
    Ok(())
}

fn configure_stream_timeouts(stream: &TcpStream) -> Result<(), NodeError> {
    let timeout = Some(Duration::from_secs(5));
    stream
        .set_read_timeout(timeout)
        .map_err(|e| NodeError::Runtime(format!("set read timeout failed: {e}")))?;
    stream
        .set_write_timeout(timeout)
        .map_err(|e| NodeError::Runtime(format!("set write timeout failed: {e}")))?;
    Ok(())
}

fn run_net_demo(args: NetDemoArgs) -> Result<(), NodeError> {
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", args.network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let miner_key_hash = cfg.genesis_reward_key_hash20()?;

    let mut local = ChainRuntime::from_config(cfg.clone())?;
    let mut remote = ChainRuntime::from_config(cfg.clone())?;
    let local_params = MiningLoopParams {
        count: args.local_blocks,
        interval_sec: args.interval_sec,
        max_nonce: args.max_nonce,
        subsidy: cfg.block_subsidy,
        miner_key_hash,
        label_prefix: "net-local",
        print_each: false,
    };
    let remote_params = MiningLoopParams {
        count: args.remote_blocks,
        interval_sec: args.interval_sec,
        max_nonce: args.max_nonce,
        subsidy: cfg.block_subsidy,
        miner_key_hash,
        label_prefix: "net-remote",
        print_each: false,
    };
    mine_blocks_on_runtime(&mut local, &local_params)?;
    mine_blocks_on_runtime(&mut remote, &remote_params)?;

    let framing = FramingConfig::default();
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| NodeError::Runtime(format!("bind failed: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| NodeError::Runtime(format!("local_addr failed: {e}")))?;

    let network_id = cfg.network_id.clone();
    let remote_tip = remote.tip_height();
    let remote_chain = remote.block_hashes().to_vec();
    let mut remote_headers = HashMap::new();
    let mut remote_blocks = HashMap::new();
    for hash in remote.block_hashes() {
        if let Some(header) = remote.header_by_hash(hash) {
            remote_headers.insert(*hash, header.clone());
        }
        if let Some(block) = remote.block_by_hash(hash) {
            remote_blocks.insert(*hash, block.clone());
        }
    }
    let max_headers = args.max_headers;
    let framing_server = framing.clone();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _peer) = listener.accept().map_err(|e| e.to_string())?;
        configure_stream_timeouts(&stream).map_err(|e| e.to_string())?;

        let server_hello = LocalHandshake {
            protocol_version: 1,
            network_id: network_id.clone(),
            user_agent: "scam-node/server".to_owned(),
            start_height: remote_tip,
        };
        let remote_peer = server_handshake(&mut stream, &framing_server, &server_hello)
            .map_err(|e| e.to_string())?;
        if remote_peer.network_id != network_id {
            return Err(format!(
                "network mismatch from client: expected {}, got {}",
                network_id, remote_peer.network_id
            ));
        }

        let ping = read_message(&mut stream, &framing_server).map_err(|e| e.to_string())?;
        match ping {
            WireMessage::Ping { nonce } => {
                send_message(&mut stream, &WireMessage::Pong { nonce }, &framing_server)
                    .map_err(|e| e.to_string())?;
            }
            other => {
                return Err(format!("expected ping, got {other:?}"));
            }
        }

        let request = read_message(&mut stream, &framing_server).map_err(|e| e.to_string())?;
        match request {
            WireMessage::GetHeaders { locator, stop } => {
                let headers = select_headers_for_peer(
                    &remote_chain,
                    &remote_headers,
                    &locator,
                    stop,
                    max_headers,
                );
                send_message(
                    &mut stream,
                    &WireMessage::Headers { headers },
                    &framing_server,
                )
                .map_err(|e| e.to_string())?;
            }
            other => {
                return Err(format!("expected getheaders, got {other:?}"));
            }
        }

        let request = read_message(&mut stream, &framing_server).map_err(|e| e.to_string())?;
        match request {
            WireMessage::GetBlocks { locator, stop } => {
                let hashes =
                    select_block_hashes_for_peer(&remote_chain, &locator, stop, max_headers);
                let items = hashes.into_iter().map(InventoryItem::Block).collect();
                send_message(&mut stream, &WireMessage::Inv { items }, &framing_server)
                    .map_err(|e| e.to_string())?;
            }
            other => {
                return Err(format!("expected getblocks, got {other:?}"));
            }
        }

        let request = read_message(&mut stream, &framing_server).map_err(|e| e.to_string())?;
        match request {
            WireMessage::GetData { items } => {
                for item in items {
                    match item {
                        InventoryItem::Block(hash) => {
                            let Some(block) = remote_blocks.get(&hash) else {
                                send_message(
                                    &mut stream,
                                    &WireMessage::NotFound {
                                        items: vec![InventoryItem::Block(hash)],
                                    },
                                    &framing_server,
                                )
                                .map_err(|e| e.to_string())?;
                                continue;
                            };
                            send_message(
                                &mut stream,
                                &WireMessage::Block {
                                    block: block.clone(),
                                },
                                &framing_server,
                            )
                            .map_err(|e| e.to_string())?;
                        }
                        InventoryItem::Tx(hash) => {
                            send_message(
                                &mut stream,
                                &WireMessage::NotFound {
                                    items: vec![InventoryItem::Tx(hash)],
                                },
                                &framing_server,
                            )
                            .map_err(|e| e.to_string())?;
                        }
                    }
                }
            }
            other => {
                return Err(format!("expected getdata, got {other:?}"));
            }
        }

        Ok(())
    });

    let mut client =
        TcpStream::connect(addr).map_err(|e| NodeError::Runtime(format!("connect failed: {e}")))?;
    configure_stream_timeouts(&client)?;
    let client_hello = LocalHandshake {
        protocol_version: 1,
        network_id: cfg.network_id.clone(),
        user_agent: "scam-node/client".to_owned(),
        start_height: local.tip_height(),
    };
    let remote_info = client_handshake(&mut client, &framing, &client_hello)?;
    if remote_info.network_id != cfg.network_id {
        return Err(NodeError::Runtime(format!(
            "network mismatch from server: expected {}, got {}",
            cfg.network_id, remote_info.network_id
        )));
    }

    send_message(&mut client, &WireMessage::Ping { nonce: 7 }, &framing)?;
    let pong = read_message(&mut client, &framing)?;
    match pong {
        WireMessage::Pong { nonce: 7 } => {}
        other => {
            return Err(NodeError::Runtime(format!("expected pong, got {other:?}")));
        }
    }

    let client_tip_before_height = local.tip_height();
    let client_tip_before_hash = local.tip_hash();
    let locator = build_block_locator(local.block_hashes());
    let headers = request_headers(&mut client, &framing, locator.clone(), None)?;
    let block_hashes = request_blocks(&mut client, &framing, locator.clone(), None)?;
    let unknown_hashes = block_hashes
        .iter()
        .copied()
        .filter(|hash| local.block_by_hash(hash).is_none())
        .collect::<Vec<_>>();

    if !unknown_hashes.is_empty() {
        let items = unknown_hashes
            .iter()
            .copied()
            .map(InventoryItem::Block)
            .collect::<Vec<_>>();
        send_message(&mut client, &WireMessage::GetData { items }, &framing)?;
    }

    let mut downloaded_blocks = 0usize;
    let mut applied_blocks = 0usize;
    let mut ignored_blocks = 0usize;
    for expected_hash in &unknown_hashes {
        let message = read_message(&mut client, &framing)?;
        match message {
            WireMessage::Block { block } => {
                let got_hash = block.header.block_hash();
                if got_hash != *expected_hash {
                    return Err(NodeError::Runtime(format!(
                        "unexpected block order from peer: expected {}, got {}",
                        expected_hash, got_hash
                    )));
                }
                downloaded_blocks = downloaded_blocks.saturating_add(1);
                let outcome = local.submit_block(block)?;
                match outcome {
                    BlockSubmissionOutcome::AlreadyKnown { .. }
                    | BlockSubmissionOutcome::StoredSideBranch { .. } => {
                        ignored_blocks = ignored_blocks.saturating_add(1);
                    }
                    BlockSubmissionOutcome::ExtendedTip { .. }
                    | BlockSubmissionOutcome::Reorged { .. } => {
                        applied_blocks = applied_blocks.saturating_add(1);
                    }
                }
            }
            WireMessage::NotFound { items } => {
                return Err(NodeError::Runtime(format!(
                    "peer did not have requested block {} (notfound: {:?})",
                    expected_hash, items
                )));
            }
            other => {
                return Err(NodeError::Runtime(format!(
                    "expected block/notfound for {}, got {other:?}",
                    expected_hash
                )));
            }
        }
    }

    let server_result = server
        .join()
        .map_err(|_| NodeError::Runtime("server thread panicked".to_owned()))?;
    if let Err(err) = server_result {
        return Err(NodeError::Runtime(format!("server error: {err}")));
    }

    println!("Net demo (TCP + handshake + headers/getblocks/getdata/block)");
    println!(
        "Client tip before sync: h={} hash={}",
        client_tip_before_height, client_tip_before_hash
    );
    println!(
        "Server tip: h={} hash={}",
        remote.tip_height(),
        remote.tip_hash()
    );
    println!("Locator sent: {}", locator.len());
    println!("Headers received: {}", headers.len());
    println!("Block hashes received: {}", block_hashes.len());
    println!("Blocks downloaded: {}", downloaded_blocks);
    println!("Blocks applied: {}", applied_blocks);
    println!("Blocks ignored: {}", ignored_blocks);
    println!(
        "Client tip after sync: h={} hash={}",
        local.tip_height(),
        local.tip_hash()
    );
    if let Some(first) = headers.first() {
        println!("First header prev: {}", first.prev_block);
    }
    if let Some(last) = headers.last() {
        println!("Last header hash: {}", last.block_hash());
    }
    if let Some(last) = block_hashes.last() {
        println!("Last announced block hash: {}", last);
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PeerSyncStats {
    headers_received: usize,
    blocks_announced: usize,
    blocks_downloaded: usize,
    blocks_applied: usize,
}

fn sync_runtime_with_peer(
    cfg: &ChainConfig,
    runtime: &mut ChainRuntime,
    peer: &str,
    max_batches: u32,
    user_agent: &str,
) -> Result<PeerSyncStats, NodeError> {
    let mut stream = TcpStream::connect(peer)
        .map_err(|e| NodeError::Runtime(format!("connect to {peer} failed: {e}")))?;
    configure_stream_timeouts(&stream)?;
    let framing = FramingConfig::default();
    let local_hello = LocalHandshake {
        protocol_version: 1,
        network_id: cfg.network_id.clone(),
        user_agent: user_agent.to_owned(),
        start_height: runtime.tip_height(),
    };
    let remote = client_handshake(&mut stream, &framing, &local_hello)?;
    if remote.network_id != cfg.network_id {
        return Err(NodeError::Runtime(format!(
            "network mismatch from peer: expected {}, got {}",
            cfg.network_id, remote.network_id
        )));
    }

    let mut stats = PeerSyncStats::default();
    for _ in 0..max_batches {
        let locator = build_block_locator(runtime.block_hashes());
        let headers = request_headers(&mut stream, &framing, locator.clone(), None)?;
        if headers.is_empty() {
            break;
        }
        stats.headers_received = stats.headers_received.saturating_add(headers.len());

        let announced = request_blocks(&mut stream, &framing, locator, None)?;
        if announced.is_empty() {
            break;
        }
        stats.blocks_announced = stats.blocks_announced.saturating_add(announced.len());
        let unknown_hashes = announced
            .iter()
            .copied()
            .filter(|hash| runtime.block_by_hash(hash).is_none())
            .collect::<Vec<_>>();
        if unknown_hashes.is_empty() {
            break;
        }

        let items = unknown_hashes
            .iter()
            .copied()
            .map(InventoryItem::Block)
            .collect::<Vec<_>>();
        send_message(&mut stream, &WireMessage::GetData { items }, &framing)?;

        for expected_hash in unknown_hashes {
            let response = read_message(&mut stream, &framing)?;
            match response {
                WireMessage::Block { block } => {
                    let got_hash = block.header.block_hash();
                    if got_hash != expected_hash {
                        return Err(NodeError::Runtime(format!(
                            "unexpected block from peer: expected {}, got {}",
                            expected_hash, got_hash
                        )));
                    }
                    stats.blocks_downloaded = stats.blocks_downloaded.saturating_add(1);
                    let outcome = runtime.submit_block(block)?;
                    if matches!(
                        outcome,
                        BlockSubmissionOutcome::ExtendedTip { .. }
                            | BlockSubmissionOutcome::Reorged { .. }
                    ) {
                        stats.blocks_applied = stats.blocks_applied.saturating_add(1);
                    }
                }
                WireMessage::NotFound { items } => {
                    return Err(NodeError::Runtime(format!(
                        "peer missing requested block {} ({items:?})",
                        expected_hash
                    )));
                }
                other => {
                    return Err(NodeError::Runtime(format!(
                        "unexpected message while syncing {}: {other:?}",
                        expected_hash
                    )));
                }
            }
        }
    }
    Ok(stats)
}

fn run_sync_peer(args: SyncPeerArgs) -> Result<(), NodeError> {
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", args.network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let runtime_db_path = args
        .runtime_db
        .unwrap_or_else(|| default_runtime_db_path(args.network));
    let (mut runtime, source) = load_runtime_from_db_or_genesis(&cfg, &runtime_db_path)?;
    let start_height = runtime.tip_height();
    let start_hash = runtime.tip_hash();

    let stats = sync_runtime_with_peer(
        &cfg,
        &mut runtime,
        &args.peer,
        args.max_batches,
        "scam-node/sync-peer",
    )?;
    persist_runtime_db(&runtime, &runtime_db_path)?;

    println!("Sync peer result:");
    println!("Peer: {}", args.peer);
    println!("Config: {}", config_path.display());
    println!("Runtime DB: {}", runtime_db_path.display());
    println!("Runtime source: {}", source);
    println!("Start tip: h={} hash={}", start_height, start_hash);
    println!(
        "End tip: h={} hash={}",
        runtime.tip_height(),
        runtime.tip_hash()
    );
    println!("Headers received: {}", stats.headers_received);
    println!("Blocks announced: {}", stats.blocks_announced);
    println!("Blocks downloaded: {}", stats.blocks_downloaded);
    println!("Blocks applied: {}", stats.blocks_applied);
    Ok(())
}

fn run_sync_book(args: SyncBookArgs) -> Result<(), NodeError> {
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", args.network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let runtime_db_path = args
        .runtime_db
        .unwrap_or_else(|| default_runtime_db_path(args.network));
    let (mut runtime, source) = load_runtime_from_db_or_genesis(&cfg, &runtime_db_path)?;

    let network_name = args.network.as_str();
    let (peers_db_path, legacy_txt_path) = peer_book_paths(&args.peers_dir, network_name);
    if let Some(parent) = peers_db_path.parent() {
        fs::create_dir_all(parent).map_err(|e| NodeError::Runtime(e.to_string()))?;
    }
    let mut peer_book = load_or_init_peer_book(network_name, &peers_db_path, &legacy_txt_path)?;
    let mut seed_imported = 0usize;
    for seed in &cfg.dns_seeds {
        for addr in resolve_dns_seed(seed) {
            let addr_string = addr.to_string();
            if peer_book
                .peers
                .iter()
                .any(|peer| peer.address == addr_string)
            {
                continue;
            }
            peer_book.peers.push(PeerAddressRecord {
                address: addr_string,
                last_seen_unix_sec: 0,
                ban_score: 0,
            });
            seed_imported = seed_imported.saturating_add(1);
        }
    }

    let now = current_unix_sec()?;
    let mut candidates = Vec::<PeerCandidate>::new();
    for peer in &peer_book.peers {
        let Ok(addr) = peer.address.parse() else {
            continue;
        };
        candidates.push(PeerCandidate {
            addr,
            last_connected_unix_sec: peer.last_seen_unix_sec,
            failure_count: peer.ban_score,
        });
    }
    if candidates.is_empty() {
        return Err(NodeError::Runtime(
            "peer book has no parseable socket addresses".to_owned(),
        ));
    }
    peer_book.peers.sort_by(|a, b| a.address.cmp(&b.address));
    peer_book.peers.dedup_by(|a, b| a.address == b.address);

    let selected = select_outbound_peers(&candidates, args.max_peers, args.rotate_after_sec, now);
    let selected = apply_bucket_cap(selected, cfg.p2p_max_outbound_per_bucket);
    if selected.is_empty() {
        return Err(NodeError::Runtime(
            "peer selection produced zero candidates".to_owned(),
        ));
    }

    let start_height = runtime.tip_height();
    let start_hash = runtime.tip_hash();
    let mut success_count = 0u32;
    let mut total_headers = 0usize;
    let mut total_announced = 0usize;
    let mut total_downloaded = 0usize;
    let mut total_applied = 0usize;

    let peers_tried = selected.len();
    for addr in selected {
        let addr_string = addr.to_string();
        let attempt_now = current_unix_sec()?;
        let attempt = sync_runtime_with_peer(
            &cfg,
            &mut runtime,
            &addr_string,
            args.max_batches_per_peer,
            "scam-node/sync-book",
        );
        match attempt {
            Ok(stats) => {
                success_count = success_count.saturating_add(1);
                total_headers = total_headers.saturating_add(stats.headers_received);
                total_announced = total_announced.saturating_add(stats.blocks_announced);
                total_downloaded = total_downloaded.saturating_add(stats.blocks_downloaded);
                total_applied = total_applied.saturating_add(stats.blocks_applied);
                if let Some(peer) = peer_book
                    .peers
                    .iter_mut()
                    .find(|peer| peer.address == addr_string)
                {
                    peer.last_seen_unix_sec = attempt_now;
                    peer.ban_score = peer.ban_score.saturating_sub(1);
                }
            }
            Err(err) => {
                if let Some(peer) = peer_book
                    .peers
                    .iter_mut()
                    .find(|peer| peer.address == addr_string)
                {
                    peer.ban_score = peer.ban_score.saturating_add(1);
                }
                println!("Sync peer failed: {} ({err})", addr_string);
            }
        }
    }

    save_peer_book_db(&peers_db_path, &peer_book)?;
    persist_runtime_db(&runtime, &runtime_db_path)?;
    if success_count == 0 {
        return Err(NodeError::Runtime(
            "sync-book finished without successful peers".to_owned(),
        ));
    }

    println!("Sync book result:");
    println!("Config: {}", config_path.display());
    println!("Runtime DB: {}", runtime_db_path.display());
    println!("Peer book: {}", peers_db_path.display());
    println!("Runtime source: {}", source);
    println!("Start tip: h={} hash={}", start_height, start_hash);
    println!(
        "End tip: h={} hash={}",
        runtime.tip_height(),
        runtime.tip_hash()
    );
    println!("Seeds imported: {}", seed_imported);
    println!("Peers tried: {}", peers_tried);
    println!("Peers succeeded: {}", success_count);
    println!("Headers received: {}", total_headers);
    println!("Blocks announced: {}", total_announced);
    println!("Blocks downloaded: {}", total_downloaded);
    println!("Blocks applied: {}", total_applied);
    Ok(())
}

fn run_reindex_runtime(args: ReindexRuntimeArgs) -> Result<(), NodeError> {
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", args.network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let runtime_db_path = args
        .runtime_db
        .unwrap_or_else(|| default_runtime_db_path(args.network));

    if !runtime_db_path.exists() {
        return Err(NodeError::Runtime(format!(
            "runtime db does not exist: {}",
            runtime_db_path.display()
        )));
    }

    let archive = load_chain_archive_db(&runtime_db_path)?;
    if archive.network_id != cfg.network_id {
        return Err(NodeError::Runtime(format!(
            "runtime db network mismatch: db='{}', config='{}'",
            archive.network_id, cfg.network_id
        )));
    }

    let runtime = ChainRuntime::from_ordered_blocks(cfg.clone(), archive.blocks_by_height)?;
    persist_runtime_db(&runtime, &runtime_db_path)?;

    println!("Runtime reindex complete");
    println!("Network: {}", cfg.network_id);
    println!("Config: {}", config_path.display());
    println!("Runtime DB: {}", runtime_db_path.display());
    println!("Tip height: {}", runtime.tip_height());
    println!("Tip hash: {}", runtime.tip_hash());
    println!("UTXO count: {}", runtime.utxo_len());
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SoakSummary {
    rounds: u32,
    blocks_mined: u64,
    start_height: u64,
    end_height: u64,
    elapsed_sec: u64,
}

#[derive(Clone, Copy, Debug)]
struct SoakExecutionParams {
    rounds: u32,
    blocks_per_round: u32,
    interval_sec: u64,
    max_nonce: u64,
    miner_key_hash: [u8; 20],
    sleep_per_round_sec: u64,
}

const SOAK_FLOW_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn derive_soak_flow_keys() -> Result<(WalletKey, [u8; 20]), NodeError> {
    let mnemonic = WalletMnemonic::parse(SOAK_FLOW_MNEMONIC)?;
    let seed = mnemonic.to_seed("");
    let sender_key = derive_wallet_key(&seed, 0, 0)?;
    let recipient_key = derive_wallet_key(&seed, 0, 1)?;
    let recipient_key_hash20 = scam_core::hash160_blake3(&recipient_key.pubkey_compressed());
    Ok((sender_key, recipient_key_hash20))
}

fn execute_soak_rounds<F>(
    runtime: &mut ChainRuntime,
    cfg: &ChainConfig,
    params: SoakExecutionParams,
    mut on_round_end: F,
) -> Result<SoakSummary, NodeError>
where
    F: FnMut(u32, &mut ChainRuntime) -> Result<(), NodeError>,
{
    let start_height = runtime.tip_height();
    let start = Instant::now();

    for round in 1..=params.rounds {
        let mining_params = MiningLoopParams {
            count: params.blocks_per_round,
            interval_sec: params.interval_sec,
            max_nonce: params.max_nonce,
            subsidy: cfg.block_subsidy,
            miner_key_hash: params.miner_key_hash,
            label_prefix: "soak",
            print_each: false,
        };
        mine_blocks_on_runtime(runtime, &mining_params)?;
        on_round_end(round, runtime)?;
        if params.sleep_per_round_sec > 0 {
            thread::sleep(Duration::from_secs(params.sleep_per_round_sec));
        }
    }

    let end_height = runtime.tip_height();
    Ok(SoakSummary {
        rounds: params.rounds,
        blocks_mined: end_height.saturating_sub(start_height),
        start_height,
        end_height,
        elapsed_sec: start.elapsed().as_secs(),
    })
}

fn run_soak(args: SoakArgs) -> Result<(), NodeError> {
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", args.network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let runtime_db_path = args
        .runtime_db
        .unwrap_or_else(|| default_runtime_db_path(args.network));
    let (mut runtime, source) = load_runtime_from_db_or_genesis(&cfg, &runtime_db_path)?;

    if args.txs_per_round > 0 && args.tx_amount == 0 {
        return Err(NodeError::Runtime(
            "tx_amount must be > 0 when txs_per_round is enabled".to_owned(),
        ));
    }

    let tx_flow_enabled = args.txs_per_round > 0;
    let (soak_sender_key, soak_recipient_key_hash20, miner_key_hash) = if tx_flow_enabled {
        let (sender_key, recipient_key_hash20) = derive_soak_flow_keys()?;
        let miner_key_hash = scam_core::hash160_blake3(&sender_key.pubkey_compressed());
        (Some(sender_key), recipient_key_hash20, miner_key_hash)
    } else {
        (None, [0u8; 20], cfg.genesis_reward_key_hash20()?)
    };

    let mut tx_blocks_mined = 0u64;
    let mut txs_included = 0u64;
    let persist_every_rounds = args.persist_every_rounds.max(1);
    let execution = SoakExecutionParams {
        rounds: args.rounds,
        blocks_per_round: args.blocks_per_round,
        interval_sec: args.interval_sec,
        max_nonce: args.max_nonce,
        miner_key_hash,
        sleep_per_round_sec: args.sleep_per_round_sec,
    };
    let summary = execute_soak_rounds(&mut runtime, &cfg, execution, |round, runtime| {
        if tx_flow_enabled {
            let sender_key = soak_sender_key
                .as_ref()
                .expect("tx flow enabled means sender key is present");
            let mut round_txs = Vec::<Transaction>::new();
            for tx_index in 0..args.txs_per_round {
                let recipient_key_hash20 = if tx_index % 2 == 0 {
                    soak_recipient_key_hash20
                } else {
                    miner_key_hash
                };
                match build_signed_transfer_tx(
                    runtime,
                    &cfg.network_id,
                    sender_key,
                    recipient_key_hash20,
                    args.tx_amount,
                    args.tx_fee,
                ) {
                    Ok(signed) => round_txs.push(signed.tx),
                    Err(NodeError::InsufficientFunds { .. }) => break,
                    Err(other) => return Err(other),
                }
            }

            if !round_txs.is_empty() {
                let tx_count = round_txs.len() as u64;
                mine_block_with_transactions(
                    runtime,
                    args.interval_sec,
                    args.max_nonce,
                    cfg.block_subsidy,
                    miner_key_hash,
                    format!("soak-tx-{round}"),
                    round_txs,
                )?;
                tx_blocks_mined = tx_blocks_mined.saturating_add(1);
                txs_included = txs_included.saturating_add(tx_count);
            }
        }

        if round % persist_every_rounds == 0 {
            persist_runtime_db(runtime, &runtime_db_path)?;
        }
        Ok(())
    })?;
    persist_runtime_db(&runtime, &runtime_db_path)?;

    let blocks_per_sec = if summary.elapsed_sec == 0 {
        summary.blocks_mined as f64
    } else {
        summary.blocks_mined as f64 / summary.elapsed_sec as f64
    };
    println!("Soak run complete");
    println!("Network: {}", cfg.network_id);
    println!("Config: {}", config_path.display());
    println!("Runtime source: {}", source);
    println!("Runtime DB: {}", runtime_db_path.display());
    println!("Rounds: {}", summary.rounds);
    println!("Blocks mined: {}", summary.blocks_mined);
    println!("Height: {} -> {}", summary.start_height, summary.end_height);
    println!("Elapsed sec: {}", summary.elapsed_sec);
    println!("Blocks/sec: {:.2}", blocks_per_sec);
    println!("TX flow enabled: {}", tx_flow_enabled);
    if tx_flow_enabled {
        let projected_wall_clock_sec =
            (args.rounds as u64).saturating_mul(args.sleep_per_round_sec);
        println!("TXs/round target: {}", args.txs_per_round);
        println!("TX amount: {}", args.tx_amount);
        println!("TX fee: {}", args.tx_fee);
        println!("TX blocks mined: {}", tx_blocks_mined);
        println!("TXs included: {}", txs_included);
        println!("Round sleep sec: {}", args.sleep_per_round_sec);
        println!(
            "Projected wall-clock sec (round sleeps): {}",
            projected_wall_clock_sec
        );
    }
    Ok(())
}

fn run_reorg_demo(args: ReorgDemoArgs) -> Result<(), NodeError> {
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", args.network.as_str())));
    let mut cfg = load_chain_config(&config_path)?;
    if cfg.difficulty_adjustment_window < 50 {
        cfg.difficulty_adjustment_window = 50;
    }
    let miner_key_hash = cfg.genesis_reward_key_hash20()?;
    let mut runtime = ChainRuntime::from_config(cfg.clone())?;

    let main_params = MiningLoopParams {
        count: args.main_blocks,
        interval_sec: args.main_interval_sec,
        max_nonce: args.max_nonce,
        subsidy: cfg.block_subsidy,
        miner_key_hash,
        label_prefix: "main",
        print_each: false,
    };
    mine_blocks_on_runtime(&mut runtime, &main_params)?;

    let old_tip = runtime.tip_hash();
    let Some(fork_from_hash) = runtime.block_hash_at_height(args.fork_from_height) else {
        return Err(NodeError::Runtime(format!(
            "fork_from_height {} out of range",
            args.fork_from_height
        )));
    };
    let Some(fork_header) = runtime.header_by_hash(&fork_from_hash).cloned() else {
        return Err(NodeError::Runtime("fork header missing".to_owned()));
    };
    let fork_target = fork_header.target;
    let mut fork_prev = fork_from_hash;
    let mut fork_ts = fork_header.timestamp.saturating_add(args.fork_interval_sec);

    let mut reorg_count = 0u32;
    for i in 0..args.fork_blocks {
        let template = BlockTemplate {
            version: 1,
            prev_block: fork_prev,
            timestamp: fork_ts,
            target: fork_target,
            transactions: vec![build_coinbase_tx(
                format!("fork-{i}"),
                cfg.block_subsidy,
                miner_key_hash,
            )],
        };

        let Some(block) = mine_block(&template, args.max_nonce) else {
            return Err(NodeError::Runtime(format!(
                "cannot mine fork block {i} in range 0..={}",
                args.max_nonce
            )));
        };
        fork_prev = block.header.block_hash();
        fork_ts = fork_ts.saturating_add(args.fork_interval_sec);

        let outcome = runtime.submit_block(block)?;
        match outcome {
            BlockSubmissionOutcome::AlreadyKnown { block_hash } => {
                println!("fork block already known: {}", block_hash);
            }
            BlockSubmissionOutcome::StoredSideBranch { block_hash } => {
                println!("stored side block: {}", block_hash);
            }
            BlockSubmissionOutcome::ExtendedTip {
                new_tip,
                new_height,
            } => {
                println!(
                    "extended tip via fork path: h={} hash={}",
                    new_height, new_tip
                );
            }
            BlockSubmissionOutcome::Reorged {
                old_tip,
                new_tip,
                new_height,
            } => {
                reorg_count += 1;
                println!(
                    "reorg occurred: old_tip={} -> new_tip={} at h={}",
                    old_tip, new_tip, new_height
                );
            }
        }
    }

    println!("Reorg demo summary");
    println!("Initial main tip: {}", old_tip);
    println!(
        "Final tip: h={} hash={}",
        runtime.tip_height(),
        runtime.tip_hash()
    );
    println!("Reorg events: {}", reorg_count);
    Ok(())
}

#[derive(Clone)]
struct StratumWork {
    job: MiningJob,
    coinbase: Transaction,
}

fn build_stratum_work(
    runtime: &ChainRuntime,
    cfg: &ChainConfig,
    channel_id: u32,
    job_id: u32,
) -> Result<StratumWork, NodeError> {
    let target = runtime.expected_target_for_next_block()?;
    let coinbase = build_coinbase_tx(
        format!("stratum-job-{job_id}"),
        cfg.block_subsidy,
        cfg.genesis_reward_key_hash20()?,
    );
    let merkle_root = scam_core::merkle::merkle_root(&[coinbase.txid()]);
    let job = MiningJob {
        channel_id,
        job_id,
        version: 1,
        prev_hash: runtime.tip_hash(),
        merkle_root,
        ntime: runtime
            .tip_header()
            .timestamp
            .saturating_add(cfg.target_block_time_sec),
        network_target: target,
    };
    Ok(StratumWork { job, coinbase })
}

fn write_sv2_message(stream: &mut TcpStream, message: &Sv2Message) -> Result<(), NodeError> {
    write_sv2_frame(stream, message)
        .map_err(|e| NodeError::Runtime(format!("stratum write failed: {e}")))
}

fn read_sv2_message(stream: &mut TcpStream) -> Result<Option<Sv2Message>, NodeError> {
    read_sv2_frame(stream).map_err(|e| NodeError::Runtime(format!("stratum read failed: {e}")))
}

#[derive(Clone)]
struct StratumServerContext {
    cfg: ChainConfig,
    runtime: Arc<Mutex<ChainRuntime>>,
    runtime_db_path: PathBuf,
    share_target: Target,
    next_channel_id: Arc<AtomicU32>,
    next_job_id: Arc<AtomicU32>,
    max_jobs_per_channel: usize,
}

fn lock_runtime<'a>(
    runtime: &'a Arc<Mutex<ChainRuntime>>,
) -> Result<std::sync::MutexGuard<'a, ChainRuntime>, NodeError> {
    runtime
        .lock()
        .map_err(|_| NodeError::Runtime("stratum runtime mutex poisoned".to_owned()))
}

fn issue_new_stratum_job(
    session: &mut Sv2Session,
    ctx: &StratumServerContext,
    stream: &mut TcpStream,
    jobs: &mut HashMap<u32, StratumWork>,
) -> Result<(), NodeError> {
    let job_id = ctx
        .next_job_id
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let runtime = lock_runtime(&ctx.runtime)?;
    let work = build_stratum_work(&runtime, &ctx.cfg, session.channel_id(), job_id)?;
    drop(runtime);

    let new_job = session.install_job(work.job.clone())?;
    write_sv2_message(stream, &new_job)?;
    let prev = session.set_new_prev_hash(&work.job)?;
    write_sv2_message(stream, &prev)?;
    jobs.insert(work.job.job_id, work);
    jobs.retain(|job_id, _| session.job(*job_id).is_some());
    Ok(())
}

fn run_stratum_client(mut stream: TcpStream, ctx: StratumServerContext) -> Result<(), NodeError> {
    configure_stream_timeouts(&stream)?;
    let channel_id = ctx
        .next_channel_id
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let mut session = Sv2Session::new(Sv2SessionConfig {
        channel_id,
        share_target: ctx.share_target,
        max_jobs: ctx.max_jobs_per_channel,
        supported_version: SUPPORTED_SV2_VERSION,
    })?;
    let mut jobs = HashMap::<u32, StratumWork>::new();

    while let Some(inbound) = read_sv2_message(&mut stream)? {
        let response = session.handle_message(inbound)?;
        for outbound in response.outbound {
            write_sv2_message(&mut stream, &outbound)?;
        }

        for event in response.events {
            match event {
                SessionEvent::SetupAccepted => {}
                SessionEvent::ChannelOpened { .. } => {
                    issue_new_stratum_job(&mut session, &ctx, &mut stream, &mut jobs)?;
                }
                SessionEvent::ShareAccepted {
                    channel_id,
                    job_id,
                    nonce,
                    ntime,
                    is_block,
                    ..
                } => {
                    if !is_block {
                        continue;
                    }
                    let Some(work) = jobs.get(&job_id).cloned() else {
                        continue;
                    };
                    let block = scam_core::Block {
                        header: scam_core::BlockHeader {
                            version: work.job.version,
                            prev_block: work.job.prev_hash,
                            merkle_root: work.job.merkle_root,
                            timestamp: ntime,
                            target: work.job.network_target,
                            nonce,
                        },
                        transactions: vec![work.coinbase],
                    };

                    let mut runtime = lock_runtime(&ctx.runtime)?;
                    let _ = runtime.submit_block(block)?;
                    persist_runtime_db(&runtime, &ctx.runtime_db_path)?;
                    drop(runtime);
                    jobs.clear();
                    if channel_id == session.channel_id() {
                        issue_new_stratum_job(&mut session, &ctx, &mut stream, &mut jobs)?;
                    }
                }
                SessionEvent::ShareRejected { .. } => {}
            }
        }
    }
    session.close();
    Ok(())
}

fn run_stratum_serve(args: StratumServeArgs) -> Result<(), NodeError> {
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", args.network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let runtime_db_path = args
        .runtime_db
        .unwrap_or_else(|| default_runtime_db_path(args.network));
    let (runtime, source) = load_runtime_from_db_or_genesis(&cfg, &runtime_db_path)?;
    let share_target = Target::from_hex(&args.share_target_hex)
        .map_err(|e| NodeError::Runtime(format!("invalid share_target_hex: {e}")))?;

    let listener = TcpListener::bind(&args.bind)
        .map_err(|e| NodeError::Runtime(format!("stratum bind failed on {}: {e}", args.bind)))?;
    println!(
        "Stratum (SV2 framed) listening on {} network={} source={} tip_h={} tip_hash={}",
        args.bind,
        cfg.network_id,
        source,
        runtime.tip_height(),
        runtime.tip_hash()
    );
    println!("Share target: {share_target}");
    println!("Max jobs/channel: {}", args.max_jobs_per_channel.max(1));
    if args.max_clients > 0 {
        println!("Max clients before exit: {}", args.max_clients);
    }

    let ctx = StratumServerContext {
        cfg,
        runtime: Arc::new(Mutex::new(runtime)),
        runtime_db_path,
        share_target,
        next_channel_id: Arc::new(AtomicU32::new(0)),
        next_job_id: Arc::new(AtomicU32::new(0)),
        max_jobs_per_channel: args.max_jobs_per_channel.max(1),
    };

    let mut served = 0u32;
    let mut handles = Vec::new();
    for incoming in listener.incoming() {
        let stream =
            incoming.map_err(|e| NodeError::Runtime(format!("stratum accept failed: {e}")))?;
        let client_ctx = ctx.clone();
        handles.push(thread::spawn(move || {
            run_stratum_client(stream, client_ctx)
        }));

        served = served.saturating_add(1);
        if args.max_clients > 0 && served >= args.max_clients {
            break;
        }
    }

    for handle in handles {
        let result = handle
            .join()
            .map_err(|_| NodeError::Runtime("stratum worker thread panicked".to_owned()))?;
        if let Err(err) = result {
            return Err(NodeError::Runtime(format!("stratum worker error: {err}")));
        }
    }
    Ok(())
}

fn json_error_body(message: &str) -> String {
    let escaped = message
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    format!("{{\"error\":\"{escaped}\"}}")
}

fn write_http_json_response(
    stream: &mut TcpStream,
    status_line: &str,
    body: &str,
) -> Result<(), NodeError> {
    let response = format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|e| NodeError::Runtime(format!("http write failed: {e}")))?;
    stream
        .flush()
        .map_err(|e| NodeError::Runtime(format!("http flush failed: {e}")))?;
    Ok(())
}

fn read_http_get_path(stream: &mut TcpStream) -> Result<Option<String>, NodeError> {
    let mut buffer = [0u8; 4096];
    let read = stream
        .read(&mut buffer)
        .map_err(|e| NodeError::Runtime(format!("http read failed: {e}")))?;
    if read == 0 {
        return Ok(None);
    }
    let raw = std::str::from_utf8(&buffer[..read])
        .map_err(|e| NodeError::Runtime(format!("invalid utf8 in request: {e}")))?;
    let Some(line) = raw.lines().next() else {
        return Ok(None);
    };
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let raw_target = parts.next().unwrap_or("/");
    if method != "GET" {
        return Err(NodeError::Runtime(format!(
            "unsupported method {method}, only GET is allowed"
        )));
    }
    let path = raw_target.split('?').next().unwrap_or("/");
    Ok(Some(path.to_owned()))
}

fn run_rpc_serve(args: RpcServeArgs) -> Result<(), NodeError> {
    let (cfg, runtime) = build_runtime_for_query(
        args.network,
        args.config,
        args.mine_blocks,
        args.interval_sec,
        args.max_nonce,
        "rpc-serve",
    )?;

    let listener = TcpListener::bind(&args.bind)
        .map_err(|e| NodeError::Runtime(format!("rpc bind failed on {}: {e}", args.bind)))?;
    println!(
        "RPC listening on {} (network={} tip_h={} tip_hash={})",
        args.bind,
        cfg.network_id,
        runtime.tip_height(),
        runtime.tip_hash()
    );
    println!("Endpoints: GET /health, /status, /block/<height>, /tx/<height>/<index>");
    if args.max_requests > 0 {
        println!("Max requests before exit: {}", args.max_requests);
    }

    let mut served = 0u32;
    for incoming in listener.incoming() {
        let mut stream =
            incoming.map_err(|e| NodeError::Runtime(format!("rpc accept failed: {e}")))?;
        configure_stream_timeouts(&stream)?;

        let path = match read_http_get_path(&mut stream) {
            Ok(Some(path)) => path,
            Ok(None) => continue,
            Err(err) => {
                let body = json_error_body(&err.to_string());
                write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                continue;
            }
        };

        let (status, body) = if path == "/health" {
            ("200 OK", "{\"ok\":true}".to_owned())
        } else if path == "/status" {
            let payload = StatusResponse {
                network_id: cfg.network_id.clone(),
                tip_height: runtime.tip_height(),
                tip_hash: runtime.tip_hash().to_hex(),
                utxo_count: runtime.utxo_len(),
                cumulative_work: runtime.cumulative_work().to_str_radix(10),
            };
            match to_pretty_json(&payload) {
                Ok(body) => ("200 OK", body),
                Err(e) => (
                    "500 Internal Server Error",
                    json_error_body(&format!("status serialization failed: {e}")),
                ),
            }
        } else if let Some(height_raw) = path.strip_prefix("/block/") {
            match height_raw.parse::<u64>() {
                Ok(height) => match runtime.block_hash_at_height(height) {
                    Some(hash) => match runtime.block_by_hash(&hash) {
                        Some(block) => {
                            let payload = header_to_block_response(
                                height,
                                &block.header,
                                block.transactions.len(),
                            );
                            match to_pretty_json(&payload) {
                                Ok(body) => ("200 OK", body),
                                Err(e) => (
                                    "500 Internal Server Error",
                                    json_error_body(&format!("block serialization failed: {e}")),
                                ),
                            }
                        }
                        None => (
                            "500 Internal Server Error",
                            json_error_body(&format!("block for height {height} missing")),
                        ),
                    },
                    None => (
                        "404 Not Found",
                        json_error_body(&format!("height {height} not found")),
                    ),
                },
                Err(_) => (
                    "400 Bad Request",
                    json_error_body("invalid block height, expected unsigned integer"),
                ),
            }
        } else if let Some(rest) = path.strip_prefix("/tx/") {
            let mut segments = rest.split('/');
            let height_raw = segments.next().unwrap_or_default();
            let index_raw = segments.next().unwrap_or_default();
            if height_raw.is_empty() || index_raw.is_empty() || segments.next().is_some() {
                (
                    "400 Bad Request",
                    json_error_body("tx path must be /tx/<height>/<index>"),
                )
            } else {
                match (height_raw.parse::<u64>(), index_raw.parse::<usize>()) {
                    (Ok(height), Ok(index)) => match runtime.block_hash_at_height(height) {
                        Some(hash) => match runtime.block_by_hash(&hash) {
                            Some(block) => match block.transactions.get(index) {
                                Some(tx) => {
                                    let payload = TxResponse::from_tx(height, index, tx);
                                    match to_pretty_json(&payload) {
                                        Ok(body) => ("200 OK", body),
                                        Err(e) => (
                                            "500 Internal Server Error",
                                            json_error_body(&format!(
                                                "tx serialization failed: {e}"
                                            )),
                                        ),
                                    }
                                }
                                None => (
                                    "404 Not Found",
                                    json_error_body(&format!(
                                        "tx index {index} not found in block at height {height}"
                                    )),
                                ),
                            },
                            None => (
                                "500 Internal Server Error",
                                json_error_body(&format!("block for height {height} missing")),
                            ),
                        },
                        None => (
                            "404 Not Found",
                            json_error_body(&format!("height {height} not found")),
                        ),
                    },
                    _ => (
                        "400 Bad Request",
                        json_error_body("invalid tx path numbers, expected /tx/<height>/<index>"),
                    ),
                }
            }
        } else {
            (
                "404 Not Found",
                json_error_body(
                    "unknown endpoint, use /health, /status, /block/<height>, /tx/<height>/<index>",
                ),
            )
        };

        write_http_json_response(&mut stream, status, &body)?;
        served = served.saturating_add(1);
        if args.max_requests > 0 && served >= args.max_requests {
            break;
        }
    }
    Ok(())
}

fn run() -> Result<(), NodeError> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Node(args)) => run_node(
            args.network,
            args.config,
            args.runtime_db,
            args.print_genesis,
        ),
        Some(Command::Status(args)) => run_status(args),
        Some(Command::GetBlock(args)) => run_get_block(args),
        Some(Command::GetTx(args)) => run_get_tx(args),
        Some(Command::ConfigScaffold(args)) => run_config_scaffold(args),
        Some(Command::AddPeer(args)) => run_add_peer(args),
        Some(Command::HashVisual(args)) => run_hash_visual(args),
        Some(Command::Wallet(args)) => run_wallet(args.command),
        Some(Command::MineOnce(args)) => run_mine_once(args),
        Some(Command::ChainDemo(args)) => run_chain_demo(args),
        Some(Command::SyncDemo(args)) => run_sync_demo(args),
        Some(Command::NetDemo(args)) => run_net_demo(args),
        Some(Command::SyncPeer(args)) => run_sync_peer(args),
        Some(Command::SyncBook(args)) => run_sync_book(args),
        Some(Command::ReindexRuntime(args)) => run_reindex_runtime(args),
        Some(Command::Soak(args)) => run_soak(args),
        Some(Command::ReorgDemo(args)) => run_reorg_demo(args),
        Some(Command::StratumServe(args)) => run_stratum_serve(args),
        Some(Command::RpcServe(args)) => run_rpc_serve(args),
        Some(Command::Snapshot(args)) => run_snapshot(args.command),
        Some(Command::P2pDemo) => run_p2p_demo(),
        None => run_node(cli.network, cli.config, cli.runtime_db, cli.print_genesis),
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use scam_chain::ChainRuntime;
    use scam_core::{ChainConfig, Hash256, OutPoint};
    use scam_miner::{BlockTemplate, mine_block};
    use scam_storage::{load_chain_archive_db, load_peer_book_db};
    use scam_wallet::{WalletMnemonic, derive_wallet_key};

    use super::{
        AddPeerArgs, ConfigScaffoldArgs, DifficultyAlgoArg, Network, ReindexRuntimeArgs,
        SOAK_FLOW_MNEMONIC, SpendableUtxo, SyncBookArgs, accepted_hrps_for_network,
        build_coinbase_tx, build_signed_transfer_tx, execute_soak_rounds, load_chain_config,
        mine_block_with_transactions, mine_blocks_on_runtime, persist_runtime_db, run_add_peer,
        run_config_scaffold, run_reindex_runtime, run_sync_book, select_utxos_for_amount,
    };

    fn utxo(seed: u8, value: u64) -> SpendableUtxo {
        SpendableUtxo {
            outpoint: OutPoint {
                txid: Hash256([seed; 32]),
                vout: seed as u32,
            },
            value,
        }
    }

    #[test]
    fn accepted_hrps_include_legacy_aliases() {
        let devnet = accepted_hrps_for_network(Network::Devnet, "sd");
        assert!(devnet.iter().any(|hrp| hrp == "sd"));
        assert!(devnet.iter().any(|hrp| hrp == "scd"));

        let testnet = accepted_hrps_for_network(Network::Testnet, "st");
        assert!(testnet.iter().any(|hrp| hrp == "st"));
        assert!(testnet.iter().any(|hrp| hrp == "sct"));

        let mainnet = accepted_hrps_for_network(Network::Mainnet, "s");
        assert!(mainnet.iter().any(|hrp| hrp == "s"));
        assert!(mainnet.iter().any(|hrp| hrp == "sc"));
    }

    #[test]
    fn coin_selection_prefers_smallest_single_input_covering_target() {
        let candidates = vec![utxo(1, 10), utxo(2, 5), utxo(3, 8), utxo(4, 12)];
        let (selected, total) = select_utxos_for_amount(&candidates, 7).expect("selection");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 8);
        assert_eq!(total, 8);
    }

    #[test]
    fn coin_selection_accumulates_multiple_inputs_if_needed() {
        let candidates = vec![utxo(1, 3), utxo(2, 4), utxo(3, 5)];
        let (selected, total) = select_utxos_for_amount(&candidates, 9).expect("selection");
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].value, 5);
        assert_eq!(selected[1].value, 4);
        assert_eq!(total, 9);
    }

    #[test]
    fn coin_selection_returns_none_for_insufficient_funds() {
        let candidates = vec![utxo(1, 3), utxo(2, 4)];
        assert!(select_utxos_for_amount(&candidates, 10).is_none());
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        PathBuf::from(format!("target/{prefix}-{ts}"))
    }

    #[test]
    fn add_peer_uses_redb_peer_book_and_deduplicates() {
        let peers_dir = temp_dir("test-peer-book");
        fs::create_dir_all(&peers_dir).expect("mkdir");

        let args = AddPeerArgs {
            network: Network::Devnet,
            peer: "127.0.0.1:8333".to_owned(),
            peers_dir: peers_dir.clone(),
        };
        run_add_peer(args).expect("first add");
        run_add_peer(AddPeerArgs {
            network: Network::Devnet,
            peer: "127.0.0.1:8333".to_owned(),
            peers_dir: peers_dir.clone(),
        })
        .expect("duplicate add");

        let peer_book_path = peers_dir.join("devnet.redb");
        let book = load_peer_book_db(&peer_book_path).expect("load peer book");
        assert_eq!(book.network_id, "devnet");
        assert_eq!(book.peers.len(), 1);
        assert_eq!(book.peers[0].address, "127.0.0.1:8333");

        let _ = fs::remove_dir_all(peers_dir);
    }

    #[test]
    fn add_peer_migrates_legacy_txt_file() {
        let peers_dir = temp_dir("test-peer-book-legacy");
        fs::create_dir_all(&peers_dir).expect("mkdir");
        fs::write(
            peers_dir.join("devnet.txt"),
            "192.168.1.10:8333\n192.168.1.10:8333\n10.0.0.7:8333\n",
        )
        .expect("write legacy file");

        run_add_peer(AddPeerArgs {
            network: Network::Devnet,
            peer: "127.0.0.1:8333".to_owned(),
            peers_dir: peers_dir.clone(),
        })
        .expect("add and migrate");

        let peer_book_path = peers_dir.join("devnet.redb");
        let book = load_peer_book_db(&peer_book_path).expect("load peer book");
        assert_eq!(book.peers.len(), 3);
        assert!(
            book.peers
                .iter()
                .any(|peer| peer.address == "192.168.1.10:8333")
        );
        assert!(
            book.peers
                .iter()
                .any(|peer| peer.address == "10.0.0.7:8333")
        );
        assert!(
            book.peers
                .iter()
                .any(|peer| peer.address == "127.0.0.1:8333")
        );

        let _ = fs::remove_dir_all(peers_dir);
    }

    #[test]
    fn config_scaffold_writes_valid_custom_config() {
        let work_dir = temp_dir("test-config-scaffold");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let out = work_dir.join("custom.toml");

        run_config_scaffold(ConfigScaffoldArgs {
            network_id: "forknet".to_owned(),
            hrp: "sc".to_owned(),
            target_block_time_sec: 90,
            difficulty_adjustment_window: 30,
            difficulty_algorithm: DifficultyAlgoArg::Lwma,
            asert_half_life_sec: 1800,
            difficulty_clamp_up: 4.0,
            difficulty_clamp_down: 0.25,
            max_block_size: 2_000_000,
            max_tx_size: 200_000,
            max_mempool_txs: 75_000,
            min_relay_fee_per_kb: 1_000,
            max_orphan_txs: 5_000,
            orphan_ttl_sec: 1_200,
            p2p_max_outbound_per_bucket: 2,
            dns_seeds: vec![
                "seed1.example.org".to_owned(),
                "seed2.example.org".to_owned(),
            ],
            coinbase_maturity: 100,
            block_subsidy: 5_000_000_000,
            genesis_message: "fork genesis".to_owned(),
            genesis_timestamp: Some(1_800_000_000),
            genesis_target: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .to_owned(),
            genesis_nonce: 0,
            genesis_reward_key_hash20: "0000000000000000000000000000000000000000".to_owned(),
            out: out.clone(),
        })
        .expect("scaffold");

        let cfg = load_chain_config(&out).expect("load");
        assert_eq!(cfg.network_id, "forknet");
        assert_eq!(cfg.hrp, "sc");
        assert_eq!(
            cfg.difficulty_algorithm,
            scam_core::DifficultyAlgorithm::Lwma
        );
        assert_eq!(cfg.p2p_max_outbound_per_bucket, 2);
        assert_eq!(cfg.dns_seeds.len(), 2);

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn sync_book_requires_non_empty_peer_book() {
        let work_dir = temp_dir("test-sync-book-empty");
        let peers_dir = work_dir.join("peers");
        fs::create_dir_all(&peers_dir).expect("mkdir peers");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write config");
        let runtime_db = work_dir.join("runtime.redb");

        let err = run_sync_book(SyncBookArgs {
            network: Network::Devnet,
            config: Some(config_path),
            runtime_db: Some(runtime_db),
            peers_dir: peers_dir.clone(),
            max_peers: 4,
            max_batches_per_peer: 1,
            rotate_after_sec: 60,
        })
        .expect_err("sync-book must fail when peer book is empty");
        let message = err.to_string();
        assert!(
            message.contains("no peers") || message.contains("peer book"),
            "unexpected sync-book error: {message}"
        );

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn reindex_runtime_rebuilds_archive_from_blocks() {
        let work_dir = temp_dir("test-reindex-runtime");
        fs::create_dir_all(&work_dir).expect("mkdir");

        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write config");
        let cfg = load_chain_config(&config_path).expect("load config");
        let runtime_db_path = work_dir.join("runtime.redb");

        let mut runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime
                .tip_header()
                .timestamp
                .saturating_add(cfg.target_block_time_sec),
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![build_coinbase_tx(
                "reindex-test".to_owned(),
                cfg.block_subsidy,
                cfg.genesis_reward_key_hash20().expect("key hash"),
            )],
        };
        let block = mine_block(&template, 500_000).expect("mine block");
        runtime.apply_next_block(block).expect("apply block");
        persist_runtime_db(&runtime, &runtime_db_path).expect("persist runtime");

        run_reindex_runtime(ReindexRuntimeArgs {
            network: Network::Devnet,
            config: Some(config_path.clone()),
            runtime_db: Some(runtime_db_path.clone()),
        })
        .expect("reindex runtime");

        let archive = load_chain_archive_db(&runtime_db_path).expect("load archive");
        assert_eq!(archive.network_id, "devnet");
        assert_eq!(archive.blocks_by_height.len(), 2);

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn soak_rounds_mine_expected_block_count() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.validate().expect("config validate");
        let mut runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let start_height = runtime.tip_height();
        let miner_key_hash = cfg.genesis_reward_key_hash20().expect("key hash");
        let params = super::SoakExecutionParams {
            rounds: 3,
            blocks_per_round: 2,
            interval_sec: 30,
            max_nonce: 500_000,
            miner_key_hash,
            sleep_per_round_sec: 0,
        };

        let summary = execute_soak_rounds(&mut runtime, &cfg, params, |_round, _rt| Ok(()))
            .expect("soak rounds");

        assert_eq!(summary.rounds, 3);
        assert_eq!(summary.blocks_mined, 6);
        assert_eq!(summary.start_height, start_height);
        assert_eq!(summary.end_height, start_height + 6);
        assert_eq!(runtime.tip_height(), start_height + 6);
    }

    #[test]
    fn soak_round_callback_can_mine_extra_blocks() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.validate().expect("config validate");
        let mut runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let start_height = runtime.tip_height();
        let miner_key_hash = cfg.genesis_reward_key_hash20().expect("key hash");
        let params = super::SoakExecutionParams {
            rounds: 2,
            blocks_per_round: 1,
            interval_sec: 30,
            max_nonce: 500_000,
            miner_key_hash,
            sleep_per_round_sec: 0,
        };

        let summary = execute_soak_rounds(&mut runtime, &cfg, params, |_round, runtime| {
            mine_block_with_transactions(
                runtime,
                30,
                500_000,
                cfg.block_subsidy,
                miner_key_hash,
                "extra".to_owned(),
                Vec::new(),
            )?;
            Ok(())
        })
        .expect("soak with extra mining");

        assert_eq!(summary.blocks_mined, 4);
        assert_eq!(summary.start_height, start_height);
        assert_eq!(summary.end_height, start_height + 4);
    }

    #[test]
    fn build_signed_transfer_tx_allows_self_transfer_after_maturity() {
        let mut cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.coinbase_maturity = 2;
        cfg.validate().expect("config validate");

        let mut runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let mnemonic = WalletMnemonic::parse(SOAK_FLOW_MNEMONIC).expect("mnemonic");
        let seed = mnemonic.to_seed("");
        let sender_key = derive_wallet_key(&seed, 0, 0).expect("sender key");
        let sender_key_hash20 = scam_core::hash160_blake3(&sender_key.pubkey_compressed());
        let params = super::MiningLoopParams {
            count: 3,
            interval_sec: 30,
            max_nonce: 500_000,
            subsidy: cfg.block_subsidy,
            miner_key_hash: sender_key_hash20,
            label_prefix: "self-send",
            print_each: false,
        };
        mine_blocks_on_runtime(&mut runtime, &params).expect("mine blocks");

        let signed = build_signed_transfer_tx(
            &runtime,
            &cfg.network_id,
            &sender_key,
            sender_key_hash20,
            1_000,
            1,
        )
        .expect("signed tx");

        assert!(signed.is_self_transfer);
        assert!(!signed.selected_inputs.is_empty());
        assert_eq!(signed.tx.outputs[0].value, 1_000);
    }
}
