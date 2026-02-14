use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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
use scam_mempool::{InsertOutcome, Mempool, MempoolError, OrphanPool};
use scam_miner::{BlockTemplate, mine_block};
use scam_p2p::{
    FramingConfig, GossipEngine, GossipError, InventoryItem, LocalHandshake, PeerCandidate,
    ReplacementRateLimit, TransportError, WireMessage, build_block_locator, client_handshake,
    read_message, request_blocks, request_headers, select_block_hashes_for_peer,
    select_headers_for_peer, select_outbound_peers, send_message, server_handshake,
};
use scam_rpc::{StatusResponse, TxResponse, header_to_block_response, to_pretty_json};
use scam_storage::{
    ChainArchive, ChainStateSnapshot, PeerAddressBook, PeerAddressRecord, StorageError,
    load_chain_archive_db, load_peer_book_db, load_snapshot, load_snapshot_db,
    save_chain_archive_db, save_peer_book_db, save_snapshot, save_snapshot_db,
};
use scam_stratum::{
    IdentityTranslator, JobDeclarator, MiningJob, MiningTemplate, NoiseSv2Transport,
    SUPPORTED_SV2_VERSION, SecureSv2Transport, SecureTransportMode, SequentialJobDeclarator,
    SessionConfig as Sv2SessionConfig, SessionEvent, Sv2Message, Sv2Session, Translator,
    generate_noise_static_keypair, read_frame as read_sv2_frame,
    read_frame_async as read_sv2_frame_async, write_frame as write_sv2_frame,
    write_frame_async as write_sv2_frame_async,
};
use scam_wallet::{
    AddressError, DeriveKeyError, MnemonicError, QrError, RescanError, SchnorrError, WalletKey,
    WalletMnemonic, WalletVaultError, decrypt_wallet_vault, derive_wallet_key, derive_watched_keys,
    load_wallet_vault, new_encrypted_wallet_vault, new_mnemonic, parse_address, qr_for_payment_uri,
    rescan_blocks, save_wallet_vault, sign_digest, to_address, verify_digest,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

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
    RelayServe(RelayServeArgs),
    ReindexRuntime(ReindexRuntimeArgs),
    Soak(SoakArgs),
    ReorgDemo(ReorgDemoArgs),
    Sv2TemplateProvider(Sv2TemplateProviderArgs),
    Sv2JobDeclarator(Sv2JobDeclaratorArgs),
    Sv2Translator(Sv2TranslatorArgs),
    StratumServe(StratumServeArgs),
    StratumMine(StratumMineArgs),
    StratumKeygen(StratumKeygenArgs),
    StratumKeyRotate(StratumKeyRotateArgs),
    Sv2Conformance(Sv2ConformanceArgs),
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
    #[arg(long, default_value_t = 2_000)]
    p2p_max_inv_items: usize,
    #[arg(long, default_value_t = 100)]
    p2p_ban_threshold: u32,
    #[arg(long, default_value_t = 60)]
    p2p_replacement_window_sec: u64,
    #[arg(long, default_value_t = 20)]
    p2p_replacement_max_per_peer: usize,
    #[arg(long, default_value_t = 25)]
    p2p_replacement_penalty: u32,
    #[arg(long = "dns-seed")]
    dns_seeds: Vec<String>,
    #[arg(long, default_value_t = 100)]
    coinbase_maturity: u32,
    #[arg(long, default_value_t = 5_000_000_000)]
    block_subsidy: u64,
    #[arg(
        long,
        default_value = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )]
    stratum_share_target: String,
    #[arg(
        long,
        default_value = "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )]
    stratum_min_share_target: String,
    #[arg(
        long,
        default_value = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )]
    stratum_max_share_target: String,
    #[arg(long, default_value_t = 6)]
    stratum_vardiff_target_shares_per_minute: u32,
    #[arg(long, default_value_t = 24)]
    stratum_vardiff_retarget_interval_shares: usize,
    #[arg(long, default_value_t = 2.0)]
    stratum_vardiff_clamp_up: f64,
    #[arg(long, default_value_t = 0.5)]
    stratum_vardiff_clamp_down: f64,
    #[arg(long, default_value_t = 64)]
    stratum_max_rejected_shares: u32,
    #[arg(long, default_value_t = 2)]
    stratum_read_timeout_sec: u64,
    #[arg(long, default_value_t = 30)]
    stratum_keepalive_sec: u64,
    #[arg(long, default_value_t = 180)]
    stratum_idle_timeout_sec: u64,
    #[arg(long, default_value_t = 64)]
    stratum_max_jobs_per_channel: usize,
    #[arg(long, default_value_t = 256)]
    stratum_max_active_clients: usize,
    #[arg(long, default_value_t = false)]
    stratum_secure_transport: bool,
    #[arg(long, value_enum, default_value_t = SecureTransportModeArg::NoiseXx)]
    stratum_secure_transport_mode: SecureTransportModeArg,
    #[arg(long, default_value_t = 10_000)]
    stratum_secure_rekey_interval_messages: u64,
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
struct RelayServeArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    runtime_db: Option<PathBuf>,
    #[arg(long, default_value = "0.0.0.0:18444")]
    bind: String,
    #[arg(long, default_value_t = 0)]
    max_clients: u32,
    #[arg(long, default_value_t = 0)]
    max_messages_per_peer: u32,
    #[arg(long, default_value_t = 5)]
    read_timeout_sec: u64,
    #[arg(long, default_value_t = 5)]
    write_timeout_sec: u64,
    #[arg(long)]
    max_inv_items: Option<usize>,
    #[arg(long)]
    ban_threshold: Option<u32>,
    #[arg(long)]
    replacement_window_sec: Option<u64>,
    #[arg(long)]
    replacement_max_per_peer: Option<usize>,
    #[arg(long)]
    replacement_penalty: Option<u32>,
    #[arg(long)]
    telemetry_out: Option<PathBuf>,
    #[arg(long, default_value_t = 30)]
    telemetry_every_sec: u64,
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
    #[arg(long)]
    telemetry_out: Option<PathBuf>,
    #[arg(long, default_value_t = 1)]
    telemetry_every_rounds: u32,
    #[arg(long, default_value_t = 8)]
    simulated_peers: u32,
    #[arg(long, default_value_t = 60)]
    replacement_window_sec: u64,
    #[arg(long, default_value_t = 20)]
    replacement_max_per_peer: usize,
    #[arg(long, default_value_t = 25)]
    replacement_penalty: u32,
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
struct Sv2TemplateProviderArgs {
    #[arg(long, default_value = "127.0.0.1:3550")]
    bind: String,
    #[arg(long, default_value_t = 0)]
    max_requests: u32,
    #[arg(long)]
    telemetry_out: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct Sv2JobDeclaratorArgs {
    #[arg(long, default_value = "127.0.0.1:3551")]
    bind: String,
    #[arg(long, default_value_t = 0)]
    max_requests: u32,
    #[arg(long, default_value_t = 0)]
    start_job_id: u32,
    #[arg(long)]
    telemetry_out: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct Sv2TranslatorArgs {
    #[arg(long, default_value = "127.0.0.1:3552")]
    bind: String,
    #[arg(long, default_value_t = 0)]
    max_requests: u32,
    #[arg(long)]
    telemetry_out: Option<PathBuf>,
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
    #[arg(long)]
    share_target_hex: Option<String>,
    #[arg(long)]
    max_jobs_per_channel: Option<usize>,
    #[arg(long, default_value_t = 0)]
    max_clients: u32,
    #[arg(long)]
    max_active_clients: Option<usize>,
    #[arg(long)]
    read_timeout_sec: Option<u64>,
    #[arg(long)]
    keepalive_sec: Option<u64>,
    #[arg(long)]
    idle_timeout_sec: Option<u64>,
    #[arg(long)]
    vardiff_target_shares_per_minute: Option<u32>,
    #[arg(long)]
    vardiff_retarget_interval_shares: Option<usize>,
    #[arg(long)]
    vardiff_clamp_up: Option<f64>,
    #[arg(long)]
    vardiff_clamp_down: Option<f64>,
    #[arg(long)]
    max_rejected_shares: Option<u32>,
    #[arg(long)]
    min_share_target_hex: Option<String>,
    #[arg(long)]
    max_share_target_hex: Option<String>,
    #[arg(long, default_value_t = false)]
    secure_transport: bool,
    #[arg(long, value_enum)]
    secure_transport_mode: Option<SecureTransportModeArg>,
    #[arg(long)]
    secure_rekey_interval_messages: Option<u64>,
    #[arg(long)]
    secure_static_secret_key_hex: Option<String>,
    #[arg(long)]
    secure_expected_remote_static_pubkey_hex: Option<String>,
    #[arg(long)]
    template_provider_addr: Option<String>,
    #[arg(long)]
    job_declarator_addr: Option<String>,
}

#[derive(Debug, Args)]
struct StratumMineArgs {
    #[arg(long)]
    pool: String,
    #[arg(long, default_value = "scam-miner")]
    user: String,
    #[arg(long, default_value_t = 2)]
    read_timeout_sec: u64,
    #[arg(long, default_value_t = 250_000)]
    max_nonce_per_cycle: u64,
    #[arg(long, default_value_t = 0)]
    max_shares: u64,
    #[arg(long, default_value_t = 0)]
    max_runtime_sec: u64,
    #[arg(long, default_value_t = false)]
    secure_transport: bool,
    #[arg(long, value_enum)]
    secure_transport_mode: Option<SecureTransportModeArg>,
    #[arg(long, default_value_t = 10_000)]
    secure_rekey_interval_messages: u64,
    #[arg(long)]
    secure_static_secret_key_hex: Option<String>,
    #[arg(long)]
    secure_expected_remote_static_pubkey_hex: Option<String>,
    #[arg(long)]
    translator_addr: Option<String>,
}

#[derive(Debug, Args)]
struct StratumKeygenArgs {
    #[arg(long, default_value = "data/stratum-keys/server.secret.hex")]
    secret_out: PathBuf,
    #[arg(long, default_value = "data/stratum-keys/server.public.hex")]
    public_out: PathBuf,
    #[arg(long, default_value_t = false)]
    force: bool,
}

#[derive(Debug, Args)]
struct StratumKeyRotateArgs {
    #[arg(long, default_value = "data/stratum-keys/server.secret.hex")]
    secret_path: PathBuf,
    #[arg(long, default_value = "data/stratum-keys/server.public.hex")]
    public_path: PathBuf,
    #[arg(long, default_value = "data/stratum-keys/archive")]
    archive_dir: PathBuf,
}

#[derive(Debug, Args)]
struct Sv2ConformanceArgs {
    #[arg(long)]
    pool: String,
    #[arg(long, default_value = "scam-conformance")]
    user: String,
    #[arg(long, default_value_t = 3)]
    read_timeout_sec: u64,
    #[arg(long, default_value_t = false)]
    secure_transport: bool,
    #[arg(long, value_enum)]
    secure_transport_mode: Option<SecureTransportModeArg>,
    #[arg(long, default_value_t = 10_000)]
    secure_rekey_interval_messages: u64,
    #[arg(long)]
    secure_static_secret_key_hex: Option<String>,
    #[arg(long)]
    secure_expected_remote_static_pubkey_hex: Option<String>,
    #[arg(long)]
    corpus: Option<PathBuf>,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    stack_name: Option<String>,
}

#[derive(Debug, Args)]
struct RpcServeArgs {
    #[arg(long, value_enum, default_value_t = Network::Devnet)]
    network: Network,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    runtime_db: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:18080")]
    bind: String,
    #[arg(long, default_value = "web")]
    ui_dir: PathBuf,
    #[arg(long)]
    relay_telemetry: Option<PathBuf>,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SecureTransportModeArg {
    Legacy,
    NoiseXx,
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

impl From<SecureTransportModeArg> for SecureTransportMode {
    fn from(value: SecureTransportModeArg) -> Self {
        match value {
            SecureTransportModeArg::Legacy => SecureTransportMode::Legacy,
            SecureTransportModeArg::NoiseXx => SecureTransportMode::NoiseXx,
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

fn parse_secure_transport_mode(value: &str) -> Result<SecureTransportMode, NodeError> {
    value
        .parse::<SecureTransportMode>()
        .map_err(|e| NodeError::Runtime(format!("invalid secure transport mode '{value}': {e}")))
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
    #[error("mempool error: {0}")]
    Mempool(#[from] MempoolError),
    #[error("gossip error: {0}")]
    Gossip(#[from] GossipError),
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

fn should_mine_query_blocks(mine_blocks: u32) -> bool {
    mine_blocks != 0
}

fn build_runtime_for_query(
    network: Network,
    config: Option<PathBuf>,
    runtime_db: Option<PathBuf>,
    mine_blocks: u32,
    interval_sec: u64,
    max_nonce: u64,
    label_prefix: &'static str,
) -> Result<(ChainConfig, ChainRuntime), NodeError> {
    let config_path =
        config.unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let runtime_db_path = runtime_db.unwrap_or_else(|| default_runtime_db_path(network));
    let (mut runtime, _) = load_runtime_from_db_or_genesis(&cfg, &runtime_db_path)?;
    if should_mine_query_blocks(mine_blocks) {
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

fn decode_optional_hex32(
    field: &'static str,
    value: &Option<String>,
) -> Result<Option<[u8; 32]>, NodeError> {
    match value {
        Some(raw) => Ok(Some(decode_fixed_hex::<32>(field, raw)?)),
        None => Ok(None),
    }
}

fn run_status(args: StatusArgs) -> Result<(), NodeError> {
    let (cfg, runtime) = build_runtime_for_query(
        args.network,
        args.config,
        None,
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
        None,
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
        None,
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
        p2p_max_inv_items: args.p2p_max_inv_items,
        p2p_ban_threshold: args.p2p_ban_threshold,
        p2p_replacement_window_sec: args.p2p_replacement_window_sec,
        p2p_replacement_max_per_peer: args.p2p_replacement_max_per_peer,
        p2p_replacement_penalty: args.p2p_replacement_penalty,
        coinbase_maturity: args.coinbase_maturity,
        block_subsidy: args.block_subsidy,
        hrp: args.hrp.clone(),
        stratum_share_target: args.stratum_share_target.clone(),
        stratum_min_share_target: args.stratum_min_share_target.clone(),
        stratum_max_share_target: args.stratum_max_share_target.clone(),
        stratum_vardiff_target_shares_per_minute: args.stratum_vardiff_target_shares_per_minute,
        stratum_vardiff_retarget_interval_shares: args.stratum_vardiff_retarget_interval_shares,
        stratum_vardiff_clamp_up: args.stratum_vardiff_clamp_up,
        stratum_vardiff_clamp_down: args.stratum_vardiff_clamp_down,
        stratum_max_rejected_shares: args.stratum_max_rejected_shares,
        stratum_read_timeout_sec: args.stratum_read_timeout_sec,
        stratum_keepalive_sec: args.stratum_keepalive_sec,
        stratum_idle_timeout_sec: args.stratum_idle_timeout_sec,
        stratum_max_jobs_per_channel: args.stratum_max_jobs_per_channel,
        stratum_max_active_clients: args.stratum_max_active_clients,
        stratum_secure_transport: args.stratum_secure_transport,
        stratum_secure_transport_mode: SecureTransportMode::from(
            args.stratum_secure_transport_mode,
        )
        .as_str()
        .to_owned(),
        stratum_secure_rekey_interval_messages: args.stratum_secure_rekey_interval_messages,
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
    println!("Stratum secure transport: {}", cfg.stratum_secure_transport);
    println!(
        "Stratum secure transport mode: {}",
        cfg.stratum_secure_transport_mode
    );
    println!(
        "Stratum secure rekey interval (messages): {}",
        cfg.stratum_secure_rekey_interval_messages
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

        println!("Balances by derived address:");
        for balance in &report.balances {
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
                None,
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
                None,
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
                None,
                mine_blocks,
                interval_sec,
                max_nonce,
                "wallet-balance",
            )?;

            let mnemonic = WalletMnemonic::parse(&mnemonic)?;
            let seed = mnemonic.to_seed(&passphrase);
            let key = derive_wallet_key(&seed, account, index)?;
            let key_hash20 = scam_core::hash160_blake3(&key.pubkey_compressed());
            let address = to_address(&runtime.config().hrp, key.pubkey_compressed())?;
            let summary = wallet_balance_response(
                &runtime,
                runtime.config(),
                account,
                index,
                address,
                key_hash20,
            );

            println!("Wallet balance:");
            println!("Tip height: {}", summary.tip_height);
            println!("Address: {}", summary.address);
            println!("Address key hash20: {}", summary.key_hash20_hex);
            println!("UTXOs: {}", summary.utxo_count);
            println!("Spendable UTXOs: {}", summary.spendable_utxo_count);
            println!("Immature UTXOs: {}", summary.immature_utxo_count);
            println!("Total: {}", summary.total);
            println!("Spendable: {}", summary.spendable);
            println!("Immature: {}", summary.immature);
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
                None,
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct P2pDemoSummary {
    inbound_peer_id: u64,
    outbound_messages: usize,
    outbound_peer_ids: Vec<u64>,
    only_inv_messages: bool,
}

fn run_p2p_demo() -> Result<P2pDemoSummary, NodeError> {
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
    let mut outbound_peer_ids = fanout.iter().map(|msg| msg.peer_id).collect::<Vec<_>>();
    outbound_peer_ids.sort_unstable();
    let only_inv_messages = fanout
        .iter()
        .all(|msg| matches!(msg.message, WireMessage::Inv { .. }));
    let summary = P2pDemoSummary {
        inbound_peer_id: 1,
        outbound_messages: fanout.len(),
        outbound_peer_ids,
        only_inv_messages,
    };

    println!("P2P gossip demo:");
    println!("Incoming: peer #1 sent tx object");
    println!(
        "Engine produced {} outbound messages",
        summary.outbound_messages
    );
    for outbound in fanout {
        println!(" -> to peer #{}: {:?}", outbound.peer_id, outbound.message);
    }
    println!("Pattern: inv/getdata/object relay with peer-level dedup");
    Ok(summary)
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

fn configure_stream_timeouts_with(
    stream: &TcpStream,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<(), NodeError> {
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|e| NodeError::Runtime(format!("set read timeout failed: {e}")))?;
    stream
        .set_write_timeout(Some(write_timeout))
        .map_err(|e| NodeError::Runtime(format!("set write timeout failed: {e}")))?;
    Ok(())
}

fn configure_stream_timeouts(stream: &TcpStream) -> Result<(), NodeError> {
    configure_stream_timeouts_with(stream, Duration::from_secs(5), Duration::from_secs(5))
}

fn ensure_network_id_match(expected: &str, got: &str, context: &str) -> Result<(), NodeError> {
    if expected == got {
        return Ok(());
    }
    Err(NodeError::Runtime(format!(
        "{context}: expected {expected}, got {got}"
    )))
}

fn ensure_expected_hash(expected: Hash256, got: Hash256, context: &str) -> Result<(), NodeError> {
    if expected == got {
        return Ok(());
    }
    Err(NodeError::Runtime(format!(
        "{context}: expected {expected}, got {got}"
    )))
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
        ensure_network_id_match(
            &network_id,
            &remote_peer.network_id,
            "network mismatch from client",
        )
        .map_err(|e| e.to_string())?;

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
    ensure_network_id_match(
        &cfg.network_id,
        &remote_info.network_id,
        "network mismatch from server",
    )?;

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
                ensure_expected_hash(*expected_hash, got_hash, "unexpected block order from peer")?;
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
    ensure_network_id_match(
        &cfg.network_id,
        &remote.network_id,
        "network mismatch from peer",
    )?;

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
                    ensure_expected_hash(expected_hash, got_hash, "unexpected block from peer")?;
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

struct RelayServerState {
    runtime: ChainRuntime,
    relay: RelayAdmissionState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayServerTelemetrySnapshot {
    timestamp_unix_sec: u64,
    active_peers: usize,
    tip_height: u64,
    tip_hash: String,
    mempool_len: usize,
    orphan_pool_len: usize,
    mempool_inserted_total: u64,
    mempool_replaced_total: u64,
    mempool_removed_by_replacement_total: u64,
    mempool_rejected_conflict_total: u64,
    orphan_accepted_total: u64,
    orphan_evicted_total: u64,
    orphan_expired_total: u64,
    orphan_promoted_total: u64,
    gossip_replacement_rate_limited_total: u64,
}

fn relay_fee_hint(tx: &Transaction) -> u64 {
    let txid = tx.txid();
    let mut hint = [0u8; 8];
    hint.copy_from_slice(&txid.0[..8]);
    u64::from_be_bytes(hint).saturating_add(1)
}

fn relay_server_snapshot(
    state: &RelayServerState,
    active_peers: usize,
    now_unix_sec: u64,
) -> RelayServerTelemetrySnapshot {
    let mem = state.relay.mempool.telemetry();
    let orphan = state.relay.orphan_pool.telemetry();
    let gossip = state.relay.gossip.telemetry();
    RelayServerTelemetrySnapshot {
        timestamp_unix_sec: now_unix_sec,
        active_peers,
        tip_height: state.runtime.tip_height(),
        tip_hash: state.runtime.tip_hash().to_hex(),
        mempool_len: state.relay.mempool.len(),
        orphan_pool_len: state.relay.orphan_pool.len(),
        mempool_inserted_total: mem.accepted_total,
        mempool_replaced_total: mem.replaced_total,
        mempool_removed_by_replacement_total: mem.removed_by_replacement_total,
        mempool_rejected_conflict_total: mem.rejected_conflict_total,
        orphan_accepted_total: orphan.accepted_total,
        orphan_evicted_total: orphan.evicted_total,
        orphan_expired_total: orphan.expired_total,
        orphan_promoted_total: orphan.promoted_total,
        gossip_replacement_rate_limited_total: gossip.replacement_rate_limited_total,
    }
}

fn append_relay_telemetry_snapshot(
    path: &Path,
    snapshot: &RelayServerTelemetrySnapshot,
) -> Result<(), NodeError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            NodeError::Runtime(format!(
                "cannot create relay telemetry directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| {
            NodeError::Runtime(format!(
                "cannot open relay telemetry output {}: {e}",
                path.display()
            ))
        })?;
    let line = serde_json::to_string(snapshot)
        .map_err(|e| NodeError::Runtime(format!("cannot encode relay telemetry json: {e}")))?;
    file.write_all(line.as_bytes()).map_err(|e| {
        NodeError::Runtime(format!(
            "cannot write relay telemetry output {}: {e}",
            path.display()
        ))
    })?;
    file.write_all(b"\n").map_err(|e| {
        NodeError::Runtime(format!(
            "cannot finalize relay telemetry output {}: {e}",
            path.display()
        ))
    })?;
    Ok(())
}

fn append_jsonl_record<T: Serialize>(
    path: &Path,
    record: &T,
    context: &str,
) -> Result<(), NodeError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            NodeError::Runtime(format!(
                "cannot create {} telemetry directory {}: {e}",
                context,
                parent.display()
            ))
        })?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| {
            NodeError::Runtime(format!(
                "cannot open {} telemetry output {}: {e}",
                context,
                path.display()
            ))
        })?;
    let line = serde_json::to_string(record).map_err(|e| {
        NodeError::Runtime(format!("cannot encode {} telemetry json: {e}", context))
    })?;
    file.write_all(line.as_bytes()).map_err(|e| {
        NodeError::Runtime(format!(
            "cannot write {} telemetry output {}: {e}",
            context,
            path.display()
        ))
    })?;
    file.write_all(b"\n").map_err(|e| {
        NodeError::Runtime(format!(
            "cannot finalize {} telemetry output {}: {e}",
            context,
            path.display()
        ))
    })?;
    Ok(())
}

fn append_role_service_telemetry(
    path: &Path,
    role: &str,
    requests_total: u64,
    success_total: u64,
    error_total: u64,
) -> Result<(), NodeError> {
    let snapshot = RoleServiceTelemetry {
        timestamp_unix_sec: current_unix_sec()?,
        role: role.to_owned(),
        requests_total,
        success_total,
        error_total,
    };
    append_jsonl_record(path, &snapshot, "role-service")
}

fn process_relay_wire_message(
    state: &mut RelayServerState,
    peer_id: u64,
    message: WireMessage,
    now_unix_sec: u64,
) -> Result<Vec<WireMessage>, NodeError> {
    match message {
        WireMessage::Ping { nonce } => Ok(vec![WireMessage::Pong { nonce }]),
        WireMessage::Version { .. } => Ok(vec![WireMessage::Verack]),
        WireMessage::Verack | WireMessage::Pong { .. } | WireMessage::Headers { .. } => {
            Ok(Vec::new())
        }
        WireMessage::GetHeaders { locator, stop } => {
            let mut headers_by_hash = HashMap::new();
            for hash in state.runtime.block_hashes() {
                if let Some(header) = state.runtime.header_by_hash(hash) {
                    headers_by_hash.insert(*hash, header.clone());
                }
            }
            let headers = select_headers_for_peer(
                state.runtime.block_hashes(),
                &headers_by_hash,
                &locator,
                stop,
                2_000,
            );
            Ok(vec![WireMessage::Headers { headers }])
        }
        WireMessage::GetBlocks { locator, stop } => {
            let hashes =
                select_block_hashes_for_peer(state.runtime.block_hashes(), &locator, stop, 2_000);
            let items = hashes.into_iter().map(InventoryItem::Block).collect();
            Ok(vec![WireMessage::Inv { items }])
        }
        WireMessage::GetData { items } => {
            let mut out = Vec::<WireMessage>::new();
            let mut not_found = Vec::<InventoryItem>::new();
            for item in items {
                match item {
                    InventoryItem::Tx(txid) => {
                        if let Some(tx) = state.relay.mempool.get(&txid).cloned() {
                            out.push(WireMessage::Tx { tx });
                        } else {
                            not_found.push(InventoryItem::Tx(txid));
                        }
                    }
                    InventoryItem::Block(hash) => {
                        if let Some(block) = state.runtime.block_by_hash(&hash).cloned() {
                            out.push(WireMessage::Block { block });
                        } else {
                            not_found.push(InventoryItem::Block(hash));
                        }
                    }
                }
            }
            if !not_found.is_empty() {
                out.push(WireMessage::NotFound { items: not_found });
            }
            Ok(out)
        }
        WireMessage::Inv { items } => {
            let outbound = state
                .relay
                .gossip
                .on_message(peer_id, WireMessage::Inv { items })?;
            Ok(outbound
                .into_iter()
                .filter(|msg| msg.peer_id == peer_id)
                .map(|msg| msg.message)
                .collect())
        }
        WireMessage::Tx { tx } => {
            let txid = tx.txid();
            let fee_hint = relay_fee_hint(&tx);
            match admit_peer_tx_into_relay(
                &mut state.relay,
                &state.runtime,
                peer_id,
                tx,
                fee_hint,
                now_unix_sec,
            ) {
                Ok(()) => Ok(vec![WireMessage::Inv {
                    items: vec![InventoryItem::Tx(txid)],
                }]),
                Err(NodeError::Gossip(GossipError::ReplacementRateLimited { .. })) => {
                    Ok(vec![WireMessage::NotFound {
                        items: vec![InventoryItem::Tx(txid)],
                    }])
                }
                Err(NodeError::Mempool(MempoolError::FeeTooLow { .. })) => Ok(Vec::new()),
                Err(err) => Err(err),
            }
        }
        WireMessage::Block { block } => {
            let txids = block
                .transactions
                .iter()
                .map(|tx| tx.txid())
                .collect::<Vec<_>>();
            match state.runtime.submit_block(block.clone()) {
                Ok(_) => {
                    let _ = state.relay.mempool.remove_confirmed_txids(&txids);
                    let _ = state.relay.gossip.announce_block(block);
                    Ok(Vec::new())
                }
                Err(err) => Err(NodeError::Chain(err)),
            }
        }
        WireMessage::NotFound { .. } => Ok(Vec::new()),
    }
}

fn run_relay_serve(args: RelayServeArgs) -> Result<(), NodeError> {
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", args.network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let runtime_db_path = args
        .runtime_db
        .unwrap_or_else(|| default_runtime_db_path(args.network));
    let (runtime, source) = load_runtime_from_db_or_genesis(&cfg, &runtime_db_path)?;

    let max_inv_items = args.max_inv_items.unwrap_or(cfg.p2p_max_inv_items).max(1);
    let ban_threshold = args.ban_threshold.unwrap_or(cfg.p2p_ban_threshold).max(1);
    let replacement = ReplacementRateLimit {
        window_sec: args
            .replacement_window_sec
            .unwrap_or(cfg.p2p_replacement_window_sec)
            .max(1),
        max_replacements: args
            .replacement_max_per_peer
            .unwrap_or(cfg.p2p_replacement_max_per_peer)
            .max(1),
        penalty: args
            .replacement_penalty
            .unwrap_or(cfg.p2p_replacement_penalty)
            .max(1),
    };
    let relay = RelayAdmissionState {
        mempool: Mempool::with_policy(cfg.max_mempool_txs as usize, cfg.min_relay_fee_per_kb)?,
        orphan_pool: OrphanPool::new(cfg.max_orphan_txs as usize, cfg.orphan_ttl_sec)?,
        gossip: GossipEngine::with_limits_and_replacement(
            max_inv_items,
            ban_threshold,
            replacement,
        )?,
    };
    let state = Arc::new(Mutex::new(RelayServerState { runtime, relay }));
    let active_peers = Arc::new(Mutex::new(0usize));
    let next_peer_id = Arc::new(AtomicU64::new(0));

    let listener = TcpListener::bind(&args.bind)
        .map_err(|e| NodeError::Runtime(format!("relay bind failed on {}: {e}", args.bind)))?;
    println!(
        "P2P relay serving on {} network={} source={} (tx mempool admission active)",
        args.bind, cfg.network_id, source
    );
    println!(
        "Relay policy: max_inv_items={} ban_threshold={} replacement_window={}s replacement_max_per_peer={} replacement_penalty={}",
        max_inv_items,
        ban_threshold,
        replacement.window_sec,
        replacement.max_replacements,
        replacement.penalty
    );

    let stop_flag = Arc::new(AtomicBool::new(false));
    let telemetry_handle = if let Some(path) = args.telemetry_out.clone() {
        let path_clone = path.clone();
        let state_clone = state.clone();
        let active_clone = active_peers.clone();
        let stop_clone = stop_flag.clone();
        let every_sec = args.telemetry_every_sec.max(1);
        Some(thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(every_sec));
                let now = match current_unix_sec() {
                    Ok(now) => now,
                    Err(_) => continue,
                };
                let peers = match active_clone.lock() {
                    Ok(guard) => *guard,
                    Err(_) => continue,
                };
                let snapshot = match state_clone.lock() {
                    Ok(guard) => relay_server_snapshot(&guard, peers, now),
                    Err(_) => continue,
                };
                let _ = append_relay_telemetry_snapshot(&path_clone, &snapshot);
            }
        }))
    } else {
        None
    };

    let mut served = 0u32;
    let mut handles = Vec::new();
    for incoming in listener.incoming() {
        let mut stream =
            incoming.map_err(|e| NodeError::Runtime(format!("relay accept failed: {e}")))?;
        configure_stream_timeouts_with(
            &stream,
            Duration::from_secs(args.read_timeout_sec.max(1)),
            Duration::from_secs(args.write_timeout_sec.max(1)),
        )?;
        let peer_id = next_peer_id
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let state_clone = state.clone();
        let active_clone = active_peers.clone();
        let cfg_clone = cfg.clone();
        let read_limit = args.max_messages_per_peer;
        handles.push(thread::spawn(move || -> Result<(), NodeError> {
            let result = (|| -> Result<(), NodeError> {
                {
                    let mut active = active_clone.lock().map_err(|_| {
                        NodeError::Runtime("relay active peer mutex poisoned".to_owned())
                    })?;
                    *active = active.saturating_add(1);
                }

                let framing = FramingConfig::default();
                let local_hello = LocalHandshake {
                    protocol_version: 1,
                    network_id: cfg_clone.network_id.clone(),
                    user_agent: "scam-node/relay-serve".to_owned(),
                    start_height: 0,
                };
                let remote = server_handshake(&mut stream, &framing, &local_hello)?;
                if remote.network_id != cfg_clone.network_id {
                    return Err(NodeError::Runtime(format!(
                        "relay peer network mismatch: expected {}, got {}",
                        cfg_clone.network_id, remote.network_id
                    )));
                }
                {
                    let mut guard = state_clone
                        .lock()
                        .map_err(|_| NodeError::Runtime("relay state mutex poisoned".to_owned()))?;
                    guard.relay.gossip.connect_peer(peer_id);
                }

                let mut seen = 0u32;
                loop {
                    if read_limit > 0 && seen >= read_limit {
                        break;
                    }
                    let inbound = match read_message(&mut stream, &framing) {
                        Ok(msg) => msg,
                        Err(TransportError::Io(err))
                            if matches!(
                                err.kind(),
                                std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::Interrupted
                                    | std::io::ErrorKind::UnexpectedEof
                            ) =>
                        {
                            break;
                        }
                        Err(err) => return Err(NodeError::Transport(err)),
                    };
                    seen = seen.saturating_add(1);
                    let now = current_unix_sec()?;
                    let outbound = {
                        let mut guard = state_clone.lock().map_err(|_| {
                            NodeError::Runtime("relay state mutex poisoned".to_owned())
                        })?;
                        process_relay_wire_message(&mut guard, peer_id, inbound, now)?
                    };
                    for msg in outbound {
                        send_message(&mut stream, &msg, &framing)?;
                    }
                    let banned = {
                        let guard = state_clone.lock().map_err(|_| {
                            NodeError::Runtime("relay state mutex poisoned".to_owned())
                        })?;
                        guard.relay.gossip.is_banned(peer_id)
                    };
                    if banned {
                        break;
                    }
                }

                Ok(())
            })();

            if let Ok(mut guard) = state_clone.lock() {
                guard.relay.gossip.disconnect_peer(peer_id);
            }
            if let Ok(mut active) = active_clone.lock() {
                *active = active.saturating_sub(1);
            }
            result
        }));

        served = served.saturating_add(1);
        if max_requests_reached(args.max_clients, served) {
            break;
        }
    }

    for handle in handles {
        let result = handle
            .join()
            .map_err(|_| NodeError::Runtime("relay worker thread panicked".to_owned()))?;
        if let Err(err) = result {
            stop_flag.store(true, Ordering::Relaxed);
            return Err(err);
        }
    }
    stop_flag.store(true, Ordering::Relaxed);
    if let Some(handle) = telemetry_handle {
        let _ = handle.join();
    }
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

struct RelayAdmissionState {
    mempool: Mempool,
    orphan_pool: OrphanPool,
    gossip: GossipEngine,
}

#[derive(Clone, Debug, Serialize)]
struct SoakTelemetrySnapshot {
    round: u32,
    unix_sec: u64,
    tip_height: u64,
    mempool_len: usize,
    orphan_pool_len: usize,
    mempool_accepted_total: u64,
    mempool_replaced_total: u64,
    mempool_removed_by_replacement_total: u64,
    mempool_evicted_total: u64,
    mempool_removed_by_block_total: u64,
    mempool_rejected_conflict_total: u64,
    orphan_accepted_total: u64,
    orphan_evicted_total: u64,
    orphan_expired_total: u64,
    orphan_promoted_total: u64,
    gossip_announced_txs_total: u64,
    gossip_removed_txs_total: u64,
    gossip_inbound_replacement_events_total: u64,
    gossip_replacement_rate_limited_total: u64,
}

fn append_soak_telemetry_snapshot(
    path: &Path,
    snapshot: &SoakTelemetrySnapshot,
) -> Result<(), NodeError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            NodeError::Runtime(format!(
                "cannot create telemetry directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| {
            NodeError::Runtime(format!(
                "cannot open telemetry output {}: {e}",
                path.display()
            ))
        })?;
    let line = serde_json::to_string(snapshot)
        .map_err(|e| NodeError::Runtime(format!("cannot encode telemetry json: {e}")))?;
    file.write_all(line.as_bytes()).map_err(|e| {
        NodeError::Runtime(format!(
            "cannot write telemetry output {}: {e}",
            path.display()
        ))
    })?;
    file.write_all(b"\n").map_err(|e| {
        NodeError::Runtime(format!(
            "cannot finalize telemetry output {}: {e}",
            path.display()
        ))
    })?;
    Ok(())
}

fn detect_missing_outpoints(
    runtime: &ChainRuntime,
    mempool: &Mempool,
    tx: &Transaction,
) -> Vec<OutPoint> {
    let mut missing = HashSet::<OutPoint>::new();
    for input in &tx.inputs {
        if runtime.utxo_set().contains_key(&input.prev_out) {
            continue;
        }
        if mempool.contains(&input.prev_out.txid) {
            continue;
        }
        missing.insert(input.prev_out.clone());
    }
    missing.into_iter().collect::<Vec<_>>()
}

fn admit_peer_tx_into_relay(
    relay: &mut RelayAdmissionState,
    runtime: &ChainRuntime,
    peer_id: u64,
    tx: Transaction,
    fee: u64,
    now_unix_sec: u64,
) -> Result<(), NodeError> {
    let mut pending = VecDeque::<(Transaction, u64)>::new();
    pending.push_back((tx, fee));

    while let Some((candidate_tx, candidate_fee)) = pending.pop_front() {
        let missing = detect_missing_outpoints(runtime, &relay.mempool, &candidate_tx);
        if !missing.is_empty() {
            let _ = relay
                .orphan_pool
                .insert(candidate_tx, candidate_fee, missing, now_unix_sec)?;
            continue;
        }

        let outcome = relay.mempool.insert_with_fee(candidate_tx, candidate_fee)?;
        let inserted_txid = match outcome {
            InsertOutcome::Accepted { txid } => Some(txid),
            InsertOutcome::Replaced { inserted, .. } => Some(inserted),
            InsertOutcome::AcceptedWithEviction { inserted, .. } => Some(inserted),
            InsertOutcome::AlreadyPresent { .. }
            | InsertOutcome::RejectedConflictInsufficientFee { .. }
            | InsertOutcome::RejectedConflictInsufficientFeerate { .. } => None,
        };

        let delta = outcome.inventory_delta();
        if !delta.announced_txids.is_empty() || !delta.removed_txids.is_empty() {
            let announced_txs = delta
                .announced_txids
                .iter()
                .filter_map(|txid| relay.mempool.get(txid).cloned())
                .collect::<Vec<_>>();
            let _ = relay.gossip.apply_mempool_inventory_delta_from_peer(
                peer_id,
                announced_txs,
                &delta.removed_txids,
                now_unix_sec,
            )?;
        }

        if let Some(txid) = inserted_txid
            && let Some(inserted_tx) = relay.mempool.get(&txid).cloned()
        {
            for vout in 0..inserted_tx.outputs.len() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                let ready = relay.orphan_pool.resolve_outpoint(&outpoint);
                for ready_orphan in ready {
                    pending.push_back((ready_orphan.tx, ready_orphan.fee));
                }
            }
        }
    }

    Ok(())
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
        if params.sleep_per_round_sec != 0 {
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

    if args.txs_per_round != 0 && args.tx_amount == 0 {
        return Err(NodeError::Runtime(
            "tx_amount must be > 0 when txs_per_round is enabled".to_owned(),
        ));
    }
    if args.telemetry_every_rounds == 0 {
        return Err(NodeError::Runtime(
            "telemetry_every_rounds must be > 0".to_owned(),
        ));
    }
    if args.simulated_peers == 0 {
        return Err(NodeError::Runtime("simulated_peers must be > 0".to_owned()));
    }
    if args.replacement_window_sec == 0 {
        return Err(NodeError::Runtime(
            "replacement_window_sec must be > 0".to_owned(),
        ));
    }
    if args.replacement_max_per_peer == 0 {
        return Err(NodeError::Runtime(
            "replacement_max_per_peer must be > 0".to_owned(),
        ));
    }
    if args.replacement_penalty == 0 {
        return Err(NodeError::Runtime(
            "replacement_penalty must be > 0".to_owned(),
        ));
    }

    if let Some(path) = args.telemetry_out.as_ref() {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| {
                NodeError::Runtime(format!(
                    "cannot create telemetry parent {}: {e}",
                    parent.display()
                ))
            })?;
        }
        fs::write(path, b"").map_err(|e| {
            NodeError::Runtime(format!(
                "cannot initialize telemetry output {}: {e}",
                path.display()
            ))
        })?;
    }

    let tx_flow_enabled = args.txs_per_round > 0;
    let (soak_sender_key, soak_recipient_key_hash20, miner_key_hash) = if tx_flow_enabled {
        let (sender_key, recipient_key_hash20) = derive_soak_flow_keys()?;
        let miner_key_hash = scam_core::hash160_blake3(&sender_key.pubkey_compressed());
        (Some(sender_key), recipient_key_hash20, miner_key_hash)
    } else {
        (None, [0u8; 20], cfg.genesis_reward_key_hash20()?)
    };

    let mut relay_state = if tx_flow_enabled {
        let mut gossip = GossipEngine::with_limits_and_replacement(
            256,
            100,
            ReplacementRateLimit {
                window_sec: args.replacement_window_sec,
                max_replacements: args.replacement_max_per_peer,
                penalty: args.replacement_penalty,
            },
        )?;
        for peer_id in 1..=args.simulated_peers {
            gossip.connect_peer(peer_id as u64);
        }
        Some(RelayAdmissionState {
            mempool: Mempool::with_policy(cfg.max_mempool_txs as usize, cfg.min_relay_fee_per_kb)?,
            orphan_pool: OrphanPool::new(cfg.max_orphan_txs as usize, cfg.orphan_ttl_sec)?,
            gossip,
        })
    } else {
        None
    };

    let mut tx_blocks_mined = 0u64;
    let mut txs_included = 0u64;
    let mut rate_limited_events = 0u64;
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
        let now_unix_sec = current_unix_sec()?;
        if tx_flow_enabled {
            let sender_key = soak_sender_key
                .as_ref()
                .expect("tx flow enabled means sender key is present");
            for tx_index in 0..args.txs_per_round {
                let recipient_key_hash20 = if tx_index % 2 == 0 {
                    soak_recipient_key_hash20
                } else {
                    miner_key_hash
                };
                let tx_fee = args.tx_fee.saturating_add((tx_index % 4) as u64);
                match build_signed_transfer_tx(
                    runtime,
                    &cfg.network_id,
                    sender_key,
                    recipient_key_hash20,
                    args.tx_amount,
                    tx_fee,
                ) {
                    Ok(signed) => {
                        let peer_id =
                            ((round as u64 + tx_index as u64) % args.simulated_peers as u64) + 1;
                        match admit_peer_tx_into_relay(
                            relay_state
                                .as_mut()
                                .expect("relay state must exist when tx flow is enabled"),
                            runtime,
                            peer_id,
                            signed.tx,
                            tx_fee,
                            now_unix_sec,
                        ) {
                            Ok(()) => {}
                            Err(NodeError::Gossip(GossipError::ReplacementRateLimited {
                                ..
                            })) => {
                                rate_limited_events = rate_limited_events.saturating_add(1);
                            }
                            Err(NodeError::Mempool(
                                MempoolError::MultipleConflicts { .. }
                                | MempoolError::ReplacementTooManyDescendants { .. }
                                | MempoolError::FeeTooLow { .. }
                                | MempoolError::Full { .. },
                            )) => {}
                            Err(other) => return Err(other),
                        }
                    }
                    Err(NodeError::InsufficientFunds { .. }) => break,
                    Err(other) => return Err(other),
                }
            }

            let relay = relay_state
                .as_mut()
                .expect("relay state must exist when tx flow is enabled");
            let ranked = relay.mempool.txids_by_feerate_desc();
            let mut round_txs = Vec::<Transaction>::new();
            for txid in ranked.into_iter().take(args.txs_per_round as usize) {
                if let Some(tx) = relay.mempool.get(&txid) {
                    round_txs.push(tx.clone());
                }
            }

            if !round_txs.is_empty() {
                let tx_count = round_txs.len() as u64;
                let included_txids = round_txs.iter().map(Transaction::txid).collect::<Vec<_>>();
                mine_block_with_transactions(
                    runtime,
                    args.interval_sec,
                    args.max_nonce,
                    cfg.block_subsidy,
                    miner_key_hash,
                    format!("soak-tx-{round}"),
                    round_txs,
                )?;
                let removed_confirmed = relay.mempool.remove_confirmed_txids(&included_txids);
                if !removed_confirmed.is_empty() {
                    let _ = relay
                        .gossip
                        .apply_mempool_inventory_delta(Vec::new(), &removed_confirmed);
                }
                tx_blocks_mined = tx_blocks_mined.saturating_add(1);
                txs_included = txs_included.saturating_add(tx_count);
            }
            let _ = relay.orphan_pool.expire(now_unix_sec);
        }

        if let Some(path) = args.telemetry_out.as_ref()
            && should_emit_periodic_round(round, args.telemetry_every_rounds)
        {
            let snapshot = if let Some(relay) = relay_state.as_ref() {
                let mem = relay.mempool.telemetry();
                let orphan = relay.orphan_pool.telemetry();
                let gossip = relay.gossip.telemetry();
                SoakTelemetrySnapshot {
                    round,
                    unix_sec: now_unix_sec,
                    tip_height: runtime.tip_height(),
                    mempool_len: relay.mempool.len(),
                    orphan_pool_len: relay.orphan_pool.len(),
                    mempool_accepted_total: mem.accepted_total,
                    mempool_replaced_total: mem.replaced_total,
                    mempool_removed_by_replacement_total: mem.removed_by_replacement_total,
                    mempool_evicted_total: mem.evicted_total,
                    mempool_removed_by_block_total: mem.removed_by_block_total,
                    mempool_rejected_conflict_total: mem.rejected_conflict_total,
                    orphan_accepted_total: orphan.accepted_total,
                    orphan_evicted_total: orphan.evicted_total,
                    orphan_expired_total: orphan.expired_total,
                    orphan_promoted_total: orphan.promoted_total,
                    gossip_announced_txs_total: gossip.announced_txs_total,
                    gossip_removed_txs_total: gossip.removed_txs_total,
                    gossip_inbound_replacement_events_total: gossip
                        .inbound_replacement_events_total,
                    gossip_replacement_rate_limited_total: gossip.replacement_rate_limited_total,
                }
            } else {
                SoakTelemetrySnapshot {
                    round,
                    unix_sec: now_unix_sec,
                    tip_height: runtime.tip_height(),
                    mempool_len: 0,
                    orphan_pool_len: 0,
                    mempool_accepted_total: 0,
                    mempool_replaced_total: 0,
                    mempool_removed_by_replacement_total: 0,
                    mempool_evicted_total: 0,
                    mempool_removed_by_block_total: 0,
                    mempool_rejected_conflict_total: 0,
                    orphan_accepted_total: 0,
                    orphan_evicted_total: 0,
                    orphan_expired_total: 0,
                    orphan_promoted_total: 0,
                    gossip_announced_txs_total: 0,
                    gossip_removed_txs_total: 0,
                    gossip_inbound_replacement_events_total: 0,
                    gossip_replacement_rate_limited_total: 0,
                }
            };
            append_soak_telemetry_snapshot(path, &snapshot)?;
        }

        if round % persist_every_rounds == 0 {
            persist_runtime_db(runtime, &runtime_db_path)?;
        }
        Ok(())
    })?;
    persist_runtime_db(&runtime, &runtime_db_path)?;

    let blocks_per_sec = blocks_per_second(summary.blocks_mined, summary.elapsed_sec);
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
        println!("Replacement rate-limited events: {}", rate_limited_events);
        if let Some(path) = args.telemetry_out.as_ref() {
            println!("Telemetry out: {}", path.display());
            println!(
                "Telemetry snapshots every {} round(s)",
                args.telemetry_every_rounds
            );
        }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RpcMiningTemplate {
    version: u32,
    prev_hash_hex: String,
    merkle_root_hex: String,
    ntime: u64,
    network_target_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TemplateProviderRequest {
    channel_id: u32,
    version: u32,
    prev_hash_hex: String,
    ntime: u64,
    network_target_hex: String,
    block_subsidy: u64,
    reward_key_hash20_hex: String,
    coinbase_label: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TemplateProviderResponse {
    template: RpcMiningTemplate,
    coinbase_tx_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JobDeclaratorRequest {
    channel_id: u32,
    template: RpcMiningTemplate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JobDeclaratorResponse {
    job_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TranslatorRequest {
    message: Sv2Message,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TranslatorResponse {
    job: Option<RpcMiningTemplateWithJob>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RpcMiningTemplateWithJob {
    channel_id: u32,
    job_id: u32,
    template: RpcMiningTemplate,
}

fn mining_template_to_rpc(template: &MiningTemplate) -> RpcMiningTemplate {
    RpcMiningTemplate {
        version: template.version,
        prev_hash_hex: template.prev_hash.to_hex(),
        merkle_root_hex: template.merkle_root.to_hex(),
        ntime: template.ntime,
        network_target_hex: template.network_target.to_hex(),
    }
}

fn mining_template_from_rpc(template: RpcMiningTemplate) -> Result<MiningTemplate, NodeError> {
    Ok(MiningTemplate {
        version: template.version,
        prev_hash: Hash256::from_hex(&template.prev_hash_hex)
            .map_err(|e| NodeError::Runtime(format!("invalid prev_hash_hex: {e}")))?,
        merkle_root: Hash256::from_hex(&template.merkle_root_hex)
            .map_err(|e| NodeError::Runtime(format!("invalid merkle_root_hex: {e}")))?,
        ntime: template.ntime,
        network_target: Target::from_hex(&template.network_target_hex)
            .map_err(|e| NodeError::Runtime(format!("invalid network_target_hex: {e}")))?,
    })
}

fn call_json_role_service<Req, Resp>(addr: &str, request: &Req) -> Result<Resp, NodeError>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let mut stream = TcpStream::connect(addr)
        .map_err(|e| NodeError::Runtime(format!("connect to role service {addr} failed: {e}")))?;
    configure_stream_timeouts_with(&stream, Duration::from_secs(3), Duration::from_secs(3))?;
    let request_json = serde_json::to_string(request)
        .map_err(|e| NodeError::Runtime(format!("cannot encode role request: {e}")))?;
    stream
        .write_all(request_json.as_bytes())
        .map_err(|e| NodeError::Runtime(format!("role request write failed: {e}")))?;
    stream
        .write_all(b"\n")
        .map_err(|e| NodeError::Runtime(format!("role request write failed: {e}")))?;
    stream
        .flush()
        .map_err(|e| NodeError::Runtime(format!("role request flush failed: {e}")))?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let bytes = reader
        .read_line(&mut line)
        .map_err(|e| NodeError::Runtime(format!("role response read failed: {e}")))?;
    if bytes == 0 {
        return Err(NodeError::Runtime(
            "role service returned empty response".to_owned(),
        ));
    }
    serde_json::from_str::<Resp>(line.trim_end())
        .map_err(|e| NodeError::Runtime(format!("cannot decode role response: {e}")))
}

fn request_template_from_provider(
    addr: &str,
    request: &TemplateProviderRequest,
) -> Result<StratumTemplateWork, NodeError> {
    let response =
        call_json_role_service::<TemplateProviderRequest, TemplateProviderResponse>(addr, request)?;
    let template = mining_template_from_rpc(response.template)?;
    let coinbase_bytes = hex::decode(response.coinbase_tx_hex)
        .map_err(|e| NodeError::Runtime(format!("invalid coinbase_tx_hex from provider: {e}")))?;
    let coinbase = bincode::deserialize::<Transaction>(&coinbase_bytes)
        .map_err(|e| NodeError::Runtime(format!("invalid coinbase tx payload: {e}")))?;
    Ok(StratumTemplateWork { template, coinbase })
}

fn request_job_id_from_declarator(
    addr: &str,
    channel_id: u32,
    template: &MiningTemplate,
) -> Result<u32, NodeError> {
    let request = JobDeclaratorRequest {
        channel_id,
        template: mining_template_to_rpc(template),
    };
    let response =
        call_json_role_service::<JobDeclaratorRequest, JobDeclaratorResponse>(addr, &request)?;
    Ok(response.job_id)
}

fn translate_remote_job_with_service(
    addr: &str,
    message: Sv2Message,
) -> Result<Option<MiningJob>, NodeError> {
    let request = TranslatorRequest { message };
    let response = call_json_role_service::<TranslatorRequest, TranslatorResponse>(addr, &request)?;
    match response.job {
        Some(job) => {
            let template = mining_template_from_rpc(job.template)?;
            Ok(Some(MiningJob {
                channel_id: job.channel_id,
                job_id: job.job_id,
                version: template.version,
                prev_hash: template.prev_hash,
                merkle_root: template.merkle_root,
                ntime: template.ntime,
                network_target: template.network_target,
            }))
        }
        None => Ok(None),
    }
}

#[derive(Clone)]
struct StratumTemplateWork {
    template: MiningTemplate,
    coinbase: Transaction,
}

#[derive(Clone)]
struct StratumWork {
    job: MiningJob,
    coinbase: Transaction,
}

trait StratumTemplateProvider {
    fn build_template(
        &self,
        runtime: &ChainRuntime,
        cfg: &ChainConfig,
    ) -> Result<StratumTemplateWork, NodeError>;
}

#[derive(Clone, Copy, Debug, Default)]
struct RuntimeTemplateProvider;

impl StratumTemplateProvider for RuntimeTemplateProvider {
    fn build_template(
        &self,
        runtime: &ChainRuntime,
        cfg: &ChainConfig,
    ) -> Result<StratumTemplateWork, NodeError> {
        let target = runtime.expected_target_for_next_block()?;
        let coinbase = build_coinbase_tx(
            format!(
                "stratum-template-h{}",
                runtime.tip_height().saturating_add(1)
            ),
            cfg.block_subsidy,
            cfg.genesis_reward_key_hash20()?,
        );
        let merkle_root = scam_core::merkle::merkle_root(&[coinbase.txid()]);
        let template = MiningTemplate {
            version: 1,
            prev_hash: runtime.tip_hash(),
            merkle_root,
            ntime: runtime
                .tip_header()
                .timestamp
                .saturating_add(cfg.target_block_time_sec),
            network_target: target,
        };
        Ok(StratumTemplateWork { template, coinbase })
    }
}

enum StratumSecureTransport {
    Legacy(SecureSv2Transport),
    Noise(NoiseSv2Transport),
}

fn write_sv2_message(
    stream: &mut TcpStream,
    secure: Option<&mut StratumSecureTransport>,
    message: &Sv2Message,
) -> Result<(), NodeError> {
    match secure {
        Some(StratumSecureTransport::Legacy(transport)) => transport
            .write_message(stream, message)
            .map_err(|e| NodeError::Runtime(format!("stratum secure(legacy) write failed: {e}"))),
        Some(StratumSecureTransport::Noise(transport)) => transport
            .write_message(stream, message)
            .map_err(|e| NodeError::Runtime(format!("stratum secure(noise_xx) write failed: {e}"))),
        None => write_sv2_frame(stream, message)
            .map_err(|e| NodeError::Runtime(format!("stratum write failed: {e}"))),
    }
}

async fn write_sv2_message_async(
    stream: &mut tokio::net::TcpStream,
    secure: Option<&mut StratumSecureTransport>,
    message: &Sv2Message,
) -> Result<(), NodeError> {
    match secure {
        Some(StratumSecureTransport::Legacy(transport)) => transport
            .write_message_async(stream, message)
            .await
            .map_err(|e| NodeError::Runtime(format!("stratum secure(legacy) write failed: {e}"))),
        Some(StratumSecureTransport::Noise(transport)) => transport
            .write_message_async(stream, message)
            .await
            .map_err(|e| NodeError::Runtime(format!("stratum secure(noise_xx) write failed: {e}"))),
        None => write_sv2_frame_async(stream, message)
            .await
            .map_err(|e| NodeError::Runtime(format!("stratum write failed: {e}"))),
    }
}

enum StratumReadOutcome {
    Message(Sv2Message),
    Timeout,
    Closed,
}

fn read_sv2_message(
    stream: &mut TcpStream,
    secure: Option<&mut StratumSecureTransport>,
) -> Result<StratumReadOutcome, NodeError> {
    let read_result = match secure {
        Some(StratumSecureTransport::Legacy(transport)) => transport.read_message(stream),
        Some(StratumSecureTransport::Noise(transport)) => transport.read_message(stream),
        None => read_sv2_frame(stream),
    };
    match read_result {
        Ok(Some(message)) => Ok(StratumReadOutcome::Message(message)),
        Ok(None) => Ok(StratumReadOutcome::Closed),
        Err(scam_stratum::StratumError::Io(err))
            if matches!(
                err.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(StratumReadOutcome::Timeout)
        }
        Err(err) => Err(NodeError::Runtime(format!("stratum read failed: {err}"))),
    }
}

async fn read_sv2_message_async(
    stream: &mut tokio::net::TcpStream,
    secure: Option<&mut StratumSecureTransport>,
    read_timeout: Duration,
) -> Result<StratumReadOutcome, NodeError> {
    let read_result = timeout(read_timeout, async {
        match secure {
            Some(StratumSecureTransport::Legacy(transport)) => {
                transport.read_message_async(stream).await
            }
            Some(StratumSecureTransport::Noise(transport)) => {
                transport.read_message_async(stream).await
            }
            None => read_sv2_frame_async(stream).await,
        }
    })
    .await;

    match read_result {
        Ok(Ok(Some(message))) => Ok(StratumReadOutcome::Message(message)),
        Ok(Ok(None)) => Ok(StratumReadOutcome::Closed),
        Err(_) => Ok(StratumReadOutcome::Timeout),
        Ok(Err(err)) => Err(NodeError::Runtime(format!("stratum read failed: {err}"))),
    }
}

#[derive(Clone)]
struct StratumServerContext {
    cfg: ChainConfig,
    runtime: Arc<Mutex<ChainRuntime>>,
    runtime_db_path: PathBuf,
    share_target: Target,
    min_share_target: Target,
    max_share_target: Target,
    vardiff_target_shares_per_minute: u32,
    vardiff_retarget_interval_shares: usize,
    vardiff_clamp_up: f64,
    vardiff_clamp_down: f64,
    max_rejected_shares: u32,
    read_timeout_sec: u64,
    keepalive_sec: u64,
    idle_timeout_sec: u64,
    next_channel_id: Arc<AtomicU32>,
    template_provider: RuntimeTemplateProvider,
    job_declarator: Arc<Mutex<SequentialJobDeclarator>>,
    max_jobs_per_channel: usize,
    active_clients: Arc<AtomicUsize>,
    secure_transport: bool,
    secure_transport_mode: SecureTransportMode,
    secure_rekey_interval_messages: u64,
    secure_static_private_key: Option<[u8; 32]>,
    secure_expected_remote_static_public_key: Option<[u8; 32]>,
    template_provider_addr: Option<String>,
    job_declarator_addr: Option<String>,
}

fn lock_runtime<'a>(
    runtime: &'a Arc<Mutex<ChainRuntime>>,
) -> Result<std::sync::MutexGuard<'a, ChainRuntime>, NodeError> {
    runtime
        .lock()
        .map_err(|_| NodeError::Runtime("stratum runtime mutex poisoned".to_owned()))
}

#[allow(dead_code)]
fn issue_new_stratum_job(
    session: &mut Sv2Session,
    ctx: &StratumServerContext,
    stream: &mut TcpStream,
    secure: &mut Option<StratumSecureTransport>,
    jobs: &mut HashMap<u32, StratumWork>,
) -> Result<Hash256, NodeError> {
    let (tip_hash, template_work) = {
        let runtime = lock_runtime(&ctx.runtime)?;
        let tip_hash = runtime.tip_hash();
        let template_work = if let Some(addr) = &ctx.template_provider_addr {
            let target = runtime.expected_target_for_next_block()?;
            let request = TemplateProviderRequest {
                channel_id: session.channel_id(),
                version: 1,
                prev_hash_hex: runtime.tip_hash().to_hex(),
                ntime: runtime
                    .tip_header()
                    .timestamp
                    .saturating_add(ctx.cfg.target_block_time_sec),
                network_target_hex: target.to_hex(),
                block_subsidy: ctx.cfg.block_subsidy,
                reward_key_hash20_hex: hex::encode(ctx.cfg.genesis_reward_key_hash20()?),
                coinbase_label: format!(
                    "stratum-template-h{}",
                    runtime.tip_height().saturating_add(1)
                ),
            };
            request_template_from_provider(addr, &request)?
        } else {
            ctx.template_provider.build_template(&runtime, &ctx.cfg)?
        };
        (tip_hash, template_work)
    };

    let template = template_work.template;
    let job_id = if let Some(addr) = &ctx.job_declarator_addr {
        request_job_id_from_declarator(addr, session.channel_id(), &template)?
    } else {
        let mut declarator = ctx
            .job_declarator
            .lock()
            .map_err(|_| NodeError::Runtime("stratum job declarator mutex poisoned".to_owned()))?;
        declarator.next_job_id()
    };
    let job = MiningJob {
        channel_id: session.channel_id(),
        job_id,
        version: template.version,
        prev_hash: template.prev_hash,
        merkle_root: template.merkle_root,
        ntime: template.ntime,
        network_target: template.network_target,
    };
    let work = StratumWork {
        job,
        coinbase: template_work.coinbase,
    };

    let new_job = session.install_job(work.job.clone())?;
    write_sv2_message(stream, secure.as_mut(), &new_job)?;
    let prev = session.set_new_prev_hash(&work.job)?;
    write_sv2_message(stream, secure.as_mut(), &prev)?;
    jobs.insert(work.job.job_id, work);
    jobs.retain(|job_id, _| session.job(*job_id).is_some());
    Ok(tip_hash)
}

async fn issue_new_stratum_job_async(
    session: &mut Sv2Session,
    ctx: &StratumServerContext,
    stream: &mut tokio::net::TcpStream,
    secure: &mut Option<StratumSecureTransport>,
    jobs: &mut HashMap<u32, StratumWork>,
) -> Result<Hash256, NodeError> {
    let (tip_hash, template_work) = {
        let runtime = lock_runtime(&ctx.runtime)?;
        let tip_hash = runtime.tip_hash();
        let template_work = if let Some(addr) = &ctx.template_provider_addr {
            let target = runtime.expected_target_for_next_block()?;
            let request = TemplateProviderRequest {
                channel_id: session.channel_id(),
                version: 1,
                prev_hash_hex: runtime.tip_hash().to_hex(),
                ntime: runtime
                    .tip_header()
                    .timestamp
                    .saturating_add(ctx.cfg.target_block_time_sec),
                network_target_hex: target.to_hex(),
                block_subsidy: ctx.cfg.block_subsidy,
                reward_key_hash20_hex: hex::encode(ctx.cfg.genesis_reward_key_hash20()?),
                coinbase_label: format!(
                    "stratum-template-h{}",
                    runtime.tip_height().saturating_add(1)
                ),
            };
            request_template_from_provider(addr, &request)?
        } else {
            ctx.template_provider.build_template(&runtime, &ctx.cfg)?
        };
        (tip_hash, template_work)
    };

    let template = template_work.template;
    let job_id = if let Some(addr) = &ctx.job_declarator_addr {
        request_job_id_from_declarator(addr, session.channel_id(), &template)?
    } else {
        let mut declarator = ctx
            .job_declarator
            .lock()
            .map_err(|_| NodeError::Runtime("stratum job declarator mutex poisoned".to_owned()))?;
        declarator.next_job_id()
    };
    let job = MiningJob {
        channel_id: session.channel_id(),
        job_id,
        version: template.version,
        prev_hash: template.prev_hash,
        merkle_root: template.merkle_root,
        ntime: template.ntime,
        network_target: template.network_target,
    };
    let work = StratumWork {
        job,
        coinbase: template_work.coinbase,
    };

    let new_job = session.install_job(work.job.clone())?;
    write_sv2_message_async(stream, secure.as_mut(), &new_job).await?;
    let prev = session.set_new_prev_hash(&work.job)?;
    write_sv2_message_async(stream, secure.as_mut(), &prev).await?;
    jobs.insert(work.job.job_id, work);
    jobs.retain(|job_id, _| session.job(*job_id).is_some());
    Ok(tip_hash)
}

fn load_runtime_tip_hash(ctx: &StratumServerContext) -> Result<Hash256, NodeError> {
    let runtime = lock_runtime(&ctx.runtime)?;
    Ok(runtime.tip_hash())
}

#[allow(dead_code)]
fn run_stratum_client(mut stream: TcpStream, ctx: StratumServerContext) -> Result<(), NodeError> {
    let read_timeout = Duration::from_secs(ctx.read_timeout_sec.max(1));
    configure_stream_timeouts_with(&stream, read_timeout, read_timeout)?;
    let mut secure_transport = if ctx.secure_transport {
        let transport = match ctx.secure_transport_mode {
            SecureTransportMode::Legacy => {
                let mut legacy =
                    SecureSv2Transport::handshake_server(&mut stream).map_err(|e| {
                        NodeError::Runtime(format!("stratum secure(legacy) handshake failed: {e}"))
                    })?;
                legacy
                    .set_rekey_interval_messages(ctx.secure_rekey_interval_messages)
                    .map_err(|e| {
                        NodeError::Runtime(format!(
                            "stratum secure(legacy) transport config failed: {e}"
                        ))
                    })?;
                StratumSecureTransport::Legacy(legacy)
            }
            SecureTransportMode::NoiseXx => {
                let mut noise = NoiseSv2Transport::handshake_server(
                    &mut stream,
                    ctx.secure_static_private_key,
                    ctx.secure_expected_remote_static_public_key,
                )
                .map_err(|e| {
                    NodeError::Runtime(format!("stratum secure(noise_xx) handshake failed: {e}"))
                })?;
                noise
                    .set_rekey_interval_messages(ctx.secure_rekey_interval_messages)
                    .map_err(|e| {
                        NodeError::Runtime(format!(
                            "stratum secure(noise_xx) transport config failed: {e}"
                        ))
                    })?;
                StratumSecureTransport::Noise(noise)
            }
        };
        Some(transport)
    } else {
        None
    };
    let channel_id = ctx
        .next_channel_id
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let mut session = Sv2Session::new(Sv2SessionConfig {
        channel_id,
        share_target: ctx.share_target,
        min_share_target: ctx.min_share_target,
        max_share_target: ctx.max_share_target,
        max_jobs: ctx.max_jobs_per_channel,
        supported_version: SUPPORTED_SV2_VERSION,
        vardiff_target_shares_per_minute: ctx.vardiff_target_shares_per_minute,
        vardiff_retarget_interval_shares: ctx.vardiff_retarget_interval_shares,
        vardiff_clamp_up: ctx.vardiff_clamp_up,
        vardiff_clamp_down: ctx.vardiff_clamp_down,
        max_rejected_shares: ctx.max_rejected_shares,
    })?;
    let mut jobs = HashMap::<u32, StratumWork>::new();
    let mut last_keepalive = Instant::now();
    let mut last_activity = Instant::now();
    let mut last_tip_hash = load_runtime_tip_hash(&ctx)?;

    loop {
        match read_sv2_message(&mut stream, secure_transport.as_mut())? {
            StratumReadOutcome::Closed => break,
            StratumReadOutcome::Timeout => {
                if session.is_active() {
                    let current_tip = load_runtime_tip_hash(&ctx)?;
                    if current_tip != last_tip_hash {
                        jobs.clear();
                        last_tip_hash = issue_new_stratum_job(
                            &mut session,
                            &ctx,
                            &mut stream,
                            &mut secure_transport,
                            &mut jobs,
                        )?;
                    }
                    if nonzero_limit_reached(ctx.keepalive_sec, last_keepalive.elapsed().as_secs())
                    {
                        write_sv2_message(
                            &mut stream,
                            secure_transport.as_mut(),
                            &Sv2Message::KeepAlive,
                        )?;
                        last_keepalive = Instant::now();
                    }
                }
                if nonzero_limit_reached(ctx.idle_timeout_sec, last_activity.elapsed().as_secs()) {
                    break;
                }
            }
            StratumReadOutcome::Message(inbound) => {
                last_activity = Instant::now();
                let response = session.handle_message(inbound)?;
                for outbound in response.outbound {
                    write_sv2_message(&mut stream, secure_transport.as_mut(), &outbound)?;
                }

                for event in response.events {
                    match event {
                        SessionEvent::SetupAccepted => {}
                        SessionEvent::ChannelOpened { .. } => {
                            last_tip_hash = issue_new_stratum_job(
                                &mut session,
                                &ctx,
                                &mut stream,
                                &mut secure_transport,
                                &mut jobs,
                            )?;
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

                            {
                                let mut runtime = lock_runtime(&ctx.runtime)?;
                                let _ = runtime.submit_block(block)?;
                                persist_runtime_db(&runtime, &ctx.runtime_db_path)?;
                                last_tip_hash = runtime.tip_hash();
                            }

                            jobs.clear();
                            if channel_id == session.channel_id() {
                                last_tip_hash = issue_new_stratum_job(
                                    &mut session,
                                    &ctx,
                                    &mut stream,
                                    &mut secure_transport,
                                    &mut jobs,
                                )?;
                            }
                        }
                        SessionEvent::ShareRejected { .. } => {}
                        SessionEvent::ShareTargetChanged { .. } => {}
                        SessionEvent::ChannelClosed { .. } => {
                            session.close();
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
    session.close();
    Ok(())
}

async fn run_stratum_client_async(
    mut stream: tokio::net::TcpStream,
    ctx: StratumServerContext,
    _permit: OwnedSemaphorePermit,
) -> Result<(), NodeError> {
    let read_timeout = Duration::from_secs(ctx.read_timeout_sec.max(1));
    let mut secure_transport = if ctx.secure_transport {
        let transport = match ctx.secure_transport_mode {
            SecureTransportMode::Legacy => {
                let mut legacy = SecureSv2Transport::handshake_server_async(&mut stream)
                    .await
                    .map_err(|e| {
                        NodeError::Runtime(format!("stratum secure(legacy) handshake failed: {e}"))
                    })?;
                legacy
                    .set_rekey_interval_messages(ctx.secure_rekey_interval_messages)
                    .map_err(|e| {
                        NodeError::Runtime(format!(
                            "stratum secure(legacy) transport config failed: {e}"
                        ))
                    })?;
                StratumSecureTransport::Legacy(legacy)
            }
            SecureTransportMode::NoiseXx => {
                let mut noise = NoiseSv2Transport::handshake_server_async(
                    &mut stream,
                    ctx.secure_static_private_key,
                    ctx.secure_expected_remote_static_public_key,
                )
                .await
                .map_err(|e| {
                    NodeError::Runtime(format!("stratum secure(noise_xx) handshake failed: {e}"))
                })?;
                noise
                    .set_rekey_interval_messages(ctx.secure_rekey_interval_messages)
                    .map_err(|e| {
                        NodeError::Runtime(format!(
                            "stratum secure(noise_xx) transport config failed: {e}"
                        ))
                    })?;
                StratumSecureTransport::Noise(noise)
            }
        };
        Some(transport)
    } else {
        None
    };
    let channel_id = ctx
        .next_channel_id
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let mut session = Sv2Session::new(Sv2SessionConfig {
        channel_id,
        share_target: ctx.share_target,
        min_share_target: ctx.min_share_target,
        max_share_target: ctx.max_share_target,
        max_jobs: ctx.max_jobs_per_channel,
        supported_version: SUPPORTED_SV2_VERSION,
        vardiff_target_shares_per_minute: ctx.vardiff_target_shares_per_minute,
        vardiff_retarget_interval_shares: ctx.vardiff_retarget_interval_shares,
        vardiff_clamp_up: ctx.vardiff_clamp_up,
        vardiff_clamp_down: ctx.vardiff_clamp_down,
        max_rejected_shares: ctx.max_rejected_shares,
    })?;
    let mut jobs = HashMap::<u32, StratumWork>::new();
    let mut last_keepalive = Instant::now();
    let mut last_activity = Instant::now();
    let mut last_tip_hash = load_runtime_tip_hash(&ctx)?;

    loop {
        match read_sv2_message_async(&mut stream, secure_transport.as_mut(), read_timeout).await? {
            StratumReadOutcome::Closed => break,
            StratumReadOutcome::Timeout => {
                if session.is_active() {
                    let current_tip = load_runtime_tip_hash(&ctx)?;
                    if current_tip != last_tip_hash {
                        jobs.clear();
                        last_tip_hash = issue_new_stratum_job_async(
                            &mut session,
                            &ctx,
                            &mut stream,
                            &mut secure_transport,
                            &mut jobs,
                        )
                        .await?;
                    }
                    if nonzero_limit_reached(ctx.keepalive_sec, last_keepalive.elapsed().as_secs())
                    {
                        write_sv2_message_async(
                            &mut stream,
                            secure_transport.as_mut(),
                            &Sv2Message::KeepAlive,
                        )
                        .await?;
                        last_keepalive = Instant::now();
                    }
                }
                if nonzero_limit_reached(ctx.idle_timeout_sec, last_activity.elapsed().as_secs()) {
                    break;
                }
            }
            StratumReadOutcome::Message(inbound) => {
                last_activity = Instant::now();
                let response = session.handle_message(inbound)?;
                for outbound in response.outbound {
                    write_sv2_message_async(&mut stream, secure_transport.as_mut(), &outbound)
                        .await?;
                }

                for event in response.events {
                    match event {
                        SessionEvent::SetupAccepted => {}
                        SessionEvent::ChannelOpened { .. } => {
                            last_tip_hash = issue_new_stratum_job_async(
                                &mut session,
                                &ctx,
                                &mut stream,
                                &mut secure_transport,
                                &mut jobs,
                            )
                            .await?;
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

                            {
                                let mut runtime = lock_runtime(&ctx.runtime)?;
                                let _ = runtime.submit_block(block)?;
                                persist_runtime_db(&runtime, &ctx.runtime_db_path)?;
                                last_tip_hash = runtime.tip_hash();
                            }

                            jobs.clear();
                            if channel_id == session.channel_id() {
                                last_tip_hash = issue_new_stratum_job_async(
                                    &mut session,
                                    &ctx,
                                    &mut stream,
                                    &mut secure_transport,
                                    &mut jobs,
                                )
                                .await?;
                            }
                        }
                        SessionEvent::ShareRejected { .. } => {}
                        SessionEvent::ShareTargetChanged { .. } => {}
                        SessionEvent::ChannelClosed { .. } => {
                            session.close();
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
    session.close();
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct RoleServiceTelemetry {
    timestamp_unix_sec: u64,
    role: String,
    requests_total: u64,
    success_total: u64,
    error_total: u64,
}

fn read_role_request<T: DeserializeOwned>(stream: &mut TcpStream) -> Result<T, NodeError> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let bytes = reader
        .read_line(&mut line)
        .map_err(|e| NodeError::Runtime(format!("role request read failed: {e}")))?;
    if bytes == 0 {
        return Err(NodeError::Runtime(
            "role request stream closed without payload".to_owned(),
        ));
    }
    serde_json::from_str::<T>(line.trim_end())
        .map_err(|e| NodeError::Runtime(format!("role request decode failed: {e}")))
}

fn write_role_response<T: Serialize>(
    stream: &mut TcpStream,
    response: &T,
) -> Result<(), NodeError> {
    let body = serde_json::to_string(response)
        .map_err(|e| NodeError::Runtime(format!("role response encode failed: {e}")))?;
    stream
        .write_all(body.as_bytes())
        .map_err(|e| NodeError::Runtime(format!("role response write failed: {e}")))?;
    stream
        .write_all(b"\n")
        .map_err(|e| NodeError::Runtime(format!("role response write failed: {e}")))?;
    stream
        .flush()
        .map_err(|e| NodeError::Runtime(format!("role response flush failed: {e}")))
}

fn max_requests_reached(max_requests: u32, served: u32) -> bool {
    max_requests > 0 && served >= max_requests
}

fn nonzero_limit_reached(limit: u64, observed: u64) -> bool {
    limit > 0 && observed >= limit
}

fn should_emit_periodic_round(round: u32, every_rounds: u32) -> bool {
    every_rounds != 0 && round.is_multiple_of(every_rounds)
}

fn blocks_per_second(blocks_mined: u64, elapsed_sec: u64) -> f64 {
    if elapsed_sec == 0 {
        blocks_mined as f64
    } else {
        blocks_mined as f64 / elapsed_sec as f64
    }
}

fn run_sv2_template_provider(args: Sv2TemplateProviderArgs) -> Result<(), NodeError> {
    let listener = TcpListener::bind(&args.bind).map_err(|e| {
        NodeError::Runtime(format!(
            "sv2-template-provider bind failed on {}: {e}",
            args.bind
        ))
    })?;
    println!("SV2 template provider listening on {}", args.bind);

    let mut served = 0u32;
    let mut requests_total = 0u64;
    let mut success_total = 0u64;
    let mut error_total = 0u64;
    for incoming in listener.incoming() {
        let mut stream = incoming
            .map_err(|e| NodeError::Runtime(format!("template provider accept failed: {e}")))?;
        requests_total = requests_total.saturating_add(1);
        let handled = (|| -> Result<(), NodeError> {
            configure_stream_timeouts_with(
                &stream,
                Duration::from_secs(3),
                Duration::from_secs(3),
            )?;
            let request: TemplateProviderRequest = read_role_request(&mut stream)?;
            let reward_key_hash20 =
                decode_fixed_hex::<20>("reward_key_hash20_hex", &request.reward_key_hash20_hex)?;
            let coinbase = build_coinbase_tx(
                request.coinbase_label.clone(),
                request.block_subsidy,
                reward_key_hash20,
            );
            let merkle_root = scam_core::merkle::merkle_root(&[coinbase.txid()]);
            let template = RpcMiningTemplate {
                version: request.version,
                prev_hash_hex: request.prev_hash_hex,
                merkle_root_hex: merkle_root.to_hex(),
                ntime: request.ntime,
                network_target_hex: request.network_target_hex,
            };
            let coinbase_tx_hex = hex::encode(
                bincode::serialize(&coinbase)
                    .map_err(|e| NodeError::Runtime(format!("coinbase encode failed: {e}")))?,
            );
            let response = TemplateProviderResponse {
                template,
                coinbase_tx_hex,
            };
            write_role_response(&mut stream, &response)?;
            Ok(())
        })();
        match handled {
            Ok(()) => {
                success_total = success_total.saturating_add(1);
            }
            Err(err) => {
                error_total = error_total.saturating_add(1);
                eprintln!("sv2-template-provider request error: {err}");
            }
        }
        if let Some(path) = args.telemetry_out.as_ref() {
            append_role_service_telemetry(
                path,
                "template_provider",
                requests_total,
                success_total,
                error_total,
            )?;
        }

        served = served.saturating_add(1);
        if max_requests_reached(args.max_requests, served) {
            break;
        }
    }
    Ok(())
}

fn run_sv2_job_declarator(args: Sv2JobDeclaratorArgs) -> Result<(), NodeError> {
    let listener = TcpListener::bind(&args.bind).map_err(|e| {
        NodeError::Runtime(format!(
            "sv2-job-declarator bind failed on {}: {e}",
            args.bind
        ))
    })?;
    println!("SV2 job declarator listening on {}", args.bind);
    let declarator = Arc::new(Mutex::new(SequentialJobDeclarator::new(args.start_job_id)));

    let mut served = 0u32;
    let mut requests_total = 0u64;
    let mut success_total = 0u64;
    let mut error_total = 0u64;
    for incoming in listener.incoming() {
        let mut stream = incoming
            .map_err(|e| NodeError::Runtime(format!("job declarator accept failed: {e}")))?;
        requests_total = requests_total.saturating_add(1);
        let handled = (|| -> Result<(), NodeError> {
            configure_stream_timeouts_with(
                &stream,
                Duration::from_secs(3),
                Duration::from_secs(3),
            )?;
            let request: JobDeclaratorRequest = read_role_request(&mut stream)?;
            let _ = mining_template_from_rpc(request.template)?;
            let job_id = {
                let mut guard = declarator
                    .lock()
                    .map_err(|_| NodeError::Runtime("job declarator mutex poisoned".to_owned()))?;
                guard.next_job_id()
            };
            let response = JobDeclaratorResponse { job_id };
            write_role_response(&mut stream, &response)?;
            Ok(())
        })();
        match handled {
            Ok(()) => {
                success_total = success_total.saturating_add(1);
            }
            Err(err) => {
                error_total = error_total.saturating_add(1);
                eprintln!("sv2-job-declarator request error: {err}");
            }
        }
        if let Some(path) = args.telemetry_out.as_ref() {
            append_role_service_telemetry(
                path,
                "job_declarator",
                requests_total,
                success_total,
                error_total,
            )?;
        }

        served = served.saturating_add(1);
        if max_requests_reached(args.max_requests, served) {
            break;
        }
    }
    Ok(())
}

fn run_sv2_translator(args: Sv2TranslatorArgs) -> Result<(), NodeError> {
    let listener = TcpListener::bind(&args.bind).map_err(|e| {
        NodeError::Runtime(format!("sv2-translator bind failed on {}: {e}", args.bind))
    })?;
    println!("SV2 translator listening on {}", args.bind);
    let translator = IdentityTranslator;

    let mut served = 0u32;
    let mut requests_total = 0u64;
    let mut success_total = 0u64;
    let mut error_total = 0u64;
    for incoming in listener.incoming() {
        let mut stream =
            incoming.map_err(|e| NodeError::Runtime(format!("translator accept failed: {e}")))?;
        requests_total = requests_total.saturating_add(1);
        let handled = (|| -> Result<(), NodeError> {
            configure_stream_timeouts_with(
                &stream,
                Duration::from_secs(3),
                Duration::from_secs(3),
            )?;
            let request: TranslatorRequest = read_role_request(&mut stream)?;
            let job = translator
                .parse_remote_job_message(request.message)
                .map_err(|e| NodeError::Runtime(format!("translator parse failed: {e}")))?;
            let response = TranslatorResponse {
                job: job.map(|job| RpcMiningTemplateWithJob {
                    channel_id: job.channel_id,
                    job_id: job.job_id,
                    template: RpcMiningTemplate {
                        version: job.version,
                        prev_hash_hex: job.prev_hash.to_hex(),
                        merkle_root_hex: job.merkle_root.to_hex(),
                        ntime: job.ntime,
                        network_target_hex: job.network_target.to_hex(),
                    },
                }),
            };
            write_role_response(&mut stream, &response)?;
            Ok(())
        })();
        match handled {
            Ok(()) => {
                success_total = success_total.saturating_add(1);
            }
            Err(err) => {
                error_total = error_total.saturating_add(1);
                eprintln!("sv2-translator request error: {err}");
            }
        }
        if let Some(path) = args.telemetry_out.as_ref() {
            append_role_service_telemetry(
                path,
                "translator",
                requests_total,
                success_total,
                error_total,
            )?;
        }

        served = served.saturating_add(1);
        if max_requests_reached(args.max_requests, served) {
            break;
        }
    }
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
    let share_target_hex = args
        .share_target_hex
        .as_deref()
        .unwrap_or(&cfg.stratum_share_target);
    let min_share_target_hex = args
        .min_share_target_hex
        .as_deref()
        .unwrap_or(&cfg.stratum_min_share_target);
    let max_share_target_hex = args
        .max_share_target_hex
        .as_deref()
        .unwrap_or(&cfg.stratum_max_share_target);

    let vardiff_target_shares_per_minute = args
        .vardiff_target_shares_per_minute
        .unwrap_or(cfg.stratum_vardiff_target_shares_per_minute);
    let vardiff_retarget_interval_shares = args
        .vardiff_retarget_interval_shares
        .unwrap_or(cfg.stratum_vardiff_retarget_interval_shares)
        .max(2);
    let vardiff_clamp_up = args
        .vardiff_clamp_up
        .unwrap_or(cfg.stratum_vardiff_clamp_up);
    let vardiff_clamp_down = args
        .vardiff_clamp_down
        .unwrap_or(cfg.stratum_vardiff_clamp_down);
    let max_rejected_shares = args
        .max_rejected_shares
        .unwrap_or(cfg.stratum_max_rejected_shares)
        .max(1);
    let read_timeout_sec = args
        .read_timeout_sec
        .unwrap_or(cfg.stratum_read_timeout_sec)
        .max(1);
    let keepalive_sec = args
        .keepalive_sec
        .unwrap_or(cfg.stratum_keepalive_sec)
        .max(1);
    let idle_timeout_sec = args
        .idle_timeout_sec
        .unwrap_or(cfg.stratum_idle_timeout_sec)
        .max(1);
    let max_jobs_per_channel = args
        .max_jobs_per_channel
        .unwrap_or(cfg.stratum_max_jobs_per_channel)
        .max(1);
    let max_active_clients = args
        .max_active_clients
        .unwrap_or(cfg.stratum_max_active_clients)
        .max(1);
    let secure_transport = cfg.stratum_secure_transport || args.secure_transport;
    let secure_transport_mode = match args.secure_transport_mode {
        Some(mode) => SecureTransportMode::from(mode),
        None => parse_secure_transport_mode(&cfg.stratum_secure_transport_mode)?,
    };
    let secure_rekey_interval_messages = args
        .secure_rekey_interval_messages
        .unwrap_or(cfg.stratum_secure_rekey_interval_messages)
        .max(1);
    let secure_static_private_key = decode_optional_hex32(
        "secure_static_secret_key_hex",
        &args.secure_static_secret_key_hex,
    )?;
    let secure_expected_remote_static_public_key = decode_optional_hex32(
        "secure_expected_remote_static_pubkey_hex",
        &args.secure_expected_remote_static_pubkey_hex,
    )?;
    if secure_transport
        && matches!(secure_transport_mode, SecureTransportMode::NoiseXx)
        && secure_static_private_key.is_none()
    {
        return Err(NodeError::Runtime(
            "secure transport mode noise_xx requires --secure-static-secret-key-hex \
             (use `scam-node stratum-keygen` to generate keys)"
                .to_owned(),
        ));
    }

    let share_target = Target::from_hex(share_target_hex)
        .map_err(|e| NodeError::Runtime(format!("invalid share_target_hex: {e}")))?;
    let min_share_target = Target::from_hex(min_share_target_hex)
        .map_err(|e| NodeError::Runtime(format!("invalid min_share_target_hex: {e}")))?;
    let max_share_target = Target::from_hex(max_share_target_hex)
        .map_err(|e| NodeError::Runtime(format!("invalid max_share_target_hex: {e}")))?;
    if min_share_target > max_share_target {
        return Err(NodeError::Runtime(
            "min_share_target_hex must be <= max_share_target_hex".to_owned(),
        ));
    }
    if share_target < min_share_target || share_target > max_share_target {
        return Err(NodeError::Runtime(
            "share_target_hex must be within [min_share_target_hex, max_share_target_hex]"
                .to_owned(),
        ));
    }
    if keepalive_sec >= idle_timeout_sec {
        return Err(NodeError::Runtime(
            "idle_timeout_sec must be greater than keepalive_sec".to_owned(),
        ));
    }

    println!(
        "Stratum (SV2 framed) listening on {} network={} source={} tip_h={} tip_hash={}",
        args.bind,
        cfg.network_id,
        source,
        runtime.tip_height(),
        runtime.tip_hash()
    );
    println!("Share target: {share_target}");
    println!(
        "VarDiff target shares/min: {}",
        vardiff_target_shares_per_minute
    );
    println!(
        "VarDiff window shares: {} clamp_down={} clamp_up={}",
        vardiff_retarget_interval_shares, vardiff_clamp_down, vardiff_clamp_up
    );
    println!(
        "Share target bounds: min={} max={}",
        min_share_target, max_share_target
    );
    println!("Max jobs/channel: {}", max_jobs_per_channel);
    println!("Max active clients: {}", max_active_clients);
    println!("I/O model: async tokio");
    println!(
        "Read timeout={}s keepalive={}s idle timeout={}s",
        read_timeout_sec, keepalive_sec, idle_timeout_sec
    );
    println!("Secure transport: {}", secure_transport);
    println!("Secure transport mode: {}", secure_transport_mode.as_str());
    println!(
        "Secure rekey interval (messages): {}",
        secure_rekey_interval_messages
    );
    println!(
        "Secure static key configured: {}",
        secure_static_private_key.is_some()
    );
    println!(
        "Secure expected remote static key configured: {}",
        secure_expected_remote_static_public_key.is_some()
    );
    if let Some(addr) = &args.template_provider_addr {
        println!("Template provider service: {addr}");
    }
    if let Some(addr) = &args.job_declarator_addr {
        println!("Job declarator service: {addr}");
    }
    if args.max_clients > 0 {
        println!("Max clients before exit: {}", args.max_clients);
    }

    let ctx = StratumServerContext {
        cfg,
        runtime: Arc::new(Mutex::new(runtime)),
        runtime_db_path,
        share_target,
        min_share_target,
        max_share_target,
        vardiff_target_shares_per_minute,
        vardiff_retarget_interval_shares,
        vardiff_clamp_up,
        vardiff_clamp_down,
        max_rejected_shares,
        read_timeout_sec,
        keepalive_sec,
        idle_timeout_sec,
        next_channel_id: Arc::new(AtomicU32::new(0)),
        template_provider: RuntimeTemplateProvider,
        job_declarator: Arc::new(Mutex::new(SequentialJobDeclarator::default())),
        max_jobs_per_channel,
        active_clients: Arc::new(AtomicUsize::new(0)),
        secure_transport,
        secure_transport_mode,
        secure_rekey_interval_messages,
        secure_static_private_key,
        secure_expected_remote_static_public_key,
        template_provider_addr: args.template_provider_addr.clone(),
        job_declarator_addr: args.job_declarator_addr.clone(),
    };
    let worker_threads = std::thread::available_parallelism()
        .map(|n| n.get().max(2))
        .unwrap_or(4);
    let runtime = TokioRuntimeBuilder::new_multi_thread()
        .enable_all()
        .worker_threads(worker_threads)
        .build()
        .map_err(|e| NodeError::Runtime(format!("stratum async runtime init failed: {e}")))?;

    let bind = args.bind.clone();
    let max_clients = args.max_clients;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&bind)
            .await
            .map_err(|e| NodeError::Runtime(format!("stratum bind failed on {bind}: {e}")))?;
        let permits = Arc::new(Semaphore::new(max_active_clients));
        let mut workers = JoinSet::<Result<(), NodeError>>::new();
        let mut served = 0u32;

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| NodeError::Runtime(format!("stratum accept failed: {e}")))?;

            let permit = match permits.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    let current_active = ctx.active_clients.load(Ordering::Relaxed);
                    println!(
                        "stratum dropping connection (active={} max_active={})",
                        current_active, max_active_clients
                    );
                    drop(stream);
                    continue;
                }
            };

            let client_ctx = ctx.clone();
            let active_clients = ctx.active_clients.clone();
            active_clients.fetch_add(1, Ordering::Relaxed);
            workers.spawn(async move {
                let result = run_stratum_client_async(stream, client_ctx, permit).await;
                active_clients.fetch_sub(1, Ordering::Relaxed);
                result
            });

            served = served.saturating_add(1);
            if max_requests_reached(max_clients, served) {
                break;
            }
        }

        while let Some(join_result) = workers.join_next().await {
            match join_result {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err),
                Err(err) => {
                    return Err(NodeError::Runtime(format!(
                        "stratum worker task panicked/cancelled: {err}"
                    )));
                }
            }
        }
        Ok(())
    })
}

fn try_find_share_for_job(
    job: &MiningJob,
    share_target: Target,
    start_nonce: u64,
    attempts: u64,
) -> Option<(u64, Hash256, bool, u64)> {
    if attempts == 0 {
        return None;
    }

    for step in 0..attempts {
        let nonce = start_nonce.wrapping_add(step);
        let header = scam_core::BlockHeader {
            version: job.version,
            prev_block: job.prev_hash,
            merkle_root: job.merkle_root,
            timestamp: job.ntime,
            target: job.network_target,
            nonce,
        };
        let hash = header.block_hash();
        if share_target.allows_hash(&hash) {
            return Some((
                nonce,
                hash,
                job.network_target.allows_hash(&hash),
                nonce.wrapping_add(1),
            ));
        }
    }
    None
}

fn run_stratum_mine(args: StratumMineArgs) -> Result<(), NodeError> {
    let mut stream = TcpStream::connect(&args.pool)
        .map_err(|e| NodeError::Runtime(format!("stratum connect failed to {}: {e}", args.pool)))?;
    let timeout = Duration::from_secs(args.read_timeout_sec.max(1));
    configure_stream_timeouts_with(&stream, timeout, timeout)?;
    let secure_transport_mode = args
        .secure_transport_mode
        .map(SecureTransportMode::from)
        .unwrap_or(SecureTransportMode::NoiseXx);
    let secure_static_private_key = decode_optional_hex32(
        "secure_static_secret_key_hex",
        &args.secure_static_secret_key_hex,
    )?;
    let secure_expected_remote_static_public_key = decode_optional_hex32(
        "secure_expected_remote_static_pubkey_hex",
        &args.secure_expected_remote_static_pubkey_hex,
    )?;
    if args.secure_transport
        && matches!(secure_transport_mode, SecureTransportMode::NoiseXx)
        && secure_static_private_key.is_none()
    {
        return Err(NodeError::Runtime(
            "secure transport mode noise_xx requires --secure-static-secret-key-hex \
             (use `scam-node stratum-keygen` to generate keys)"
                .to_owned(),
        ));
    }
    let mut secure_transport = if args.secure_transport {
        let transport = match secure_transport_mode {
            SecureTransportMode::Legacy => {
                let mut legacy =
                    SecureSv2Transport::handshake_client(&mut stream).map_err(|e| {
                        NodeError::Runtime(format!("stratum secure(legacy) handshake failed: {e}"))
                    })?;
                legacy
                    .set_rekey_interval_messages(args.secure_rekey_interval_messages.max(1))
                    .map_err(|e| {
                        NodeError::Runtime(format!(
                            "stratum secure(legacy) transport config failed: {e}"
                        ))
                    })?;
                StratumSecureTransport::Legacy(legacy)
            }
            SecureTransportMode::NoiseXx => {
                let mut noise = NoiseSv2Transport::handshake_client(
                    &mut stream,
                    secure_static_private_key,
                    secure_expected_remote_static_public_key,
                )
                .map_err(|e| {
                    NodeError::Runtime(format!("stratum secure(noise_xx) handshake failed: {e}"))
                })?;
                noise
                    .set_rekey_interval_messages(args.secure_rekey_interval_messages.max(1))
                    .map_err(|e| {
                        NodeError::Runtime(format!(
                            "stratum secure(noise_xx) transport config failed: {e}"
                        ))
                    })?;
                StratumSecureTransport::Noise(noise)
            }
        };
        Some(transport)
    } else {
        None
    };

    println!("Stratum miner connecting to {}", args.pool);
    println!("Secure transport: {}", args.secure_transport);
    if args.secure_transport {
        println!("Secure transport mode: {}", secure_transport_mode.as_str());
        println!(
            "Secure rekey interval (messages): {}",
            args.secure_rekey_interval_messages.max(1)
        );
        println!(
            "Secure static key configured: {}",
            secure_static_private_key.is_some()
        );
        println!(
            "Secure expected remote static key configured: {}",
            secure_expected_remote_static_public_key.is_some()
        );
    }
    if let Some(addr) = &args.translator_addr {
        println!("Translator service: {addr}");
    }
    write_sv2_message(
        &mut stream,
        secure_transport.as_mut(),
        &Sv2Message::SetupConnection {
            protocol: 2,
            min_version: SUPPORTED_SV2_VERSION,
            max_version: SUPPORTED_SV2_VERSION,
            flags: 0,
            user_agent: "scam-node/stratum-mine".to_owned(),
        },
    )?;

    let started_at = Instant::now();
    let mut last_io = Instant::now();
    let mut open_sent = false;
    let mut share_target = Target::MAX;
    let mut channel_id = None::<u32>;
    let mut active_job_id = None::<u32>;
    let mut jobs = HashMap::<u32, MiningJob>::new();
    let mut nonce_cursor = HashMap::<u32, u64>::new();
    let translator_addr = args.translator_addr.clone();
    let translator = IdentityTranslator;
    let mut submitted_shares = 0u64;
    let mut accepted_shares = 0u64;
    let mut found_blocks = 0u64;

    loop {
        if nonzero_limit_reached(args.max_runtime_sec, started_at.elapsed().as_secs()) {
            println!(
                "stratum miner stopped by max_runtime_sec={} (submitted={}, accepted={}, blocks={})",
                args.max_runtime_sec, submitted_shares, accepted_shares, found_blocks
            );
            break;
        }
        if nonzero_limit_reached(args.max_shares, accepted_shares) {
            println!(
                "stratum miner reached max_shares={} (submitted={}, blocks={})",
                args.max_shares, submitted_shares, found_blocks
            );
            break;
        }

        match read_sv2_message(&mut stream, secure_transport.as_mut())? {
            StratumReadOutcome::Closed => {
                println!("stratum pool closed connection");
                break;
            }
            StratumReadOutcome::Timeout => {
                if let Some(job_id) = active_job_id {
                    if let Some(job) = jobs.get(&job_id) {
                        let cursor = *nonce_cursor.get(&job_id).unwrap_or(&0);
                        if let Some((nonce, hash, is_block, next_cursor)) = try_find_share_for_job(
                            job,
                            share_target,
                            cursor,
                            args.max_nonce_per_cycle,
                        ) {
                            nonce_cursor.insert(job_id, next_cursor);
                            write_sv2_message(
                                &mut stream,
                                secure_transport.as_mut(),
                                &Sv2Message::SubmitSharesStandard {
                                    channel_id: job.channel_id,
                                    job_id,
                                    nonce,
                                    ntime: job.ntime,
                                },
                            )?;
                            submitted_shares = submitted_shares.saturating_add(1);
                            println!(
                                "submitted share: channel={} job={} nonce={} hash={} is_block={}",
                                job.channel_id, job_id, nonce, hash, is_block
                            );
                            last_io = Instant::now();
                        } else {
                            nonce_cursor.insert(
                                job_id,
                                cursor.wrapping_add(args.max_nonce_per_cycle.saturating_add(1)),
                            );
                        }
                    }
                } else if last_io.elapsed().as_secs() >= 10 {
                    write_sv2_message(
                        &mut stream,
                        secure_transport.as_mut(),
                        &Sv2Message::KeepAlive,
                    )?;
                    last_io = Instant::now();
                }
            }
            StratumReadOutcome::Message(message) => match message {
                Sv2Message::SetupConnectionSuccess { .. } => {
                    if !open_sent {
                        write_sv2_message(
                            &mut stream,
                            secure_transport.as_mut(),
                            &Sv2Message::OpenStandardMiningChannel {
                                request_id: 1,
                                user: args.user.clone(),
                            },
                        )?;
                        open_sent = true;
                        last_io = Instant::now();
                    }
                }
                Sv2Message::SetupConnectionError { code, reason } => {
                    return Err(NodeError::Runtime(format!(
                        "stratum setup rejected: code={code} reason={reason}"
                    )));
                }
                Sv2Message::OpenStandardMiningChannelSuccess {
                    channel_id: opened_channel,
                    target_hex,
                    ..
                } => {
                    channel_id = Some(opened_channel);
                    share_target = Target::from_hex(&target_hex).map_err(|e| {
                        NodeError::Runtime(format!("invalid share target from pool: {e}"))
                    })?;
                    println!(
                        "channel opened: id={} initial_share_target={}",
                        opened_channel, share_target
                    );
                }
                Sv2Message::OpenStandardMiningChannelError { code, reason, .. } => {
                    return Err(NodeError::Runtime(format!(
                        "stratum open channel rejected: code={code} reason={reason}"
                    )));
                }
                Sv2Message::SetTarget {
                    channel_id: msg_channel,
                    maximum_target_hex,
                } => {
                    if channel_id == Some(msg_channel) {
                        share_target = Target::from_hex(&maximum_target_hex).map_err(|e| {
                            NodeError::Runtime(format!("invalid set_target from pool: {e}"))
                        })?;
                        println!(
                            "share target updated: channel={} target={}",
                            msg_channel, share_target
                        );
                    }
                }
                Sv2Message::SetNewPrevHash {
                    channel_id: msg_channel,
                    job_id,
                    prev_hash_hex,
                    ntime,
                    network_target_hex,
                } => {
                    if channel_id == Some(msg_channel)
                        && let Some(job) = jobs.get_mut(&job_id)
                    {
                        job.prev_hash = Hash256::from_hex(&prev_hash_hex).map_err(|e| {
                            NodeError::Runtime(format!(
                                "invalid prev_hash in set_new_prev_hash: {e}"
                            ))
                        })?;
                        job.ntime = ntime;
                        job.network_target =
                            Target::from_hex(&network_target_hex).map_err(|e| {
                                NodeError::Runtime(format!(
                                    "invalid network_target in set_new_prev_hash: {e}"
                                ))
                            })?;
                        active_job_id = Some(job_id);
                    }
                }
                Sv2Message::SubmitSharesSuccess {
                    accepted, is_block, ..
                } => {
                    accepted_shares = accepted_shares.saturating_add(accepted as u64);
                    if is_block {
                        found_blocks = found_blocks.saturating_add(1);
                    }
                    println!(
                        "share accepted: accepted={} total_accepted={} blocks={}",
                        accepted, accepted_shares, found_blocks
                    );
                }
                Sv2Message::SubmitSharesError { code, reason, .. } => {
                    println!("share rejected: code={} reason={}", code, reason);
                }
                Sv2Message::KeepAlive => {
                    write_sv2_message(
                        &mut stream,
                        secure_transport.as_mut(),
                        &Sv2Message::KeepAlive,
                    )?;
                    last_io = Instant::now();
                }
                other => {
                    let translated = if let Some(addr) = translator_addr.as_deref() {
                        translate_remote_job_with_service(addr, other)?
                    } else {
                        translator.parse_remote_job_message(other).map_err(|e| {
                            NodeError::Runtime(format!("stratum translate failed: {e}"))
                        })?
                    };
                    if let Some(job) = translated {
                        active_job_id = Some(job.job_id);
                        nonce_cursor.insert(job.job_id, 0);
                        println!(
                            "new mining job: channel={} job={} ntime={} target={}",
                            job.channel_id, job.job_id, job.ntime, job.network_target
                        );
                        jobs.insert(job.job_id, job);
                    }
                }
            },
        }
    }

    println!(
        "stratum miner summary: submitted={} accepted={} blocks={} runtime_sec={}",
        submitted_shares,
        accepted_shares,
        found_blocks,
        started_at.elapsed().as_secs()
    );
    Ok(())
}

fn run_stratum_keygen(args: StratumKeygenArgs) -> Result<(), NodeError> {
    if !args.force {
        if args.secret_out.exists() {
            return Err(NodeError::Runtime(format!(
                "secret_out already exists (use --force to overwrite): {}",
                args.secret_out.display()
            )));
        }
        if args.public_out.exists() {
            return Err(NodeError::Runtime(format!(
                "public_out already exists (use --force to overwrite): {}",
                args.public_out.display()
            )));
        }
    }

    if let Some(parent) = args.secret_out.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            NodeError::Runtime(format!(
                "cannot create secret key directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    if let Some(parent) = args.public_out.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            NodeError::Runtime(format!(
                "cannot create public key directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    let keypair = generate_noise_static_keypair()
        .map_err(|e| NodeError::Runtime(format!("stratum noise keygen failed: {e}")))?;
    let secret_hex = hex::encode(keypair.private);
    let public_hex = hex::encode(keypair.public);

    fs::write(&args.secret_out, format!("{secret_hex}\n")).map_err(|e| {
        NodeError::Runtime(format!(
            "cannot write secret key {}: {e}",
            args.secret_out.display()
        ))
    })?;
    fs::write(&args.public_out, format!("{public_hex}\n")).map_err(|e| {
        NodeError::Runtime(format!(
            "cannot write public key {}: {e}",
            args.public_out.display()
        ))
    })?;

    println!("Generated Stratum Noise XX static keypair");
    println!("Secret key: {}", args.secret_out.display());
    println!("Public key: {}", args.public_out.display());
    println!("Public key hex: {public_hex}");
    Ok(())
}

fn run_stratum_key_rotate(args: StratumKeyRotateArgs) -> Result<(), NodeError> {
    if !args.secret_path.exists() {
        return Err(NodeError::Runtime(format!(
            "secret key file does not exist: {}",
            args.secret_path.display()
        )));
    }
    if !args.public_path.exists() {
        return Err(NodeError::Runtime(format!(
            "public key file does not exist: {}",
            args.public_path.display()
        )));
    }
    fs::create_dir_all(&args.archive_dir).map_err(|e| {
        NodeError::Runtime(format!(
            "cannot create archive directory {}: {e}",
            args.archive_dir.display()
        ))
    })?;

    let timestamp = current_unix_sec()?;
    let archived_secret = args
        .archive_dir
        .join(format!("server.secret.{timestamp}.hex"));
    let archived_public = args
        .archive_dir
        .join(format!("server.public.{timestamp}.hex"));
    fs::rename(&args.secret_path, &archived_secret).map_err(|e| {
        NodeError::Runtime(format!(
            "cannot archive secret key {} -> {}: {e}",
            args.secret_path.display(),
            archived_secret.display()
        ))
    })?;
    fs::rename(&args.public_path, &archived_public).map_err(|e| {
        NodeError::Runtime(format!(
            "cannot archive public key {} -> {}: {e}",
            args.public_path.display(),
            archived_public.display()
        ))
    })?;

    run_stratum_keygen(StratumKeygenArgs {
        secret_out: args.secret_path.clone(),
        public_out: args.public_path.clone(),
        force: false,
    })?;

    println!("Archived old secret key: {}", archived_secret.display());
    println!("Archived old public key: {}", archived_public.display());
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct Sv2ConformanceStep {
    sent: String,
    received: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Sv2ConformanceReport {
    timestamp_unix_sec: u64,
    stack_name: String,
    endpoint: String,
    secure_transport: bool,
    secure_transport_mode: String,
    corpus_source: String,
    setup_success: bool,
    channel_opened: bool,
    job_messages_seen: u32,
    set_target_seen: bool,
    pass: bool,
    observed_messages: Vec<String>,
    errors: Vec<String>,
    steps: Vec<Sv2ConformanceStep>,
}

fn sv2_message_kind(message: &Sv2Message) -> &'static str {
    match message {
        Sv2Message::SetupConnection { .. } => "SetupConnection",
        Sv2Message::SetupConnectionSuccess { .. } => "SetupConnectionSuccess",
        Sv2Message::SetupConnectionError { .. } => "SetupConnectionError",
        Sv2Message::OpenStandardMiningChannel { .. } => "OpenStandardMiningChannel",
        Sv2Message::OpenStandardMiningChannelSuccess { .. } => "OpenStandardMiningChannelSuccess",
        Sv2Message::OpenStandardMiningChannelError { .. } => "OpenStandardMiningChannelError",
        Sv2Message::NewMiningJob { .. } => "NewMiningJob",
        Sv2Message::SetNewPrevHash { .. } => "SetNewPrevHash",
        Sv2Message::SetTarget { .. } => "SetTarget",
        Sv2Message::SubmitSharesStandard { .. } => "SubmitSharesStandard",
        Sv2Message::SubmitSharesSuccess { .. } => "SubmitSharesSuccess",
        Sv2Message::SubmitSharesError { .. } => "SubmitSharesError",
        Sv2Message::KeepAlive => "KeepAlive",
    }
}

fn default_sv2_conformance_corpus(user: &str) -> Vec<Sv2Message> {
    vec![
        Sv2Message::SetupConnection {
            protocol: 2,
            min_version: SUPPORTED_SV2_VERSION,
            max_version: SUPPORTED_SV2_VERSION,
            flags: 0,
            user_agent: "scam-node/sv2-conformance".to_owned(),
        },
        Sv2Message::OpenStandardMiningChannel {
            request_id: 1,
            user: user.to_owned(),
        },
        Sv2Message::KeepAlive,
    ]
}

fn load_sv2_corpus(path: &Path, user: &str) -> Result<Vec<Sv2Message>, NodeError> {
    #[derive(Deserialize)]
    struct Envelope {
        messages: Vec<Sv2Message>,
    }

    let raw = fs::read_to_string(path).map_err(|e| {
        NodeError::Runtime(format!("cannot read sv2 corpus {}: {e}", path.display()))
    })?;
    if let Ok(messages) = serde_json::from_str::<Vec<Sv2Message>>(&raw) {
        if messages.is_empty() {
            return Err(NodeError::Runtime("sv2 corpus is empty".to_owned()));
        }
        return Ok(messages);
    }
    if let Ok(envelope) = serde_json::from_str::<Envelope>(&raw) {
        if envelope.messages.is_empty() {
            return Err(NodeError::Runtime("sv2 corpus is empty".to_owned()));
        }
        return Ok(envelope.messages);
    }

    // Backward-compatible fallback: treat corpus as "default" keyword.
    if raw.trim() == "default" {
        return Ok(default_sv2_conformance_corpus(user));
    }
    Err(NodeError::Runtime(format!(
        "cannot decode sv2 corpus {} (expected JSON array or {{\"messages\": [...]}})",
        path.display()
    )))
}

fn read_next_sv2_message(
    stream: &mut TcpStream,
    secure_transport: &mut Option<StratumSecureTransport>,
    attempts: usize,
) -> Result<Option<Sv2Message>, NodeError> {
    for _ in 0..attempts.max(1) {
        match read_sv2_message(stream, secure_transport.as_mut())? {
            StratumReadOutcome::Message(msg) => return Ok(Some(msg)),
            StratumReadOutcome::Timeout => continue,
            StratumReadOutcome::Closed => return Ok(None),
        }
    }
    Ok(None)
}

fn run_sv2_conformance(args: Sv2ConformanceArgs) -> Result<(), NodeError> {
    let mut stream = TcpStream::connect(&args.pool)
        .map_err(|e| NodeError::Runtime(format!("sv2 conformance connect failed: {e}")))?;
    let timeout = Duration::from_secs(args.read_timeout_sec.max(1));
    configure_stream_timeouts_with(&stream, timeout, timeout)?;

    let secure_transport_mode = args
        .secure_transport_mode
        .map(SecureTransportMode::from)
        .unwrap_or(SecureTransportMode::NoiseXx);
    let secure_static_private_key = decode_optional_hex32(
        "secure_static_secret_key_hex",
        &args.secure_static_secret_key_hex,
    )?;
    let secure_expected_remote_static_public_key = decode_optional_hex32(
        "secure_expected_remote_static_pubkey_hex",
        &args.secure_expected_remote_static_pubkey_hex,
    )?;
    if args.secure_transport
        && matches!(secure_transport_mode, SecureTransportMode::NoiseXx)
        && secure_static_private_key.is_none()
    {
        return Err(NodeError::Runtime(
            "secure transport mode noise_xx requires --secure-static-secret-key-hex \
             (use `scam-node stratum-keygen` to generate keys)"
                .to_owned(),
        ));
    }

    let mut secure_transport = if args.secure_transport {
        let transport = match secure_transport_mode {
            SecureTransportMode::Legacy => {
                let mut legacy =
                    SecureSv2Transport::handshake_client(&mut stream).map_err(|e| {
                        NodeError::Runtime(format!("sv2 conformance legacy handshake failed: {e}"))
                    })?;
                legacy
                    .set_rekey_interval_messages(args.secure_rekey_interval_messages.max(1))
                    .map_err(|e| {
                        NodeError::Runtime(format!(
                            "sv2 conformance legacy transport config failed: {e}"
                        ))
                    })?;
                StratumSecureTransport::Legacy(legacy)
            }
            SecureTransportMode::NoiseXx => {
                let mut noise = NoiseSv2Transport::handshake_client(
                    &mut stream,
                    secure_static_private_key,
                    secure_expected_remote_static_public_key,
                )
                .map_err(|e| {
                    NodeError::Runtime(format!("sv2 conformance noise_xx handshake failed: {e}"))
                })?;
                noise
                    .set_rekey_interval_messages(args.secure_rekey_interval_messages.max(1))
                    .map_err(|e| {
                        NodeError::Runtime(format!(
                            "sv2 conformance noise_xx transport config failed: {e}"
                        ))
                    })?;
                StratumSecureTransport::Noise(noise)
            }
        };
        Some(transport)
    } else {
        None
    };

    let (corpus, corpus_source) = if let Some(path) = args.corpus.as_ref() {
        (
            load_sv2_corpus(path, &args.user)?,
            path.display().to_string(),
        )
    } else {
        (
            default_sv2_conformance_corpus(&args.user),
            "builtin/default".to_owned(),
        )
    };

    let mut setup_success = false;
    let mut channel_opened = false;
    let mut job_messages_seen = 0u32;
    let mut set_target_seen = false;
    let mut observed_messages = Vec::<String>::new();
    let mut errors = Vec::<String>::new();
    let mut steps = Vec::<Sv2ConformanceStep>::new();

    for message in corpus {
        let sent = sv2_message_kind(&message).to_owned();
        write_sv2_message(&mut stream, secure_transport.as_mut(), &message)?;
        let received = match read_next_sv2_message(&mut stream, &mut secure_transport, 3)? {
            Some(response) => {
                let kind = sv2_message_kind(&response).to_owned();
                observed_messages.push(kind.clone());
                match response {
                    Sv2Message::SetupConnectionSuccess { .. } => setup_success = true,
                    Sv2Message::SetupConnectionError { code, reason } => {
                        errors.push(format!("setup error: code={code} reason={reason}"));
                    }
                    Sv2Message::OpenStandardMiningChannelSuccess { .. } => channel_opened = true,
                    Sv2Message::OpenStandardMiningChannelError { code, reason, .. } => {
                        errors.push(format!("open channel error: code={code} reason={reason}"));
                    }
                    Sv2Message::NewMiningJob { .. } | Sv2Message::SetNewPrevHash { .. } => {
                        job_messages_seen = job_messages_seen.saturating_add(1);
                    }
                    Sv2Message::SetTarget { .. } => {
                        set_target_seen = true;
                    }
                    _ => {}
                }
                Some(kind)
            }
            None => None,
        };
        steps.push(Sv2ConformanceStep { sent, received });
    }

    for _ in 0..8 {
        let Some(msg) = read_next_sv2_message(&mut stream, &mut secure_transport, 1)? else {
            break;
        };
        let kind = sv2_message_kind(&msg).to_owned();
        observed_messages.push(kind.clone());
        match msg {
            Sv2Message::NewMiningJob { .. } | Sv2Message::SetNewPrevHash { .. } => {
                job_messages_seen = job_messages_seen.saturating_add(1);
            }
            Sv2Message::SetTarget { .. } => set_target_seen = true,
            Sv2Message::SetupConnectionSuccess { .. } => setup_success = true,
            Sv2Message::OpenStandardMiningChannelSuccess { .. } => channel_opened = true,
            Sv2Message::SetupConnectionError { code, reason } => {
                errors.push(format!("setup error: code={code} reason={reason}"));
            }
            Sv2Message::OpenStandardMiningChannelError { code, reason, .. } => {
                errors.push(format!("open channel error: code={code} reason={reason}"));
            }
            _ => {}
        }
    }

    let pass = setup_success && channel_opened && errors.is_empty();
    let report = Sv2ConformanceReport {
        timestamp_unix_sec: current_unix_sec()?,
        stack_name: args
            .stack_name
            .clone()
            .unwrap_or_else(|| "unknown".to_owned()),
        endpoint: args.pool.clone(),
        secure_transport: args.secure_transport,
        secure_transport_mode: secure_transport_mode.as_str().to_owned(),
        corpus_source,
        setup_success,
        channel_opened,
        job_messages_seen,
        set_target_seen,
        pass,
        observed_messages,
        errors,
        steps,
    };

    let rendered = serde_json::to_string_pretty(&report)
        .map_err(|e| NodeError::Runtime(format!("cannot encode conformance report json: {e}")))?;
    if let Some(path) = args.out.as_ref() {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| {
                NodeError::Runtime(format!(
                    "cannot create conformance report directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        fs::write(path, format!("{rendered}\n")).map_err(|e| {
            NodeError::Runtime(format!(
                "cannot write conformance report {}: {e}",
                path.display()
            ))
        })?;
        println!("SV2 conformance report saved: {}", path.display());
    }
    println!("{rendered}");
    if !report.pass {
        return Err(NodeError::Runtime(
            "sv2 conformance check failed (see report)".to_owned(),
        ));
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

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct WalletNewRpcRequest {
    words: usize,
    passphrase: String,
    account: u32,
    index: u32,
    hrp: Option<String>,
}

impl Default for WalletNewRpcRequest {
    fn default() -> Self {
        Self {
            words: 12,
            passphrase: String::new(),
            account: 0,
            index: 0,
            hrp: None,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct WalletAddressRpcRequest {
    mnemonic: String,
    passphrase: String,
    account: u32,
    index: u32,
    hrp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WalletDecodeRpcRequest {
    address: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct WalletBalanceRpcRequest {
    mnemonic: String,
    passphrase: String,
    account: u32,
    index: u32,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct WalletSendPreviewRpcRequest {
    mnemonic: String,
    passphrase: String,
    account: u32,
    index: u32,
    to: String,
    amount: u64,
    fee: u64,
}

impl Default for WalletSendPreviewRpcRequest {
    fn default() -> Self {
        Self {
            mnemonic: String::new(),
            passphrase: String::new(),
            account: 0,
            index: 0,
            to: String::new(),
            amount: 0,
            fee: 1,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct WalletQrRpcRequest {
    address: String,
    amount: Option<u64>,
    label: Option<String>,
}

#[derive(Debug, Serialize)]
struct WalletAddressRpcResponse {
    network_id: String,
    hrp: String,
    account: u32,
    index: u32,
    address: String,
    pubkey_compressed_hex: String,
    key_hash20_hex: String,
}

#[derive(Debug, Serialize)]
struct WalletBalanceRpcResponse {
    network_id: String,
    account: u32,
    index: u32,
    address: String,
    key_hash20_hex: String,
    tip_height: u64,
    utxo_count: usize,
    spendable_utxo_count: usize,
    immature_utxo_count: usize,
    total: u128,
    spendable: u128,
    immature: u128,
}

#[derive(Debug, Serialize)]
struct WalletSendPreviewInput {
    txid: String,
    vout: u32,
    value: u64,
}

#[derive(Debug, Serialize)]
struct WalletSendPreviewRpcResponse {
    network_id: String,
    txid: String,
    raw_tx_hex: String,
    amount: u64,
    fee: u64,
    input_total: u64,
    change: u64,
    is_self_transfer: bool,
    selected_inputs: Vec<WalletSendPreviewInput>,
}

#[derive(Debug, Serialize)]
struct WalletDecodeRpcResponse {
    hrp: String,
    key_hash20_hex: String,
}

#[derive(Debug, Serialize)]
struct WalletQrRpcResponse {
    ascii: String,
}

#[derive(Debug, Serialize)]
struct MempoolSummaryRpcResponse {
    available: bool,
    source: String,
    snapshot: Option<RelayServerTelemetrySnapshot>,
}

fn wallet_address_response(
    cfg: &ChainConfig,
    account: u32,
    index: u32,
    hrp: &str,
    key: &WalletKey,
) -> Result<WalletAddressRpcResponse, NodeError> {
    let pubkey = key.pubkey_compressed();
    let address = to_address(hrp, pubkey)?;
    let key_hash20 = scam_core::hash160_blake3(&pubkey);
    Ok(WalletAddressRpcResponse {
        network_id: cfg.network_id.clone(),
        hrp: hrp.to_owned(),
        account,
        index,
        address,
        pubkey_compressed_hex: hex::encode(pubkey),
        key_hash20_hex: hex::encode(key_hash20),
    })
}

fn wallet_balance_response(
    runtime: &ChainRuntime,
    cfg: &ChainConfig,
    account: u32,
    index: u32,
    address: String,
    key_hash20: [u8; 20],
) -> WalletBalanceRpcResponse {
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
        let is_immature_coinbase =
            utxo.is_coinbase && tip_height < utxo.created_height.saturating_add(coinbase_maturity);
        if is_immature_coinbase {
            immature_count += 1;
            immature = immature.saturating_add(utxo.value as u128);
        } else {
            spendable_count += 1;
            spendable = spendable.saturating_add(utxo.value as u128);
        }
    }

    WalletBalanceRpcResponse {
        network_id: cfg.network_id.clone(),
        account,
        index,
        address,
        key_hash20_hex: hex::encode(key_hash20),
        tip_height,
        utxo_count,
        spendable_utxo_count: spendable_count,
        immature_utxo_count: immature_count,
        total,
        spendable,
        immature,
    }
}

fn write_http_response(
    stream: &mut TcpStream,
    status_line: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), NodeError> {
    let headers = format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .map_err(|e| NodeError::Runtime(format!("http write failed: {e}")))?;
    stream
        .write_all(body)
        .map_err(|e| NodeError::Runtime(format!("http write failed: {e}")))?;
    stream
        .flush()
        .map_err(|e| NodeError::Runtime(format!("http flush failed: {e}")))?;
    Ok(())
}

fn write_http_json_response(
    stream: &mut TcpStream,
    status_line: &str,
    body: &str,
) -> Result<(), NodeError> {
    write_http_response(
        stream,
        status_line,
        "application/json; charset=utf-8",
        body.as_bytes(),
    )
}

fn find_http_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> Result<usize, NodeError> {
    for line in headers.lines().skip(1) {
        let mut parts = line.splitn(2, ':');
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next() else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value.trim().parse::<usize>().map_err(|e| {
                NodeError::Runtime(format!(
                    "invalid Content-Length header '{}': {e}",
                    value.trim()
                ))
            });
        }
    }
    Ok(0)
}

fn read_http_request(stream: &mut TcpStream) -> Result<Option<HttpRequest>, NodeError> {
    let mut buffer = Vec::<u8>::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut header_end = None::<usize>;
    let mut content_length = 0usize;

    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|e| NodeError::Runtime(format!("http read failed: {e}")))?;
        if read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);

        if buffer.len() > 2 * 1024 * 1024 {
            return Err(NodeError::Runtime(
                "http request too large (max 2 MiB)".to_owned(),
            ));
        }

        if header_end.is_none()
            && let Some(pos) = find_http_header_terminator(&buffer)
        {
            let end = pos + 4;
            let headers = std::str::from_utf8(&buffer[..end])
                .map_err(|e| NodeError::Runtime(format!("invalid utf8 in request headers: {e}")))?;
            content_length = parse_content_length(headers)?;
            header_end = Some(end);
        }

        if let Some(end) = header_end
            && buffer.len() >= end.saturating_add(content_length)
        {
            break;
        }
    }

    let Some(end) = header_end else {
        return Err(NodeError::Runtime(
            "malformed http request: missing header terminator".to_owned(),
        ));
    };

    let headers = std::str::from_utf8(&buffer[..end])
        .map_err(|e| NodeError::Runtime(format!("invalid utf8 in request: {e}")))?;
    let Some(line) = headers.lines().next() else {
        return Ok(None);
    };
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let raw_target = parts.next().unwrap_or("/");
    let path = raw_target.split('?').next().unwrap_or("/");

    let available_body = buffer.len().saturating_sub(end);
    if available_body < content_length {
        return Err(NodeError::Runtime(format!(
            "malformed http request: expected body length {}, got {}",
            content_length, available_body
        )));
    }
    let body = if content_length == 0 {
        Vec::new()
    } else {
        buffer[end..end + content_length].to_vec()
    };

    Ok(Some(HttpRequest {
        method,
        path: path.to_owned(),
        body,
    }))
}

fn parse_json_body<T: DeserializeOwned>(request: &HttpRequest) -> Result<T, NodeError> {
    if request.body.is_empty() {
        return serde_json::from_str("{}")
            .map_err(|e| NodeError::Runtime(format!("invalid json body: {e}")));
    }
    serde_json::from_slice::<T>(&request.body)
        .map_err(|e| NodeError::Runtime(format!("invalid json body: {e}")))
}

fn load_latest_jsonl_record<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, NodeError> {
    if !path.exists() {
        return Ok(None);
    }
    let file = fs::File::open(path).map_err(|e| {
        NodeError::Runtime(format!("cannot open telemetry {}: {e}", path.display()))
    })?;
    let reader = BufReader::new(file);
    let mut last = None::<String>;
    for line in reader.lines() {
        let line =
            line.map_err(|e| NodeError::Runtime(format!("cannot read telemetry line: {e}")))?;
        if line.trim().is_empty() {
            continue;
        }
        last = Some(line);
    }
    let Some(line) = last else {
        return Ok(None);
    };
    let parsed = serde_json::from_str::<T>(line.trim_end())
        .map_err(|e| NodeError::Runtime(format!("invalid telemetry json record: {e}")))?;
    Ok(Some(parsed))
}

fn sanitize_ui_path(path: &str) -> Option<PathBuf> {
    let normalized = path.trim_start_matches('/');
    if normalized.is_empty() {
        return Some(PathBuf::from("index.html"));
    }
    let candidate = PathBuf::from(normalized);
    if candidate
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return None;
    }
    Some(candidate)
}

fn guess_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}

fn try_serve_ui_asset(
    stream: &mut TcpStream,
    ui_dir: &Path,
    request_path: &str,
) -> Result<bool, NodeError> {
    if !ui_dir.exists() || !ui_dir.is_dir() {
        return Ok(false);
    }
    let Some(relative) = sanitize_ui_path(request_path) else {
        write_http_json_response(
            stream,
            "400 Bad Request",
            &json_error_body("invalid asset path"),
        )?;
        return Ok(true);
    };
    let candidate = ui_dir.join(relative);
    let asset_path = if candidate.exists() && candidate.is_file() {
        candidate
    } else {
        let index = ui_dir.join("index.html");
        if index.exists() && index.is_file() {
            index
        } else {
            return Ok(false);
        }
    };
    let body = fs::read(&asset_path).map_err(|e| {
        NodeError::Runtime(format!(
            "cannot read ui asset {}: {e}",
            asset_path.display()
        ))
    })?;
    write_http_response(stream, "200 OK", guess_content_type(&asset_path), &body)?;
    Ok(true)
}

fn run_rpc_serve(args: RpcServeArgs) -> Result<(), NodeError> {
    let RpcServeArgs {
        network,
        config,
        runtime_db,
        bind,
        ui_dir,
        relay_telemetry,
        mine_blocks,
        interval_sec,
        max_nonce,
        max_requests,
    } = args;
    let (cfg, runtime) = build_runtime_for_query(
        network,
        config,
        runtime_db,
        mine_blocks,
        interval_sec,
        max_nonce,
        "rpc-serve",
    )?;

    let listener = TcpListener::bind(&bind)
        .map_err(|e| NodeError::Runtime(format!("rpc bind failed on {}: {e}", bind)))?;
    println!(
        "RPC listening on {} (network={} tip_h={} tip_hash={})",
        bind,
        cfg.network_id,
        runtime.tip_height(),
        runtime.tip_hash()
    );
    println!(
        "Endpoints: GET /health, /status, /block/<height>, /tx/<height>/<index>, /mempool; POST /wallet/new, /wallet/address, /wallet/decode, /wallet/balance, /wallet/send-preview, /wallet/qr"
    );
    println!("UI assets directory: {}", ui_dir.display());
    if let Some(path) = relay_telemetry.as_ref() {
        println!("Relay telemetry source: {}", path.display());
    }
    if max_requests_reached(max_requests, max_requests) {
        println!("Max requests before exit: {}", max_requests);
    }

    let mut served = 0u32;
    for incoming in listener.incoming() {
        let mut stream =
            incoming.map_err(|e| NodeError::Runtime(format!("rpc accept failed: {e}")))?;
        configure_stream_timeouts(&stream)?;

        let request = match read_http_request(&mut stream) {
            Ok(Some(request)) => request,
            Ok(None) => continue,
            Err(err) => {
                let body = json_error_body(&err.to_string());
                write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                continue;
            }
        };

        let method = request.method.as_str();
        let path = request.path.as_str();
        let (status, body) = if method == "GET" && path == "/health" {
            ("200 OK", "{\"ok\":true}".to_owned())
        } else if method == "GET" && path == "/status" {
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
        } else if method == "GET" && path == "/mempool" {
            let summary = if let Some(telemetry_path) = relay_telemetry.as_ref() {
                match load_latest_jsonl_record::<RelayServerTelemetrySnapshot>(telemetry_path) {
                    Ok(Some(snapshot)) => MempoolSummaryRpcResponse {
                        available: true,
                        source: telemetry_path.display().to_string(),
                        snapshot: Some(snapshot),
                    },
                    Ok(None) => MempoolSummaryRpcResponse {
                        available: false,
                        source: telemetry_path.display().to_string(),
                        snapshot: None,
                    },
                    Err(err) => {
                        let body = json_error_body(&err.to_string());
                        write_http_json_response(&mut stream, "500 Internal Server Error", &body)?;
                        continue;
                    }
                }
            } else {
                MempoolSummaryRpcResponse {
                    available: false,
                    source: "relay telemetry not configured".to_owned(),
                    snapshot: None,
                }
            };
            match to_pretty_json(&summary) {
                Ok(body) => ("200 OK", body),
                Err(e) => (
                    "500 Internal Server Error",
                    json_error_body(&format!("mempool summary serialization failed: {e}")),
                ),
            }
        } else if method == "GET"
            && let Some(height_raw) = path.strip_prefix("/block/")
        {
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
        } else if method == "GET"
            && let Some(rest) = path.strip_prefix("/tx/")
        {
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
        } else if method == "POST" && path == "/wallet/new" {
            let req = match parse_json_body::<WalletNewRpcRequest>(&request) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let mnemonic = match new_mnemonic(req.words) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let seed = mnemonic.to_seed(&req.passphrase);
            let key = match derive_wallet_key(&seed, req.account, req.index) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let hrp = req.hrp.unwrap_or_else(|| cfg.hrp.clone());
            let payload = match wallet_address_response(&cfg, req.account, req.index, &hrp, &key) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let body = serde_json::json!({
                "mnemonic": mnemonic.phrase(),
                "network_id": payload.network_id,
                "hrp": payload.hrp,
                "account": payload.account,
                "index": payload.index,
                "address": payload.address,
                "pubkey_compressed_hex": payload.pubkey_compressed_hex,
                "key_hash20_hex": payload.key_hash20_hex
            });
            match serde_json::to_string_pretty(&body) {
                Ok(rendered) => ("200 OK", rendered),
                Err(e) => (
                    "500 Internal Server Error",
                    json_error_body(&format!("wallet new serialization failed: {e}")),
                ),
            }
        } else if method == "POST" && path == "/wallet/address" {
            let req = match parse_json_body::<WalletAddressRpcRequest>(&request) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let mnemonic = match WalletMnemonic::parse(&req.mnemonic) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let seed = mnemonic.to_seed(&req.passphrase);
            let key = match derive_wallet_key(&seed, req.account, req.index) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let hrp = req.hrp.unwrap_or_else(|| cfg.hrp.clone());
            let payload = match wallet_address_response(&cfg, req.account, req.index, &hrp, &key) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            match to_pretty_json(&payload) {
                Ok(body) => ("200 OK", body),
                Err(e) => (
                    "500 Internal Server Error",
                    json_error_body(&format!("wallet address serialization failed: {e}")),
                ),
            }
        } else if method == "POST" && path == "/wallet/decode" {
            let req = match parse_json_body::<WalletDecodeRpcRequest>(&request) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let decoded = match parse_address(&req.address) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let payload = WalletDecodeRpcResponse {
                hrp: decoded.hrp,
                key_hash20_hex: hex::encode(decoded.key_hash20),
            };
            match to_pretty_json(&payload) {
                Ok(body) => ("200 OK", body),
                Err(e) => (
                    "500 Internal Server Error",
                    json_error_body(&format!("wallet decode serialization failed: {e}")),
                ),
            }
        } else if method == "POST" && path == "/wallet/balance" {
            let req = match parse_json_body::<WalletBalanceRpcRequest>(&request) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let mnemonic = match WalletMnemonic::parse(&req.mnemonic) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let seed = mnemonic.to_seed(&req.passphrase);
            let key = match derive_wallet_key(&seed, req.account, req.index) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let address_payload =
                match wallet_address_response(&cfg, req.account, req.index, &cfg.hrp, &key) {
                    Ok(value) => value,
                    Err(err) => {
                        let body = json_error_body(&err.to_string());
                        write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                        continue;
                    }
                };
            let key_hash20 = scam_core::hash160_blake3(&key.pubkey_compressed());
            let payload = wallet_balance_response(
                &runtime,
                &cfg,
                req.account,
                req.index,
                address_payload.address,
                key_hash20,
            );
            match to_pretty_json(&payload) {
                Ok(body) => ("200 OK", body),
                Err(e) => (
                    "500 Internal Server Error",
                    json_error_body(&format!("wallet balance serialization failed: {e}")),
                ),
            }
        } else if method == "POST" && path == "/wallet/send-preview" {
            let req = match parse_json_body::<WalletSendPreviewRpcRequest>(&request) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            if req.amount == 0 {
                let body = json_error_body("amount must be > 0");
                write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                continue;
            }
            let recipient = match parse_address(&req.to) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let accepted_hrps = accepted_hrps_for_network(network, &cfg.hrp);
            if !accepted_hrps.iter().any(|hrp| hrp == &recipient.hrp) {
                let body = json_error_body(&format!(
                    "address hrp '{}' is not valid for network '{}' (accepted: {})",
                    recipient.hrp,
                    cfg.network_id,
                    accepted_hrps.join(", ")
                ));
                write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                continue;
            }
            let mnemonic = match WalletMnemonic::parse(&req.mnemonic) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let seed = mnemonic.to_seed(&req.passphrase);
            let key = match derive_wallet_key(&seed, req.account, req.index) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let signed = match build_signed_transfer_tx(
                &runtime,
                &cfg.network_id,
                &key,
                recipient.key_hash20,
                req.amount,
                req.fee,
            ) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let payload = WalletSendPreviewRpcResponse {
                network_id: cfg.network_id.clone(),
                txid: signed.tx.txid().to_hex(),
                raw_tx_hex: hex::encode(signed.tx.encode_for_hash()),
                amount: req.amount,
                fee: req.fee,
                input_total: signed.input_total,
                change: signed.change_value,
                is_self_transfer: signed.is_self_transfer,
                selected_inputs: signed
                    .selected_inputs
                    .into_iter()
                    .map(|item| WalletSendPreviewInput {
                        txid: item.outpoint.txid.to_hex(),
                        vout: item.outpoint.vout,
                        value: item.value,
                    })
                    .collect(),
            };
            match to_pretty_json(&payload) {
                Ok(body) => ("200 OK", body),
                Err(e) => (
                    "500 Internal Server Error",
                    json_error_body(&format!("wallet send serialization failed: {e}")),
                ),
            }
        } else if method == "POST" && path == "/wallet/qr" {
            let req = match parse_json_body::<WalletQrRpcRequest>(&request) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            if req.address.trim().is_empty() {
                let body = json_error_body("address must not be empty");
                write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                continue;
            }
            let ascii = match qr_for_payment_uri(&req.address, req.amount, req.label.as_deref()) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let payload = WalletQrRpcResponse { ascii };
            match to_pretty_json(&payload) {
                Ok(body) => ("200 OK", body),
                Err(e) => (
                    "500 Internal Server Error",
                    json_error_body(&format!("wallet qr serialization failed: {e}")),
                ),
            }
        } else {
            if method == "GET" && try_serve_ui_asset(&mut stream, &ui_dir, path)? {
                served = served.saturating_add(1);
                if max_requests_reached(max_requests, served) {
                    break;
                }
                continue;
            }
            ("404 Not Found", json_error_body("unknown endpoint"))
        };

        write_http_json_response(&mut stream, status, &body)?;
        served = served.saturating_add(1);
        if max_requests_reached(max_requests, served) {
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
        Some(Command::RelayServe(args)) => run_relay_serve(args),
        Some(Command::ReindexRuntime(args)) => run_reindex_runtime(args),
        Some(Command::Soak(args)) => run_soak(args),
        Some(Command::ReorgDemo(args)) => run_reorg_demo(args),
        Some(Command::Sv2TemplateProvider(args)) => run_sv2_template_provider(args),
        Some(Command::Sv2JobDeclarator(args)) => run_sv2_job_declarator(args),
        Some(Command::Sv2Translator(args)) => run_sv2_translator(args),
        Some(Command::StratumServe(args)) => run_stratum_serve(args),
        Some(Command::StratumMine(args)) => run_stratum_mine(args),
        Some(Command::StratumKeygen(args)) => run_stratum_keygen(args),
        Some(Command::StratumKeyRotate(args)) => run_stratum_key_rotate(args),
        Some(Command::Sv2Conformance(args)) => run_sv2_conformance(args),
        Some(Command::RpcServe(args)) => run_rpc_serve(args),
        Some(Command::Snapshot(args)) => run_snapshot(args.command),
        Some(Command::P2pDemo) => run_p2p_demo().map(|_| ()),
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
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use scam_chain::ChainRuntime;
    use scam_core::{ChainConfig, Hash256, OutPoint, Transaction, TxIn, TxOut};
    use scam_mempool::{Mempool, OrphanPool};
    use scam_miner::{BlockTemplate, mine_block};
    use scam_p2p::{GossipEngine, InventoryItem, ReplacementRateLimit, WireMessage};
    use scam_storage::{load_chain_archive_db, load_peer_book_db};
    use scam_stratum::{IdentityTranslator, Sv2Message, Translator, read_frame, write_frame};
    use scam_wallet::{WalletMnemonic, derive_wallet_key};

    use super::{
        AddPeerArgs, ConfigScaffoldArgs, DifficultyAlgoArg, Network, ReindexRuntimeArgs,
        RelayAdmissionState, RelayServerState, RpcServeArgs, SOAK_FLOW_MNEMONIC, SpendableUtxo,
        StratumMineArgs, StratumServeArgs, Sv2ConformanceArgs, Sv2JobDeclaratorArgs,
        Sv2TemplateProviderArgs, Sv2TranslatorArgs, SyncBookArgs, TemplateProviderRequest,
        accepted_hrps_for_network, admit_peer_tx_into_relay, build_coinbase_tx,
        build_signed_transfer_tx, execute_soak_rounds, load_chain_config,
        mine_block_with_transactions, mine_blocks_on_runtime, persist_runtime_db,
        process_relay_wire_message, relay_fee_hint, request_job_id_from_declarator,
        request_template_from_provider, run_add_peer, run_config_scaffold, run_reindex_runtime,
        run_rpc_serve, run_stratum_mine, run_stratum_serve, run_sv2_conformance,
        run_sv2_job_declarator, run_sv2_template_provider, run_sv2_translator, run_sync_book,
        run_wallet, select_utxos_for_amount, translate_remote_job_with_service,
        try_find_share_for_job,
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

    fn allocate_local_addr() -> Option<String> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener.local_addr().ok().map(|addr| addr.to_string()),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(err) => panic!("bind failed: {err}"),
        }
    }

    fn read_http_request_from_raw(
        raw: &[u8],
    ) -> Result<Option<super::HttpRequest>, super::NodeError> {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(super::NodeError::Runtime(
                    "socket bind permission denied".to_owned(),
                ));
            }
            Err(err) => panic!("bind listener: {err}"),
        };
        let addr = listener.local_addr().expect("listener addr");
        let payload = raw.to_vec();
        let sender = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("set write timeout");
            stream.write_all(&payload).expect("send raw http request");
            stream.flush().expect("flush request");
            stream
                .shutdown(Shutdown::Write)
                .expect("shutdown write half");
        });

        let (mut incoming, _) = listener.accept().expect("accept");
        incoming
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let request = super::read_http_request(&mut incoming);
        sender.join().expect("sender join");
        request
    }

    fn connect_with_retry(addr: &str) -> TcpStream {
        for _ in 0..20 {
            match TcpStream::connect(addr) {
                Ok(stream) => return stream,
                Err(_) => thread::sleep(Duration::from_millis(25)),
            }
        }
        panic!("connect retry exhausted for {addr}");
    }

    fn send_http_request(addr: &str, request: &str) -> String {
        let mut stream = connect_with_retry(addr);
        stream
            .write_all(request.as_bytes())
            .expect("write request bytes");
        stream
            .shutdown(Shutdown::Write)
            .expect("shutdown write half");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        response
    }

    fn send_http_json_post(addr: &str, path: &str, body: &str) -> String {
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        send_http_request(addr, &request)
    }

    #[test]
    fn max_requests_guard_logic_is_strict() {
        assert!(!super::max_requests_reached(0, 0));
        assert!(!super::max_requests_reached(0, 100));
        assert!(!super::max_requests_reached(2, 0));
        assert!(!super::max_requests_reached(2, 1));
        assert!(super::max_requests_reached(2, 2));
        assert!(super::max_requests_reached(2, 3));
    }

    #[test]
    fn helper_guards_for_limits_and_rates_are_consistent() {
        assert!(!super::nonzero_limit_reached(0, 10));
        assert!(!super::nonzero_limit_reached(5, 4));
        assert!(super::nonzero_limit_reached(5, 5));
        assert!(super::nonzero_limit_reached(5, 6));

        assert!(!super::should_emit_periodic_round(1, 2));
        assert!(super::should_emit_periodic_round(2, 2));
        assert!(!super::should_emit_periodic_round(2, 0));

        assert_eq!(super::blocks_per_second(10, 0), 10.0);
        assert!((super::blocks_per_second(9, 3) - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn network_and_hash_match_helpers_reject_mismatches() {
        super::ensure_network_id_match("devnet", "devnet", "ctx").expect("match");
        let network_err = super::ensure_network_id_match("devnet", "testnet", "ctx")
            .expect_err("network mismatch must fail");
        assert!(
            network_err
                .to_string()
                .contains("expected devnet, got testnet")
        );

        let hash = Hash256([1u8; 32]);
        super::ensure_expected_hash(hash, hash, "block order").expect("hash match");
        let hash_err = super::ensure_expected_hash(hash, Hash256([2u8; 32]), "block order")
            .expect_err("hash mismatch must fail");
        assert!(hash_err.to_string().contains("block order"));
    }

    #[test]
    fn configure_stream_timeouts_sets_requested_values() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind: {err}"),
        };
        let addr = listener.local_addr().expect("addr");
        let client = thread::spawn(move || TcpStream::connect(addr).expect("connect"));
        let (stream, _) = listener.accept().expect("accept");
        let _client_stream = client.join().expect("join");

        super::configure_stream_timeouts_with(
            &stream,
            Duration::from_secs(2),
            Duration::from_secs(3),
        )
        .expect("set explicit timeouts");
        assert_eq!(
            stream.read_timeout().expect("read timeout"),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            stream.write_timeout().expect("write timeout"),
            Some(Duration::from_secs(3))
        );

        super::configure_stream_timeouts(&stream).expect("set default timeouts");
        assert_eq!(
            stream.read_timeout().expect("read timeout"),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            stream.write_timeout().expect("write timeout"),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn telemetry_append_helpers_create_parent_dirs_and_write_jsonl() {
        let work_dir = temp_dir("test-telemetry-append");
        let relay_path = work_dir.join("relay/telemetry.jsonl");
        let role_path = work_dir.join("role/telemetry.jsonl");
        let soak_path = work_dir.join("soak/telemetry.jsonl");
        let generic_path = work_dir.join("generic/telemetry.jsonl");

        let relay_snapshot = super::RelayServerTelemetrySnapshot {
            timestamp_unix_sec: 1,
            active_peers: 2,
            tip_height: 3,
            tip_hash: "abcd".to_owned(),
            mempool_len: 4,
            orphan_pool_len: 5,
            mempool_inserted_total: 6,
            mempool_replaced_total: 7,
            mempool_removed_by_replacement_total: 8,
            mempool_rejected_conflict_total: 9,
            orphan_accepted_total: 10,
            orphan_evicted_total: 11,
            orphan_expired_total: 12,
            orphan_promoted_total: 13,
            gossip_replacement_rate_limited_total: 14,
        };
        super::append_relay_telemetry_snapshot(&relay_path, &relay_snapshot).expect("relay append");
        assert!(relay_path.exists(), "relay telemetry file must exist");

        super::append_jsonl_record(
            &generic_path,
            &serde_json::json!({ "kind": "generic", "value": 42 }),
            "generic",
        )
        .expect("generic append");
        assert!(generic_path.exists(), "generic telemetry file must exist");

        super::append_role_service_telemetry(&role_path, "template-provider", 3, 2, 1)
            .expect("role append");
        assert!(role_path.exists(), "role telemetry file must exist");

        let soak_snapshot = super::SoakTelemetrySnapshot {
            round: 1,
            unix_sec: 1,
            tip_height: 10,
            mempool_len: 0,
            orphan_pool_len: 0,
            mempool_accepted_total: 0,
            mempool_replaced_total: 0,
            mempool_removed_by_replacement_total: 0,
            mempool_evicted_total: 0,
            mempool_removed_by_block_total: 0,
            mempool_rejected_conflict_total: 0,
            orphan_accepted_total: 0,
            orphan_evicted_total: 0,
            orphan_expired_total: 0,
            orphan_promoted_total: 0,
            gossip_announced_txs_total: 0,
            gossip_removed_txs_total: 0,
            gossip_inbound_replacement_events_total: 0,
            gossip_replacement_rate_limited_total: 0,
        };
        super::append_soak_telemetry_snapshot(&soak_path, &soak_snapshot).expect("soak append");
        assert!(soak_path.exists(), "soak telemetry file must exist");

        let relay_lines = fs::read_to_string(&relay_path).expect("read relay");
        assert!(
            relay_lines
                .lines()
                .next()
                .unwrap_or_default()
                .contains("\"tip_height\":3"),
            "relay snapshot content mismatch"
        );
        let role_lines = fs::read_to_string(&role_path).expect("read role");
        assert!(
            role_lines
                .lines()
                .next()
                .unwrap_or_default()
                .contains("\"role\":\"template-provider\""),
            "role snapshot content mismatch"
        );
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn default_runtime_db_path_uses_network_name() {
        let path = super::default_runtime_db_path(Network::Testnet);
        assert_eq!(path, PathBuf::from("data/testnet.runtime.redb"));
    }

    #[test]
    fn runtime_commands_fail_fast_when_config_is_missing() {
        let missing_cfg = temp_dir("test-missing-config").join("missing.toml");

        let node_err = super::run_node(Network::Devnet, Some(missing_cfg.clone()), None, false)
            .expect_err("missing config must fail node startup");
        assert!(node_err.to_string().contains("config"));

        let status_err = super::run_status(super::StatusArgs {
            network: Network::Devnet,
            config: Some(missing_cfg.clone()),
            mine_blocks: 0,
            interval_sec: 120,
            max_nonce: 1,
            json: true,
        })
        .expect_err("missing config must fail status");
        assert!(status_err.to_string().contains("config"));

        let block_err = super::run_get_block(super::GetBlockArgs {
            network: Network::Devnet,
            config: Some(missing_cfg.clone()),
            height: 0,
            interval_sec: 120,
            max_nonce: 1,
            json: true,
        })
        .expect_err("missing config must fail get-block");
        assert!(block_err.to_string().contains("config"));

        let tx_err = super::run_get_tx(super::GetTxArgs {
            network: Network::Devnet,
            config: Some(missing_cfg),
            height: 0,
            tx_index: 0,
            interval_sec: 120,
            max_nonce: 1,
            json: true,
        })
        .expect_err("missing config must fail get-tx");
        assert!(tx_err.to_string().contains("config"));
    }

    #[test]
    fn other_command_entrypoints_fail_fast_with_missing_config_or_inputs() {
        let missing_cfg = temp_dir("test-other-missing-config").join("missing.toml");

        let mine_err = super::run_mine_once(super::MineOnceArgs {
            network: Network::Devnet,
            config: Some(missing_cfg.clone()),
            max_nonce: 1,
        })
        .expect_err("missing config must fail mine-once");
        assert!(mine_err.to_string().contains("config"));

        let chain_err = super::run_chain_demo(super::ChainDemoArgs {
            network: Network::Devnet,
            config: Some(missing_cfg.clone()),
            blocks: 1,
            max_nonce: 1,
            interval_sec: 1,
        })
        .expect_err("missing config must fail chain-demo");
        assert!(chain_err.to_string().contains("config"));

        let sync_demo_err = super::run_sync_demo(super::SyncDemoArgs {
            network: Network::Devnet,
            config: Some(missing_cfg.clone()),
            local_blocks: 1,
            remote_blocks: 1,
            max_headers: 1,
            interval_sec: 1,
            max_nonce: 1,
        })
        .expect_err("missing config must fail sync-demo");
        assert!(sync_demo_err.to_string().contains("config"));

        let net_demo_err = super::run_net_demo(super::NetDemoArgs {
            network: Network::Devnet,
            config: Some(missing_cfg.clone()),
            local_blocks: 1,
            remote_blocks: 1,
            max_headers: 1,
            interval_sec: 1,
            max_nonce: 1,
        })
        .expect_err("missing config must fail net-demo");
        assert!(net_demo_err.to_string().contains("config"));

        let sync_peer_err = super::run_sync_peer(super::SyncPeerArgs {
            network: Network::Devnet,
            config: Some(missing_cfg.clone()),
            runtime_db: None,
            peer: "127.0.0.1:18444".to_owned(),
            max_batches: 1,
        })
        .expect_err("missing config must fail sync-peer");
        assert!(sync_peer_err.to_string().contains("config"));

        let sync_book_err = run_sync_book(SyncBookArgs {
            network: Network::Devnet,
            config: Some(missing_cfg.clone()),
            runtime_db: None,
            peers_dir: temp_dir("test-other-sync-book"),
            max_peers: 1,
            max_batches_per_peer: 1,
            rotate_after_sec: 1,
        })
        .expect_err("missing config must fail sync-book");
        assert!(sync_book_err.to_string().contains("config"));

        let reorg_err = super::run_reorg_demo(super::ReorgDemoArgs {
            network: Network::Devnet,
            config: Some(missing_cfg.clone()),
            main_blocks: 1,
            fork_blocks: 1,
            fork_from_height: 0,
            main_interval_sec: 1,
            fork_interval_sec: 1,
            max_nonce: 1,
        })
        .expect_err("missing config must fail reorg-demo");
        assert!(reorg_err.to_string().contains("config"));

        let relay_err = super::run_relay_serve(super::RelayServeArgs {
            network: Network::Devnet,
            config: Some(missing_cfg),
            runtime_db: None,
            bind: "127.0.0.1:0".to_owned(),
            max_clients: 1,
            max_messages_per_peer: 1,
            read_timeout_sec: 1,
            write_timeout_sec: 1,
            max_inv_items: None,
            ban_threshold: None,
            replacement_window_sec: None,
            replacement_max_per_peer: None,
            replacement_penalty: None,
            telemetry_out: None,
            telemetry_every_sec: 1,
        })
        .expect_err("missing config must fail relay-serve");
        assert!(relay_err.to_string().contains("config"));

        let snapshot_err = super::run_snapshot(super::SnapshotCommand::Show {
            path: temp_dir("test-snapshot-missing").join("missing.snapshot"),
        })
        .expect_err("missing snapshot file must fail");
        assert!(snapshot_err.to_string().contains("snapshot"));
    }

    #[test]
    fn load_runtime_from_db_validates_network_id_and_db_source() {
        let work_dir = temp_dir("test-load-runtime-db");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let runtime_db_path = work_dir.join("runtime.redb");

        let cfg_devnet: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("devnet config");
        let runtime = ChainRuntime::from_config(cfg_devnet.clone()).expect("runtime");
        persist_runtime_db(&runtime, &runtime_db_path).expect("persist runtime db");

        let (_loaded, source) =
            super::load_runtime_from_db_or_genesis(&cfg_devnet, &runtime_db_path)
                .expect("load from matching db");
        assert_eq!(source, "db");

        let cfg_testnet: ChainConfig =
            toml::from_str(include_str!("../../../config/testnet.toml")).expect("testnet config");
        let mismatch = match super::load_runtime_from_db_or_genesis(&cfg_testnet, &runtime_db_path)
        {
            Ok(_) => panic!("network mismatch must fail"),
            Err(err) => err,
        };
        assert!(
            mismatch.to_string().contains("runtime db network mismatch"),
            "unexpected mismatch error: {mismatch}"
        );

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn query_runtime_mining_guard_uses_nonzero_semantics() {
        assert!(!super::should_mine_query_blocks(0));
        assert!(super::should_mine_query_blocks(1));

        let work_dir = temp_dir("test-query-runtime-mining");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let runtime_db = work_dir.join("runtime.redb");

        let (_cfg_zero, runtime_zero) = super::build_runtime_for_query(
            Network::Devnet,
            Some(config_path.clone()),
            Some(runtime_db.clone()),
            0,
            30,
            500_000,
            "query-zero",
        )
        .expect("build runtime zero");
        assert_eq!(runtime_zero.tip_height(), 0);

        let (_cfg_two, runtime_two) = super::build_runtime_for_query(
            Network::Devnet,
            Some(config_path),
            Some(runtime_db),
            2,
            30,
            500_000,
            "query-two",
        )
        .expect("build runtime two");
        assert_eq!(runtime_two.tip_height(), 2);

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn run_p2p_demo_returns_expected_fanout_summary() {
        let summary = super::run_p2p_demo().expect("p2p demo");
        assert_eq!(summary.inbound_peer_id, 1);
        assert_eq!(summary.outbound_messages, 2);
        assert_eq!(summary.outbound_peer_ids, vec![2, 3]);
        assert!(summary.only_inv_messages);
    }

    #[test]
    fn decode_helpers_validate_lengths_and_optional_behavior() {
        let full = "11".repeat(32);
        let with_prefix = format!("0x{full}");
        let parsed =
            super::decode_fixed_hex::<32>("digest", &with_prefix).expect("decode fixed hex");
        assert_eq!(parsed, [0x11; 32]);

        let err =
            super::decode_fixed_hex::<32>("digest", "0x1234").expect_err("short digest must fail");
        assert!(err.to_string().contains("must be 32 bytes"));

        let empty = super::decode_optional_hex32("opt", &None).expect("none");
        assert_eq!(empty, None);

        let some = super::decode_optional_hex32("opt", &Some(full)).expect("some");
        assert_eq!(some, Some([0x11; 32]));
    }

    #[test]
    fn time_dns_bucket_and_cap_helpers_behave() {
        let now = super::current_unix_sec().expect("current unix sec");
        assert!(
            now > 1_700_000_000,
            "unexpected unix timestamp: {now}; clock likely broken"
        );

        let parsed = super::resolve_dns_seed("127.0.0.1:18444");
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0],
            "127.0.0.1:18444"
                .parse::<std::net::SocketAddr>()
                .expect("socket addr parse")
        );
        assert!(super::resolve_dns_seed("").is_empty());

        let v4 = "203.0.113.77:8333"
            .parse::<std::net::SocketAddr>()
            .expect("v4 parse");
        let v6 = "[2001:db8::1]:8333"
            .parse::<std::net::SocketAddr>()
            .expect("v6 parse");
        assert_eq!(super::peer_diversity_bucket(v4), "v4-203.0");
        assert_eq!(super::peer_diversity_bucket(v6), "v6-2001:db8");

        let capped = super::apply_bucket_cap(
            vec![
                "203.0.113.1:8333".parse().expect("addr1"),
                "198.51.100.1:8333".parse().expect("addr2"),
                "203.0.113.2:8333".parse().expect("addr3"),
            ],
            1,
        );
        assert_eq!(capped.len(), 2);
        assert!(super::apply_bucket_cap(capped.clone(), 0).is_empty());
        assert_eq!(super::apply_bucket_cap(capped.clone(), 10), capped);
    }

    #[test]
    fn hash_visual_and_json_helpers_handle_errors_and_escaping() {
        let err = super::run_hash_visual(super::HashVisualArgs {
            hash_hex: "xyz".to_owned(),
        })
        .expect_err("invalid hash must fail");
        assert!(err.to_string().contains("bad hash"));

        let json = super::json_error_body("line1\nquote\"slash\\");
        assert_eq!(json, "{\"error\":\"line1\\nquote\\\"slash\\\\\"}");

        let input = b"GET / HTTP/1.1\r\nHost: local\r\n\r\nbody";
        let pos = super::find_http_header_terminator(input).expect("terminator");
        assert_eq!(&input[pos..pos + 4], b"\r\n\r\n");
        assert!(super::find_http_header_terminator(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn soak_argument_validation_rejects_invalid_limits() {
        let work_dir = temp_dir("test-soak-invalid");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");

        let base = || super::SoakArgs {
            network: Network::Devnet,
            config: Some(config_path.clone()),
            runtime_db: None,
            rounds: 1,
            blocks_per_round: 1,
            interval_sec: 1,
            max_nonce: 1_000,
            persist_every_rounds: 1,
            txs_per_round: 0,
            tx_amount: 1,
            tx_fee: 1,
            sleep_per_round_sec: 0,
            telemetry_out: None,
            telemetry_every_rounds: 1,
            simulated_peers: 1,
            replacement_window_sec: 1,
            replacement_max_per_peer: 1,
            replacement_penalty: 1,
        };

        let tx_amount_err = super::run_soak(super::SoakArgs {
            txs_per_round: 1,
            tx_amount: 0,
            ..base()
        })
        .expect_err("zero tx amount must fail");
        assert!(tx_amount_err.to_string().contains("tx_amount must be > 0"));

        let telemetry_err = super::run_soak(super::SoakArgs {
            telemetry_every_rounds: 0,
            ..base()
        })
        .expect_err("telemetry cadence must fail");
        assert!(
            telemetry_err
                .to_string()
                .contains("telemetry_every_rounds must be > 0")
        );

        let peers_err = super::run_soak(super::SoakArgs {
            simulated_peers: 0,
            ..base()
        })
        .expect_err("simulated peers zero must fail");
        assert!(
            peers_err
                .to_string()
                .contains("simulated_peers must be > 0")
        );

        let window_err = super::run_soak(super::SoakArgs {
            replacement_window_sec: 0,
            ..base()
        })
        .expect_err("replacement window zero must fail");
        assert!(
            window_err
                .to_string()
                .contains("replacement_window_sec must be > 0")
        );

        let max_per_peer_err = super::run_soak(super::SoakArgs {
            replacement_max_per_peer: 0,
            ..base()
        })
        .expect_err("replacement max per peer zero must fail");
        assert!(
            max_per_peer_err
                .to_string()
                .contains("replacement_max_per_peer must be > 0")
        );

        let penalty_err = super::run_soak(super::SoakArgs {
            replacement_penalty: 0,
            ..base()
        })
        .expect_err("replacement penalty zero must fail");
        assert!(
            penalty_err
                .to_string()
                .contains("replacement_penalty must be > 0")
        );

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn soak_allows_zero_tx_amount_when_tx_flow_is_disabled() {
        let work_dir = temp_dir("test-soak-no-tx-flow");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let runtime_db = work_dir.join("runtime.redb");
        super::run_soak(super::SoakArgs {
            network: Network::Devnet,
            config: Some(config_path),
            runtime_db: Some(runtime_db),
            rounds: 0,
            blocks_per_round: 0,
            interval_sec: 1,
            max_nonce: 1_000,
            persist_every_rounds: 1,
            txs_per_round: 0,
            tx_amount: 0,
            tx_fee: 1,
            sleep_per_round_sec: 0,
            telemetry_out: None,
            telemetry_every_rounds: 1,
            simulated_peers: 1,
            replacement_window_sec: 1,
            replacement_max_per_peer: 1,
            replacement_penalty: 1,
        })
        .expect("soak without tx flow should allow zero tx amount");
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn stratum_share_target_validation_checks_bounds_before_network_bind() {
        let work_dir = temp_dir("test-stratum-target-bounds");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let runtime_db = work_dir.join("runtime.redb");

        let min_target = format!("00{}", "ff".repeat(31));
        let below_min_target = "00".repeat(32);

        let out_of_range_err = run_stratum_serve(StratumServeArgs {
            network: Network::Devnet,
            config: Some(config_path.clone()),
            runtime_db: Some(runtime_db.clone()),
            bind: "not-an-addr".to_owned(),
            share_target_hex: Some(below_min_target),
            max_jobs_per_channel: None,
            max_clients: 0,
            max_active_clients: None,
            read_timeout_sec: None,
            keepalive_sec: Some(5),
            idle_timeout_sec: Some(6),
            vardiff_target_shares_per_minute: None,
            vardiff_retarget_interval_shares: None,
            vardiff_clamp_up: None,
            vardiff_clamp_down: None,
            max_rejected_shares: None,
            min_share_target_hex: Some(min_target.clone()),
            max_share_target_hex: Some(scam_core::Target::MAX.to_hex()),
            secure_transport: false,
            secure_transport_mode: None,
            secure_rekey_interval_messages: None,
            secure_static_secret_key_hex: None,
            secure_expected_remote_static_pubkey_hex: None,
            template_provider_addr: None,
            job_declarator_addr: None,
        })
        .expect_err("share target below min must fail");
        assert!(
            out_of_range_err
                .to_string()
                .contains("share_target_hex must be within"),
            "unexpected error: {out_of_range_err}"
        );

        let boundary_err = run_stratum_serve(StratumServeArgs {
            network: Network::Devnet,
            config: Some(config_path),
            runtime_db: Some(runtime_db),
            bind: "not-an-addr".to_owned(),
            share_target_hex: Some(min_target.clone()),
            max_jobs_per_channel: None,
            max_clients: 0,
            max_active_clients: None,
            read_timeout_sec: None,
            keepalive_sec: Some(10),
            idle_timeout_sec: Some(10),
            vardiff_target_shares_per_minute: None,
            vardiff_retarget_interval_shares: None,
            vardiff_clamp_up: None,
            vardiff_clamp_down: None,
            max_rejected_shares: None,
            min_share_target_hex: Some(min_target.clone()),
            max_share_target_hex: Some(min_target),
            secure_transport: false,
            secure_transport_mode: None,
            secure_rekey_interval_messages: None,
            secure_static_secret_key_hex: None,
            secure_expected_remote_static_pubkey_hex: None,
            template_provider_addr: None,
            job_declarator_addr: None,
        })
        .expect_err("idle timeout validation must trigger after valid share bounds");
        assert!(
            boundary_err
                .to_string()
                .contains("idle_timeout_sec must be greater than keepalive_sec"),
            "unexpected error: {boundary_err}"
        );

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn stratum_keygen_and_rotate_validate_paths_and_archive_old_keys() {
        let work_dir = temp_dir("test-stratum-keygen-rotate");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let secret = work_dir.join("server.secret.hex");
        let public = work_dir.join("server.public.hex");
        let archive = work_dir.join("archive");

        super::run_stratum_keygen(super::StratumKeygenArgs {
            secret_out: secret.clone(),
            public_out: public.clone(),
            force: false,
        })
        .expect("first keygen");
        assert!(secret.exists());
        assert!(public.exists());

        let secret_before = fs::read_to_string(&secret).expect("read secret before");
        let public_before = fs::read_to_string(&public).expect("read public before");
        assert!(!secret_before.trim().is_empty());
        assert!(!public_before.trim().is_empty());

        let overwrite_err = super::run_stratum_keygen(super::StratumKeygenArgs {
            secret_out: secret.clone(),
            public_out: public.clone(),
            force: false,
        })
        .expect_err("second keygen without force must fail");
        assert!(overwrite_err.to_string().contains("already exists"));

        super::run_stratum_keygen(super::StratumKeygenArgs {
            secret_out: secret.clone(),
            public_out: public.clone(),
            force: true,
        })
        .expect("forced keygen");
        let secret_after = fs::read_to_string(&secret).expect("read secret after");
        let public_after = fs::read_to_string(&public).expect("read public after");
        assert!(!secret_after.trim().is_empty());
        assert!(!public_after.trim().is_empty());

        super::run_stratum_key_rotate(super::StratumKeyRotateArgs {
            secret_path: secret.clone(),
            public_path: public.clone(),
            archive_dir: archive.clone(),
        })
        .expect("rotate keys");
        assert!(secret.exists());
        assert!(public.exists());

        let archived = fs::read_dir(&archive)
            .expect("read archive")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .collect::<Vec<_>>();
        assert!(
            archived
                .iter()
                .any(|name| name.starts_with("server.secret.") && name.ends_with(".hex"))
        );
        assert!(
            archived
                .iter()
                .any(|name| name.starts_with("server.public.") && name.ends_with(".hex"))
        );

        let missing_secret_err = super::run_stratum_key_rotate(super::StratumKeyRotateArgs {
            secret_path: work_dir.join("missing.secret"),
            public_path: public,
            archive_dir: archive,
        })
        .expect_err("rotate must reject missing secret file");
        assert!(
            missing_secret_err
                .to_string()
                .contains("secret key file does not exist")
        );

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn sv2_message_kind_covers_all_public_messages() {
        let setup = super::sv2_message_kind(&Sv2Message::SetupConnection {
            protocol: 2,
            min_version: 2,
            max_version: 2,
            flags: 0,
            user_agent: "ua".to_owned(),
        });
        let open = super::sv2_message_kind(&Sv2Message::OpenStandardMiningChannel {
            request_id: 1,
            user: "miner".to_owned(),
        });
        let job = super::sv2_message_kind(&Sv2Message::NewMiningJob {
            channel_id: 1,
            job_id: 1,
            version: 1,
            prev_hash_hex: Hash256::ZERO.to_hex(),
            merkle_root_hex: Hash256::ZERO.to_hex(),
            ntime: 1_800_000_000,
            network_target_hex: scam_core::Target::MAX.to_hex(),
        });
        let target = super::sv2_message_kind(&Sv2Message::SetTarget {
            channel_id: 1,
            maximum_target_hex: scam_core::Target::MAX.to_hex(),
        });
        let submit = super::sv2_message_kind(&Sv2Message::SubmitSharesStandard {
            channel_id: 1,
            job_id: 1,
            nonce: 42,
            ntime: 1_800_000_000,
        });
        let keepalive = super::sv2_message_kind(&Sv2Message::KeepAlive);

        assert_eq!(setup, "SetupConnection");
        assert_eq!(open, "OpenStandardMiningChannel");
        assert_eq!(job, "NewMiningJob");
        assert_eq!(target, "SetTarget");
        assert_eq!(submit, "SubmitSharesStandard");
        assert_eq!(keepalive, "KeepAlive");
    }

    #[test]
    fn read_http_request_rejects_invalid_content_length_header() {
        let raw = b"POST /wallet/new HTTP/1.1\r\nHost: localhost\r\nContent-Length: nope\r\n\r\n";
        let result = read_http_request_from_raw(raw);
        if let Err(err) = &result
            && err.to_string().contains("permission denied")
        {
            return;
        }
        let err = result.expect_err("must reject invalid content-length");
        assert!(err.to_string().contains("invalid Content-Length"));
    }

    #[test]
    fn read_http_request_rejects_missing_header_terminator() {
        let raw = b"GET /health HTTP/1.1\r\nHost: localhost\r\n";
        let result = read_http_request_from_raw(raw);
        if let Err(err) = &result
            && err.to_string().contains("permission denied")
        {
            return;
        }
        let err = result.expect_err("must reject malformed headers");
        assert!(err.to_string().contains("missing header terminator"));
    }

    #[test]
    fn read_http_request_parses_body_and_strips_query_string() {
        let body = r#"{"hello":"world"}"#;
        let raw = format!(
            "POST /wallet/new?foo=bar HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let parsed = read_http_request_from_raw(raw.as_bytes());
        if let Err(err) = &parsed
            && err.to_string().contains("permission denied")
        {
            return;
        }
        let parsed = parsed.expect("parse request");
        let request = parsed.expect("request present");
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/wallet/new");
        assert_eq!(request.body, body.as_bytes());
    }

    #[test]
    fn wallet_balance_response_handles_empty_and_immature_outputs() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");

        let empty = super::wallet_balance_response(
            &runtime,
            &cfg,
            0,
            0,
            "sd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpk5fg".to_owned(),
            [0xAA; 20],
        );
        assert_eq!(empty.utxo_count, 0);
        assert_eq!(empty.total, 0);
        assert_eq!(empty.spendable, 0);
        assert_eq!(empty.immature, 0);

        let genesis_key = cfg.genesis_reward_key_hash20().expect("key hash");
        let immature = super::wallet_balance_response(
            &runtime,
            &cfg,
            0,
            0,
            "sd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpk5fg".to_owned(),
            genesis_key,
        );
        assert_eq!(immature.utxo_count, 1);
        assert_eq!(immature.spendable_utxo_count, 0);
        assert_eq!(immature.immature_utxo_count, 1);
        assert_eq!(immature.total, cfg.block_subsidy as u128);
        assert_eq!(immature.immature, cfg.block_subsidy as u128);
    }

    #[test]
    fn wallet_balance_maturity_boundary_moves_coinbase_to_spendable() {
        let mut cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.coinbase_maturity = 2;
        cfg.validate().expect("config validate");

        let mut runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let miner_key_hash = cfg.genesis_reward_key_hash20().expect("key hash");
        let params = super::MiningLoopParams {
            count: cfg.coinbase_maturity,
            interval_sec: cfg.target_block_time_sec,
            max_nonce: 500_000,
            subsidy: cfg.block_subsidy,
            miner_key_hash,
            label_prefix: "maturity-boundary",
            print_each: false,
        };
        mine_blocks_on_runtime(&mut runtime, &params).expect("mine maturity blocks");

        let balance = super::wallet_balance_response(
            &runtime,
            &cfg,
            0,
            0,
            "sd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpk5fg".to_owned(),
            miner_key_hash,
        );
        assert!(balance.total > 0);
        assert!(
            balance.spendable > 0,
            "expected at least one matured coinbase at boundary"
        );
        assert!(balance.spendable_utxo_count > 0);
    }

    #[test]
    fn static_asset_helpers_handle_unknown_suffix_and_traversal() {
        assert_eq!(
            super::guess_content_type(std::path::Path::new("bundle.unknown")),
            "application/octet-stream"
        );
        assert_eq!(
            super::guess_content_type(std::path::Path::new("logo.png")),
            "image/png"
        );

        let ui_dir = temp_dir("test-ui-assets");
        fs::create_dir_all(&ui_dir).expect("mkdir");
        fs::write(ui_dir.join("index.html"), "<html>ok</html>").expect("write index");

        let Some(addr) = allocate_local_addr() else {
            let _ = fs::remove_dir_all(ui_dir);
            return;
        };
        let listener = match TcpListener::bind(&addr) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                let _ = fs::remove_dir_all(ui_dir);
                return;
            }
            Err(err) => panic!("bind: {err}"),
        };
        let addr = listener.local_addr().expect("addr");
        let ui_clone = ui_dir.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let served = super::try_serve_ui_asset(&mut stream, &ui_clone, "/../secrets.txt")
                .expect("serve");
            assert!(served);
        });

        let mut client = TcpStream::connect(addr).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let mut body = String::new();
        client.read_to_string(&mut body).expect("read response");
        server.join().expect("server join");
        assert!(body.starts_with("HTTP/1.1 400 Bad Request"));

        let Some(addr) = allocate_local_addr() else {
            let _ = fs::remove_dir_all(ui_dir);
            return;
        };
        let listener = match TcpListener::bind(&addr) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                let _ = fs::remove_dir_all(ui_dir);
                return;
            }
            Err(err) => panic!("bind: {err}"),
        };
        let addr = listener.local_addr().expect("addr");
        let ui_clone = ui_dir.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let served = super::try_serve_ui_asset(&mut stream, &ui_clone, "/does-not-exist")
                .expect("serve");
            assert!(served);
        });
        let mut client = TcpStream::connect(addr).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let mut body = String::new();
        client.read_to_string(&mut body).expect("read response");
        server.join().expect("server join");
        assert!(body.starts_with("HTTP/1.1 200 OK"));
        assert!(body.contains("<html>ok</html>"));

        let _ = fs::remove_dir_all(ui_dir);
    }

    #[test]
    fn run_rpc_serve_dispatches_health_and_unknown_routes() {
        let Some(addr) = allocate_local_addr() else {
            return;
        };
        let work_dir = temp_dir("test-rpc-serve-routes");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let runtime_db = work_dir.join("runtime.redb");
        let ui_dir = work_dir.join("ui");
        fs::create_dir_all(&ui_dir).expect("mkdir ui");
        fs::write(ui_dir.join("index.html"), "<html>ui</html>").expect("write ui");

        let server_addr = addr.clone();
        let server = thread::spawn(move || {
            run_rpc_serve(RpcServeArgs {
                network: Network::Devnet,
                config: Some(config_path),
                runtime_db: Some(runtime_db),
                bind: server_addr,
                ui_dir,
                relay_telemetry: None,
                mine_blocks: 0,
                interval_sec: 120,
                max_nonce: 500_000,
                max_requests: 2,
            })
            .expect("rpc serve");
        });

        let mut health_stream = connect_with_retry(&addr);
        health_stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write health");
        health_stream
            .shutdown(Shutdown::Write)
            .expect("shutdown write health");
        let mut health_response = String::new();
        health_stream
            .read_to_string(&mut health_response)
            .expect("read health");
        assert!(health_response.starts_with("HTTP/1.1 200 OK"));
        assert!(health_response.contains("{\"ok\":true}"));

        let mut unknown_stream = connect_with_retry(&addr);
        unknown_stream
            .write_all(b"GET /nope HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write unknown");
        unknown_stream
            .shutdown(Shutdown::Write)
            .expect("shutdown write unknown");
        let mut unknown_response = String::new();
        unknown_stream
            .read_to_string(&mut unknown_response)
            .expect("read unknown");
        // With a present UI directory, unknown GET paths are intentionally served
        // through index.html (SPA-style fallback), not 404.
        assert!(unknown_response.starts_with("HTTP/1.1 200 OK"));
        assert!(unknown_response.contains("<html>ui</html>"));

        server.join().expect("server join");
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn run_rpc_serve_dispatches_core_and_wallet_routes() {
        let Some(addr) = allocate_local_addr() else {
            return;
        };
        let work_dir = temp_dir("test-rpc-serve-wallet-routes");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let runtime_db = work_dir.join("runtime.redb");
        let ui_dir = work_dir.join("ui");
        fs::create_dir_all(&ui_dir).expect("mkdir ui");
        fs::write(ui_dir.join("index.html"), "<html>ui</html>").expect("write ui");

        let server_addr = addr.clone();
        let server = thread::spawn(move || {
            run_rpc_serve(RpcServeArgs {
                network: Network::Devnet,
                config: Some(config_path),
                runtime_db: Some(runtime_db),
                bind: server_addr,
                ui_dir,
                relay_telemetry: None,
                mine_blocks: 0,
                interval_sec: 120,
                max_nonce: 500_000,
                max_requests: 9,
            })
            .expect("rpc serve");
        });

        let status = send_http_request(&addr, "GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(status.starts_with("HTTP/1.1 200 OK"));
        let block = send_http_request(&addr, "GET /block/0 HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(block.starts_with("HTTP/1.1 200 OK"));
        let tx = send_http_request(&addr, "GET /tx/0/0 HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(tx.starts_with("HTTP/1.1 200 OK"));

        let wallet_new = send_http_json_post(&addr, "/wallet/new", "{}");
        assert!(wallet_new.starts_with("HTTP/1.1 200 OK"));
        let wallet_address = send_http_json_post(&addr, "/wallet/address", "{}");
        assert!(wallet_address.starts_with("HTTP/1.1 400 Bad Request"));
        let wallet_decode = send_http_json_post(&addr, "/wallet/decode", "{}");
        assert!(wallet_decode.starts_with("HTTP/1.1 400 Bad Request"));
        let wallet_balance = send_http_json_post(&addr, "/wallet/balance", "{}");
        assert!(wallet_balance.starts_with("HTTP/1.1 400 Bad Request"));
        let wallet_send = send_http_json_post(&addr, "/wallet/send-preview", "{}");
        assert!(wallet_send.starts_with("HTTP/1.1 400 Bad Request"));
        let wallet_qr = send_http_json_post(&addr, "/wallet/qr", "{\"address\":\"scam\"}");
        assert!(wallet_qr.starts_with("HTTP/1.1 200 OK"));

        server.join().expect("server join");
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn stratum_config_validation_errors_are_exposed_early() {
        let work_dir = temp_dir("test-stratum-validate");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let runtime_db = work_dir.join("runtime.redb");

        let serve_err = run_stratum_serve(StratumServeArgs {
            network: Network::Devnet,
            config: Some(config_path.clone()),
            runtime_db: Some(runtime_db.clone()),
            bind: "127.0.0.1:0".to_owned(),
            share_target_hex: None,
            max_jobs_per_channel: None,
            max_clients: 0,
            max_active_clients: None,
            read_timeout_sec: None,
            keepalive_sec: None,
            idle_timeout_sec: None,
            vardiff_target_shares_per_minute: None,
            vardiff_retarget_interval_shares: None,
            vardiff_clamp_up: None,
            vardiff_clamp_down: None,
            max_rejected_shares: None,
            min_share_target_hex: None,
            max_share_target_hex: None,
            secure_transport: true,
            secure_transport_mode: Some(super::SecureTransportModeArg::NoiseXx),
            secure_rekey_interval_messages: Some(1_000),
            secure_static_secret_key_hex: None,
            secure_expected_remote_static_pubkey_hex: None,
            template_provider_addr: None,
            job_declarator_addr: None,
        })
        .expect_err("serve must reject missing noise static key");
        assert!(
            serve_err
                .to_string()
                .contains("requires --secure-static-secret-key-hex"),
            "unexpected serve error: {serve_err}"
        );

        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                let _ = fs::remove_dir_all(work_dir);
                return;
            }
            Err(err) => panic!("bind: {err}"),
        };
        let pool = listener.local_addr().expect("addr").to_string();
        let acceptor = thread::spawn(move || {
            let _ = listener.accept();
        });
        let mine_err = run_stratum_mine(StratumMineArgs {
            pool,
            user: "miner".to_owned(),
            read_timeout_sec: 1,
            max_nonce_per_cycle: 100,
            max_shares: 0,
            max_runtime_sec: 0,
            secure_transport: true,
            secure_transport_mode: Some(super::SecureTransportModeArg::NoiseXx),
            secure_rekey_interval_messages: 1_000,
            secure_static_secret_key_hex: None,
            secure_expected_remote_static_pubkey_hex: None,
            translator_addr: None,
        })
        .expect_err("mine must reject missing noise static key");
        assert!(
            mine_err
                .to_string()
                .contains("requires --secure-static-secret-key-hex"),
            "unexpected mine error: {mine_err}"
        );
        acceptor.join().expect("acceptor join");
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn run_wallet_reports_decode_and_network_hrp_errors() {
        let decode_err = run_wallet(super::WalletCommand::Decode {
            address: "not-an-address".to_owned(),
        })
        .expect_err("invalid address must fail");
        assert!(decode_err.to_string().contains("bech32 error"));

        let mnemonic = WalletMnemonic::parse(SOAK_FLOW_MNEMONIC).expect("mnemonic");
        let seed = mnemonic.to_seed("");
        let key = derive_wallet_key(&seed, 0, 0).expect("wallet key");
        let mainnet_address =
            scam_wallet::to_address("s", key.pubkey_compressed()).expect("address");
        let work_dir = temp_dir("test-wallet-send-hrp");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");

        let send_err = run_wallet(super::WalletCommand::Send {
            network: Network::Devnet,
            config: Some(config_path),
            mnemonic: SOAK_FLOW_MNEMONIC.to_owned(),
            passphrase: "".to_owned(),
            account: 0,
            index: 0,
            to: mainnet_address,
            amount: 1,
            fee: 1,
            mine_blocks: 0,
            interval_sec: 120,
            max_nonce: 500_000,
        })
        .expect_err("mismatched hrp must fail");
        assert!(
            send_err.to_string().contains("is not valid for network"),
            "unexpected send error: {send_err}"
        );
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn run_wallet_address_secure_address_and_rescan_propagate_errors() {
        let address_err = run_wallet(super::WalletCommand::Address {
            mnemonic: "invalid mnemonic words".to_owned(),
            passphrase: "".to_owned(),
            account: 0,
            index: 0,
            hrp: "sd".to_owned(),
        })
        .expect_err("invalid mnemonic must fail address derivation");
        assert!(address_err.to_string().contains("mnemonic"));

        let work_dir = temp_dir("test-wallet-secure-address-rescan-errors");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let wallet_path = work_dir.join("wallet.vault");

        let vault =
            scam_wallet::new_encrypted_wallet_vault(SOAK_FLOW_MNEMONIC, "", "correct-password")
                .expect("new vault");
        scam_wallet::save_wallet_vault(&wallet_path, &vault).expect("save vault");

        let secure_addr_err = run_wallet(super::WalletCommand::SecureAddress {
            wallet: wallet_path,
            password: "wrong-password".to_owned(),
            account: 0,
            index: 0,
            hrp: "sd".to_owned(),
        })
        .expect_err("wrong password must fail secure-address");
        assert!(
            secure_addr_err.to_string().contains("wallet vault"),
            "unexpected secure-address error: {secure_addr_err}"
        );

        let rescan_err = run_wallet(super::WalletCommand::Rescan {
            network: Network::Devnet,
            config: Some(config_path),
            mnemonic: SOAK_FLOW_MNEMONIC.to_owned(),
            passphrase: "".to_owned(),
            account: 0,
            start_index: 5,
            end_index: 4,
            mine_blocks: 0,
            interval_sec: 120,
            max_nonce: 500_000,
        })
        .expect_err("invalid range must fail rescan");
        assert!(
            rescan_err.to_string().contains("invalid index range"),
            "unexpected rescan error: {rescan_err}"
        );

        let _ = fs::remove_dir_all(work_dir);
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
            p2p_max_inv_items: 2_000,
            p2p_ban_threshold: 100,
            p2p_replacement_window_sec: 60,
            p2p_replacement_max_per_peer: 20,
            p2p_replacement_penalty: 25,
            dns_seeds: vec![
                "seed1.example.org".to_owned(),
                "seed2.example.org".to_owned(),
            ],
            coinbase_maturity: 100,
            block_subsidy: 5_000_000_000,
            stratum_share_target:
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
            stratum_min_share_target:
                "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
            stratum_max_share_target:
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
            stratum_vardiff_target_shares_per_minute: 6,
            stratum_vardiff_retarget_interval_shares: 24,
            stratum_vardiff_clamp_up: 2.0,
            stratum_vardiff_clamp_down: 0.5,
            stratum_max_rejected_shares: 64,
            stratum_read_timeout_sec: 2,
            stratum_keepalive_sec: 30,
            stratum_idle_timeout_sec: 180,
            stratum_max_jobs_per_channel: 64,
            stratum_max_active_clients: 256,
            stratum_secure_transport: false,
            stratum_secure_transport_mode: super::SecureTransportModeArg::NoiseXx,
            stratum_secure_rekey_interval_messages: 10_000,
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
        assert_eq!(cfg.p2p_max_inv_items, 2_000);
        assert_eq!(cfg.p2p_ban_threshold, 100);
        assert_eq!(cfg.p2p_replacement_window_sec, 60);
        assert_eq!(cfg.p2p_replacement_max_per_peer, 20);
        assert_eq!(cfg.p2p_replacement_penalty, 25);
        assert_eq!(cfg.dns_seeds.len(), 2);
        assert_eq!(cfg.stratum_vardiff_target_shares_per_minute, 6);
        assert_eq!(cfg.stratum_vardiff_retarget_interval_shares, 24);
        assert_eq!(cfg.stratum_max_jobs_per_channel, 64);
        assert_eq!(cfg.stratum_max_active_clients, 256);
        assert!(!cfg.stratum_secure_transport);
        assert_eq!(cfg.stratum_secure_transport_mode, "noise_xx");
        assert_eq!(cfg.stratum_secure_rekey_interval_messages, 10_000);

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
    fn soak_rounds_apply_sleep_when_configured() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.validate().expect("config validate");
        let mut runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let params = super::SoakExecutionParams {
            rounds: 1,
            blocks_per_round: 0,
            interval_sec: 1,
            max_nonce: 1,
            miner_key_hash: cfg.genesis_reward_key_hash20().expect("key hash"),
            sleep_per_round_sec: 1,
        };
        let summary = execute_soak_rounds(&mut runtime, &cfg, params, |_round, _rt| Ok(()))
            .expect("soak rounds");
        assert!(
            summary.elapsed_sec >= 1,
            "sleep-per-round must contribute to elapsed time"
        );
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

    #[test]
    fn collect_spendable_utxos_filters_owner_and_coinbase_maturity() {
        let mut cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.coinbase_maturity = 2;
        cfg.validate().expect("config validate");

        let mut runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let owner_key_hash20 = cfg.genesis_reward_key_hash20().expect("owner key hash");
        let params = super::MiningLoopParams {
            count: 2,
            interval_sec: 30,
            max_nonce: 500_000,
            subsidy: cfg.block_subsidy,
            miner_key_hash: owner_key_hash20,
            label_prefix: "collect-spendable",
            print_each: false,
        };
        mine_blocks_on_runtime(&mut runtime, &params).expect("mine blocks");

        let (owner_spendable, owner_total) =
            super::collect_spendable_utxos(&runtime, owner_key_hash20);
        assert_eq!(owner_spendable.len(), 1);
        assert_eq!(owner_total, cfg.block_subsidy as u128);

        let (other_spendable, other_total) = super::collect_spendable_utxos(&runtime, [0xAA; 20]);
        assert!(other_spendable.is_empty());
        assert_eq!(other_total, 0);
    }

    #[test]
    fn build_signed_transfer_tx_change_output_is_emitted_only_when_positive() {
        let mut cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.coinbase_maturity = 1;
        cfg.validate().expect("config validate");

        let mut runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let mnemonic = WalletMnemonic::parse(SOAK_FLOW_MNEMONIC).expect("mnemonic");
        let seed = mnemonic.to_seed("");
        let sender_key = derive_wallet_key(&seed, 0, 0).expect("sender key");
        let sender_key_hash20 = scam_core::hash160_blake3(&sender_key.pubkey_compressed());
        let recipient_key_hash20 = [0x55; 20];

        let params = super::MiningLoopParams {
            count: 2,
            interval_sec: 30,
            max_nonce: 500_000,
            subsidy: cfg.block_subsidy,
            miner_key_hash: sender_key_hash20,
            label_prefix: "change-output",
            print_each: false,
        };
        mine_blocks_on_runtime(&mut runtime, &params).expect("mine blocks");

        let no_change = build_signed_transfer_tx(
            &runtime,
            &cfg.network_id,
            &sender_key,
            recipient_key_hash20,
            cfg.block_subsidy.saturating_sub(1),
            1,
        )
        .expect("signed tx without change");
        assert_eq!(no_change.change_value, 0);
        assert_eq!(no_change.tx.outputs.len(), 1);

        let with_change = build_signed_transfer_tx(
            &runtime,
            &cfg.network_id,
            &sender_key,
            recipient_key_hash20,
            cfg.block_subsidy.saturating_sub(2),
            1,
        )
        .expect("signed tx with change");
        assert_eq!(with_change.change_value, 1);
        assert_eq!(with_change.tx.outputs.len(), 2);
    }

    #[test]
    fn parse_remote_job_decodes_valid_new_job_message() {
        let translator = IdentityTranslator;
        let message = Sv2Message::NewMiningJob {
            channel_id: 9,
            job_id: 77,
            version: 1,
            prev_hash_hex: "0000000000000000000000000000000000000000000000000000000000000001"
                .to_owned(),
            merkle_root_hex: "0000000000000000000000000000000000000000000000000000000000000002"
                .to_owned(),
            ntime: 1_800_000_000,
            network_target_hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .to_owned(),
        };
        let job = translator
            .parse_remote_job_message(message)
            .expect("parse")
            .expect("job present");
        assert_eq!(job.channel_id, 9);
        assert_eq!(job.job_id, 77);
        assert_eq!(job.ntime, 1_800_000_000);
    }

    #[test]
    fn try_find_share_for_job_finds_nonce_for_max_target() {
        let job = scam_stratum::MiningJob {
            channel_id: 1,
            job_id: 2,
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            ntime: 1_800_000_000,
            network_target: scam_core::Target::MAX,
        };
        let found = try_find_share_for_job(&job, scam_core::Target::MAX, 0, 100)
            .expect("must find share immediately");
        assert_eq!(found.0, 0);
        assert!(found.2);
    }

    #[test]
    fn load_sv2_corpus_accepts_default_keyword_and_json_envelope() {
        let work_dir = temp_dir("test-sv2-corpus");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let default_path = work_dir.join("default.txt");
        fs::write(&default_path, "default").expect("write default keyword");
        let default_messages =
            super::load_sv2_corpus(&default_path, "user").expect("default corpus parse");
        assert!(
            default_messages
                .iter()
                .any(|msg| matches!(msg, Sv2Message::SetupConnection { .. })),
            "default corpus must include setup"
        );

        let envelope_path = work_dir.join("envelope.json");
        fs::write(&envelope_path, r#"{"messages":[{"KeepAlive":null}]}"#).expect("write envelope");
        let envelope_messages =
            super::load_sv2_corpus(&envelope_path, "user").expect("envelope parse");
        assert_eq!(envelope_messages, vec![Sv2Message::KeepAlive]);
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn sv2_conformance_happy_path_reports_expected_sequence() {
        let Some(addr) = allocate_local_addr() else {
            return;
        };
        let listener = match TcpListener::bind(&addr) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind failed: {err}"),
        };
        let work_dir = temp_dir("test-sv2-conformance-pass");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let report_path = work_dir.join("report.json");

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("set write timeout");

            let setup = read_frame(&mut stream).expect("read setup").expect("setup");
            assert!(matches!(setup, Sv2Message::SetupConnection { .. }));
            write_frame(
                &mut stream,
                &Sv2Message::SetupConnectionSuccess {
                    used_version: 2,
                    flags: 0,
                },
            )
            .expect("write setup success");

            let open = read_frame(&mut stream).expect("read open").expect("open");
            let request_id = match open {
                Sv2Message::OpenStandardMiningChannel { request_id, .. } => request_id,
                other => panic!("unexpected open message: {other:?}"),
            };
            write_frame(
                &mut stream,
                &Sv2Message::OpenStandardMiningChannelSuccess {
                    request_id,
                    channel_id: 7,
                    target_hex: scam_core::Target::MAX.to_hex(),
                    extranonce_prefix_hex: "00000007".to_owned(),
                },
            )
            .expect("write open success");

            let keepalive = read_frame(&mut stream)
                .expect("read keepalive")
                .expect("keepalive");
            assert!(matches!(keepalive, Sv2Message::KeepAlive));
            write_frame(&mut stream, &Sv2Message::KeepAlive).expect("write keepalive");
        });

        run_sv2_conformance(Sv2ConformanceArgs {
            pool: addr,
            user: "sv2-test-user".to_owned(),
            read_timeout_sec: 1,
            secure_transport: false,
            secure_transport_mode: None,
            secure_rekey_interval_messages: 10_000,
            secure_static_secret_key_hex: None,
            secure_expected_remote_static_pubkey_hex: None,
            corpus: None,
            out: Some(report_path.clone()),
            stack_name: Some("mock-stack".to_owned()),
        })
        .expect("conformance should pass");
        server.join().expect("server join");

        let rendered = fs::read_to_string(&report_path).expect("read report");
        let report: serde_json::Value = serde_json::from_str(&rendered).expect("parse report");
        assert_eq!(report["pass"], serde_json::Value::Bool(true));
        assert_eq!(
            report["setup_success"],
            serde_json::Value::Bool(true),
            "setup flag"
        );
        assert_eq!(
            report["channel_opened"],
            serde_json::Value::Bool(true),
            "channel-opened flag"
        );
        let steps = report["steps"].as_array().expect("steps array");
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0]["sent"], "SetupConnection");
        assert_eq!(steps[0]["received"], "SetupConnectionSuccess");
        assert_eq!(steps[1]["sent"], "OpenStandardMiningChannel");
        assert_eq!(steps[1]["received"], "OpenStandardMiningChannelSuccess");
        assert_eq!(steps[2]["sent"], "KeepAlive");
        assert_eq!(steps[2]["received"], "KeepAlive");

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn sv2_conformance_error_path_reports_fail_and_errors() {
        let Some(addr) = allocate_local_addr() else {
            return;
        };
        let listener = match TcpListener::bind(&addr) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind failed: {err}"),
        };
        let work_dir = temp_dir("test-sv2-conformance-fail");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let report_path = work_dir.join("report.json");

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("set write timeout");

            let setup = read_frame(&mut stream).expect("read setup").expect("setup");
            assert!(matches!(setup, Sv2Message::SetupConnection { .. }));
            write_frame(
                &mut stream,
                &Sv2Message::SetupConnectionError {
                    code: "unsupported_version".to_owned(),
                    reason: "mock failure".to_owned(),
                },
            )
            .expect("write setup error");

            let open = read_frame(&mut stream).expect("read open").expect("open");
            let request_id = match open {
                Sv2Message::OpenStandardMiningChannel { request_id, .. } => request_id,
                other => panic!("unexpected open message: {other:?}"),
            };
            write_frame(
                &mut stream,
                &Sv2Message::OpenStandardMiningChannelError {
                    request_id,
                    code: "denied".to_owned(),
                    reason: "mock open failure".to_owned(),
                },
            )
            .expect("write open error");

            let keepalive = read_frame(&mut stream)
                .expect("read keepalive")
                .expect("keepalive");
            assert!(matches!(keepalive, Sv2Message::KeepAlive));
            write_frame(&mut stream, &Sv2Message::KeepAlive).expect("write keepalive");
        });

        let err = run_sv2_conformance(Sv2ConformanceArgs {
            pool: addr,
            user: "sv2-test-user".to_owned(),
            read_timeout_sec: 1,
            secure_transport: false,
            secure_transport_mode: None,
            secure_rekey_interval_messages: 10_000,
            secure_static_secret_key_hex: None,
            secure_expected_remote_static_pubkey_hex: None,
            corpus: None,
            out: Some(report_path.clone()),
            stack_name: Some("mock-stack".to_owned()),
        })
        .expect_err("conformance must fail on setup/open errors");
        assert!(err.to_string().contains("conformance check failed"));
        server.join().expect("server join");

        let rendered = fs::read_to_string(&report_path).expect("read report");
        let report: serde_json::Value = serde_json::from_str(&rendered).expect("parse report");
        assert_eq!(report["pass"], serde_json::Value::Bool(false));
        let errors = report["errors"].as_array().expect("errors array");
        assert!(!errors.is_empty());
        assert!(
            errors
                .iter()
                .any(|entry| { entry.as_str().unwrap_or_default().contains("setup error") }),
            "expected setup error entry"
        );

        let _ = fs::remove_dir_all(work_dir);
    }

    fn relay_tx(spend: OutPoint, sig_seed: u8, out_seed: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: spend,
                signature: vec![sig_seed; 64],
                pubkey_compressed: vec![0x02; 33],
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [out_seed; 20],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn detect_missing_outpoints_reports_only_unavailable_inputs() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.validate().expect("config validate");
        let runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let known = runtime
            .utxo_set()
            .keys()
            .next()
            .cloned()
            .expect("genesis utxo");
        let missing = OutPoint {
            txid: Hash256([99u8; 32]),
            vout: 0,
        };
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_out: known,
                    signature: vec![1u8; 64],
                    pubkey_compressed: vec![0x02; 33],
                    sequence: 0,
                },
                TxIn {
                    prev_out: missing.clone(),
                    signature: vec![2u8; 64],
                    pubkey_compressed: vec![0x02; 33],
                    sequence: 0,
                },
            ],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [1u8; 20],
            }],
            lock_time: 0,
        };
        let mempool = Mempool::with_policy(cfg.max_mempool_txs as usize, cfg.min_relay_fee_per_kb)
            .expect("mempool");
        let missing_outpoints = super::detect_missing_outpoints(&runtime, &mempool, &tx);
        assert_eq!(missing_outpoints, vec![missing]);
    }

    #[test]
    fn relay_admission_announces_new_inventory_to_gossip_engine() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.validate().expect("config validate");
        let runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let base_outpoint = runtime
            .utxo_set()
            .keys()
            .next()
            .cloned()
            .expect("genesis utxo must exist");

        let mut gossip = GossipEngine::with_limits_and_replacement(
            256,
            50,
            ReplacementRateLimit {
                window_sec: 60,
                max_replacements: 5,
                penalty: 10,
            },
        )
        .expect("gossip");
        gossip.connect_peer(1);

        let mut relay = RelayAdmissionState {
            mempool: Mempool::with_policy(cfg.max_mempool_txs as usize, cfg.min_relay_fee_per_kb)
                .expect("mempool"),
            orphan_pool: OrphanPool::new(cfg.max_orphan_txs as usize, cfg.orphan_ttl_sec)
                .expect("orphan"),
            gossip,
        };
        admit_peer_tx_into_relay(
            &mut relay,
            &runtime,
            1,
            relay_tx(base_outpoint, 7, 42),
            1_000,
            1_000,
        )
        .expect("admit tx");
        assert!(
            relay.gossip.telemetry().announced_txs_total > 0,
            "mempool admission should produce gossip inventory announcements"
        );
    }

    #[test]
    fn relay_admission_enforces_peer_replacement_rate_limit() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.validate().expect("config validate");
        let runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let base_outpoint = runtime
            .utxo_set()
            .keys()
            .next()
            .cloned()
            .expect("genesis utxo must exist");

        let mut gossip = GossipEngine::with_limits_and_replacement(
            256,
            50,
            ReplacementRateLimit {
                window_sec: 60,
                max_replacements: 1,
                penalty: 60,
            },
        )
        .expect("gossip");
        gossip.connect_peer(1);

        let mut relay = RelayAdmissionState {
            mempool: Mempool::with_policy(cfg.max_mempool_txs as usize, cfg.min_relay_fee_per_kb)
                .expect("mempool"),
            orphan_pool: OrphanPool::new(cfg.max_orphan_txs as usize, cfg.orphan_ttl_sec)
                .expect("orphan"),
            gossip,
        };

        let tx1 = relay_tx(base_outpoint.clone(), 1, 11);
        let tx2 = relay_tx(base_outpoint.clone(), 2, 12);
        let tx3 = relay_tx(base_outpoint.clone(), 3, 13);

        admit_peer_tx_into_relay(&mut relay, &runtime, 1, tx1, 1_000, 1_000).expect("first");
        admit_peer_tx_into_relay(&mut relay, &runtime, 1, tx2, 1_001, 1_001)
            .expect("replacement 1");
        let err = admit_peer_tx_into_relay(&mut relay, &runtime, 1, tx3, 1_002, 1_002)
            .expect_err("replacement 2 should be rate limited");
        assert!(matches!(
            err,
            super::NodeError::Gossip(scam_p2p::GossipError::ReplacementRateLimited {
                peer_id: 1,
                ..
            })
        ));
    }

    #[test]
    fn relay_runtime_wire_path_enforces_peer_replacement_quota() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.validate().expect("config validate");
        let runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let base_outpoint = runtime
            .utxo_set()
            .keys()
            .next()
            .cloned()
            .expect("genesis utxo must exist");

        let mut gossip = GossipEngine::with_limits_and_replacement(
            256,
            50,
            ReplacementRateLimit {
                window_sec: 60,
                max_replacements: 1,
                penalty: 60,
            },
        )
        .expect("gossip");
        gossip.connect_peer(7);
        let relay = RelayAdmissionState {
            mempool: Mempool::with_policy(cfg.max_mempool_txs as usize, cfg.min_relay_fee_per_kb)
                .expect("mempool"),
            orphan_pool: OrphanPool::new(cfg.max_orphan_txs as usize, cfg.orphan_ttl_sec)
                .expect("orphan"),
            gossip,
        };
        let mut state = RelayServerState { runtime, relay };

        let mut txs = [
            relay_tx(base_outpoint.clone(), 1, 11),
            relay_tx(base_outpoint.clone(), 2, 12),
            relay_tx(base_outpoint, 3, 13),
        ];
        txs.sort_by_key(relay_fee_hint);

        let _ = process_relay_wire_message(
            &mut state,
            7,
            WireMessage::Tx { tx: txs[0].clone() },
            1_000,
        )
        .expect("first");
        let _ = process_relay_wire_message(
            &mut state,
            7,
            WireMessage::Tx { tx: txs[1].clone() },
            1_001,
        )
        .expect("replacement 1");
        let out = process_relay_wire_message(
            &mut state,
            7,
            WireMessage::Tx { tx: txs[2].clone() },
            1_002,
        )
        .expect("rate-limited response");

        assert!(
            out.iter().any(|msg| matches!(
                msg,
                WireMessage::NotFound { items }
                    if items.contains(&InventoryItem::Tx(txs[2].txid()))
            )),
            "expected notfound response for rate-limited replacement"
        );
        assert_eq!(
            state
                .relay
                .gossip
                .telemetry()
                .replacement_rate_limited_total,
            1
        );
    }

    #[test]
    fn template_provider_service_roundtrip() {
        let Some(addr) = allocate_local_addr() else {
            return;
        };
        let server = thread::spawn({
            let addr = addr.clone();
            move || {
                run_sv2_template_provider(Sv2TemplateProviderArgs {
                    bind: addr,
                    max_requests: 1,
                    telemetry_out: None,
                })
            }
        });
        thread::sleep(Duration::from_millis(25));

        let request = TemplateProviderRequest {
            channel_id: 1,
            version: 1,
            prev_hash_hex: Hash256::ZERO.to_hex(),
            ntime: 1_800_000_000,
            network_target_hex: scam_core::Target::MAX.to_hex(),
            block_subsidy: 5_000_000_000,
            reward_key_hash20_hex: "0000000000000000000000000000000000000000".to_owned(),
            coinbase_label: "svc".to_owned(),
        };
        let response = request_template_from_provider(&addr, &request).expect("provider response");
        assert_eq!(response.template.version, 1);
        assert_eq!(response.template.prev_hash, Hash256::ZERO);
        assert_eq!(response.template.ntime, 1_800_000_000);
        server.join().expect("template provider").expect("ok");
    }

    #[test]
    fn job_declarator_service_roundtrip() {
        let Some(addr) = allocate_local_addr() else {
            return;
        };
        let server = thread::spawn({
            let addr = addr.clone();
            move || {
                run_sv2_job_declarator(Sv2JobDeclaratorArgs {
                    bind: addr,
                    max_requests: 2,
                    start_job_id: 41,
                    telemetry_out: None,
                })
            }
        });
        thread::sleep(Duration::from_millis(25));

        let template = scam_stratum::MiningTemplate {
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            ntime: 1_800_000_000,
            network_target: scam_core::Target::MAX,
        };
        let first = request_job_id_from_declarator(&addr, 1, &template).expect("first");
        let second = request_job_id_from_declarator(&addr, 1, &template).expect("second");
        assert_eq!(first, 42);
        assert_eq!(second, 43);
        server.join().expect("job declarator").expect("ok");
    }

    #[test]
    fn translator_service_roundtrip() {
        let Some(addr) = allocate_local_addr() else {
            return;
        };
        let server = thread::spawn({
            let addr = addr.clone();
            move || {
                run_sv2_translator(Sv2TranslatorArgs {
                    bind: addr,
                    max_requests: 1,
                    telemetry_out: None,
                })
            }
        });
        thread::sleep(Duration::from_millis(25));

        let job = translate_remote_job_with_service(
            &addr,
            Sv2Message::NewMiningJob {
                channel_id: 3,
                job_id: 9,
                version: 1,
                prev_hash_hex: Hash256::ZERO.to_hex(),
                merkle_root_hex: Hash256::ZERO.to_hex(),
                ntime: 1_800_000_000,
                network_target_hex: scam_core::Target::MAX.to_hex(),
            },
        )
        .expect("translated")
        .expect("job");
        assert_eq!(job.channel_id, 3);
        assert_eq!(job.job_id, 9);
        server.join().expect("translator").expect("ok");
    }
}
