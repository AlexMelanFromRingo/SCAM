use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use clap::{Args, Parser, Subcommand, ValueEnum};
use scam_chain::{BlockSubmissionOutcome, ChainError, ChainRuntime};
use scam_consensus::{TxValidationError, UtxoSet, validate_and_apply_block};
use scam_core::{
    ChainConfig, ChainConfigError, DifficultyAlgorithm, Hash256, OutPoint, Target, Transaction,
    TxIn, TxOut, block_meets_pow, render_hash_bitmap_16x16,
};
use scam_mempool::{InsertOutcome, Mempool, MempoolError, OrphanPool};
use scam_miner::{BlockTemplate, MempoolTemplateParams, build_template_from_mempool, mine_block};
use scam_p2p::{
    FramingConfig, GossipEngine, GossipError, InventoryItem, LocalHandshake, PeerCandidate,
    ReplacementRateLimit, TransportError, WireMessage, build_block_locator, client_handshake,
    read_message, request_blocks, request_headers, select_block_hashes_for_peer,
    select_headers_for_peer, select_outbound_peers, send_message, server_handshake,
};
use scam_rpc::{StatusResponse, TxResponse, header_to_block_response, to_pretty_json};
use scam_storage::{
    ChainArchive, ChainStateSnapshot, MempoolSnapshot, MempoolTxRecord, PeerAddressBook,
    PeerAddressRecord, StorageError, load_chain_archive_db, load_mempool_db, load_peer_book_db,
    load_snapshot, load_snapshot_db, save_chain_archive_db, save_mempool_db, save_peer_book_db,
    save_snapshot, save_snapshot_db,
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
use tokio::io::{AsyncRead, AsyncWrite};
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
    #[arg(long, default_value = "data/peers")]
    peers_dir: PathBuf,
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
    #[arg(long, default_value_t = false)]
    outbound_connect: bool,
    #[arg(long, default_value_t = 5)]
    outbound_redial_sec: u64,
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
    BalanceAddress {
        #[arg(long, value_enum, default_value_t = Network::Devnet)]
        network: Network,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        address: String,
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

fn default_mempool_db_path(runtime_db_path: &Path) -> PathBuf {
    runtime_db_path.with_file_name("mempool.redb")
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

fn mempool_snapshot_from_pool(cfg: &ChainConfig, mempool: &Mempool) -> MempoolSnapshot {
    let mut entries = mempool
        .txids_by_feerate_desc()
        .into_iter()
        .filter_map(|txid| {
            mempool
                .get_with_fee(&txid)
                .map(|(tx, fee)| MempoolTxRecord {
                    txid,
                    tx: tx.clone(),
                    fee,
                })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.txid.cmp(&b.txid));
    MempoolSnapshot {
        network_id: cfg.network_id.clone(),
        entries,
    }
}

fn persist_mempool_db(
    cfg: &ChainConfig,
    mempool: &Mempool,
    mempool_db_path: &Path,
) -> Result<(), NodeError> {
    let snapshot = mempool_snapshot_from_pool(cfg, mempool);
    save_mempool_db(mempool_db_path, &snapshot)?;
    Ok(())
}

fn load_mempool_from_db_or_empty(
    cfg: &ChainConfig,
    mempool_db_path: &Path,
) -> Result<Mempool, NodeError> {
    let mut mempool = Mempool::with_policy(cfg.max_mempool_txs as usize, cfg.min_relay_fee_per_kb)?;
    if !mempool_db_path.exists() {
        return Ok(mempool);
    }
    let snapshot = load_mempool_db(mempool_db_path)?;
    if snapshot.network_id != cfg.network_id {
        return Err(NodeError::Runtime(format!(
            "mempool db network mismatch: db='{}', config='{}'",
            snapshot.network_id, cfg.network_id
        )));
    }
    for entry in snapshot.entries {
        let _ = mempool.insert_with_fee(entry.tx, entry.fee);
    }
    Ok(mempool)
}

fn remove_confirmed_txids_from_mempool_db(
    cfg: &ChainConfig,
    mempool_db_path: &Path,
    txids: &[Hash256],
) -> Result<usize, NodeError> {
    if txids.is_empty() {
        return Ok(0);
    }
    let mut mempool = load_mempool_from_db_or_empty(cfg, mempool_db_path)?;
    let removed = mempool.remove_confirmed_txids(txids);
    if removed.is_empty() && !mempool_db_path.exists() {
        return Ok(0);
    }
    persist_mempool_db_with_retry(cfg, &mempool, mempool_db_path, 80, 25)?;
    Ok(removed.len())
}

fn is_runtime_db_lock_conflict(err: &NodeError) -> bool {
    let msg = err.to_string();
    msg.contains("Database already open") || msg.contains("Cannot acquire lock")
}

fn is_mempool_db_lock_conflict(err: &NodeError) -> bool {
    let msg = err.to_string();
    msg.contains("Database already open") || msg.contains("Cannot acquire lock")
}

fn persist_with_retry<F>(
    attempts: usize,
    backoff_ms: u64,
    is_lock_conflict: fn(&NodeError) -> bool,
    unknown_err_message: &'static str,
    mut persist_op: F,
) -> Result<(), NodeError>
where
    F: FnMut() -> Result<(), NodeError>,
{
    let mut last_err = None;
    let tries = attempts.max(1);
    for idx in 0..tries {
        match persist_op() {
            Ok(()) => return Ok(()),
            Err(err) if is_lock_conflict(&err) => {
                last_err = Some(err);
                if idx + 1 < tries {
                    std::thread::sleep(Duration::from_millis(backoff_ms.max(1)));
                    continue;
                }
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_err.unwrap_or_else(|| NodeError::Runtime(unknown_err_message.to_owned())))
}

fn persist_runtime_db_with_retry(
    runtime: &ChainRuntime,
    runtime_db_path: &Path,
    attempts: usize,
    backoff_ms: u64,
) -> Result<(), NodeError> {
    persist_with_retry(
        attempts,
        backoff_ms,
        is_runtime_db_lock_conflict,
        "runtime db persist failed for unknown reason",
        || persist_runtime_db(runtime, runtime_db_path),
    )
}

fn persist_mempool_db_with_retry(
    cfg: &ChainConfig,
    mempool: &Mempool,
    mempool_db_path: &Path,
    attempts: usize,
    backoff_ms: u64,
) -> Result<(), NodeError> {
    persist_with_retry(
        attempts,
        backoff_ms,
        is_mempool_db_lock_conflict,
        "mempool db persist failed for unknown reason",
        || persist_mempool_db(cfg, mempool, mempool_db_path),
    )
}

fn next_stratum_job_timestamp(runtime: &ChainRuntime, cfg: &ChainConfig) -> u64 {
    const CONSENSUS_MAX_FUTURE_BLOCK_TIME_SEC: u64 = 2 * 60 * 60;
    let tip_ts = runtime.tip_header().timestamp;
    let min_next = tip_ts.saturating_add(1);
    let wall_now = current_unix_sec().unwrap_or(min_next);
    let max_future = wall_now.saturating_add(CONSENSUS_MAX_FUTURE_BLOCK_TIME_SEC);
    let ideal = tip_ts.saturating_add(cfg.target_block_time_sec);
    std::cmp::max(min_next, ideal.min(max_future))
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
        WalletCommand::BalanceAddress {
            network,
            config,
            address,
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
                "wallet-balance-address",
            )?;
            let decoded = parse_address(&address)?;
            let accepted_hrps = accepted_hrps_for_network(network, &cfg.hrp);
            if !accepted_hrps.iter().any(|hrp| hrp == &decoded.hrp) {
                return Err(NodeError::Runtime(format!(
                    "address hrp '{}' is not valid for network '{}' (accepted: {})",
                    decoded.hrp,
                    cfg.network_id,
                    accepted_hrps.join(", ")
                )));
            }
            let summary =
                wallet_balance_response(&runtime, &cfg, 0, 0, address, decoded.key_hash20);
            println!("Wallet balance (watch-only):");
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

fn configure_stream_timeouts_with_ops<SetRead, SetWrite>(
    set_read_timeout: SetRead,
    set_write_timeout: SetWrite,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<(), NodeError>
where
    SetRead: FnOnce(Option<Duration>) -> std::io::Result<()>,
    SetWrite: FnOnce(Option<Duration>) -> std::io::Result<()>,
{
    set_read_timeout(Some(read_timeout))
        .map_err(|e| NodeError::Runtime(format!("set read timeout failed: {e}")))?;
    set_write_timeout(Some(write_timeout))
        .map_err(|e| NodeError::Runtime(format!("set write timeout failed: {e}")))?;
    Ok(())
}

const DEFAULT_STREAM_TIMEOUT: Duration = Duration::from_secs(5);

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

fn has_unknown_hashes(hashes: &[Hash256]) -> bool {
    !hashes.is_empty()
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
        configure_stream_timeouts_with_ops(
            |duration| stream.set_read_timeout(duration),
            |duration| stream.set_write_timeout(duration),
            DEFAULT_STREAM_TIMEOUT,
            DEFAULT_STREAM_TIMEOUT,
        )
        .map_err(|e| e.to_string())?;

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
    configure_stream_timeouts_with_ops(
        |duration| client.set_read_timeout(duration),
        |duration| client.set_write_timeout(duration),
        DEFAULT_STREAM_TIMEOUT,
        DEFAULT_STREAM_TIMEOUT,
    )?;
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

    if has_unknown_hashes(&unknown_hashes) {
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
    configure_stream_timeouts_with_ops(
        |duration| stream.set_read_timeout(duration),
        |duration| stream.set_write_timeout(duration),
        DEFAULT_STREAM_TIMEOUT,
        DEFAULT_STREAM_TIMEOUT,
    )?;
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

fn peer_book_contains_address(peer_book: &PeerAddressBook, address: &str) -> bool {
    peer_book.peers.iter().any(|peer| peer.address == address)
}

fn sort_and_dedup_peer_book(peer_book: &mut PeerAddressBook) {
    peer_book.peers.sort_by(|a, b| a.address.cmp(&b.address));
    peer_book.peers.dedup_by(|a, b| a.address == b.address);
}

fn find_peer_record_mut<'a>(
    peer_book: &'a mut PeerAddressBook,
    address: &str,
) -> Option<&'a mut PeerAddressRecord> {
    peer_book
        .peers
        .iter_mut()
        .find(|peer| peer.address == address)
}

fn sync_book_has_success(success_count: u32) -> bool {
    success_count != 0
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
            if peer_book_contains_address(&peer_book, &addr_string) {
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
    sort_and_dedup_peer_book(&mut peer_book);

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
                if let Some(peer) = find_peer_record_mut(&mut peer_book, &addr_string) {
                    peer.last_seen_unix_sec = attempt_now;
                    peer.ban_score = peer.ban_score.saturating_sub(1);
                }
            }
            Err(err) => {
                if let Some(peer) = find_peer_record_mut(&mut peer_book, &addr_string) {
                    peer.ban_score = peer.ban_score.saturating_add(1);
                }
                println!("Sync peer failed: {} ({err})", addr_string);
            }
        }
    }

    save_peer_book_db(&peers_db_path, &peer_book)?;
    persist_runtime_db(&runtime, &runtime_db_path)?;
    match sync_book_has_success(success_count) {
        true => {}
        false => {
            return Err(NodeError::Runtime(
                "sync-book finished without successful peers".to_owned(),
            ));
        }
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

fn nonempty_parent_dir(path: &Path) -> Option<&Path> {
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() {
        None
    } else {
        Some(parent)
    }
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
    if let Some(parent) = nonempty_parent_dir(path) {
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
    if let Some(parent) = nonempty_parent_dir(path) {
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
            if has_inventory_delta_changes(0, not_found.len()) {
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

fn push_inv_batches(out: &mut Vec<WireMessage>, items: Vec<InventoryItem>, max_inv_items: usize) {
    if items.is_empty() || max_inv_items == 0 {
        return;
    }
    for chunk in items.chunks(max_inv_items) {
        out.push(WireMessage::Inv {
            items: chunk.to_vec(),
        });
    }
}

fn relay_proactive_inventory_messages(
    state: &RelayServerState,
    last_tip_announced: &mut Option<Hash256>,
    announced_txids: &mut HashSet<Hash256>,
    max_inv_items: usize,
) -> Vec<WireMessage> {
    let mut out = Vec::<WireMessage>::new();
    let tip = state.runtime.tip_hash();
    if *last_tip_announced != Some(tip) {
        push_inv_batches(&mut out, vec![InventoryItem::Block(tip)], max_inv_items);
        *last_tip_announced = Some(tip);
    }

    let current_txids = state.relay.mempool.txids_by_feerate_desc();
    let current_set = current_txids.iter().copied().collect::<HashSet<_>>();
    announced_txids.retain(|txid| current_set.contains(txid));
    let mut new_items = Vec::<InventoryItem>::new();
    for txid in current_txids {
        if announced_txids.insert(txid) {
            new_items.push(InventoryItem::Tx(txid));
        }
    }
    push_inv_batches(&mut out, new_items, max_inv_items);
    out
}

#[derive(Clone, Copy)]
enum RelayPeerSessionMode {
    Inbound,
    Outbound,
}

fn load_relay_outbound_targets(
    peers_dir: &Path,
    network_name: &str,
) -> Result<Vec<String>, NodeError> {
    let (peers_db_path, legacy_txt_path) = peer_book_paths(peers_dir, network_name);
    let mut peer_book = load_or_init_peer_book(network_name, &peers_db_path, &legacy_txt_path)?;
    sort_and_dedup_peer_book(&mut peer_book);
    Ok(peer_book
        .peers
        .into_iter()
        .map(|peer| peer.address)
        .collect::<Vec<_>>())
}

fn relay_target_matches_bind(bind_addr: &str, target: &str) -> bool {
    if bind_addr == target {
        return true;
    }
    let bind = match bind_addr.parse::<SocketAddr>() {
        Ok(bind) => bind,
        Err(_) => return false,
    };
    let peer = match target.parse::<SocketAddr>() {
        Ok(peer) => peer,
        Err(_) => return false,
    };
    if bind.port() != peer.port() {
        return false;
    }
    if bind.ip() == peer.ip() {
        return true;
    }
    bind.ip().is_unspecified() && peer.ip().is_loopback()
}

#[allow(clippy::too_many_arguments)]
fn run_relay_outbound_worker(
    target: String,
    bind_addr: String,
    stop_flag: Arc<AtomicBool>,
    next_peer_id: Arc<AtomicU64>,
    state: Arc<Mutex<RelayServerState>>,
    active_peers: Arc<Mutex<usize>>,
    cfg: ChainConfig,
    runtime_db_path: PathBuf,
    mempool_db_path: PathBuf,
    max_inv_items: usize,
    read_limit: u32,
    read_timeout_sec: u64,
    write_timeout_sec: u64,
    redial_sec: u64,
) {
    if target.trim().is_empty() || relay_target_matches_bind(&bind_addr, &target) {
        return;
    }
    let redial_delay = Duration::from_secs(redial_sec.max(1));
    while !stop_flag.load(Ordering::Relaxed) {
        let mut stream = match TcpStream::connect(&target) {
            Ok(stream) => stream,
            Err(err) => {
                if !stop_flag.load(Ordering::Relaxed) {
                    eprintln!("warning: outbound relay connect to {target} failed: {err}");
                }
                thread::sleep(redial_delay);
                continue;
            }
        };
        if let Err(err) = configure_stream_timeouts_with_ops(
            |duration| stream.set_read_timeout(duration),
            |duration| stream.set_write_timeout(duration),
            Duration::from_secs(read_timeout_sec.max(1)),
            Duration::from_secs(write_timeout_sec.max(1)),
        ) {
            if !stop_flag.load(Ordering::Relaxed) {
                eprintln!("warning: outbound relay timeout config for {target} failed: {err}");
            }
            thread::sleep(redial_delay);
            continue;
        }
        let peer_id = next_peer_id
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if let Err(err) = run_relay_peer_session(
            &mut stream,
            RelayPeerSessionMode::Outbound,
            peer_id,
            &state,
            &active_peers,
            &cfg,
            &runtime_db_path,
            &mempool_db_path,
            max_inv_items,
            read_limit,
        ) && !stop_flag.load(Ordering::Relaxed)
        {
            eprintln!("warning: outbound relay session with {target} ended: {err}");
        }
        thread::sleep(redial_delay);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_relay_outbound_supervisor(
    stop_flag: Arc<AtomicBool>,
    peers_dir: PathBuf,
    bind_addr: String,
    next_peer_id: Arc<AtomicU64>,
    state: Arc<Mutex<RelayServerState>>,
    active_peers: Arc<Mutex<usize>>,
    cfg: ChainConfig,
    runtime_db_path: PathBuf,
    mempool_db_path: PathBuf,
    max_inv_items: usize,
    read_limit: u32,
    read_timeout_sec: u64,
    write_timeout_sec: u64,
    redial_sec: u64,
) {
    let redial_delay = Duration::from_secs(redial_sec.max(1));
    let mut workers = HashMap::<String, thread::JoinHandle<()>>::new();

    while !stop_flag.load(Ordering::Relaxed) {
        let mut finished = Vec::<String>::new();
        for (target, handle) in &workers {
            if handle.is_finished() {
                finished.push(target.clone());
            }
        }
        for target in finished {
            if let Some(handle) = workers.remove(&target)
                && handle.join().is_err()
            {
                eprintln!("warning: outbound relay worker thread panicked for {target}");
            }
        }

        match load_relay_outbound_targets(&peers_dir, &cfg.network_id) {
            Ok(targets) => {
                for target in targets {
                    if workers.contains_key(&target)
                        || relay_target_matches_bind(&bind_addr, &target)
                    {
                        continue;
                    }
                    let stop_clone = stop_flag.clone();
                    let next_peer_clone = next_peer_id.clone();
                    let state_clone = state.clone();
                    let active_clone = active_peers.clone();
                    let cfg_clone = cfg.clone();
                    let runtime_db_path_clone = runtime_db_path.clone();
                    let mempool_db_path_clone = mempool_db_path.clone();
                    let bind_addr_clone = bind_addr.clone();
                    let target_clone = target.clone();
                    workers.insert(
                        target,
                        thread::spawn(move || {
                            run_relay_outbound_worker(
                                target_clone,
                                bind_addr_clone,
                                stop_clone,
                                next_peer_clone,
                                state_clone,
                                active_clone,
                                cfg_clone,
                                runtime_db_path_clone,
                                mempool_db_path_clone,
                                max_inv_items,
                                read_limit,
                                read_timeout_sec,
                                write_timeout_sec,
                                redial_sec,
                            );
                        }),
                    );
                }
            }
            Err(err) => eprintln!(
                "warning: outbound relay peer-book reload failed ({}): {err}",
                peers_dir.display()
            ),
        }
        thread::sleep(redial_delay);
    }

    for (target, handle) in workers {
        if handle.join().is_err() {
            eprintln!("warning: outbound relay worker thread panicked for {target}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_relay_peer_session(
    stream: &mut TcpStream,
    mode: RelayPeerSessionMode,
    peer_id: u64,
    state: &Arc<Mutex<RelayServerState>>,
    active: &Arc<Mutex<usize>>,
    cfg: &ChainConfig,
    runtime_db_path: &Path,
    mempool_db_path: &Path,
    max_inv_items: usize,
    read_limit: u32,
) -> Result<(), NodeError> {
    let result = (|| -> Result<(), NodeError> {
        {
            let mut active_guard = active
                .lock()
                .map_err(|_| NodeError::Runtime("relay active peer mutex poisoned".to_owned()))?;
            *active_guard = active_guard.saturating_add(1);
        }

        let framing = FramingConfig::default();
        let local_hello = LocalHandshake {
            protocol_version: 1,
            network_id: cfg.network_id.clone(),
            user_agent: "scam-node/relay-serve".to_owned(),
            start_height: 0,
        };
        let remote = match mode {
            RelayPeerSessionMode::Inbound => server_handshake(stream, &framing, &local_hello)?,
            RelayPeerSessionMode::Outbound => client_handshake(stream, &framing, &local_hello)?,
        };
        ensure_relay_peer_network(&cfg.network_id, &remote.network_id)?;
        {
            let mut guard = state
                .lock()
                .map_err(|_| NodeError::Runtime("relay state mutex poisoned".to_owned()))?;
            guard.relay.gossip.connect_peer(peer_id);
        }

        if matches!(mode, RelayPeerSessionMode::Outbound) {
            let locator = {
                let guard = state
                    .lock()
                    .map_err(|_| NodeError::Runtime("relay state mutex poisoned".to_owned()))?;
                build_block_locator(guard.runtime.block_hashes())
            };
            send_message(
                stream,
                &WireMessage::GetBlocks {
                    locator,
                    stop: None,
                },
                &framing,
            )?;
        }

        let mut seen = 0u32;
        let mut runtime_db_seen_mtime = runtime_db_mtime(runtime_db_path);
        let mut mempool_db_seen_mtime = mempool_db_mtime(mempool_db_path);
        let mut last_tip_announced = None::<Hash256>;
        let mut announced_txids = HashSet::<Hash256>::new();
        loop {
            if should_stop_after_seen_messages(read_limit, seen) {
                break;
            }
            {
                let mut guard = state
                    .lock()
                    .map_err(|_| NodeError::Runtime("relay state mutex poisoned".to_owned()))?;
                refresh_runtime_from_db_if_changed(
                    cfg,
                    &mut guard.runtime,
                    runtime_db_path,
                    &mut runtime_db_seen_mtime,
                )?;
                refresh_mempool_from_db_if_changed(
                    cfg,
                    &mut guard.relay,
                    mempool_db_path,
                    &mut mempool_db_seen_mtime,
                )?;
            }

            let inbound = match map_relay_read_result(read_message(stream, &framing))? {
                RelayReadOutcome::Timeout => {
                    let proactive = {
                        let guard = state.lock().map_err(|_| {
                            NodeError::Runtime("relay state mutex poisoned".to_owned())
                        })?;
                        relay_proactive_inventory_messages(
                            &guard,
                            &mut last_tip_announced,
                            &mut announced_txids,
                            max_inv_items,
                        )
                    };
                    for msg in proactive {
                        send_message(stream, &msg, &framing)?;
                    }
                    continue;
                }
                RelayReadOutcome::Closed => break,
                RelayReadOutcome::Message(message) => message,
            };

            seen = seen.saturating_add(1);
            let now = current_unix_sec()?;
            let (outbound, runtime_changed, mempool_changed) = {
                let mut guard = state
                    .lock()
                    .map_err(|_| NodeError::Runtime("relay state mutex poisoned".to_owned()))?;
                let tip_before = guard.runtime.tip_hash();
                let mempool_before = guard.relay.mempool.revision();
                let outbound = process_relay_wire_message(&mut guard, peer_id, inbound, now)?;
                let runtime_changed = guard.runtime.tip_hash() != tip_before;
                let mempool_changed = guard.relay.mempool.revision() != mempool_before;
                (outbound, runtime_changed, mempool_changed)
            };
            if runtime_changed {
                let guard = state
                    .lock()
                    .map_err(|_| NodeError::Runtime("relay state mutex poisoned".to_owned()))?;
                persist_runtime_db_with_retry(&guard.runtime, runtime_db_path, 80, 25)?;
                runtime_db_seen_mtime = runtime_db_mtime(runtime_db_path);
            }
            if mempool_changed {
                let guard = state
                    .lock()
                    .map_err(|_| NodeError::Runtime("relay state mutex poisoned".to_owned()))?;
                persist_mempool_db_with_retry(cfg, &guard.relay.mempool, mempool_db_path, 80, 25)?;
                mempool_db_seen_mtime = mempool_db_mtime(mempool_db_path);
            }
            for msg in outbound {
                send_message(stream, &msg, &framing)?;
            }
            let banned = {
                let guard = state
                    .lock()
                    .map_err(|_| NodeError::Runtime("relay state mutex poisoned".to_owned()))?;
                guard.relay.gossip.is_banned(peer_id)
            };
            if banned {
                break;
            }
        }
        Ok(())
    })();

    if let Ok(mut guard) = state.lock() {
        guard.relay.gossip.disconnect_peer(peer_id);
    }
    if let Ok(mut active_guard) = active.lock() {
        *active_guard = active_guard.saturating_sub(1);
    }
    result
}

fn run_relay_serve(args: RelayServeArgs) -> Result<(), NodeError> {
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", args.network.as_str())));
    let cfg = load_chain_config(&config_path)?;
    let runtime_db_path = args
        .runtime_db
        .unwrap_or_else(|| default_runtime_db_path(args.network));
    let mempool_db_path = default_mempool_db_path(&runtime_db_path);
    let (runtime, source) = load_runtime_from_db_or_genesis(&cfg, &runtime_db_path)?;

    let max_inv_items = args.max_inv_items.unwrap_or(cfg.p2p_max_inv_items).max(1);
    let ban_threshold = args.ban_threshold.unwrap_or(cfg.p2p_ban_threshold).max(1);
    let read_timeout_sec = args.read_timeout_sec.max(1);
    let write_timeout_sec = args.write_timeout_sec.max(1);
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
        mempool: load_mempool_from_db_or_empty(&cfg, &mempool_db_path)?,
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
    println!("Mempool DB: {}", mempool_db_path.display());
    println!(
        "Peer book: {}",
        args.peers_dir
            .join(format!("{}.redb", cfg.network_id))
            .display()
    );
    println!(
        "Relay policy: max_inv_items={} ban_threshold={} replacement_window={}s replacement_max_per_peer={} replacement_penalty={}",
        max_inv_items,
        ban_threshold,
        replacement.window_sec,
        replacement.max_replacements,
        replacement.penalty
    );
    {
        let guard = state
            .lock()
            .map_err(|_| NodeError::Runtime("relay state mutex poisoned".to_owned()))?;
        persist_mempool_db_with_retry(&cfg, &guard.relay.mempool, &mempool_db_path, 20, 25)?;
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    let telemetry_handle = if let Some(path) = args.telemetry_out.clone() {
        let path_clone = path.clone();
        let state_clone = state.clone();
        let active_clone = active_peers.clone();
        let stop_clone = stop_flag.clone();
        let every_sec = args.telemetry_every_sec.max(1);
        Some(thread::spawn(move || {
            while relay_telemetry_thread_running(&stop_clone) {
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
    let outbound_handle = if args.outbound_connect {
        let stop_clone = stop_flag.clone();
        let peers_dir_clone = args.peers_dir.clone();
        let bind_addr_clone = args.bind.clone();
        let next_peer_clone = next_peer_id.clone();
        let state_clone = state.clone();
        let active_clone = active_peers.clone();
        let cfg_clone = cfg.clone();
        let runtime_db_path_clone = runtime_db_path.clone();
        let mempool_db_path_clone = mempool_db_path.clone();
        let read_limit = args.max_messages_per_peer;
        let outbound_redial_sec = args.outbound_redial_sec.max(1);
        println!(
            "Outbound relay dialer: enabled (redial={}s)",
            outbound_redial_sec
        );
        Some(thread::spawn(move || {
            run_relay_outbound_supervisor(
                stop_clone,
                peers_dir_clone,
                bind_addr_clone,
                next_peer_clone,
                state_clone,
                active_clone,
                cfg_clone,
                runtime_db_path_clone,
                mempool_db_path_clone,
                max_inv_items,
                read_limit,
                read_timeout_sec,
                write_timeout_sec,
                outbound_redial_sec,
            )
        }))
    } else {
        println!("Outbound relay dialer: disabled");
        None
    };

    let mut served = 0u32;
    let mut handles = Vec::new();
    let mut accept_error = None::<NodeError>;
    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(stream) => stream,
            Err(e) => {
                accept_error = Some(NodeError::Runtime(format!("relay accept failed: {e}")));
                break;
            }
        };
        configure_stream_timeouts_with_ops(
            |duration| stream.set_read_timeout(duration),
            |duration| stream.set_write_timeout(duration),
            Duration::from_secs(read_timeout_sec),
            Duration::from_secs(write_timeout_sec),
        )?;
        let peer_id = next_peer_id
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let state_clone = state.clone();
        let active_clone = active_peers.clone();
        let cfg_clone = cfg.clone();
        let runtime_db_path_clone = runtime_db_path.clone();
        let mempool_db_path_clone = mempool_db_path.clone();
        let max_inv_items_clone = max_inv_items;
        let read_limit = args.max_messages_per_peer;
        handles.push(thread::spawn(move || {
            run_relay_peer_session(
                &mut stream,
                RelayPeerSessionMode::Inbound,
                peer_id,
                &state_clone,
                &active_clone,
                &cfg_clone,
                &runtime_db_path_clone,
                &mempool_db_path_clone,
                max_inv_items_clone,
                read_limit,
            )
        }));

        served = served.saturating_add(1);
        if max_requests_reached(args.max_clients, served) {
            break;
        }
    }

    let mut first_error = accept_error;
    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
            Err(_) => {
                if first_error.is_none() {
                    first_error = Some(NodeError::Runtime(
                        "relay worker thread panicked".to_owned(),
                    ));
                }
            }
        }
    }
    stop_flag.store(true, Ordering::Relaxed);
    if let Some(handle) = outbound_handle {
        let _ = handle.join();
    }
    if let Some(handle) = telemetry_handle {
        let _ = handle.join();
    }
    if let Some(err) = first_error {
        return Err(err);
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
    if let Some(parent) = nonempty_parent_dir(path) {
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
        if has_inventory_delta_changes(delta.announced_txids.len(), delta.removed_txids.len()) {
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
        if let Some(parent) = nonempty_parent_dir(path) {
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

    let tx_flow_enabled = is_tx_flow_enabled(args.txs_per_round);
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
                let recipient_key_hash20 =
                    soak_recipient_key_hash(tx_index, soak_recipient_key_hash20, miner_key_hash);
                let tx_fee = soak_tx_fee_for_index(args.tx_fee, tx_index);
                match build_signed_transfer_tx(
                    runtime,
                    &cfg.network_id,
                    sender_key,
                    recipient_key_hash20,
                    args.tx_amount,
                    tx_fee,
                ) {
                    Ok(signed) => {
                        let peer_id = soak_peer_id_for_round(round, tx_index, args.simulated_peers);
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
                if has_inventory_delta_changes(0, removed_confirmed.len()) {
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

        if should_persist_round(round, persist_every_rounds) {
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
    cfg.difficulty_adjustment_window =
        reorg_min_difficulty_window(cfg.difficulty_adjustment_window);
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
                reorg_count = reorg_count.saturating_add(1);
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

fn role_service_response_is_empty(bytes_read: usize) -> bool {
    bytes_read == 0
}

fn call_json_role_service<Req, Resp>(addr: &str, request: &Req) -> Result<Resp, NodeError>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let mut stream = TcpStream::connect(addr)
        .map_err(|e| NodeError::Runtime(format!("connect to role service {addr} failed: {e}")))?;
    configure_stream_timeouts_with_ops(
        |duration| stream.set_read_timeout(duration),
        |duration| stream.set_write_timeout(duration),
        Duration::from_secs(3),
        Duration::from_secs(3),
    )?;
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
    if role_service_response_is_empty(bytes) {
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
    Ok(StratumTemplateWork {
        template,
        block_txs: vec![coinbase],
    })
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
    block_txs: Vec<Transaction>,
}

#[derive(Clone)]
struct StratumWork {
    job: MiningJob,
    block_txs: Vec<Transaction>,
}

trait StratumTemplateProvider {
    fn build_template(
        &self,
        runtime: &ChainRuntime,
        cfg: &ChainConfig,
        mempool_db_path: &Path,
        max_template_txs: usize,
        reward_key_hash20: [u8; 20],
        coinbase_label: &str,
    ) -> Result<StratumTemplateWork, NodeError>;
}

#[derive(Clone, Copy, Debug, Default)]
struct RuntimeTemplateProvider;

impl StratumTemplateProvider for RuntimeTemplateProvider {
    fn build_template(
        &self,
        runtime: &ChainRuntime,
        cfg: &ChainConfig,
        mempool_db_path: &Path,
        max_template_txs: usize,
        reward_key_hash20: [u8; 20],
        coinbase_label: &str,
    ) -> Result<StratumTemplateWork, NodeError> {
        let prev_block = runtime.tip_hash();
        let target = runtime.expected_target_for_next_block()?;
        let mempool = load_mempool_from_db_or_empty(cfg, mempool_db_path)?;
        let params = MempoolTemplateParams {
            version: 1,
            prev_block,
            timestamp: next_stratum_job_timestamp(runtime, cfg),
            target,
            block_subsidy: cfg.block_subsidy,
            miner_key_hash20: reward_key_hash20,
            coinbase_tag: stratum_coinbase_tag(coinbase_label, prev_block),
            max_txs: max_template_txs.max(1),
        };
        let (template_block, _summary) = build_template_from_mempool(&params, &mempool)
            .map_err(|e| NodeError::Runtime(format!("stratum template build failed: {e}")))?;
        let txids = template_block
            .transactions
            .iter()
            .map(Transaction::txid)
            .collect::<Vec<_>>();
        let merkle_root = scam_core::merkle::merkle_root(&txids);
        let template = MiningTemplate {
            version: template_block.version,
            prev_hash: template_block.prev_block,
            merkle_root,
            ntime: template_block.timestamp,
            network_target: template_block.target,
        };
        Ok(StratumTemplateWork {
            template,
            block_txs: template_block.transactions,
        })
    }
}

enum StratumSecureTransport {
    Legacy(SecureSv2Transport),
    Noise(NoiseSv2Transport),
}

enum StratumReadOutcome {
    Message(Sv2Message),
    Timeout,
    Closed,
}

fn sv2_io_error_is_timeout_like(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
    )
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
    map_sv2_read_result(read_result)
}

async fn read_sv2_message_async<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
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
    mempool_db_path: PathBuf,
    max_template_txs: usize,
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
async fn issue_new_stratum_job_async<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Sv2Session,
    ctx: &StratumServerContext,
    stream: &mut S,
    secure: &mut Option<StratumSecureTransport>,
    jobs: &mut HashMap<u32, StratumWork>,
    reward_key_hash20: [u8; 20],
    coinbase_label: &str,
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
                ntime: next_stratum_job_timestamp(&runtime, &ctx.cfg),
                network_target_hex: target.to_hex(),
                block_subsidy: ctx.cfg.block_subsidy,
                reward_key_hash20_hex: hex::encode(reward_key_hash20),
                coinbase_label: coinbase_label.to_owned(),
            };
            request_template_from_provider(addr, &request)?
        } else {
            ctx.template_provider.build_template(
                &runtime,
                &ctx.cfg,
                &ctx.mempool_db_path,
                ctx.max_template_txs,
                reward_key_hash20,
                coinbase_label,
            )?
        };
        (tip_hash, template_work)
    };

    let template = template_work.template;
    let job_id = if let Some(addr) = &ctx.job_declarator_addr {
        let request = JobDeclaratorRequest {
            channel_id: session.channel_id(),
            template: mining_template_to_rpc(&template),
        };
        call_json_role_service::<JobDeclaratorRequest, JobDeclaratorResponse>(addr, &request)?
            .job_id
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
        block_txs: template_work.block_txs,
    };

    let new_job = session.install_job(work.job.clone())?;
    match secure.as_mut() {
        Some(StratumSecureTransport::Legacy(transport)) => transport
            .write_message_async(stream, &new_job)
            .await
            .map_err(|e| NodeError::Runtime(format!("stratum secure(legacy) write failed: {e}")))?,
        Some(StratumSecureTransport::Noise(transport)) => transport
            .write_message_async(stream, &new_job)
            .await
            .map_err(|e| {
                NodeError::Runtime(format!("stratum secure(noise_xx) write failed: {e}"))
            })?,
        None => write_sv2_frame_async(stream, &new_job)
            .await
            .map_err(|e| NodeError::Runtime(format!("stratum write failed: {e}")))?,
    }
    let prev = session.set_new_prev_hash(&work.job)?;
    match secure.as_mut() {
        Some(StratumSecureTransport::Legacy(transport)) => transport
            .write_message_async(stream, &prev)
            .await
            .map_err(|e| NodeError::Runtime(format!("stratum secure(legacy) write failed: {e}")))?,
        Some(StratumSecureTransport::Noise(transport)) => transport
            .write_message_async(stream, &prev)
            .await
            .map_err(|e| {
                NodeError::Runtime(format!("stratum secure(noise_xx) write failed: {e}"))
            })?,
        None => write_sv2_frame_async(stream, &prev)
            .await
            .map_err(|e| NodeError::Runtime(format!("stratum write failed: {e}")))?,
    }
    jobs.insert(work.job.job_id, work);
    jobs.retain(|job_id, _| session.job(*job_id).is_some());
    Ok(tip_hash)
}

fn load_runtime_tip_hash(ctx: &StratumServerContext) -> Result<Hash256, NodeError> {
    let runtime = lock_runtime(&ctx.runtime)?;
    Ok(runtime.tip_hash())
}

async fn run_stratum_client_async<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
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
    macro_rules! send_sv2_async {
        ($message:expr) => {{
            match secure_transport.as_mut() {
                Some(StratumSecureTransport::Legacy(transport)) => transport
                    .write_message_async(&mut stream, $message)
                    .await
                    .map_err(|e| {
                        NodeError::Runtime(format!("stratum secure(legacy) write failed: {e}"))
                    })?,
                Some(StratumSecureTransport::Noise(transport)) => transport
                    .write_message_async(&mut stream, $message)
                    .await
                    .map_err(|e| {
                        NodeError::Runtime(format!("stratum secure(noise_xx) write failed: {e}"))
                    })?,
                None => write_sv2_frame_async(&mut stream, $message)
                    .await
                    .map_err(|e| NodeError::Runtime(format!("stratum write failed: {e}")))?,
            }
        }};
    }
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
    let mut payout_key_hash20 = ctx.cfg.genesis_reward_key_hash20()?;
    let mut payout_label = stratum_coinbase_label(session.channel_id(), "default");

    loop {
        match read_sv2_message_async(&mut stream, secure_transport.as_mut(), read_timeout).await? {
            StratumReadOutcome::Closed => break,
            StratumReadOutcome::Timeout => {
                if session.is_active() {
                    let current_tip = load_runtime_tip_hash(&ctx)?;
                    if tip_changed(current_tip, last_tip_hash) {
                        jobs.clear();
                        last_tip_hash = issue_new_stratum_job_async(
                            &mut session,
                            &ctx,
                            &mut stream,
                            &mut secure_transport,
                            &mut jobs,
                            payout_key_hash20,
                            &payout_label,
                        )
                        .await?;
                    }
                    if nonzero_limit_reached(ctx.keepalive_sec, last_keepalive.elapsed().as_secs())
                    {
                        send_sv2_async!(&Sv2Message::KeepAlive);
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
                    send_sv2_async!(&outbound);
                }

                for event in response.events {
                    match event {
                        SessionEvent::SetupAccepted => {}
                        SessionEvent::ChannelOpened { user, .. } => {
                            if let Some(parsed) = stratum_user_payout_key_hash20(&user) {
                                payout_key_hash20 = parsed;
                                payout_label = stratum_coinbase_label(session.channel_id(), &user);
                            } else {
                                payout_key_hash20 = ctx.cfg.genesis_reward_key_hash20()?;
                                payout_label =
                                    stratum_coinbase_label(session.channel_id(), "default");
                            }
                            last_tip_hash = issue_new_stratum_job_async(
                                &mut session,
                                &ctx,
                                &mut stream,
                                &mut secure_transport,
                                &mut jobs,
                                payout_key_hash20,
                                &payout_label,
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
                            if should_process_share_as_block(is_block) {
                                let Some(work) = jobs.get(&job_id).cloned() else {
                                    continue;
                                };
                                let included_txids = work
                                    .block_txs
                                    .iter()
                                    .skip(1)
                                    .map(Transaction::txid)
                                    .collect::<Vec<_>>();
                                let block = scam_core::Block {
                                    header: scam_core::BlockHeader {
                                        version: work.job.version,
                                        prev_block: work.job.prev_hash,
                                        merkle_root: work.job.merkle_root,
                                        timestamp: ntime,
                                        target: work.job.network_target,
                                        nonce,
                                    },
                                    transactions: work.block_txs,
                                };

                                {
                                    let mut runtime = lock_runtime(&ctx.runtime)?;
                                    let _ = runtime.submit_block(block)?;
                                    match persist_runtime_db_with_retry(
                                        &runtime,
                                        &ctx.runtime_db_path,
                                        80,
                                        25,
                                    ) {
                                        Ok(()) => {}
                                        Err(err) if is_runtime_db_lock_conflict(&err) => {
                                            eprintln!(
                                                "warning: runtime db lock contention while persisting mined block; keeping in-memory tip {}",
                                                runtime.tip_hash()
                                            );
                                        }
                                        Err(err) => return Err(err),
                                    }
                                    last_tip_hash = runtime.tip_hash();
                                }
                                if let Err(err) = remove_confirmed_txids_from_mempool_db(
                                    &ctx.cfg,
                                    &ctx.mempool_db_path,
                                    &included_txids,
                                ) {
                                    eprintln!(
                                        "warning: failed to trim confirmed txids from mempool db: {err}"
                                    );
                                }

                                jobs.clear();
                                if should_reissue_job_for_channel(channel_id, session.channel_id())
                                {
                                    last_tip_hash = issue_new_stratum_job_async(
                                        &mut session,
                                        &ctx,
                                        &mut stream,
                                        &mut secure_transport,
                                        &mut jobs,
                                        payout_key_hash20,
                                        &payout_label,
                                    )
                                    .await?;
                                }
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

fn read_role_request<T: DeserializeOwned, R: Read>(stream: &mut R) -> Result<T, NodeError> {
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

fn map_sv2_read_result(
    read_result: Result<Option<Sv2Message>, scam_stratum::StratumError>,
) -> Result<StratumReadOutcome, NodeError> {
    match read_result {
        Ok(Some(message)) => Ok(StratumReadOutcome::Message(message)),
        Ok(None) => Ok(StratumReadOutcome::Closed),
        Err(scam_stratum::StratumError::Io(err)) if sv2_io_error_is_timeout_like(&err) => {
            Ok(StratumReadOutcome::Timeout)
        }
        Err(err) => Err(NodeError::Runtime(format!("stratum read failed: {err}"))),
    }
}

fn has_inventory_delta_changes(announced_len: usize, removed_len: usize) -> bool {
    announced_len != 0 || removed_len != 0
}

fn relay_telemetry_thread_running(stop_flag: &AtomicBool) -> bool {
    !stop_flag.load(Ordering::Relaxed)
}

fn should_stop_after_seen_messages(read_limit: u32, seen: u32) -> bool {
    read_limit != 0 && seen >= read_limit
}

#[derive(Debug)]
enum RelayReadOutcome {
    Message(WireMessage),
    Timeout,
    Closed,
}

fn relay_io_error_is_timeout_like(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
    )
}

fn relay_io_error_is_closed_like(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
    )
}

fn ensure_relay_peer_network(
    expected_network_id: &str,
    actual_network_id: &str,
) -> Result<(), NodeError> {
    if actual_network_id == expected_network_id {
        Ok(())
    } else {
        Err(NodeError::Runtime(format!(
            "relay peer network mismatch: expected {}, got {}",
            expected_network_id, actual_network_id
        )))
    }
}

fn map_relay_read_result(
    result: Result<WireMessage, TransportError>,
) -> Result<RelayReadOutcome, NodeError> {
    match result {
        Ok(message) => Ok(RelayReadOutcome::Message(message)),
        Err(TransportError::Io(err)) if relay_io_error_is_timeout_like(&err) => {
            Ok(RelayReadOutcome::Timeout)
        }
        Err(TransportError::Io(err)) if relay_io_error_is_closed_like(&err) => {
            Ok(RelayReadOutcome::Closed)
        }
        Err(err) => Err(NodeError::Transport(err)),
    }
}

fn should_require_noise_static_key(
    secure_transport: bool,
    mode: SecureTransportMode,
    has_static_private_key: bool,
) -> bool {
    secure_transport && matches!(mode, SecureTransportMode::NoiseXx) && !has_static_private_key
}

fn should_apply_set_new_prev_hash(active_channel: Option<u32>, incoming_channel: u32) -> bool {
    active_channel == Some(incoming_channel)
}

fn should_apply_set_target(active_channel: Option<u32>, incoming_channel: u32) -> bool {
    active_channel == Some(incoming_channel)
}

fn tip_changed(current: Hash256, previous: Hash256) -> bool {
    current != previous
}

fn should_process_share_as_block(is_block: bool) -> bool {
    is_block
}

fn should_reissue_job_for_channel(channel_id: u32, active_channel_id: u32) -> bool {
    channel_id == active_channel_id
}

fn stratum_user_payout_key_hash20(user: &str) -> Option<[u8; 20]> {
    parse_address(user).ok().map(|decoded| decoded.key_hash20)
}

fn stratum_coinbase_label(channel_id: u32, user_hint: &str) -> String {
    let compact = user_hint
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(24)
        .collect::<String>();
    let suffix = if compact.is_empty() {
        "default".to_owned()
    } else {
        compact
    };
    format!("stratum-ch{channel_id}-{suffix}")
}

fn stratum_coinbase_tag(base_label: &str, prev_hash: Hash256) -> String {
    let prev = prev_hash.to_hex();
    format!("{base_label}-{}", &prev[..16])
}

fn should_send_open_standard_channel(open_sent: bool) -> bool {
    !open_sent
}

fn should_emit_miner_keepalive(elapsed_sec: u64) -> bool {
    elapsed_sec >= 10
}

fn wallet_send_preview_has_invalid_amount(amount: u64) -> bool {
    amount == 0
}

fn tx_submit_has_invalid_payload(tx_hex: &str) -> bool {
    tx_hex.trim().is_empty()
}

fn decode_tx_from_bincode_hex(raw: &str) -> Result<Transaction, NodeError> {
    let trimmed = raw.trim();
    let decoded =
        hex::decode(trimmed).map_err(|e| NodeError::Runtime(format!("invalid tx_hex: {e}")))?;
    bincode::deserialize::<Transaction>(&decoded)
        .map_err(|e| NodeError::Runtime(format!("invalid tx payload: {e}")))
}

#[derive(Clone, Copy)]
struct ResolvedPrevout {
    value: u64,
    key_hash20: [u8; 20],
    is_coinbase: bool,
    created_height: u64,
}

fn resolve_prevout_for_admission(
    runtime: &ChainRuntime,
    mempool: &Mempool,
    outpoint: &OutPoint,
) -> Option<ResolvedPrevout> {
    if let Some(entry) = runtime.utxo_set().get(outpoint) {
        return Some(ResolvedPrevout {
            value: entry.value,
            key_hash20: entry.key_hash20,
            is_coinbase: entry.is_coinbase,
            created_height: entry.created_height,
        });
    }
    let (parent_tx, _fee) = mempool.get_with_fee(&outpoint.txid)?;
    let output = parent_tx.outputs.get(outpoint.vout as usize)?;
    Some(ResolvedPrevout {
        value: output.value,
        key_hash20: output.key_hash20,
        is_coinbase: false,
        created_height: runtime.tip_height().saturating_add(1),
    })
}

fn validate_tx_for_local_admission(
    cfg: &ChainConfig,
    runtime: &ChainRuntime,
    mempool: &Mempool,
    tx: &Transaction,
) -> Result<u64, NodeError> {
    if tx.is_coinbase() {
        return Err(NodeError::Runtime(
            "coinbase transaction cannot be submitted to mempool".to_owned(),
        ));
    }
    if tx.inputs.is_empty() {
        return Err(NodeError::Runtime(
            "transaction must include at least one input".to_owned(),
        ));
    }
    if tx.outputs.is_empty() {
        return Err(NodeError::Runtime(
            "transaction must include at least one output".to_owned(),
        ));
    }

    let mut seen = HashSet::<OutPoint>::new();
    let mut input_sum = 0u128;
    let mut output_sum = 0u128;
    let mut missing = Vec::<String>::new();
    let tip_height = runtime.tip_height();
    let maturity = cfg.coinbase_maturity as u64;

    for (output_index, output) in tx.outputs.iter().enumerate() {
        if output.value == 0 {
            return Err(NodeError::Runtime(format!(
                "output #{output_index} has zero value"
            )));
        }
        output_sum = output_sum
            .checked_add(output.value as u128)
            .ok_or_else(|| NodeError::Runtime("output value overflow".to_owned()))?;
    }

    for (input_index, input) in tx.inputs.iter().enumerate() {
        if input.prev_out.is_coinbase() {
            return Err(NodeError::Runtime(format!(
                "input #{input_index} references coinbase prevout"
            )));
        }
        if !seen.insert(input.prev_out.clone()) {
            return Err(NodeError::Runtime(format!(
                "input #{input_index} double-spends prevout within tx"
            )));
        }
        if input.pubkey_compressed.len() != 33 {
            return Err(NodeError::Runtime(format!(
                "input #{input_index} has invalid pubkey length {}",
                input.pubkey_compressed.len()
            )));
        }
        if !matches!(input.pubkey_compressed[0], 0x02 | 0x03) {
            return Err(NodeError::Runtime(format!(
                "input #{input_index} has invalid pubkey prefix {:02x}",
                input.pubkey_compressed[0]
            )));
        }
        if input.signature.len() != 64 {
            return Err(NodeError::Runtime(format!(
                "input #{input_index} has invalid signature length {}",
                input.signature.len()
            )));
        }

        let Some(prevout) = resolve_prevout_for_admission(runtime, mempool, &input.prev_out) else {
            missing.push(format!("{}:{}", input.prev_out.txid, input.prev_out.vout));
            continue;
        };

        if prevout.is_coinbase && tip_height < prevout.created_height.saturating_add(maturity) {
            return Err(NodeError::Runtime(format!(
                "input #{input_index} spends immature coinbase (created_height={}, maturity={})",
                prevout.created_height, maturity
            )));
        }
        let derived_key_hash20 = scam_core::hash160_blake3(&input.pubkey_compressed);
        if derived_key_hash20 != prevout.key_hash20 {
            return Err(NodeError::Runtime(format!(
                "input #{input_index} pubkey hash mismatch with referenced output"
            )));
        }

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&input.signature);
        let mut pubkey = [0u8; 33];
        pubkey.copy_from_slice(&input.pubkey_compressed);
        let digest = tx
            .signing_digest_with_chain_domain(input_index, cfg.network_id.as_bytes())
            .map_err(|e| {
                NodeError::Runtime(format!("input #{input_index} signing digest failed: {e}"))
            })?;
        let sig_ok = verify_digest(digest.0, signature, pubkey)?;
        if !sig_ok {
            return Err(NodeError::Runtime(format!(
                "input #{input_index} signature verification failed"
            )));
        }

        input_sum = input_sum
            .checked_add(prevout.value as u128)
            .ok_or_else(|| NodeError::Runtime("input value overflow".to_owned()))?;
    }

    if !missing.is_empty() {
        return Err(NodeError::Runtime(format!(
            "transaction has unresolved inputs: {}",
            missing.join(", ")
        )));
    }
    if input_sum < output_sum {
        return Err(NodeError::Runtime(format!(
            "transaction overspends: inputs={} outputs={}",
            input_sum, output_sum
        )));
    }
    let fee = input_sum.saturating_sub(output_sum);
    u64::try_from(fee).map_err(|_| NodeError::Runtime("transaction fee overflow".to_owned()))
}

fn mempool_outcome_label(outcome: &InsertOutcome) -> &'static str {
    match outcome {
        InsertOutcome::Accepted { .. } => "accepted",
        InsertOutcome::Replaced { .. } => "replaced",
        InsertOutcome::AcceptedWithEviction { .. } => "accepted_with_eviction",
        InsertOutcome::AlreadyPresent { .. } => "already_present",
        InsertOutcome::RejectedConflictInsufficientFee { .. } => {
            "rejected_conflict_insufficient_fee"
        }
        InsertOutcome::RejectedConflictInsufficientFeerate { .. } => {
            "rejected_conflict_insufficient_feerate"
        }
    }
}

fn submit_tx_via_mempool_db(
    cfg: &ChainConfig,
    runtime_db_path: &Path,
    mempool_db_path: &Path,
    tx: Transaction,
    requested_fee: u64,
) -> Result<(Hash256, String, u64), NodeError> {
    let (runtime, _) = load_runtime_from_db_or_genesis(cfg, runtime_db_path)?;
    let mut mempool = load_mempool_from_db_or_empty(cfg, mempool_db_path)?;
    let implied_fee = validate_tx_for_local_admission(cfg, &runtime, &mempool, &tx)?;
    let fee = if requested_fee == 0 {
        implied_fee
    } else {
        requested_fee
    };
    if fee < implied_fee {
        return Err(NodeError::Runtime(format!(
            "provided fee {} is lower than implied fee {}",
            fee, implied_fee
        )));
    }
    let txid = tx.txid();
    let outcome = mempool.insert_with_fee(tx, fee)?;
    persist_mempool_db_with_retry(cfg, &mempool, mempool_db_path, 80, 25)?;
    Ok((txid, mempool_outcome_label(&outcome).to_owned(), fee))
}

fn share_target_in_bounds(
    share_target: Target,
    min_share_target: Target,
    max_share_target: Target,
) -> bool {
    share_target >= min_share_target && share_target <= max_share_target
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

fn reorg_min_difficulty_window(window: u32) -> u32 {
    window.max(50)
}

fn is_tx_flow_enabled(txs_per_round: u32) -> bool {
    txs_per_round > 0
}

fn soak_recipient_key_hash(
    tx_index: u32,
    recipient_key_hash20: [u8; 20],
    miner_key_hash: [u8; 20],
) -> [u8; 20] {
    if tx_index.is_multiple_of(2) {
        recipient_key_hash20
    } else {
        miner_key_hash
    }
}

fn soak_tx_fee_for_index(base_fee: u64, tx_index: u32) -> u64 {
    base_fee.saturating_add((tx_index % 4) as u64)
}

fn soak_peer_id_for_round(round: u32, tx_index: u32, simulated_peers: u32) -> u64 {
    ((round as u64 + tx_index as u64) % simulated_peers as u64) + 1
}

fn should_persist_round(round: u32, persist_every_rounds: u32) -> bool {
    persist_every_rounds != 0 && round.is_multiple_of(persist_every_rounds)
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
            configure_stream_timeouts_with_ops(
                |duration| stream.set_read_timeout(duration),
                |duration| stream.set_write_timeout(duration),
                Duration::from_secs(3),
                Duration::from_secs(3),
            )?;
            let request: TemplateProviderRequest = read_role_request(&mut stream)?;
            let reward_key_hash20 =
                decode_fixed_hex::<20>("reward_key_hash20_hex", &request.reward_key_hash20_hex)?;
            let prev_hash = Hash256(decode_fixed_hex::<32>(
                "prev_hash_hex",
                &request.prev_hash_hex,
            )?);
            let coinbase = build_coinbase_tx(
                stratum_coinbase_tag(&request.coinbase_label, prev_hash),
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
            configure_stream_timeouts_with_ops(
                |duration| stream.set_read_timeout(duration),
                |duration| stream.set_write_timeout(duration),
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
            configure_stream_timeouts_with_ops(
                |duration| stream.set_read_timeout(duration),
                |duration| stream.set_write_timeout(duration),
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
    let mempool_db_path = default_mempool_db_path(&runtime_db_path);
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
    if !share_target_in_bounds(share_target, min_share_target, max_share_target) {
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
    println!("Mempool DB: {}", mempool_db_path.display());
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
    println!("Max clients before exit: {}", args.max_clients);
    let max_template_txs = cfg.max_mempool_txs as usize;

    let ctx = StratumServerContext {
        cfg,
        runtime: Arc::new(Mutex::new(runtime)),
        runtime_db_path,
        mempool_db_path,
        max_template_txs,
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
                if let Err(err) = &result {
                    eprintln!("stratum worker error: {err}");
                }
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
    configure_stream_timeouts_with_ops(
        |duration| stream.set_read_timeout(duration),
        |duration| stream.set_write_timeout(duration),
        timeout,
        timeout,
    )?;
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
    if should_require_noise_static_key(
        args.secure_transport,
        secure_transport_mode,
        secure_static_private_key.is_some(),
    ) {
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
    macro_rules! send_sv2_sync {
        ($message:expr) => {{
            match secure_transport.as_mut() {
                Some(StratumSecureTransport::Legacy(transport)) => transport
                    .write_message(&mut stream, $message)
                    .map_err(|e| {
                        NodeError::Runtime(format!("stratum secure(legacy) write failed: {e}"))
                    })?,
                Some(StratumSecureTransport::Noise(transport)) => transport
                    .write_message(&mut stream, $message)
                    .map_err(|e| {
                        NodeError::Runtime(format!("stratum secure(noise_xx) write failed: {e}"))
                    })?,
                None => write_sv2_frame(&mut stream, $message)
                    .map_err(|e| NodeError::Runtime(format!("stratum write failed: {e}")))?,
            }
        }};
    }

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
    send_sv2_sync!(&Sv2Message::SetupConnection {
        protocol: 2,
        min_version: SUPPORTED_SV2_VERSION,
        max_version: SUPPORTED_SV2_VERSION,
        flags: 0,
        user_agent: "scam-node/stratum-mine".to_owned(),
    });

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
                            send_sv2_sync!(&Sv2Message::SubmitSharesStandard {
                                channel_id: job.channel_id,
                                job_id,
                                nonce,
                                ntime: job.ntime,
                            });
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
                } else if should_emit_miner_keepalive(last_io.elapsed().as_secs()) {
                    send_sv2_sync!(&Sv2Message::KeepAlive);
                    last_io = Instant::now();
                }
            }
            StratumReadOutcome::Message(message) => match message {
                Sv2Message::SetupConnectionSuccess { .. } => {
                    if should_send_open_standard_channel(open_sent) {
                        send_sv2_sync!(&Sv2Message::OpenStandardMiningChannel {
                            request_id: 1,
                            user: args.user.clone(),
                        });
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
                    if should_apply_set_target(channel_id, msg_channel) {
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
                    if should_apply_set_new_prev_hash(channel_id, msg_channel)
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
                    send_sv2_sync!(&Sv2Message::KeepAlive);
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

    if let Some(parent) = nonempty_parent_dir(&args.secret_out) {
        fs::create_dir_all(parent).map_err(|e| {
            NodeError::Runtime(format!(
                "cannot create secret key directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    if let Some(parent) = nonempty_parent_dir(&args.public_out) {
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

fn update_sv2_conformance_state(
    setup_success: &mut bool,
    channel_opened: &mut bool,
    job_messages_seen: &mut u32,
    set_target_seen: &mut bool,
    errors: &mut Vec<String>,
    response: &Sv2Message,
) {
    match response {
        Sv2Message::SetupConnectionSuccess { .. } => *setup_success = true,
        Sv2Message::SetupConnectionError { code, reason } => {
            errors.push(format!("setup error: code={code} reason={reason}"));
        }
        Sv2Message::OpenStandardMiningChannelSuccess { .. } => *channel_opened = true,
        Sv2Message::OpenStandardMiningChannelError { code, reason, .. } => {
            errors.push(format!("open channel error: code={code} reason={reason}"));
        }
        Sv2Message::NewMiningJob { .. } | Sv2Message::SetNewPrevHash { .. } => {
            *job_messages_seen = job_messages_seen.saturating_add(1);
        }
        Sv2Message::SetTarget { .. } => {
            *set_target_seen = true;
        }
        _ => {}
    }
}

fn sv2_conformance_pass(setup_success: bool, channel_opened: bool, errors: &[String]) -> bool {
    setup_success && channel_opened && errors.is_empty()
}

fn ensure_sv2_conformance_pass(pass: bool) -> Result<(), NodeError> {
    if pass {
        Ok(())
    } else {
        Err(NodeError::Runtime(
            "sv2 conformance check failed (see report)".to_owned(),
        ))
    }
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

fn read_next_sv2_message_with<F>(
    attempts: usize,
    mut read_once: F,
) -> Result<Option<Sv2Message>, NodeError>
where
    F: FnMut() -> Result<StratumReadOutcome, NodeError>,
{
    for _ in 0..attempts.max(1) {
        match read_once()? {
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
    configure_stream_timeouts_with_ops(
        |duration| stream.set_read_timeout(duration),
        |duration| stream.set_write_timeout(duration),
        timeout,
        timeout,
    )?;

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
    if should_require_noise_static_key(
        args.secure_transport,
        secure_transport_mode,
        secure_static_private_key.is_some(),
    ) {
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
    macro_rules! send_sv2_sync {
        ($message:expr) => {{
            match secure_transport.as_mut() {
                Some(StratumSecureTransport::Legacy(transport)) => transport
                    .write_message(&mut stream, $message)
                    .map_err(|e| {
                        NodeError::Runtime(format!("stratum secure(legacy) write failed: {e}"))
                    })?,
                Some(StratumSecureTransport::Noise(transport)) => transport
                    .write_message(&mut stream, $message)
                    .map_err(|e| {
                        NodeError::Runtime(format!("stratum secure(noise_xx) write failed: {e}"))
                    })?,
                None => write_sv2_frame(&mut stream, $message)
                    .map_err(|e| NodeError::Runtime(format!("stratum write failed: {e}")))?,
            }
        }};
    }

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
        send_sv2_sync!(&message);
        let received = match read_next_sv2_message_with(3, || {
            read_sv2_message(&mut stream, secure_transport.as_mut())
        })? {
            Some(response) => {
                let kind = sv2_message_kind(&response).to_owned();
                observed_messages.push(kind.clone());
                update_sv2_conformance_state(
                    &mut setup_success,
                    &mut channel_opened,
                    &mut job_messages_seen,
                    &mut set_target_seen,
                    &mut errors,
                    &response,
                );
                Some(kind)
            }
            None => None,
        };
        steps.push(Sv2ConformanceStep { sent, received });
    }

    for _ in 0..8 {
        let Some(msg) = read_next_sv2_message_with(1, || {
            read_sv2_message(&mut stream, secure_transport.as_mut())
        })?
        else {
            break;
        };
        let kind = sv2_message_kind(&msg).to_owned();
        observed_messages.push(kind.clone());
        update_sv2_conformance_state(
            &mut setup_success,
            &mut channel_opened,
            &mut job_messages_seen,
            &mut set_target_seen,
            &mut errors,
            &msg,
        );
    }

    let pass = sv2_conformance_pass(setup_success, channel_opened, &errors);
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
        if let Some(parent) = nonempty_parent_dir(path) {
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
    ensure_sv2_conformance_pass(report.pass)
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

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct WalletBalanceByAddressRpcRequest {
    address: String,
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

#[derive(Debug, Deserialize)]
#[serde(default)]
struct TxSubmitRpcRequest {
    tx_hex: String,
    fee: u64,
}

impl Default for TxSubmitRpcRequest {
    fn default() -> Self {
        Self {
            tx_hex: String::new(),
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
    tx_bincode_hex: String,
    amount: u64,
    fee: u64,
    input_total: u64,
    change: u64,
    is_self_transfer: bool,
    selected_inputs: Vec<WalletSendPreviewInput>,
}

#[derive(Debug, Serialize)]
struct WalletSendRpcResponse {
    network_id: String,
    txid: String,
    fee: u64,
    amount: u64,
    input_total: u64,
    change: u64,
    is_self_transfer: bool,
    mempool_outcome: String,
    selected_inputs: Vec<WalletSendPreviewInput>,
}

#[derive(Debug, Serialize)]
struct TxSubmitRpcResponse {
    network_id: String,
    txid: String,
    fee: u64,
    mempool_outcome: String,
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
    tx_count: Option<usize>,
    txids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RpcEventSnapshot {
    network_id: String,
    tip_height: u64,
    tip_hash: String,
    utxo_count: usize,
    cumulative_work: String,
    mempool_available: bool,
    mempool_tx_count: usize,
    unix_sec: u64,
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

fn mempool_tx_count_from_db(mempool_db_path: &Path) -> Result<(bool, usize), NodeError> {
    if !mempool_db_path.exists() {
        return Ok((false, 0));
    }
    let snapshot = load_mempool_db(mempool_db_path)?;
    Ok((true, snapshot.entries.len()))
}

fn build_rpc_event_snapshot(
    cfg: &ChainConfig,
    runtime: &ChainRuntime,
    mempool_db_path: &Path,
) -> Result<RpcEventSnapshot, NodeError> {
    let (mempool_available, mempool_tx_count) = mempool_tx_count_from_db(mempool_db_path)?;
    Ok(RpcEventSnapshot {
        network_id: cfg.network_id.clone(),
        tip_height: runtime.tip_height(),
        tip_hash: runtime.tip_hash().to_hex(),
        utxo_count: runtime.utxo_len(),
        cumulative_work: runtime.cumulative_work().to_str_radix(10),
        mempool_available,
        mempool_tx_count,
        unix_sec: current_unix_sec()?,
    })
}

fn write_http_response<W: Write>(
    stream: &mut W,
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

fn write_http_json_response<W: Write>(
    stream: &mut W,
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

fn write_http_sse_headers<W: Write>(stream: &mut W) -> Result<(), NodeError> {
    let headers = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/event-stream; charset=utf-8\r\n",
        "Cache-Control: no-cache\r\n",
        "Connection: keep-alive\r\n",
        "\r\n"
    );
    stream
        .write_all(headers.as_bytes())
        .map_err(|e| NodeError::Runtime(format!("http write failed: {e}")))?;
    stream
        .flush()
        .map_err(|e| NodeError::Runtime(format!("http flush failed: {e}")))?;
    Ok(())
}

fn write_http_sse_event<W: Write>(
    stream: &mut W,
    event_name: &str,
    payload_json: &str,
) -> Result<(), NodeError> {
    let frame = format!("event: {event_name}\ndata: {payload_json}\n\n");
    stream
        .write_all(frame.as_bytes())
        .map_err(|e| NodeError::Runtime(format!("http write failed: {e}")))?;
    stream
        .flush()
        .map_err(|e| NodeError::Runtime(format!("http flush failed: {e}")))?;
    Ok(())
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

fn http_io_error_is_timeout_like(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
    )
}

fn http_io_error_is_closed_like(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
    )
}

fn read_http_request<R: Read>(stream: &mut R) -> Result<Option<HttpRequest>, NodeError> {
    let mut buffer = Vec::<u8>::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut header_end = None::<usize>;
    let mut content_length = 0usize;

    loop {
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(err) if http_io_error_is_timeout_like(&err) => {
                if buffer.is_empty() {
                    return Ok(None);
                }
                return Err(NodeError::Runtime(format!(
                    "http read timeout while waiting for full request: {err}"
                )));
            }
            Err(err) if http_io_error_is_closed_like(&err) => {
                if buffer.is_empty() {
                    return Ok(None);
                }
                return Err(NodeError::Runtime(format!(
                    "http connection closed while reading request: {err}"
                )));
            }
            Err(err) => {
                return Err(NodeError::Runtime(format!("http read failed: {err}")));
            }
        };
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

fn ui_dir_is_servable(ui_dir: &Path) -> bool {
    ui_dir.exists() && ui_dir.is_dir()
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok()?.modified().ok()
}

fn runtime_db_mtime(path: &Path) -> Option<SystemTime> {
    file_mtime(path)
}

fn mempool_db_mtime(path: &Path) -> Option<SystemTime> {
    file_mtime(path)
}

fn refresh_runtime_from_db_if_changed(
    cfg: &ChainConfig,
    runtime: &mut ChainRuntime,
    runtime_db_path: &Path,
    last_seen_mtime: &mut Option<SystemTime>,
) -> Result<(), NodeError> {
    let current_mtime = runtime_db_mtime(runtime_db_path);
    if current_mtime == *last_seen_mtime {
        return Ok(());
    }
    let mut fresh = None;
    for attempt in 0..10 {
        match load_runtime_from_db_or_genesis(cfg, runtime_db_path) {
            Ok((loaded, _source)) => {
                fresh = Some(loaded);
                break;
            }
            Err(err) if is_runtime_db_lock_conflict(&err) => {
                if attempt < 9 {
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                // Another process owns the runtime DB lock at the moment.
                // Keep serving with the latest in-memory runtime and retry refresh on next request.
                return Ok(());
            }
            Err(err) => return Err(err),
        }
    }
    let Some(fresh) = fresh else {
        return Ok(());
    };
    *runtime = fresh;
    *last_seen_mtime = current_mtime;
    Ok(())
}

fn refresh_mempool_from_db_if_changed(
    cfg: &ChainConfig,
    relay: &mut RelayAdmissionState,
    mempool_db_path: &Path,
    last_seen_mtime: &mut Option<SystemTime>,
) -> Result<(), NodeError> {
    let current_mtime = mempool_db_mtime(mempool_db_path);
    if current_mtime == *last_seen_mtime {
        return Ok(());
    }

    let mut fresh = None;
    for attempt in 0..10 {
        match load_mempool_from_db_or_empty(cfg, mempool_db_path) {
            Ok(mempool) => {
                fresh = Some(mempool);
                break;
            }
            Err(err) if is_mempool_db_lock_conflict(&err) => {
                if attempt < 9 {
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                // Another process owns the mempool DB lock right now.
                // Keep serving with the latest in-memory mempool and retry later.
                return Ok(());
            }
            Err(err) => return Err(err),
        }
    }
    if let Some(mempool) = fresh {
        relay.mempool = mempool;
        *last_seen_mtime = current_mtime;
    }
    Ok(())
}

fn try_serve_ui_asset<W: Write>(
    stream: &mut W,
    ui_dir: &Path,
    request_path: &str,
) -> Result<bool, NodeError> {
    if ui_dir_is_servable(ui_dir) {
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
    } else {
        Ok(false)
    }
}

fn rpc_exact_route_matches(
    method: &str,
    path: &str,
    expected_method: &str,
    expected_path: &str,
) -> bool {
    method == expected_method && path == expected_path
}

fn is_get_method(method: &str) -> bool {
    method == "GET"
}

fn rpc_block_height_path<'a>(method: &str, path: &'a str) -> Option<&'a str> {
    if is_get_method(method) {
        path.strip_prefix("/block/")
    } else {
        None
    }
}

fn rpc_tx_path_parts<'a>(method: &str, path: &'a str) -> Option<(&'a str, &'a str, bool)> {
    if !is_get_method(method) {
        return None;
    }
    let rest = path.strip_prefix("/tx/")?;
    let mut segments = rest.split('/');
    let height_raw = segments.next().unwrap_or_default();
    let index_raw = segments.next().unwrap_or_default();
    let has_extra = segments.next().is_some();
    Some((height_raw, index_raw, has_extra))
}

fn rpc_tx_path_is_invalid(height_raw: &str, index_raw: &str, has_extra: bool) -> bool {
    height_raw.is_empty() || index_raw.is_empty() || has_extra
}

fn parse_tx_height_and_index(height_raw: &str, index_raw: &str) -> Option<(u64, usize)> {
    match (height_raw.parse::<u64>(), index_raw.parse::<usize>()) {
        (Ok(height), Ok(index)) => Some((height, index)),
        _ => None,
    }
}

fn address_hrp_is_accepted(accepted_hrps: &[String], hrp: &str) -> bool {
    accepted_hrps.iter().any(|candidate| candidate == hrp)
}

fn should_reject_send_preview_hrp(accepted_hrps: &[String], hrp: &str) -> bool {
    !address_hrp_is_accepted(accepted_hrps, hrp)
}

fn should_attempt_ui_asset_serve(method: &str) -> bool {
    is_get_method(method)
}

fn should_serve_ui_asset_for_route(method: &str, ui_served: bool) -> bool {
    should_attempt_ui_asset_serve(method) && ui_served
}

fn should_reply_bad_http_request(err: &NodeError) -> bool {
    match err {
        NodeError::Runtime(msg) => {
            !(msg.contains("http read timeout while waiting for full request")
                || msg.contains("http connection closed while reading request"))
        }
        _ => true,
    }
}

fn rpc_sse_write_error_is_closed_like(err: &NodeError) -> bool {
    match err {
        NodeError::Runtime(msg) => {
            let lowered = msg.to_ascii_lowercase();
            lowered.contains("broken pipe")
                || lowered.contains("connection reset")
                || lowered.contains("connection aborted")
                || lowered.contains("not connected")
        }
        _ => false,
    }
}

fn rpc_events_worker_should_continue(stop_flag: &AtomicBool) -> bool {
    !stop_flag.load(Ordering::Relaxed)
}

fn reap_finished_rpc_event_workers(handles: &mut Vec<thread::JoinHandle<()>>) {
    let mut idx = 0usize;
    while idx < handles.len() {
        if handles[idx].is_finished() {
            let handle = handles.swap_remove(idx);
            let _ = handle.join();
            continue;
        }
        idx += 1;
    }
}

fn run_rpc_events_worker(
    mut stream: TcpStream,
    cfg: ChainConfig,
    runtime_db_path: PathBuf,
    mempool_db_path: PathBuf,
    stop_flag: Arc<AtomicBool>,
    interval: Duration,
) -> Result<(), NodeError> {
    let (mut runtime, _) = load_runtime_from_db_or_genesis(&cfg, &runtime_db_path)?;
    let mut runtime_db_seen_mtime = runtime_db_mtime(&runtime_db_path);
    if let Err(err) = write_http_sse_headers(&mut stream) {
        if rpc_sse_write_error_is_closed_like(&err) {
            return Ok(());
        }
        return Err(err);
    }

    while rpc_events_worker_should_continue(&stop_flag) {
        refresh_runtime_from_db_if_changed(
            &cfg,
            &mut runtime,
            &runtime_db_path,
            &mut runtime_db_seen_mtime,
        )?;
        let snapshot = build_rpc_event_snapshot(&cfg, &runtime, &mempool_db_path)?;
        let payload = serde_json::to_string(&snapshot)
            .map_err(|e| NodeError::Runtime(format!("events serialization failed: {e}")))?;
        if let Err(err) = write_http_sse_event(&mut stream, "snapshot", &payload) {
            if rpc_sse_write_error_is_closed_like(&err) {
                return Ok(());
            }
            return Err(err);
        }
        thread::sleep(interval);
    }
    Ok(())
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
    let runtime_db_path = runtime_db
        .clone()
        .unwrap_or_else(|| default_runtime_db_path(network));
    let mempool_db_path = default_mempool_db_path(&runtime_db_path);
    let (cfg, mut runtime) = build_runtime_for_query(
        network,
        config,
        Some(runtime_db_path.clone()),
        mine_blocks,
        interval_sec,
        max_nonce,
        "rpc-serve",
    )?;
    let mut runtime_db_seen_mtime = runtime_db_mtime(&runtime_db_path);

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
        "Endpoints: GET /health, /status, /block/<height>, /tx/<height>/<index>, /mempool, /events; POST /wallet/new, /wallet/address, /wallet/decode, /wallet/balance, /wallet/balance-by-address, /wallet/send-preview, /wallet/send, /tx/submit, /wallet/qr"
    );
    println!("UI assets directory: {}", ui_dir.display());
    println!("Mempool DB source: {}", mempool_db_path.display());
    if let Some(path) = relay_telemetry.as_ref() {
        println!("Relay telemetry source: {}", path.display());
    }
    if max_requests_reached(max_requests, max_requests) {
        println!("Max requests before exit: {}", max_requests);
    }

    let events_stop_flag = Arc::new(AtomicBool::new(false));
    let mut events_workers = Vec::<thread::JoinHandle<()>>::new();
    let events_interval = Duration::from_secs(1);

    let mut served = 0u32;
    for incoming in listener.incoming() {
        reap_finished_rpc_event_workers(&mut events_workers);
        let mut stream =
            incoming.map_err(|e| NodeError::Runtime(format!("rpc accept failed: {e}")))?;
        configure_stream_timeouts_with_ops(
            |duration| stream.set_read_timeout(duration),
            |duration| stream.set_write_timeout(duration),
            DEFAULT_STREAM_TIMEOUT,
            DEFAULT_STREAM_TIMEOUT,
        )?;

        let request = match read_http_request(&mut stream) {
            Ok(Some(request)) => request,
            Ok(None) => continue,
            Err(err) => {
                if should_reply_bad_http_request(&err) {
                    let body = json_error_body(&err.to_string());
                    let _ = write_http_json_response(&mut stream, "400 Bad Request", &body);
                }
                continue;
            }
        };

        let method = request.method.as_str();
        let path = request.path.as_str();
        if rpc_exact_route_matches(method, path, "GET", "/events") {
            let cfg_clone = cfg.clone();
            let runtime_db_path_clone = runtime_db_path.clone();
            let mempool_db_path_clone = mempool_db_path.clone();
            let stop_clone = events_stop_flag.clone();
            events_workers.push(thread::spawn(move || {
                if let Err(err) = run_rpc_events_worker(
                    stream,
                    cfg_clone,
                    runtime_db_path_clone,
                    mempool_db_path_clone,
                    stop_clone,
                    events_interval,
                ) {
                    eprintln!("warning: rpc events stream failed: {err}");
                }
            }));
            served = served.saturating_add(1);
            if max_requests_reached(max_requests, served) {
                break;
            }
            continue;
        }
        refresh_runtime_from_db_if_changed(
            &cfg,
            &mut runtime,
            &runtime_db_path,
            &mut runtime_db_seen_mtime,
        )?;
        let (status, body) = if rpc_exact_route_matches(method, path, "GET", "/health") {
            ("200 OK", "{\"ok\":true}".to_owned())
        } else if rpc_exact_route_matches(method, path, "GET", "/status") {
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
        } else if rpc_exact_route_matches(method, path, "GET", "/mempool") {
            let (mempool_tx_count, mempool_txids) = if mempool_db_path.exists() {
                match load_mempool_db(&mempool_db_path) {
                    Ok(snapshot) => (
                        Some(snapshot.entries.len()),
                        snapshot
                            .entries
                            .iter()
                            .map(|entry| entry.txid.to_hex())
                            .collect::<Vec<_>>(),
                    ),
                    Err(err) => {
                        let body = json_error_body(&format!(
                            "mempool db load failed ({}): {err}",
                            mempool_db_path.display()
                        ));
                        write_http_json_response(&mut stream, "500 Internal Server Error", &body)?;
                        continue;
                    }
                }
            } else {
                (None, Vec::new())
            };
            let summary = if let Some(telemetry_path) = relay_telemetry.as_ref() {
                match load_latest_jsonl_record::<RelayServerTelemetrySnapshot>(telemetry_path) {
                    Ok(Some(snapshot)) => MempoolSummaryRpcResponse {
                        available: true,
                        source: telemetry_path.display().to_string(),
                        snapshot: Some(snapshot),
                        tx_count: mempool_tx_count,
                        txids: mempool_txids.clone(),
                    },
                    Ok(None) => MempoolSummaryRpcResponse {
                        available: mempool_tx_count.is_some(),
                        source: telemetry_path.display().to_string(),
                        snapshot: None,
                        tx_count: mempool_tx_count,
                        txids: mempool_txids.clone(),
                    },
                    Err(err) => {
                        let body = json_error_body(&err.to_string());
                        write_http_json_response(&mut stream, "500 Internal Server Error", &body)?;
                        continue;
                    }
                }
            } else {
                MempoolSummaryRpcResponse {
                    available: mempool_tx_count.is_some(),
                    source: format!("mempool db: {}", mempool_db_path.display()),
                    snapshot: None,
                    tx_count: mempool_tx_count,
                    txids: mempool_txids,
                }
            };
            match to_pretty_json(&summary) {
                Ok(body) => ("200 OK", body),
                Err(e) => (
                    "500 Internal Server Error",
                    json_error_body(&format!("mempool summary serialization failed: {e}")),
                ),
            }
        } else if let Some(height_raw) = rpc_block_height_path(method, path) {
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
        } else if let Some((height_raw, index_raw, has_extra)) = rpc_tx_path_parts(method, path) {
            if rpc_tx_path_is_invalid(height_raw, index_raw, has_extra) {
                (
                    "400 Bad Request",
                    json_error_body("tx path must be /tx/<height>/<index>"),
                )
            } else {
                match parse_tx_height_and_index(height_raw, index_raw) {
                    Some((height, index)) => match runtime.block_hash_at_height(height) {
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
                    None => (
                        "400 Bad Request",
                        json_error_body("invalid tx path numbers, expected /tx/<height>/<index>"),
                    ),
                }
            }
        } else if rpc_exact_route_matches(method, path, "POST", "/wallet/new") {
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
        } else if rpc_exact_route_matches(method, path, "POST", "/wallet/address") {
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
        } else if rpc_exact_route_matches(method, path, "POST", "/wallet/decode") {
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
        } else if rpc_exact_route_matches(method, path, "POST", "/wallet/balance") {
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
        } else if rpc_exact_route_matches(method, path, "POST", "/wallet/balance-by-address") {
            let req = match parse_json_body::<WalletBalanceByAddressRpcRequest>(&request) {
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
            let accepted_hrps = accepted_hrps_for_network(network, &cfg.hrp);
            if should_reject_send_preview_hrp(&accepted_hrps, &decoded.hrp) {
                let body = json_error_body(&format!(
                    "address hrp '{}' is not valid for network '{}' (accepted: {})",
                    decoded.hrp,
                    cfg.network_id,
                    accepted_hrps.join(", ")
                ));
                write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                continue;
            }
            let payload =
                wallet_balance_response(&runtime, &cfg, 0, 0, req.address, decoded.key_hash20);
            match to_pretty_json(&payload) {
                Ok(body) => ("200 OK", body),
                Err(e) => (
                    "500 Internal Server Error",
                    json_error_body(&format!(
                        "wallet balance-by-address serialization failed: {e}"
                    )),
                ),
            }
        } else if rpc_exact_route_matches(method, path, "POST", "/wallet/send-preview") {
            let req = match parse_json_body::<WalletSendPreviewRpcRequest>(&request) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            if wallet_send_preview_has_invalid_amount(req.amount) {
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
            if should_reject_send_preview_hrp(&accepted_hrps, &recipient.hrp) {
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
                tx_bincode_hex: hex::encode(
                    bincode::serialize(&signed.tx)
                        .map_err(|e| NodeError::Runtime(format!("tx encode failed: {e}")))?,
                ),
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
        } else if rpc_exact_route_matches(method, path, "POST", "/wallet/send") {
            let req = match parse_json_body::<WalletSendPreviewRpcRequest>(&request) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            if wallet_send_preview_has_invalid_amount(req.amount) {
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
            if should_reject_send_preview_hrp(&accepted_hrps, &recipient.hrp) {
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
            let (txid, outcome, effective_fee) = match submit_tx_via_mempool_db(
                &cfg,
                &runtime_db_path,
                &mempool_db_path,
                signed.tx.clone(),
                req.fee,
            ) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let payload = WalletSendRpcResponse {
                network_id: cfg.network_id.clone(),
                txid: txid.to_hex(),
                fee: effective_fee,
                amount: req.amount,
                input_total: signed.input_total,
                change: signed.change_value,
                is_self_transfer: signed.is_self_transfer,
                mempool_outcome: outcome,
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
        } else if rpc_exact_route_matches(method, path, "POST", "/tx/submit") {
            let req = match parse_json_body::<TxSubmitRpcRequest>(&request) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            if tx_submit_has_invalid_payload(&req.tx_hex) {
                let body = json_error_body("tx_hex must not be empty");
                write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                continue;
            }
            let tx = match decode_tx_from_bincode_hex(&req.tx_hex) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let (txid, outcome, effective_fee) = match submit_tx_via_mempool_db(
                &cfg,
                &runtime_db_path,
                &mempool_db_path,
                tx,
                req.fee,
            ) {
                Ok(value) => value,
                Err(err) => {
                    let body = json_error_body(&err.to_string());
                    write_http_json_response(&mut stream, "400 Bad Request", &body)?;
                    continue;
                }
            };
            let payload = TxSubmitRpcResponse {
                network_id: cfg.network_id.clone(),
                txid: txid.to_hex(),
                fee: effective_fee,
                mempool_outcome: outcome,
            };
            match to_pretty_json(&payload) {
                Ok(body) => ("200 OK", body),
                Err(e) => (
                    "500 Internal Server Error",
                    json_error_body(&format!("tx submit serialization failed: {e}")),
                ),
            }
        } else if rpc_exact_route_matches(method, path, "POST", "/wallet/qr") {
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
            let ui_served = if should_attempt_ui_asset_serve(method) {
                try_serve_ui_asset(&mut stream, &ui_dir, path)?
            } else {
                false
            };
            if should_serve_ui_asset_for_route(method, ui_served) {
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
    events_stop_flag.store(true, Ordering::Relaxed);
    for handle in events_workers {
        let _ = handle.join();
    }
    Ok(())
}

fn run_command(cli: Cli) -> Result<(), NodeError> {
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

fn run_from_args<I, T>(args: I) -> Result<(), NodeError>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::try_parse_from(args).map_err(|e| NodeError::Runtime(e.to_string()))?;
    run_command(cli)
}

fn main() {
    if let Err(err) = run_from_args(std::env::args_os()) {
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
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use scam_chain::ChainRuntime;
    use scam_core::{ChainConfig, Hash256, OutPoint, Target, Transaction, TxIn, TxOut};
    use scam_mempool::{Mempool, OrphanPool};
    use scam_miner::{BlockTemplate, mine_block};
    use scam_p2p::{
        FramingConfig, GossipEngine, InventoryItem, LocalHandshake, ReplacementRateLimit,
        WireMessage, client_handshake, read_message, send_message, server_handshake,
    };
    use scam_storage::{
        MempoolSnapshot, PeerAddressBook, PeerAddressRecord, load_chain_archive_db,
        load_peer_book_db, save_mempool_db,
    };
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
        process_relay_wire_message, relay_fee_hint, request_template_from_provider, run_add_peer,
        run_config_scaffold, run_reindex_runtime, run_rpc_serve, run_stratum_mine,
        run_stratum_serve, run_sv2_conformance, run_sv2_job_declarator, run_sv2_template_provider,
        run_sv2_translator, run_sync_book, run_wallet, select_utxos_for_amount,
        translate_remote_job_with_service, try_find_share_for_job,
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

    fn network_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
        let mut cursor = std::io::Cursor::new(raw.to_vec());
        super::read_http_request(&mut cursor)
    }

    fn connect_with_retry(addr: &str) -> TcpStream {
        let mut last_err = None;
        for _ in 0..200 {
            match TcpStream::connect(addr) {
                Ok(stream) => return stream,
                Err(err) => {
                    last_err = Some(err);
                    thread::sleep(Duration::from_millis(25));
                }
            }
        }
        panic!(
            "connect retry exhausted for {addr}; last error: {}",
            last_err
                .map(|err| err.to_string())
                .unwrap_or_else(|| "unknown".to_owned())
        );
    }

    fn send_http_request(addr: &str, request: &str) -> String {
        let mut stream = connect_with_retry(addr);
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .expect("set write timeout");
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

    fn send_http_request_until(
        addr: &str,
        request: &str,
        expected_fragment: &str,
        timeout: Duration,
    ) -> String {
        let mut stream = connect_with_retry(addr);
        stream
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("set read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .expect("set write timeout");
        stream
            .write_all(request.as_bytes())
            .expect("write request bytes");
        stream
            .shutdown(Shutdown::Write)
            .expect("shutdown write half");
        let start = Instant::now();
        let mut response = String::new();
        let mut buffer = [0u8; 1024];
        while start.elapsed() < timeout {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    response.push_str(&String::from_utf8_lossy(&buffer[..read]));
                    if response.contains(expected_fragment) {
                        break;
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(err) => panic!("read response: {err}"),
            }
        }
        response
    }

    fn join_with_timeout<T: Send + 'static>(
        handle: thread::JoinHandle<T>,
        timeout: Duration,
        label: &str,
    ) -> T {
        let (tx, rx) = mpsc::sync_channel(1);
        let label_owned = label.to_owned();
        thread::spawn(move || {
            let _ = tx.send(handle.join());
        });
        match rx.recv_timeout(timeout) {
            Ok(joined) => match joined {
                Ok(value) => value,
                Err(_) => panic!("{label_owned} thread panicked"),
            },
            Err(_) => panic!(
                "{label_owned} thread did not finish within {} ms",
                timeout.as_millis()
            ),
        }
    }

    fn spawn_sync_peer_server_from_runtime(
        cfg: &ChainConfig,
        remote: &ChainRuntime,
    ) -> Option<(String, thread::JoinHandle<Result<(), String>>)> {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(err) => panic!("bind sync peer: {err}"),
        };
        let addr = listener.local_addr().expect("addr").to_string();

        let remote_tip = remote.tip_height();
        let remote_chain = remote.block_hashes().to_vec();
        let network_id = cfg.network_id.clone();
        let mut remote_headers =
            std::collections::HashMap::<Hash256, scam_core::BlockHeader>::new();
        let mut remote_blocks_by_hash =
            std::collections::HashMap::<Hash256, scam_core::Block>::new();
        for hash in &remote_chain {
            if let Some(header) = remote.header_by_hash(hash) {
                remote_headers.insert(*hash, header.clone());
            }
            if let Some(block) = remote.block_by_hash(hash) {
                remote_blocks_by_hash.insert(*hash, block.clone());
            }
        }

        let handle = thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener.accept().map_err(|e| e.to_string())?;
            super::configure_stream_timeouts_with_ops(
                |duration| stream.set_read_timeout(duration),
                |duration| stream.set_write_timeout(duration),
                super::DEFAULT_STREAM_TIMEOUT,
                super::DEFAULT_STREAM_TIMEOUT,
            )
            .map_err(|e| e.to_string())?;
            let framing = FramingConfig::default();
            let local_hello = LocalHandshake {
                protocol_version: 1,
                network_id: network_id.clone(),
                user_agent: "scam-node/test-sync-peer".to_owned(),
                start_height: remote_tip,
            };
            let remote_peer =
                server_handshake(&mut stream, &framing, &local_hello).map_err(|e| e.to_string())?;
            if remote_peer.network_id != network_id {
                return Err(format!(
                    "network mismatch: expected {network_id}, got {}",
                    remote_peer.network_id
                ));
            }

            let request = read_message(&mut stream, &framing).map_err(|e| e.to_string())?;
            match request {
                WireMessage::GetHeaders { locator, stop } => {
                    let headers = super::select_headers_for_peer(
                        &remote_chain,
                        &remote_headers,
                        &locator,
                        stop,
                        2_000,
                    );
                    send_message(&mut stream, &WireMessage::Headers { headers }, &framing)
                        .map_err(|e| e.to_string())?;
                }
                other => return Err(format!("expected getheaders, got {other:?}")),
            }

            let request = read_message(&mut stream, &framing).map_err(|e| e.to_string())?;
            match request {
                WireMessage::GetBlocks { locator, stop } => {
                    let hashes =
                        super::select_block_hashes_for_peer(&remote_chain, &locator, stop, 2_000);
                    let items = hashes.into_iter().map(InventoryItem::Block).collect();
                    send_message(&mut stream, &WireMessage::Inv { items }, &framing)
                        .map_err(|e| e.to_string())?;
                }
                other => return Err(format!("expected getblocks, got {other:?}")),
            }

            let request = read_message(&mut stream, &framing).map_err(|e| e.to_string())?;
            match request {
                WireMessage::GetData { items } => {
                    for item in items {
                        match item {
                            InventoryItem::Block(hash) => {
                                let Some(block) = remote_blocks_by_hash.get(&hash) else {
                                    return Err(format!("missing requested block {hash}"));
                                };
                                send_message(
                                    &mut stream,
                                    &WireMessage::Block {
                                        block: block.clone(),
                                    },
                                    &framing,
                                )
                                .map_err(|e| e.to_string())?;
                            }
                            InventoryItem::Tx(hash) => {
                                return Err(format!("unexpected tx getdata request {hash}"));
                            }
                        }
                    }
                }
                other => return Err(format!("expected getdata, got {other:?}")),
            }
            Ok(())
        });

        Some((addr, handle))
    }

    fn spawn_sync_peer_server(
        cfg: &ChainConfig,
        remote_blocks: u32,
    ) -> Option<(String, thread::JoinHandle<Result<(), String>>)> {
        let mut remote = ChainRuntime::from_config(cfg.clone()).expect("remote runtime");
        let params = super::MiningLoopParams {
            count: remote_blocks,
            interval_sec: cfg.target_block_time_sec,
            max_nonce: 500_000,
            subsidy: cfg.block_subsidy,
            miner_key_hash: cfg.genesis_reward_key_hash20().expect("key hash"),
            label_prefix: "sync-peer-test",
            print_each: false,
        };
        mine_blocks_on_runtime(&mut remote, &params).expect("mine remote chain");
        spawn_sync_peer_server_from_runtime(cfg, &remote)
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

        assert!(!super::is_tx_flow_enabled(0));
        assert!(super::is_tx_flow_enabled(1));
        let recipient = [0x11u8; 20];
        let miner = [0x22u8; 20];
        assert_eq!(
            super::soak_recipient_key_hash(0, recipient, miner),
            recipient
        );
        assert_eq!(super::soak_recipient_key_hash(1, recipient, miner), miner);
        assert_eq!(super::soak_tx_fee_for_index(100, 0), 100);
        assert_eq!(super::soak_tx_fee_for_index(100, 3), 103);
        assert_eq!(super::soak_peer_id_for_round(1, 0, 4), 2);
        assert_eq!(super::soak_peer_id_for_round(2, 3, 4), 2);
        assert!(super::should_persist_round(4, 2));
        assert!(!super::should_persist_round(3, 2));
        assert!(!super::should_persist_round(3, 0));
        assert!(!super::has_unknown_hashes(&[]));
        assert!(super::has_unknown_hashes(&[Hash256::ZERO]));

        assert!(super::has_inventory_delta_changes(1, 0));
        assert!(super::has_inventory_delta_changes(0, 1));
        assert!(!super::has_inventory_delta_changes(0, 0));

        let stop = std::sync::atomic::AtomicBool::new(false);
        assert!(super::relay_telemetry_thread_running(&stop));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(!super::relay_telemetry_thread_running(&stop));

        assert!(!super::should_stop_after_seen_messages(0, 100));
        assert!(!super::should_stop_after_seen_messages(2, 1));
        assert!(super::should_stop_after_seen_messages(2, 2));

        let io_timeout = std::io::Error::from(std::io::ErrorKind::TimedOut);
        let io_reset = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        let io_broken_pipe = std::io::Error::from(std::io::ErrorKind::BrokenPipe);
        let io_denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(super::relay_io_error_is_timeout_like(&io_timeout));
        assert!(!super::relay_io_error_is_timeout_like(&io_reset));
        assert!(!super::relay_io_error_is_timeout_like(&io_broken_pipe));
        assert!(!super::relay_io_error_is_closed_like(&io_timeout));
        assert!(super::relay_io_error_is_closed_like(&io_reset));
        assert!(super::relay_io_error_is_closed_like(&io_broken_pipe));
        assert!(!super::relay_io_error_is_closed_like(&io_denied));
        assert!(super::sv2_io_error_is_timeout_like(&io_timeout));
        assert!(!super::sv2_io_error_is_timeout_like(&io_reset));
        assert!(!super::http_io_error_is_timeout_like(&io_broken_pipe));
        assert!(super::http_io_error_is_closed_like(&io_reset));
        assert!(super::http_io_error_is_closed_like(&io_broken_pipe));
        assert!(!super::http_io_error_is_closed_like(&io_denied));

        assert!(!super::should_require_noise_static_key(
            false,
            super::SecureTransportMode::NoiseXx,
            false
        ));
        assert!(!super::should_require_noise_static_key(
            true,
            super::SecureTransportMode::Legacy,
            false
        ));
        assert!(!super::should_require_noise_static_key(
            true,
            super::SecureTransportMode::NoiseXx,
            true
        ));
        assert!(super::should_require_noise_static_key(
            true,
            super::SecureTransportMode::NoiseXx,
            false
        ));

        assert!(super::should_apply_set_new_prev_hash(Some(7), 7));
        assert!(!super::should_apply_set_new_prev_hash(Some(7), 8));
        assert!(!super::should_apply_set_new_prev_hash(None, 7));
        assert!(super::should_apply_set_target(Some(7), 7));
        assert!(!super::should_apply_set_target(Some(7), 8));
        assert!(!super::should_apply_set_target(None, 7));

        let a = Hash256([1u8; 32]);
        let b = Hash256([2u8; 32]);
        assert!(!super::tip_changed(a, a));
        assert!(super::tip_changed(a, b));

        assert!(super::should_process_share_as_block(true));
        assert!(!super::should_process_share_as_block(false));
        assert!(super::should_reissue_job_for_channel(7, 7));
        assert!(!super::should_reissue_job_for_channel(7, 8));
        let payout_seed = WalletMnemonic::parse(SOAK_FLOW_MNEMONIC)
            .expect("mnemonic")
            .to_seed("");
        let payout_key = derive_wallet_key(&payout_seed, 0, 0).expect("wallet key");
        let payout_addr =
            scam_wallet::to_address("s", payout_key.pubkey_compressed()).expect("address");
        let payout = super::stratum_user_payout_key_hash20(&payout_addr).expect("payout decode");
        assert_eq!(
            payout,
            scam_core::hash160_blake3(&payout_key.pubkey_compressed())
        );
        assert!(super::stratum_user_payout_key_hash20("not-an-address").is_none());
        assert_eq!(
            super::stratum_coinbase_label(7, "sd1q-User_01"),
            "stratum-ch7-sd1qUser01"
        );
        let tag_a = super::stratum_coinbase_tag("stratum-ch7-sd1qUser01", Hash256([0x11; 32]));
        let tag_b = super::stratum_coinbase_tag("stratum-ch7-sd1qUser01", Hash256([0x22; 32]));
        assert_ne!(tag_a, tag_b);
        assert!(tag_a.starts_with("stratum-ch7-sd1qUser01-"));
        assert!(super::should_send_open_standard_channel(false));
        assert!(!super::should_send_open_standard_channel(true));
        assert!(!super::should_emit_miner_keepalive(9));
        assert!(super::should_emit_miner_keepalive(10));
        assert!(super::should_emit_miner_keepalive(11));
        assert!(super::wallet_send_preview_has_invalid_amount(0));
        assert!(!super::wallet_send_preview_has_invalid_amount(1));
        assert!(!super::should_reply_bad_http_request(
            &super::NodeError::Runtime(
                "http read timeout while waiting for full request: timed out".to_owned()
            )
        ));
        assert!(!super::should_reply_bad_http_request(
            &super::NodeError::Runtime(
                "http connection closed while reading request: broken pipe".to_owned()
            )
        ));
        assert!(super::should_reply_bad_http_request(
            &super::NodeError::Runtime("malformed http request".to_owned())
        ));
        assert!(super::rpc_sse_write_error_is_closed_like(
            &super::NodeError::Runtime("http write failed: Broken pipe".to_owned())
        ));
        assert!(super::rpc_sse_write_error_is_closed_like(
            &super::NodeError::Runtime("http flush failed: Connection reset by peer".to_owned())
        ));
        assert!(!super::rpc_sse_write_error_is_closed_like(
            &super::NodeError::Runtime("http write failed: permission denied".to_owned())
        ));
        let events_stop = std::sync::atomic::AtomicBool::new(false);
        assert!(super::rpc_events_worker_should_continue(&events_stop));
        events_stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(!super::rpc_events_worker_should_continue(&events_stop));

        assert!(super::share_target_in_bounds(
            Target::MAX,
            Target::MAX,
            Target::MAX
        ));
        let tiny_target = Target::from_hex(&format!("00{}", "ff".repeat(31))).expect("tiny target");
        assert!(!super::share_target_in_bounds(
            tiny_target,
            Target::MAX,
            Target::MAX
        ));

        super::ensure_relay_peer_network("devnet", "devnet").expect("network ok");
        let network_err =
            super::ensure_relay_peer_network("devnet", "testnet").expect_err("network mismatch");
        assert!(network_err.to_string().contains("network mismatch"));

        assert_eq!(super::reorg_min_difficulty_window(49), 50);
        assert_eq!(super::reorg_min_difficulty_window(50), 50);
        assert_eq!(super::reorg_min_difficulty_window(75), 75);

        assert!(super::nonempty_parent_dir(std::path::Path::new("report.json")).is_none());
        assert_eq!(
            super::nonempty_parent_dir(std::path::Path::new("dir/report.json"))
                .expect("non-empty parent"),
            std::path::Path::new("dir")
        );
    }

    #[test]
    fn decode_optional_hex32_handles_none_valid_and_invalid_values() {
        let none = super::decode_optional_hex32("field", &None).expect("none decode");
        assert!(none.is_none());

        let valid_raw = Some("11".repeat(32));
        let valid = super::decode_optional_hex32("field", &valid_raw).expect("valid decode");
        assert_eq!(valid, Some([0x11u8; 32]));

        let invalid_len = Some("aa".repeat(31));
        let err = super::decode_optional_hex32("field", &invalid_len).expect_err("invalid len");
        match err {
            super::NodeError::InvalidHexLength {
                field,
                expected,
                got,
            } => {
                assert_eq!(field, "field");
                assert_eq!(expected, 32);
                assert_eq!(got, 31);
            }
            other => panic!("unexpected decode error variant: {other}"),
        }
    }

    #[test]
    fn lock_conflict_detectors_are_exact_and_case_sensitive_for_expected_fragments() {
        let lock_open = super::NodeError::Runtime("Database already open".to_owned());
        let lock_acquire = super::NodeError::Runtime("Cannot acquire lock".to_owned());
        let other = super::NodeError::Runtime("permission denied".to_owned());
        let lowercase = super::NodeError::Runtime("database already open".to_owned());

        assert!(super::is_runtime_db_lock_conflict(&lock_open));
        assert!(super::is_runtime_db_lock_conflict(&lock_acquire));
        assert!(!super::is_runtime_db_lock_conflict(&other));
        assert!(!super::is_runtime_db_lock_conflict(&lowercase));

        assert!(super::is_mempool_db_lock_conflict(&lock_open));
        assert!(super::is_mempool_db_lock_conflict(&lock_acquire));
        assert!(!super::is_mempool_db_lock_conflict(&other));
        assert!(!super::is_mempool_db_lock_conflict(&lowercase));
    }

    #[test]
    fn persist_with_retry_retries_only_for_lock_conflicts() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tries_ok = Arc::new(AtomicUsize::new(0));
        let tries_ok_clone = tries_ok.clone();
        super::persist_with_retry(
            3,
            1,
            super::is_runtime_db_lock_conflict,
            "unknown",
            move || {
                let attempt = tries_ok_clone.fetch_add(1, Ordering::Relaxed);
                if attempt == 0 {
                    Err(super::NodeError::Runtime(
                        "Database already open".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            },
        )
        .expect("second attempt should succeed");
        assert_eq!(tries_ok.load(Ordering::Relaxed), 2);

        let tries_err = Arc::new(AtomicUsize::new(0));
        let tries_err_clone = tries_err.clone();
        let non_lock_err = super::persist_with_retry(
            5,
            20,
            super::is_runtime_db_lock_conflict,
            "unknown",
            move || {
                tries_err_clone.fetch_add(1, Ordering::Relaxed);
                Err(super::NodeError::Runtime("permission denied".to_owned()))
            },
        )
        .expect_err("non lock errors should not retry");
        assert!(non_lock_err.to_string().contains("permission denied"));
        assert_eq!(tries_err.load(Ordering::Relaxed), 1);

        let tries_zero = Arc::new(AtomicUsize::new(0));
        let tries_zero_clone = tries_zero.clone();
        let exhausted = super::persist_with_retry(
            0,
            1,
            super::is_runtime_db_lock_conflict,
            "unknown runtime persist error",
            move || {
                tries_zero_clone.fetch_add(1, Ordering::Relaxed);
                Err(super::NodeError::Runtime(
                    "Database already open".to_owned(),
                ))
            },
        )
        .expect_err("attempts=0 still performs one try");
        assert!(exhausted.to_string().contains("Database already open"));
        assert_eq!(tries_zero.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn remove_confirmed_txids_from_mempool_db_handles_missing_and_readonly_db_paths() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let work_dir = temp_dir("test-remove-confirmed-mempool-db");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let missing_db = work_dir.join("missing-mempool.redb");
        let txid = Hash256([0x55; 32]);

        let removed = super::remove_confirmed_txids_from_mempool_db(&cfg, &missing_db, &[txid])
            .expect("missing db path should be accepted");
        assert_eq!(removed, 0);
        assert!(
            !missing_db.exists(),
            "missing mempool DB should stay absent when nothing is removed"
        );

        let existing_db = work_dir.join("existing-mempool.redb");
        let snapshot = MempoolSnapshot {
            network_id: cfg.network_id.clone(),
            entries: Vec::new(),
        };
        save_mempool_db(&existing_db, &snapshot).expect("persist snapshot");
        let mut perms = fs::metadata(&existing_db).expect("metadata").permissions();
        perms.set_readonly(true);
        fs::set_permissions(&existing_db, perms).expect("set readonly");

        let err = super::remove_confirmed_txids_from_mempool_db(&cfg, &existing_db, &[txid])
            .expect_err("readonly existing db should fail on persist");
        assert!(
            err.to_string().contains("Permission denied"),
            "unexpected readonly error: {err}"
        );

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn next_stratum_job_timestamp_caps_future_window_and_advances_over_tip() {
        let mut cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let tip_ts = runtime.tip_header().timestamp;
        let expected_ideal = tip_ts.saturating_add(cfg.target_block_time_sec);
        let ts = super::next_stratum_job_timestamp(&runtime, &cfg);
        assert_eq!(ts, expected_ideal);

        cfg.target_block_time_sec = u64::MAX / 4;
        let runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime huge target");
        let now = super::current_unix_sec().expect("now");
        let capped = super::next_stratum_job_timestamp(&runtime, &cfg);
        assert!(
            capped >= now.saturating_add(6_000),
            "expected cap close to 2h in future, got {capped} (now={now})"
        );
        assert!(
            capped <= now.saturating_add(7_200),
            "expected 2h future cap upper bound, got {capped} (now={now})"
        );
    }

    #[test]
    fn map_relay_read_result_handles_io_and_protocol_errors() {
        let ok = super::map_relay_read_result(Ok(WireMessage::Ping { nonce: 7 }))
            .expect("ok relay message");
        assert!(matches!(
            ok,
            super::RelayReadOutcome::Message(WireMessage::Ping { nonce: 7 })
        ));

        let timeout = super::map_relay_read_result(Err(scam_p2p::TransportError::Io(
            std::io::Error::from(std::io::ErrorKind::TimedOut),
        )))
        .expect("timeout maps to timeout");
        assert!(matches!(timeout, super::RelayReadOutcome::Timeout));

        let reset = super::map_relay_read_result(Err(scam_p2p::TransportError::Io(
            std::io::Error::from(std::io::ErrorKind::ConnectionReset),
        )))
        .expect("connection reset maps to closed");
        assert!(matches!(reset, super::RelayReadOutcome::Closed));

        let broken = super::map_relay_read_result(Err(scam_p2p::TransportError::Io(
            std::io::Error::from(std::io::ErrorKind::BrokenPipe),
        )))
        .expect("broken pipe maps to closed");
        assert!(matches!(broken, super::RelayReadOutcome::Closed));

        let denied = super::map_relay_read_result(Err(scam_p2p::TransportError::Io(
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        )))
        .expect_err("unexpected io errors must bubble up");
        assert!(denied.to_string().contains("io error"));
    }

    #[test]
    fn map_sv2_read_result_handles_timeout_and_fatal_errors() {
        let timeout = super::map_sv2_read_result(Err(scam_stratum::StratumError::Io(
            std::io::Error::from(std::io::ErrorKind::TimedOut),
        )))
        .expect("timeout maps to read timeout");
        assert!(matches!(timeout, super::StratumReadOutcome::Timeout));

        let keepalive = super::map_sv2_read_result(Ok(Some(Sv2Message::KeepAlive)))
            .expect("message pass-through");
        assert!(matches!(
            keepalive,
            super::StratumReadOutcome::Message(Sv2Message::KeepAlive)
        ));

        let closed = super::map_sv2_read_result(Ok(None)).expect("closed pass-through");
        assert!(matches!(closed, super::StratumReadOutcome::Closed));

        let fatal = match super::map_sv2_read_result(Err(
            scam_stratum::StratumError::InvalidFrameLength(17),
        )) {
            Ok(_) => panic!("fatal stratum error should bubble up"),
            Err(err) => err,
        };
        assert!(fatal.to_string().contains("stratum read failed"));

        let fatal_io = match super::map_sv2_read_result(Err(scam_stratum::StratumError::Io(
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        ))) {
            Ok(_) => panic!("non-timeout io errors must bubble up"),
            Err(err) => err,
        };
        assert!(fatal_io.to_string().contains("stratum read failed"));
    }

    #[test]
    fn read_next_sv2_message_with_retries_timeouts_and_closed_paths() {
        use std::collections::VecDeque;

        let mut sequence = VecDeque::from(vec![
            Ok(super::StratumReadOutcome::Timeout),
            Ok(super::StratumReadOutcome::Message(Sv2Message::KeepAlive)),
        ]);
        let message = super::read_next_sv2_message_with(3, || {
            sequence
                .pop_front()
                .unwrap_or(Ok(super::StratumReadOutcome::Timeout))
        })
        .expect("message after timeout");
        assert!(matches!(message, Some(Sv2Message::KeepAlive)));

        let mut all_timeouts = VecDeque::from(vec![
            Ok(super::StratumReadOutcome::Timeout),
            Ok(super::StratumReadOutcome::Timeout),
        ]);
        let none = super::read_next_sv2_message_with(2, || {
            all_timeouts
                .pop_front()
                .unwrap_or(Ok(super::StratumReadOutcome::Timeout))
        })
        .expect("timeout path");
        assert!(none.is_none());

        let mut closed = VecDeque::from(vec![Ok(super::StratumReadOutcome::Closed)]);
        let closed_result = super::read_next_sv2_message_with(1, || {
            closed
                .pop_front()
                .unwrap_or(Ok(super::StratumReadOutcome::Timeout))
        })
        .expect("closed path");
        assert!(closed_result.is_none());

        let mut zero_attempt_sequence = VecDeque::from(vec![Ok(
            super::StratumReadOutcome::Message(Sv2Message::KeepAlive),
        )]);
        let zero_attempt_result = super::read_next_sv2_message_with(0, || {
            zero_attempt_sequence
                .pop_front()
                .unwrap_or(Ok(super::StratumReadOutcome::Timeout))
        })
        .expect("attempts=0 still executes one read");
        assert!(matches!(zero_attempt_result, Some(Sv2Message::KeepAlive)));

        let mut errored = false;
        let err = super::read_next_sv2_message_with(1, || {
            errored = true;
            Err(super::NodeError::Runtime("boom".to_owned()))
        })
        .expect_err("error path must bubble up");
        assert!(errored);
        assert!(err.to_string().contains("boom"));
    }

    #[test]
    fn rpc_route_helpers_are_strict_for_method_path_and_prefixes() {
        assert!(super::rpc_exact_route_matches(
            "GET", "/health", "GET", "/health"
        ));
        assert!(!super::rpc_exact_route_matches(
            "POST", "/health", "GET", "/health"
        ));
        assert!(!super::rpc_exact_route_matches(
            "GET", "/status", "GET", "/health"
        ));
        assert!(super::is_get_method("GET"));
        assert!(!super::is_get_method("POST"));

        assert_eq!(
            super::rpc_block_height_path("GET", "/block/123"),
            Some("123")
        );
        assert_eq!(super::rpc_block_height_path("POST", "/block/123"), None);
        assert_eq!(super::rpc_block_height_path("GET", "/status"), None);

        assert_eq!(
            super::rpc_tx_path_parts("GET", "/tx/10/2"),
            Some(("10", "2", false))
        );
        assert_eq!(
            super::rpc_tx_path_parts("GET", "/tx/10/2/extra"),
            Some(("10", "2", true))
        );
        assert_eq!(
            super::rpc_tx_path_parts("GET", "/tx/10"),
            Some(("10", "", false))
        );
        assert_eq!(super::rpc_tx_path_parts("POST", "/tx/10/2"), None);

        assert!(super::rpc_tx_path_is_invalid("10", "2", true));
        assert!(super::rpc_tx_path_is_invalid("", "2", false));
        assert!(super::rpc_tx_path_is_invalid("10", "", false));
        assert!(!super::rpc_tx_path_is_invalid("10", "2", false));
        assert_eq!(super::parse_tx_height_and_index("10", "2"), Some((10, 2)));
        assert_eq!(super::parse_tx_height_and_index("ten", "2"), None);
        assert_eq!(super::parse_tx_height_and_index("10", "two"), None);

        let accepted = vec!["sd".to_owned(), "td".to_owned()];
        assert!(super::address_hrp_is_accepted(&accepted, "sd"));
        assert!(!super::address_hrp_is_accepted(&accepted, "s"));
        assert!(!super::should_reject_send_preview_hrp(&accepted, "sd"));
        assert!(super::should_reject_send_preview_hrp(&accepted, "s"));
        assert!(super::should_attempt_ui_asset_serve("GET"));
        assert!(!super::should_attempt_ui_asset_serve("POST"));
        assert!(super::should_serve_ui_asset_for_route("GET", true));
        assert!(!super::should_serve_ui_asset_for_route("GET", false));
        assert!(!super::should_serve_ui_asset_for_route("POST", true));

        assert!(super::role_service_response_is_empty(0));
        assert!(!super::role_service_response_is_empty(1));
    }

    #[test]
    fn run_stratum_client_async_rejects_submit_before_setup_without_tcp_socket() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let runtime_db_path = temp_dir("test-stratum-client-async-logic").join("runtime.redb");
        let mempool_db_path = runtime_db_path.with_file_name("mempool.redb");
        let ctx = super::StratumServerContext {
            cfg: cfg.clone(),
            runtime: std::sync::Arc::new(std::sync::Mutex::new(runtime)),
            runtime_db_path,
            mempool_db_path,
            max_template_txs: cfg.max_mempool_txs as usize,
            share_target: Target::MAX,
            min_share_target: Target::from_hex(&cfg.stratum_min_share_target)
                .expect("min share target parse"),
            max_share_target: Target::from_hex(&cfg.stratum_max_share_target)
                .expect("max share target parse"),
            vardiff_target_shares_per_minute: cfg.stratum_vardiff_target_shares_per_minute,
            vardiff_retarget_interval_shares: cfg.stratum_vardiff_retarget_interval_shares as usize,
            vardiff_clamp_up: cfg.stratum_vardiff_clamp_up,
            vardiff_clamp_down: cfg.stratum_vardiff_clamp_down,
            max_rejected_shares: cfg.stratum_max_rejected_shares,
            read_timeout_sec: 1,
            keepalive_sec: 1,
            idle_timeout_sec: 3,
            next_channel_id: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            template_provider: super::RuntimeTemplateProvider,
            job_declarator: std::sync::Arc::new(std::sync::Mutex::new(
                scam_stratum::SequentialJobDeclarator::default(),
            )),
            max_jobs_per_channel: cfg.stratum_max_jobs_per_channel as usize,
            active_clients: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            secure_transport: false,
            secure_transport_mode: super::SecureTransportMode::NoiseXx,
            secure_rekey_interval_messages: 16,
            secure_static_private_key: None,
            secure_expected_remote_static_public_key: None,
            template_provider_addr: None,
            job_declarator_addr: None,
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let (mut peer, server_stream) = tokio::io::duplex(8 * 1024);
            super::write_sv2_frame_async(
                &mut peer,
                &Sv2Message::SubmitSharesStandard {
                    channel_id: 1,
                    job_id: 7,
                    nonce: 0,
                    ntime: 0,
                },
            )
            .await
            .expect("send malformed-for-state message");
            drop(peer);

            let permit = std::sync::Arc::new(tokio::sync::Semaphore::new(1))
                .acquire_owned()
                .await
                .expect("permit");
            let err = super::run_stratum_client_async(server_stream, ctx, permit)
                .await
                .expect_err("submit-before-setup must be rejected");
            assert!(
                err.to_string()
                    .contains("submit_share received before active channel"),
                "unexpected error: {err}"
            );
        });
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
    fn sync_book_helpers_match_addresses_and_dedup_records() {
        let mut book = PeerAddressBook {
            network_id: "devnet".to_owned(),
            peers: vec![
                PeerAddressRecord {
                    address: "127.0.0.1:18444".to_owned(),
                    last_seen_unix_sec: 1,
                    ban_score: 2,
                },
                PeerAddressRecord {
                    address: "127.0.0.1:18443".to_owned(),
                    last_seen_unix_sec: 0,
                    ban_score: 0,
                },
                PeerAddressRecord {
                    address: "127.0.0.1:18444".to_owned(),
                    last_seen_unix_sec: 9,
                    ban_score: 9,
                },
            ],
        };

        assert!(super::peer_book_contains_address(&book, "127.0.0.1:18444"));
        assert!(!super::peer_book_contains_address(&book, "127.0.0.1:29999"));

        super::sort_and_dedup_peer_book(&mut book);
        assert_eq!(book.peers.len(), 2);
        assert_eq!(book.peers[0].address, "127.0.0.1:18443");
        assert_eq!(book.peers[1].address, "127.0.0.1:18444");

        let peer = super::find_peer_record_mut(&mut book, "127.0.0.1:18444").expect("peer");
        peer.ban_score = 7;
        assert_eq!(
            super::find_peer_record_mut(&mut book, "127.0.0.1:18444")
                .expect("peer")
                .ban_score,
            7
        );
        assert_eq!(
            book.peers
                .iter()
                .find(|peer| peer.address == "127.0.0.1:18443")
                .expect("other peer")
                .ban_score,
            0,
            "mutating a matched peer must not affect other entries"
        );
        assert_eq!(
            book.peers
                .iter()
                .find(|peer| peer.address == "127.0.0.1:18444")
                .expect("target peer")
                .ban_score,
            7
        );
        assert!(!super::sync_book_has_success(0));
        assert!(super::sync_book_has_success(1));
    }

    #[test]
    fn configure_stream_timeouts_sets_requested_values() {
        #[derive(Default)]
        struct MockTimeoutState {
            read_timeout: std::sync::Mutex<Option<Duration>>,
            write_timeout: std::sync::Mutex<Option<Duration>>,
        }

        let state = MockTimeoutState::default();
        super::configure_stream_timeouts_with_ops(
            |duration| {
                *state.read_timeout.lock().expect("read timeout") = duration;
                Ok(())
            },
            |duration| {
                *state.write_timeout.lock().expect("write timeout") = duration;
                Ok(())
            },
            Duration::from_secs(2),
            Duration::from_secs(3),
        )
        .expect("set explicit timeouts");
        assert_eq!(
            *state.read_timeout.lock().expect("read timeout"),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            *state.write_timeout.lock().expect("write timeout"),
            Some(Duration::from_secs(3))
        );

        super::configure_stream_timeouts_with_ops(
            |duration| {
                *state.read_timeout.lock().expect("read timeout") = duration;
                Ok(())
            },
            |duration| {
                *state.write_timeout.lock().expect("write timeout") = duration;
                Ok(())
            },
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .expect("set default timeouts");
        assert_eq!(
            *state.read_timeout.lock().expect("read timeout"),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            *state.write_timeout.lock().expect("write timeout"),
            Some(Duration::from_secs(5))
        );

        assert!(
            super::configure_stream_timeouts_with_ops(
                |_duration| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
                |_duration| Ok(()),
                Duration::from_secs(1),
                Duration::from_secs(1)
            )
            .is_err(),
            "read timeout error must propagate"
        );

        assert!(
            super::configure_stream_timeouts_with_ops(
                |_duration| Ok(()),
                |_duration| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
                Duration::from_secs(1),
                Duration::from_secs(1)
            )
            .is_err(),
            "write timeout error must propagate"
        );
    }

    #[test]
    fn configure_stream_timeouts_defaults_use_constant_values() {
        #[derive(Default)]
        struct MockTimeoutState {
            read_timeout: std::sync::Mutex<Option<Duration>>,
            write_timeout: std::sync::Mutex<Option<Duration>>,
        }

        let state = MockTimeoutState::default();
        super::configure_stream_timeouts_with_ops(
            |duration| {
                *state.read_timeout.lock().expect("read timeout") = duration;
                Ok(())
            },
            |duration| {
                *state.write_timeout.lock().expect("write timeout") = duration;
                Ok(())
            },
            super::DEFAULT_STREAM_TIMEOUT,
            super::DEFAULT_STREAM_TIMEOUT,
        )
        .expect("set default timeouts");
        assert_eq!(
            *state.read_timeout.lock().expect("read timeout"),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            *state.write_timeout.lock().expect("write timeout"),
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
    fn load_latest_jsonl_record_reads_last_non_empty_line() {
        let work_dir = temp_dir("test-load-latest-jsonl");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let path = work_dir.join("telemetry.jsonl");
        fs::write(&path, b"{\"round\":1}\n\n{\"round\":2}\n").expect("write jsonl");

        let latest = super::load_latest_jsonl_record::<serde_json::Value>(&path)
            .expect("load latest")
            .expect("record");
        assert_eq!(latest["round"], serde_json::json!(2));

        let missing =
            super::load_latest_jsonl_record::<serde_json::Value>(&work_dir.join("missing.jsonl"))
                .expect("missing file should be ok");
        assert!(missing.is_none());

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
            peers_dir: temp_dir("test-other-relay-peers"),
            outbound_connect: false,
            outbound_redial_sec: 1,
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
    fn relay_serve_rejects_network_id_mismatch_after_handshake() {
        let _net_guard = network_test_guard();
        let work_dir = temp_dir("test-relay-network-mismatch");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let runtime_db = work_dir.join("runtime.redb");
        let peers_dir = work_dir.join("peers");

        let Some(bind) = allocate_local_addr() else {
            return;
        };
        let server_bind = bind.clone();
        let server = thread::spawn(move || {
            super::run_relay_serve(super::RelayServeArgs {
                network: Network::Devnet,
                config: Some(config_path),
                runtime_db: Some(runtime_db),
                bind: server_bind,
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
                peers_dir,
                outbound_connect: false,
                outbound_redial_sec: 1,
            })
        });

        let mut stream = connect_with_retry(&bind);
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let framing = FramingConfig::default();
        let local_hello = LocalHandshake {
            protocol_version: 1,
            network_id: "wrongnet".to_owned(),
            user_agent: "test-client".to_owned(),
            start_height: 0,
        };
        let _ = client_handshake(&mut stream, &framing, &local_hello);
        drop(stream);

        let result = join_with_timeout(server, Duration::from_secs(5), "relay mismatch server");
        let err = result.expect_err("relay must fail on network mismatch");
        assert!(err.to_string().contains("network mismatch"));
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn relay_serve_enforces_per_peer_message_limit() {
        let _net_guard = network_test_guard();
        let work_dir = temp_dir("test-relay-message-limit");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let runtime_db = work_dir.join("runtime.redb");
        let peers_dir = work_dir.join("peers");
        let Some(bind) = allocate_local_addr() else {
            return;
        };

        let server_bind = bind.clone();
        let server = thread::spawn(move || {
            super::run_relay_serve(super::RelayServeArgs {
                network: Network::Devnet,
                config: Some(config_path),
                runtime_db: Some(runtime_db),
                bind: server_bind,
                max_clients: 1,
                max_messages_per_peer: 1,
                read_timeout_sec: 2,
                write_timeout_sec: 2,
                max_inv_items: None,
                ban_threshold: None,
                replacement_window_sec: None,
                replacement_max_per_peer: None,
                replacement_penalty: None,
                telemetry_out: None,
                telemetry_every_sec: 1,
                peers_dir,
                outbound_connect: false,
                outbound_redial_sec: 1,
            })
        });

        let mut stream = connect_with_retry(&bind);
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let framing = FramingConfig::default();
        let local_hello = LocalHandshake {
            protocol_version: 1,
            network_id: "devnet".to_owned(),
            user_agent: "test-client".to_owned(),
            start_height: 0,
        };
        let _remote = client_handshake(&mut stream, &framing, &local_hello).expect("handshake");

        send_message(&mut stream, &WireMessage::Ping { nonce: 1 }, &framing).expect("ping1");
        let first = read_message(&mut stream, &framing).expect("pong1");
        assert!(matches!(first, WireMessage::Pong { nonce: 1 }));

        // The relay may close immediately after the quota is exceeded:
        // either the second write fails, or write succeeds and read fails.
        let second_send = send_message(&mut stream, &WireMessage::Ping { nonce: 2 }, &framing);
        if second_send.is_ok() {
            let second = read_message(&mut stream, &framing);
            assert!(second.is_err(), "second message must not be processed");
        } else {
            let err = second_send.expect_err("expected second send error");
            let kind = match err {
                scam_p2p::TransportError::Io(io_err) => io_err.kind(),
                other => panic!("unexpected second send error: {other}"),
            };
            assert!(
                matches!(
                    kind,
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotConnected
                ),
                "unexpected io error kind for second ping: {kind:?}"
            );
        }

        drop(stream);
        join_with_timeout(server, Duration::from_secs(5), "relay message-limit server")
            .expect("relay serve should exit cleanly");
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn relay_serve_persists_telemetry_snapshots_when_enabled() {
        let _net_guard = network_test_guard();
        let work_dir = temp_dir("test-relay-telemetry");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let runtime_db = work_dir.join("runtime.redb");
        let telemetry_path = work_dir.join("relay.telemetry.jsonl");
        let peers_dir = work_dir.join("peers");
        let Some(bind) = allocate_local_addr() else {
            return;
        };

        let server_bind = bind.clone();
        let telemetry_out = telemetry_path.clone();
        let server = thread::spawn(move || {
            super::run_relay_serve(super::RelayServeArgs {
                network: Network::Devnet,
                config: Some(config_path),
                runtime_db: Some(runtime_db),
                bind: server_bind,
                max_clients: 1,
                max_messages_per_peer: 0,
                read_timeout_sec: 1,
                write_timeout_sec: 1,
                max_inv_items: None,
                ban_threshold: None,
                replacement_window_sec: None,
                replacement_max_per_peer: None,
                replacement_penalty: None,
                telemetry_out: Some(telemetry_out),
                telemetry_every_sec: 1,
                peers_dir,
                outbound_connect: false,
                outbound_redial_sec: 1,
            })
        });

        let mut stream = connect_with_retry(&bind);
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let framing = FramingConfig::default();
        let local_hello = LocalHandshake {
            protocol_version: 1,
            network_id: "devnet".to_owned(),
            user_agent: "test-client".to_owned(),
            start_height: 0,
        };
        let _remote = client_handshake(&mut stream, &framing, &local_hello).expect("handshake");
        thread::sleep(Duration::from_millis(1_250));
        drop(stream);

        join_with_timeout(server, Duration::from_secs(6), "relay telemetry server")
            .expect("relay serve should exit cleanly");

        let content = fs::read_to_string(&telemetry_path).expect("read telemetry");
        assert!(
            content.lines().any(|line| !line.trim().is_empty()),
            "expected at least one telemetry snapshot line"
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
    fn write_http_json_response_propagates_writer_errors() {
        struct FailWriter;
        impl Write for FailWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
        }

        let mut writer = FailWriter;
        let err = super::write_http_json_response(&mut writer, "200 OK", "{\"ok\":true}")
            .expect_err("writer error must propagate");
        assert!(err.to_string().contains("http write failed"));
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
    fn soak_does_not_mine_extra_tx_blocks_when_no_transactions_are_available() {
        let work_dir = temp_dir("test-soak-empty-tx-round");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let runtime_db = work_dir.join("runtime.redb");

        super::run_soak(super::SoakArgs {
            network: Network::Devnet,
            config: Some(config_path.clone()),
            runtime_db: Some(runtime_db.clone()),
            rounds: 1,
            blocks_per_round: 0,
            interval_sec: 1,
            max_nonce: 1_000,
            persist_every_rounds: 1,
            txs_per_round: 2,
            tx_amount: u64::MAX / 2,
            tx_fee: 1,
            sleep_per_round_sec: 0,
            telemetry_out: None,
            telemetry_every_rounds: 1,
            simulated_peers: 2,
            replacement_window_sec: 1,
            replacement_max_per_peer: 1,
            replacement_penalty: 1,
        })
        .expect("soak with empty tx rounds must succeed");

        let cfg = load_chain_config(&config_path).expect("load cfg");
        let (runtime_after, _) =
            super::load_runtime_from_db_or_genesis(&cfg, &runtime_db).expect("load runtime");
        assert_eq!(
            runtime_after.tip_height(),
            0,
            "no base blocks and no accepted txs should keep height unchanged"
        );

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
        let max_target = min_target.clone();
        let above_max_target = "ff".repeat(32);

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

        let above_max_err = run_stratum_serve(StratumServeArgs {
            network: Network::Devnet,
            config: Some(config_path.clone()),
            runtime_db: Some(runtime_db.clone()),
            bind: "not-an-addr".to_owned(),
            share_target_hex: Some(above_max_target),
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
            max_share_target_hex: Some(max_target.clone()),
            secure_transport: false,
            secure_transport_mode: None,
            secure_rekey_interval_messages: None,
            secure_static_secret_key_hex: None,
            secure_expected_remote_static_pubkey_hex: None,
            template_provider_addr: None,
            job_declarator_addr: None,
        })
        .expect_err("share target above max must fail");
        assert!(
            above_max_err
                .to_string()
                .contains("share_target_hex must be within"),
            "unexpected error: {above_max_err}"
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
            max_share_target_hex: Some(max_target),
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
    fn sv2_conformance_state_helpers_track_messages_and_pass_gate() {
        let mut setup_success = false;
        let mut channel_opened = false;
        let mut job_messages_seen = 0u32;
        let mut set_target_seen = false;
        let mut errors = Vec::<String>::new();

        super::update_sv2_conformance_state(
            &mut setup_success,
            &mut channel_opened,
            &mut job_messages_seen,
            &mut set_target_seen,
            &mut errors,
            &Sv2Message::SetupConnectionSuccess {
                used_version: 2,
                flags: 0,
            },
        );
        super::update_sv2_conformance_state(
            &mut setup_success,
            &mut channel_opened,
            &mut job_messages_seen,
            &mut set_target_seen,
            &mut errors,
            &Sv2Message::OpenStandardMiningChannelSuccess {
                request_id: 1,
                channel_id: 2,
                target_hex: Target::MAX.to_hex(),
                extranonce_prefix_hex: "00".to_owned(),
            },
        );
        super::update_sv2_conformance_state(
            &mut setup_success,
            &mut channel_opened,
            &mut job_messages_seen,
            &mut set_target_seen,
            &mut errors,
            &Sv2Message::NewMiningJob {
                channel_id: 2,
                job_id: 42,
                version: 1,
                prev_hash_hex: Hash256::ZERO.to_hex(),
                merkle_root_hex: Hash256::ZERO.to_hex(),
                ntime: 1_800_000_000,
                network_target_hex: Target::MAX.to_hex(),
            },
        );
        super::update_sv2_conformance_state(
            &mut setup_success,
            &mut channel_opened,
            &mut job_messages_seen,
            &mut set_target_seen,
            &mut errors,
            &Sv2Message::SetTarget {
                channel_id: 2,
                maximum_target_hex: Target::MAX.to_hex(),
            },
        );
        assert!(setup_success);
        assert!(channel_opened);
        assert_eq!(job_messages_seen, 1);
        assert!(set_target_seen);
        assert!(errors.is_empty());
        assert!(super::sv2_conformance_pass(
            setup_success,
            channel_opened,
            &errors
        ));

        super::update_sv2_conformance_state(
            &mut setup_success,
            &mut channel_opened,
            &mut job_messages_seen,
            &mut set_target_seen,
            &mut errors,
            &Sv2Message::SetupConnectionError {
                code: "bad".to_owned(),
                reason: "oops".to_owned(),
            },
        );
        super::update_sv2_conformance_state(
            &mut setup_success,
            &mut channel_opened,
            &mut job_messages_seen,
            &mut set_target_seen,
            &mut errors,
            &Sv2Message::OpenStandardMiningChannelError {
                request_id: 7,
                code: "not-authorized".to_owned(),
                reason: "denied".to_owned(),
            },
        );
        assert!(!errors.is_empty());
        assert!(
            errors.iter().any(|entry| entry.contains("setup error")),
            "setup errors must be retained in report state"
        );
        assert!(
            errors
                .iter()
                .any(|entry| entry.contains("open channel error")),
            "open channel errors must be retained in report state"
        );
        assert!(!super::sv2_conformance_pass(
            setup_success,
            channel_opened,
            &errors
        ));
        super::ensure_sv2_conformance_pass(false).expect_err("must fail on false pass flag");
        super::ensure_sv2_conformance_pass(true).expect("must pass on true flag");
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
        let parsed = read_http_request_from_raw(raw.as_bytes()).expect("parse request");
        let request = parsed.expect("request present");
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/wallet/new");
        assert_eq!(request.body, body.as_bytes());
    }

    #[test]
    fn read_http_request_accepts_payload_larger_than_one_mebibyte() {
        let body = vec![b'a'; 1_200_000];
        let mut raw = format!(
            "POST /wallet/new HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(&body);
        let parsed = read_http_request_from_raw(&raw).expect("parse request");
        let request = parsed.expect("request");
        assert_eq!(request.path, "/wallet/new");
        assert_eq!(request.body.len(), body.len());
    }

    #[test]
    fn read_http_request_accepts_exact_two_mebibyte_total_request_size() {
        let max_total = 2 * 1024 * 1024usize;
        let mut body_len = max_total;
        let mut header = String::new();
        for _ in 0..8 {
            header = format!(
                "POST /wallet/new HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
                body_len
            );
            let total = header.len().saturating_add(body_len);
            if total == max_total {
                break;
            }
            if total > max_total {
                body_len = body_len.saturating_sub(total - max_total);
            } else {
                body_len = body_len.saturating_add(max_total - total);
            }
        }
        assert_eq!(
            header.len().saturating_add(body_len),
            max_total,
            "header/body adjustment must converge to exact 2 MiB total"
        );
        let mut raw = header.into_bytes();
        raw.extend_from_slice(&vec![b'a'; body_len]);
        let parsed = read_http_request_from_raw(&raw).expect("parse exact 2 MiB request");
        let request = parsed.expect("request");
        assert_eq!(request.path, "/wallet/new");
        assert_eq!(request.body.len(), body_len);
    }

    #[test]
    fn read_http_request_waits_for_full_body_across_multiple_reads() {
        #[derive(Default)]
        struct ChunkReader {
            chunks: Vec<Vec<u8>>,
            next: usize,
        }

        impl Read for ChunkReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.next >= self.chunks.len() {
                    return Ok(0);
                }
                let chunk = &self.chunks[self.next];
                let len = chunk.len().min(buf.len());
                buf[..len].copy_from_slice(&chunk[..len]);
                self.next = self.next.saturating_add(1);
                Ok(len)
            }
        }

        let body = b"{\"k\":1234}".to_vec();
        let header = format!(
            "POST /wallet/new HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let split = body.len() / 2;
        let mut reader = ChunkReader {
            chunks: vec![header, body[..split].to_vec(), body[split..].to_vec()],
            next: 0,
        };
        let parsed = super::read_http_request(&mut reader).expect("parse");
        let request = parsed.expect("request");
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/wallet/new");
        assert_eq!(request.body, body);
    }

    #[test]
    fn read_http_request_rejects_truncated_body_at_eof() {
        let raw = b"POST /wallet/new HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nabc";
        let err = read_http_request_from_raw(raw).expect_err("truncated body must fail");
        assert!(err.to_string().contains("expected body length"));
    }

    #[test]
    fn read_http_request_timeout_without_bytes_is_treated_as_no_request() {
        struct TimeoutReader;

        impl Read for TimeoutReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
            }
        }

        let mut reader = TimeoutReader;
        let parsed = super::read_http_request(&mut reader).expect("timeout without bytes");
        assert!(
            parsed.is_none(),
            "idle timeout should be treated as empty request"
        );
    }

    #[test]
    fn read_http_request_timeout_after_partial_payload_is_rejected() {
        #[derive(Default)]
        struct PartialThenTimeout {
            calls: usize,
        }

        impl Read for PartialThenTimeout {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.calls == 0 {
                    let part = b"POST /wallet/new HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nab";
                    let len = part.len().min(buf.len());
                    buf[..len].copy_from_slice(&part[..len]);
                    self.calls = 1;
                    return Ok(len);
                }
                Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
            }
        }

        let mut reader = PartialThenTimeout::default();
        let err = super::read_http_request(&mut reader).expect_err("partial timeout must fail");
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn read_http_request_connection_closed_without_bytes_is_treated_as_no_request() {
        struct ClosedReader;

        impl Read for ClosedReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
            }
        }

        let mut reader = ClosedReader;
        let parsed = super::read_http_request(&mut reader).expect("closed without bytes");
        assert!(
            parsed.is_none(),
            "closed idle socket should produce no request"
        );
    }

    #[test]
    fn read_http_request_connection_closed_after_partial_payload_is_rejected() {
        #[derive(Default)]
        struct PartialThenClosed {
            calls: usize,
        }

        impl Read for PartialThenClosed {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.calls == 0 {
                    let part = b"POST /wallet/new HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nab";
                    let len = part.len().min(buf.len());
                    buf[..len].copy_from_slice(&part[..len]);
                    self.calls = 1;
                    return Ok(len);
                }
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
            }
        }

        let mut reader = PartialThenClosed::default();
        let err = super::read_http_request(&mut reader).expect_err("partial close must fail");
        assert!(err.to_string().contains("connection closed"));
    }

    #[test]
    fn read_http_request_non_timeout_non_close_io_error_is_reported() {
        struct PermissionDeniedReader;

        impl Read for PermissionDeniedReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            }
        }

        let mut reader = PermissionDeniedReader;
        let err =
            super::read_http_request(&mut reader).expect_err("permission denied must bubble up");
        assert!(err.to_string().contains("http read failed"));
    }

    #[test]
    fn read_role_request_handles_empty_invalid_and_valid_payloads() {
        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        let err = super::read_role_request::<serde_json::Value, _>(&mut empty)
            .expect_err("empty role request must fail");
        assert!(err.to_string().contains("closed without payload"));

        let mut invalid = std::io::Cursor::new(b"{not-json}\n".to_vec());
        let err = super::read_role_request::<serde_json::Value, _>(&mut invalid)
            .expect_err("invalid role request must fail");
        assert!(err.to_string().contains("decode failed"));

        let mut valid = std::io::Cursor::new(br#"{"job":1}"#.to_vec());
        let parsed = super::read_role_request::<serde_json::Value, _>(&mut valid)
            .expect("valid role request");
        assert_eq!(parsed["job"], serde_json::json!(1));
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
    fn rpc_event_snapshot_reports_runtime_and_mempool_state() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let work_dir = temp_dir("test-rpc-event-snapshot");
        fs::create_dir_all(&work_dir).expect("mkdir");

        let missing_mempool = work_dir.join("missing-mempool.redb");
        let missing = super::build_rpc_event_snapshot(&cfg, &runtime, &missing_mempool)
            .expect("snapshot without mempool db");
        assert_eq!(missing.network_id, cfg.network_id);
        assert_eq!(missing.tip_height, runtime.tip_height());
        assert_eq!(missing.tip_hash, runtime.tip_hash().to_hex());
        assert!(!missing.mempool_available);
        assert_eq!(missing.mempool_tx_count, 0);
        assert!(missing.unix_sec > 0);

        let mempool_db = work_dir.join("mempool.redb");
        let snapshot = MempoolSnapshot {
            network_id: cfg.network_id.clone(),
            entries: Vec::new(),
        };
        save_mempool_db(&mempool_db, &snapshot).expect("persist empty mempool");
        let present = super::build_rpc_event_snapshot(&cfg, &runtime, &mempool_db)
            .expect("snapshot with mempool db");
        assert!(present.mempool_available);
        assert_eq!(present.mempool_tx_count, 0);

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn static_asset_helpers_handle_unknown_suffix_and_traversal() {
        assert_eq!(
            super::guess_content_type(std::path::Path::new("index.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            super::guess_content_type(std::path::Path::new("favicon.ico")),
            "image/x-icon"
        );
        assert_eq!(
            super::guess_content_type(std::path::Path::new("styles.css")),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            super::guess_content_type(std::path::Path::new("bundle.js")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            super::guess_content_type(std::path::Path::new("data.json")),
            "application/json; charset=utf-8"
        );
        assert_eq!(
            super::guess_content_type(std::path::Path::new("diagram.svg")),
            "image/svg+xml"
        );
        assert_eq!(
            super::guess_content_type(std::path::Path::new("bundle.unknown")),
            "application/octet-stream"
        );
        assert_eq!(
            super::guess_content_type(std::path::Path::new("logo.png")),
            "image/png"
        );
        assert_eq!(
            super::guess_content_type(std::path::Path::new("photo.jpg")),
            "image/jpeg"
        );
        assert_eq!(
            super::guess_content_type(std::path::Path::new("photo.jpeg")),
            "image/jpeg"
        );

        let ui_dir = temp_dir("test-ui-assets");
        fs::create_dir_all(&ui_dir).expect("mkdir");
        fs::write(ui_dir.join("index.html"), "<html>ok</html>").expect("write index");
        fs::create_dir_all(ui_dir.join("folder")).expect("mkdir folder");
        let mut invalid_path_response = Vec::<u8>::new();
        let served =
            super::try_serve_ui_asset(&mut invalid_path_response, &ui_dir, "/../secrets.txt")
                .expect("serve invalid path");
        assert!(served);
        let invalid_path_response =
            String::from_utf8(invalid_path_response).expect("utf8 invalid-path response");
        assert!(invalid_path_response.starts_with("HTTP/1.1 400 Bad Request"));

        let mut fallback_response = Vec::<u8>::new();
        let served = super::try_serve_ui_asset(&mut fallback_response, &ui_dir, "/does-not-exist")
            .expect("serve fallback");
        assert!(served);
        let fallback_response =
            String::from_utf8(fallback_response).expect("utf8 fallback response");
        assert!(fallback_response.starts_with("HTTP/1.1 200 OK"));
        assert!(fallback_response.contains("<html>ok</html>"));

        let mut directory_response = Vec::<u8>::new();
        let served = super::try_serve_ui_asset(&mut directory_response, &ui_dir, "/folder")
            .expect("serve directory path fallback");
        assert!(served);
        let directory_response =
            String::from_utf8(directory_response).expect("utf8 directory fallback response");
        assert!(directory_response.starts_with("HTTP/1.1 200 OK"));
        assert!(directory_response.contains("<html>ok</html>"));

        let missing_ui = ui_dir.join("missing-ui");
        let mut missing_response = Vec::<u8>::new();
        let served = super::try_serve_ui_asset(&mut missing_response, &missing_ui, "/index.html")
            .expect("serve missing ui");
        assert!(!served);
        assert!(missing_response.is_empty());

        let broken_ui = ui_dir.join("broken-ui");
        fs::create_dir_all(broken_ui.join("index.html")).expect("mkdir broken index");
        let mut broken_response = Vec::<u8>::new();
        let served = super::try_serve_ui_asset(&mut broken_response, &broken_ui, "/missing")
            .expect("serve broken ui");
        assert!(!served);
        assert!(broken_response.is_empty());

        let _ = fs::remove_dir_all(ui_dir);
    }

    #[test]
    fn ui_dir_is_servable_requires_existing_directory() {
        let work_dir = temp_dir("test-ui-dir-servable");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let missing = work_dir.join("missing");
        assert!(!super::ui_dir_is_servable(&missing));

        let file_path = work_dir.join("single-file.txt");
        fs::write(&file_path, b"x").expect("write file");
        assert!(!super::ui_dir_is_servable(&file_path));

        let dir_path = work_dir.join("ui");
        fs::create_dir_all(&dir_path).expect("mkdir ui");
        assert!(super::ui_dir_is_servable(&dir_path));

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn run_rpc_serve_dispatches_health_and_unknown_routes() {
        let _net_guard = network_test_guard();
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

        let health_response =
            send_http_request(&addr, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(health_response.starts_with("HTTP/1.1 200 OK"));
        assert!(health_response.contains("{\"ok\":true}"));

        let unknown_response =
            send_http_request(&addr, "GET /nope HTTP/1.1\r\nHost: localhost\r\n\r\n");
        // With a present UI directory, unknown GET paths are intentionally served
        // through index.html (SPA-style fallback), not 404.
        assert!(unknown_response.starts_with("HTTP/1.1 200 OK"));
        assert!(unknown_response.contains("<html>ui</html>"));

        join_with_timeout(server, Duration::from_secs(5), "rpc health routes server");
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn run_rpc_serve_dispatches_core_and_wallet_routes() {
        let _net_guard = network_test_guard();
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
                // run_rpc_serve counts only fully handled request paths in `served`;
                // several requests below intentionally hit early 400 error paths.
                max_requests: 5,
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

        join_with_timeout(server, Duration::from_secs(5), "rpc core routes server");
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn run_rpc_serve_streams_event_snapshots() {
        let _net_guard = network_test_guard();
        let Some(addr) = allocate_local_addr() else {
            return;
        };
        let work_dir = temp_dir("test-rpc-serve-events");
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

        let events = send_http_request_until(
            &addr,
            "GET /events HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "event: snapshot",
            Duration::from_secs(5),
        );
        assert!(events.starts_with("HTTP/1.1 200 OK"));
        assert!(events.contains("text/event-stream"));
        assert!(events.contains("event: snapshot"));
        assert!(events.contains("data: {\"network_id\":\"devnet\""));

        let health = send_http_request(&addr, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(health.starts_with("HTTP/1.1 200 OK"));

        join_with_timeout(server, Duration::from_secs(5), "rpc events server");
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn run_rpc_serve_rejects_invalid_bind_address() {
        let work_dir = temp_dir("test-rpc-bind-error");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let runtime_db = work_dir.join("runtime.redb");

        let err = run_rpc_serve(RpcServeArgs {
            network: Network::Devnet,
            config: Some(config_path),
            runtime_db: Some(runtime_db),
            bind: "invalid-bind".to_owned(),
            ui_dir: work_dir.join("ui"),
            relay_telemetry: None,
            mine_blocks: 0,
            interval_sec: 120,
            max_nonce: 500_000,
            max_requests: 1,
        })
        .expect_err("invalid bind should fail");
        assert!(err.to_string().contains("rpc bind failed"));

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn run_rpc_serve_route_matching_and_hrp_validation_are_strict() {
        let _net_guard = network_test_guard();
        let Some(addr) = allocate_local_addr() else {
            return;
        };
        let work_dir = temp_dir("test-rpc-serve-strict-routes");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let runtime_db = work_dir.join("runtime.redb");
        let ui_dir = work_dir.join("no-ui-assets");

        let seed = WalletMnemonic::parse(SOAK_FLOW_MNEMONIC)
            .expect("mnemonic")
            .to_seed("");
        let recipient_key = derive_wallet_key(&seed, 0, 1).expect("recipient");
        let valid_recipient =
            scam_wallet::to_address("sd", recipient_key.pubkey_compressed()).expect("valid addr");
        let invalid_recipient = scam_wallet::to_address("s", recipient_key.pubkey_compressed())
            .expect("invalid hrp addr");

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
                // Two send-preview requests below intentionally return early 400 responses,
                // which do not increment internal `served`.
                max_requests: 9,
            })
            .expect("rpc serve");
        });

        let health = send_http_request(&addr, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(health.starts_with("HTTP/1.1 200 OK"));

        let unknown = send_http_request(&addr, "GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(unknown.starts_with("HTTP/1.1 404 Not Found"));
        assert!(unknown.contains("\"unknown endpoint\""));

        let mempool = send_http_request(&addr, "GET /mempool HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(mempool.starts_with("HTTP/1.1 200 OK"));
        assert!(mempool.contains("\"available\""));

        let tx = send_http_request(&addr, "GET /tx/0/0 HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(tx.starts_with("HTTP/1.1 200 OK"));
        let block = send_http_request(&addr, "GET /block/0 HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(block.starts_with("HTTP/1.1 200 OK"));

        let wallet_address_req = serde_json::json!({
            "mnemonic": SOAK_FLOW_MNEMONIC,
            "passphrase": "",
            "account": 0,
            "index": 0
        })
        .to_string();
        let wallet_address = send_http_json_post(&addr, "/wallet/address", &wallet_address_req);
        assert!(wallet_address.starts_with("HTTP/1.1 200 OK"));
        assert!(wallet_address.contains("\"address\""));

        let valid_send_req = serde_json::json!({
            "mnemonic": SOAK_FLOW_MNEMONIC,
            "passphrase": "",
            "account": 0,
            "index": 0,
            "to": valid_recipient,
            // Force deterministic non-funding error path after HRP validation.
            "amount": u64::MAX,
            "fee": 1
        })
        .to_string();
        let valid_send = send_http_json_post(&addr, "/wallet/send-preview", &valid_send_req);
        assert!(valid_send.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(
            !valid_send.contains("address hrp"),
            "valid network hrp must not be rejected as wrong network"
        );

        let invalid_send_req = serde_json::json!({
            "mnemonic": SOAK_FLOW_MNEMONIC,
            "passphrase": "",
            "account": 0,
            "index": 0,
            "to": invalid_recipient,
            "amount": 1,
            "fee": 1
        })
        .to_string();
        let invalid_send = send_http_json_post(&addr, "/wallet/send-preview", &invalid_send_req);
        assert!(invalid_send.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(invalid_send.contains("address hrp"));

        // Keep counted routes last so `max_requests` is reached after assertions above.
        let wallet_balance_req = serde_json::json!({
            "mnemonic": SOAK_FLOW_MNEMONIC,
            "passphrase": "",
            "account": 0,
            "index": 0
        })
        .to_string();
        let wallet_balance = send_http_json_post(&addr, "/wallet/balance", &wallet_balance_req);
        assert!(wallet_balance.starts_with("HTTP/1.1 200 OK"));
        assert!(wallet_balance.contains("\"spendable\""));

        let wallet_balance_by_address_req = serde_json::json!({
            "address": valid_recipient
        })
        .to_string();
        let wallet_balance_by_address = send_http_json_post(
            &addr,
            "/wallet/balance-by-address",
            &wallet_balance_by_address_req,
        );
        assert!(wallet_balance_by_address.starts_with("HTTP/1.1 200 OK"));
        assert!(wallet_balance_by_address.contains("\"address\""));

        let wallet_decode_req = serde_json::json!({
            "address": invalid_recipient.clone()
        })
        .to_string();
        let wallet_decode = send_http_json_post(&addr, "/wallet/decode", &wallet_decode_req);
        assert!(wallet_decode.starts_with("HTTP/1.1 200 OK"));
        assert!(wallet_decode.contains("\"key_hash20_hex\""));

        join_with_timeout(server, Duration::from_secs(5), "rpc strict routes server");
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
    fn run_stratum_mine_rejects_invalid_pool_address() {
        let err = run_stratum_mine(StratumMineArgs {
            pool: "not-a-socket-address".to_owned(),
            user: "miner".to_owned(),
            read_timeout_sec: 1,
            max_nonce_per_cycle: 1_000,
            max_shares: 0,
            max_runtime_sec: 0,
            secure_transport: false,
            secure_transport_mode: None,
            secure_rekey_interval_messages: 10_000,
            secure_static_secret_key_hex: None,
            secure_expected_remote_static_pubkey_hex: None,
            translator_addr: None,
        })
        .expect_err("invalid pool address must fail");
        assert!(err.to_string().contains("stratum connect failed"));
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

        let balance_addr_err = run_wallet(super::WalletCommand::BalanceAddress {
            network: Network::Devnet,
            config: Some(work_dir.join("devnet.toml")),
            address: scam_wallet::to_address("s", key.pubkey_compressed()).expect("address"),
            mine_blocks: 0,
            interval_sec: 120,
            max_nonce: 500_000,
        })
        .expect_err("watch-only balance must reject mismatched hrp");
        assert!(
            balance_addr_err
                .to_string()
                .contains("is not valid for network"),
            "unexpected balance-by-address error: {balance_addr_err}"
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
    fn relay_target_matches_bind_covers_exact_unspecified_and_mismatch_paths() {
        assert!(super::relay_target_matches_bind(
            "127.0.0.1:18444",
            "127.0.0.1:18444"
        ));
        assert!(super::relay_target_matches_bind(
            "0.0.0.0:18444",
            "127.0.0.1:18444"
        ));
        assert!(!super::relay_target_matches_bind(
            "127.0.0.1:18444",
            "127.0.0.1:18445"
        ));
        assert!(!super::relay_target_matches_bind(
            "127.0.0.1:18444",
            "10.0.0.7:18444"
        ));
        assert!(!super::relay_target_matches_bind(
            "invalid-bind",
            "127.0.0.1:18444"
        ));
        assert!(!super::relay_target_matches_bind(
            "127.0.0.1:18444",
            "invalid-peer"
        ));
        assert!(super::relay_target_matches_bind(
            "[::]:18444",
            "[::1]:18444"
        ));
        assert!(!super::relay_target_matches_bind(
            "0.0.0.0:18444",
            "127.0.0.1:18445"
        ));
    }

    #[test]
    fn push_inv_batches_respects_empty_and_chunking_contracts() {
        let mut out = Vec::<WireMessage>::new();
        super::push_inv_batches(&mut out, Vec::new(), 8);
        assert!(out.is_empty());

        super::push_inv_batches(&mut out, vec![InventoryItem::Tx(Hash256([1u8; 32]))], 0);
        assert!(out.is_empty());

        super::push_inv_batches(
            &mut out,
            vec![
                InventoryItem::Tx(Hash256([1u8; 32])),
                InventoryItem::Tx(Hash256([2u8; 32])),
                InventoryItem::Tx(Hash256([3u8; 32])),
            ],
            2,
        );
        assert_eq!(out.len(), 2);
        match &out[0] {
            WireMessage::Inv { items } => assert_eq!(items.len(), 2),
            other => panic!("unexpected first message: {other:?}"),
        }
        match &out[1] {
            WireMessage::Inv { items } => assert_eq!(items.len(), 1),
            other => panic!("unexpected second message: {other:?}"),
        }
    }

    #[test]
    fn refresh_runtime_from_db_skips_reload_when_mtime_unchanged() {
        let cfg_devnet: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("devnet config");
        let cfg_testnet: ChainConfig =
            toml::from_str(include_str!("../../../config/testnet.toml")).expect("testnet config");
        let work_dir = temp_dir("test-refresh-runtime-mtime");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let runtime_db_path = work_dir.join("runtime.redb");

        let runtime_testnet = ChainRuntime::from_config(cfg_testnet.clone()).expect("runtime");
        persist_runtime_db(&runtime_testnet, &runtime_db_path).expect("persist runtime");
        let mut local_runtime = ChainRuntime::from_config(cfg_devnet.clone()).expect("runtime");
        let mut last_seen = super::runtime_db_mtime(&runtime_db_path);
        let before_tip = local_runtime.tip_hash();

        super::refresh_runtime_from_db_if_changed(
            &cfg_devnet,
            &mut local_runtime,
            &runtime_db_path,
            &mut last_seen,
        )
        .expect("mtime unchanged should skip mismatched reload");
        assert_eq!(local_runtime.tip_hash(), before_tip);
        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn load_relay_outbound_targets_returns_sorted_and_deduped_peer_addresses() {
        let peers_dir = temp_dir("test-relay-outbound-targets");
        fs::create_dir_all(&peers_dir).expect("mkdir");
        let peers_db_path = peers_dir.join("devnet.redb");
        super::save_peer_book_db(
            &peers_db_path,
            &PeerAddressBook {
                network_id: "devnet".to_owned(),
                peers: vec![
                    PeerAddressRecord {
                        address: "127.0.0.1:18446".to_owned(),
                        last_seen_unix_sec: 0,
                        ban_score: 0,
                    },
                    PeerAddressRecord {
                        address: "127.0.0.1:18445".to_owned(),
                        last_seen_unix_sec: 0,
                        ban_score: 0,
                    },
                    PeerAddressRecord {
                        address: "127.0.0.1:18446".to_owned(),
                        last_seen_unix_sec: 1,
                        ban_score: 0,
                    },
                ],
            },
        )
        .expect("save peer book");

        let targets = super::load_relay_outbound_targets(&peers_dir, "devnet")
            .expect("load outbound targets");
        assert_eq!(
            targets,
            vec!["127.0.0.1:18445".to_owned(), "127.0.0.1:18446".to_owned()]
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
    fn sync_runtime_with_peer_downloads_and_applies_blocks() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let mut runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let Some((peer_addr, peer_server)) = spawn_sync_peer_server(&cfg, 2) else {
            return;
        };

        let stats = super::sync_runtime_with_peer(
            &cfg,
            &mut runtime,
            &peer_addr,
            1,
            "scam-node/test-sync-runtime",
        )
        .expect("sync from peer");
        assert!(stats.headers_received >= 1);
        assert!(stats.blocks_announced >= 1);
        assert!(stats.blocks_downloaded >= 1);
        assert!(stats.blocks_applied >= 1);
        assert_eq!(runtime.tip_height(), 2);

        peer_server.join().expect("peer join").expect("peer ok");
    }

    #[test]
    fn sync_runtime_with_peer_reports_connect_failure_for_unreachable_peer() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let mut runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let invalid_peer = "invalid-peer-address";

        let err = super::sync_runtime_with_peer(
            &cfg,
            &mut runtime,
            invalid_peer,
            1,
            "scam-node/test-sync-unreachable",
        )
        .expect_err("invalid peer address must fail");
        assert!(err.to_string().contains("connect to"));
    }

    #[test]
    fn sync_book_succeeds_with_reachable_peer_and_updates_runtime_db() {
        let work_dir = temp_dir("test-sync-book-success");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let peers_dir = work_dir.join("peers");
        fs::create_dir_all(&peers_dir).expect("mkdir peers");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write cfg");
        let cfg = load_chain_config(&config_path).expect("load cfg");
        let runtime_db = work_dir.join("runtime.redb");

        let Some((peer_addr, peer_server)) = spawn_sync_peer_server(&cfg, 1) else {
            return;
        };
        run_add_peer(AddPeerArgs {
            network: Network::Devnet,
            peer: peer_addr,
            peers_dir: peers_dir.clone(),
        })
        .expect("add peer");

        run_sync_book(SyncBookArgs {
            network: Network::Devnet,
            config: Some(config_path),
            runtime_db: Some(runtime_db.clone()),
            peers_dir: peers_dir.clone(),
            max_peers: 1,
            max_batches_per_peer: 1,
            rotate_after_sec: 60,
        })
        .expect("sync book");

        let archive = load_chain_archive_db(&runtime_db).expect("load archive");
        assert!(archive.blocks_by_height.len() >= 2);

        peer_server.join().expect("peer join").expect("peer ok");
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
    fn reindex_runtime_requires_existing_db_path() {
        let work_dir = temp_dir("test-reindex-runtime-missing-db");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let config_path = work_dir.join("devnet.toml");
        fs::write(&config_path, include_str!("../../../config/devnet.toml")).expect("write config");
        let missing_db = work_dir.join("missing.redb");

        let err = run_reindex_runtime(ReindexRuntimeArgs {
            network: Network::Devnet,
            config: Some(config_path),
            runtime_db: Some(missing_db),
        })
        .expect_err("missing runtime db must fail reindex");
        assert!(err.to_string().contains("runtime db does not exist"));

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
    fn submit_tx_via_mempool_db_accepts_valid_signed_transaction() {
        let mut cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.coinbase_maturity = 1;
        cfg.validate().expect("config validate");

        let work_dir = temp_dir("test-submit-mempool-db");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let runtime_db = work_dir.join("runtime.redb");
        let mempool_db = work_dir.join("mempool.redb");

        let mnemonic = WalletMnemonic::parse(SOAK_FLOW_MNEMONIC).expect("mnemonic");
        let seed = mnemonic.to_seed("");
        let sender_key = derive_wallet_key(&seed, 0, 0).expect("sender key");
        let recipient_key = derive_wallet_key(&seed, 0, 1).expect("recipient key");
        let sender_key_hash20 = scam_core::hash160_blake3(&sender_key.pubkey_compressed());
        let recipient_key_hash20 = scam_core::hash160_blake3(&recipient_key.pubkey_compressed());

        let mut runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let params = super::MiningLoopParams {
            count: 2,
            interval_sec: cfg.target_block_time_sec,
            max_nonce: 500_000,
            subsidy: cfg.block_subsidy,
            miner_key_hash: sender_key_hash20,
            label_prefix: "submit-mempool",
            print_each: false,
        };
        mine_blocks_on_runtime(&mut runtime, &params).expect("mine blocks");
        persist_runtime_db(&runtime, &runtime_db).expect("persist runtime");

        let signed = build_signed_transfer_tx(
            &runtime,
            &cfg.network_id,
            &sender_key,
            recipient_key_hash20,
            1_000_000,
            500,
        )
        .expect("build signed tx");
        let (txid, outcome, fee) =
            super::submit_tx_via_mempool_db(&cfg, &runtime_db, &mempool_db, signed.tx, 500)
                .expect("submit tx");

        assert_eq!(fee, 500);
        assert_eq!(outcome, "accepted");
        let snapshot = scam_storage::load_mempool_db(&mempool_db).expect("load mempool db");
        assert_eq!(snapshot.network_id, cfg.network_id);
        assert!(snapshot.entries.iter().any(|entry| entry.txid == txid));

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn tx_submit_mine_and_sync_updates_receiver_balance() {
        let _net_guard = network_test_guard();
        let mut cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.coinbase_maturity = 1;
        cfg.validate().expect("config validate");

        let work_dir = temp_dir("test-tx-submit-mine-sync");
        fs::create_dir_all(&work_dir).expect("mkdir");
        let runtime_db = work_dir.join("runtime.redb");
        let mempool_db = work_dir.join("mempool.redb");

        let mnemonic = WalletMnemonic::parse(SOAK_FLOW_MNEMONIC).expect("mnemonic");
        let seed = mnemonic.to_seed("");
        let sender_key = derive_wallet_key(&seed, 0, 0).expect("sender key");
        let recipient_key = derive_wallet_key(&seed, 0, 1).expect("recipient key");
        let sender_key_hash20 = scam_core::hash160_blake3(&sender_key.pubkey_compressed());
        let recipient_key_hash20 = scam_core::hash160_blake3(&recipient_key.pubkey_compressed());
        let recipient_address =
            scam_wallet::to_address(&cfg.hrp, recipient_key.pubkey_compressed()).expect("address");

        let mut producer_runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let mining_seed = super::MiningLoopParams {
            count: 2,
            interval_sec: cfg.target_block_time_sec,
            max_nonce: 500_000,
            subsidy: cfg.block_subsidy,
            miner_key_hash: sender_key_hash20,
            label_prefix: "tx-e2e-seed",
            print_each: false,
        };
        mine_blocks_on_runtime(&mut producer_runtime, &mining_seed).expect("seed mining");
        persist_runtime_db(&producer_runtime, &runtime_db).expect("persist runtime");

        let send_amount = 1_250_000u64;
        let fee = 500u64;
        let signed = build_signed_transfer_tx(
            &producer_runtime,
            &cfg.network_id,
            &sender_key,
            recipient_key_hash20,
            send_amount,
            fee,
        )
        .expect("build signed tx");
        let submitted_txid = signed.tx.txid();
        let (txid, outcome, effective_fee) =
            super::submit_tx_via_mempool_db(&cfg, &runtime_db, &mempool_db, signed.tx, fee)
                .expect("submit tx");
        assert_eq!(txid, submitted_txid);
        assert_eq!(outcome, "accepted");
        assert_eq!(effective_fee, fee);

        let mempool = super::load_mempool_from_db_or_empty(&cfg, &mempool_db).expect("mempool");
        assert!(mempool.contains(&submitted_txid));

        let template_params = super::MempoolTemplateParams {
            version: 1,
            prev_block: producer_runtime.tip_hash(),
            timestamp: producer_runtime
                .tip_header()
                .timestamp
                .saturating_add(cfg.target_block_time_sec),
            target: producer_runtime
                .expected_target_for_next_block()
                .expect("target"),
            block_subsidy: cfg.block_subsidy,
            miner_key_hash20: sender_key_hash20,
            coinbase_tag: "tx-e2e-template".to_owned(),
            max_txs: cfg.max_mempool_txs as usize,
        };
        let (template, summary) =
            super::build_template_from_mempool(&template_params, &mempool).expect("template");
        assert!(
            summary.included_txids.contains(&submitted_txid),
            "submitted tx must be selected into mined template"
        );

        let mined = mine_block(&template, 500_000).expect("mine block");
        assert!(
            mined
                .transactions
                .iter()
                .any(|tx| tx.txid() == submitted_txid),
            "submitted tx must appear in mined block"
        );
        producer_runtime
            .apply_next_block(mined.clone())
            .expect("apply mined block");
        let confirmed_txids = mined
            .transactions
            .iter()
            .skip(1)
            .map(Transaction::txid)
            .collect::<Vec<_>>();
        super::remove_confirmed_txids_from_mempool_db(&cfg, &mempool_db, &confirmed_txids)
            .expect("trim mempool");
        persist_runtime_db(&producer_runtime, &runtime_db).expect("persist runtime");

        let post_mine_snapshot =
            scam_storage::load_mempool_db(&mempool_db).expect("mempool snapshot");
        assert!(
            post_mine_snapshot
                .entries
                .iter()
                .all(|entry| entry.txid != submitted_txid),
            "confirmed tx must be removed from mempool snapshot"
        );

        let Some((peer_addr, peer_server)) =
            spawn_sync_peer_server_from_runtime(&cfg, &producer_runtime)
        else {
            let _ = fs::remove_dir_all(work_dir);
            return;
        };
        let mut follower_runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let sync_stats = super::sync_runtime_with_peer(
            &cfg,
            &mut follower_runtime,
            &peer_addr,
            1,
            "scam-node/test-tx-e2e",
        )
        .expect("sync follower");
        assert!(sync_stats.blocks_applied >= 1);
        assert_eq!(follower_runtime.tip_hash(), producer_runtime.tip_hash());
        peer_server
            .join()
            .expect("peer join")
            .expect("peer server ok");

        let balance = super::wallet_balance_response(
            &follower_runtime,
            &cfg,
            0,
            0,
            recipient_address,
            recipient_key_hash20,
        );
        assert_eq!(balance.total, send_amount as u128);
        assert_eq!(balance.spendable, send_amount as u128);
        assert_eq!(balance.utxo_count, 1);

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn relay_proactive_inventory_messages_announces_tip_and_new_mempool_txids_once() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");

        let mut relay = RelayAdmissionState {
            mempool: Mempool::with_policy(cfg.max_mempool_txs as usize, cfg.min_relay_fee_per_kb)
                .expect("mempool"),
            orphan_pool: OrphanPool::new(cfg.max_orphan_txs as usize, cfg.orphan_ttl_sec)
                .expect("orphan"),
            gossip: GossipEngine::new(128).expect("gossip"),
        };
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: Hash256([7u8; 32]),
                    vout: 0,
                },
                signature: vec![1u8; 64],
                pubkey_compressed: vec![2u8; 33],
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 10,
                key_hash20: [9u8; 20],
            }],
            lock_time: 0,
        };
        relay
            .mempool
            .insert_with_fee(tx.clone(), 2_000)
            .expect("insert tx");

        let state = RelayServerState { runtime, relay };
        let mut last_tip_announced = None;
        let mut announced_txids = std::collections::HashSet::<Hash256>::new();
        let first = super::relay_proactive_inventory_messages(
            &state,
            &mut last_tip_announced,
            &mut announced_txids,
            128,
        );
        assert!(
            first.iter().any(|msg| match msg {
                WireMessage::Inv { items } => items.iter().any(|item| {
                    matches!(item, InventoryItem::Block(hash) if *hash == state.runtime.tip_hash())
                }),
                _ => false,
            }),
            "first proactive pass must announce tip hash"
        );
        assert!(
            first.iter().any(|msg| match msg {
                WireMessage::Inv { items } => items
                    .iter()
                    .any(|item| matches!(item, InventoryItem::Tx(txid) if *txid == tx.txid())),
                _ => false,
            }),
            "first proactive pass must announce unseen mempool txid"
        );

        let second = super::relay_proactive_inventory_messages(
            &state,
            &mut last_tip_announced,
            &mut announced_txids,
            128,
        );
        assert!(
            second.is_empty(),
            "second proactive pass must not re-announce unchanged inventory"
        );
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
        let _net_guard = network_test_guard();
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
        join_with_timeout(
            server,
            Duration::from_secs(5),
            "sv2 conformance pass server",
        );

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
        let _net_guard = network_test_guard();
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
        join_with_timeout(
            server,
            Duration::from_secs(5),
            "sv2 conformance fail server",
        );

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
    fn relay_getdata_with_known_inventory_does_not_emit_notfound() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.validate().expect("config validate");
        let runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let spend = runtime.utxo_set().keys().next().cloned().expect("utxo");
        let tx = relay_tx(spend, 9, 77);
        let txid = tx.txid();

        let mut relay = RelayAdmissionState {
            mempool: Mempool::with_policy(cfg.max_mempool_txs as usize, cfg.min_relay_fee_per_kb)
                .expect("mempool"),
            orphan_pool: OrphanPool::new(cfg.max_orphan_txs as usize, cfg.orphan_ttl_sec)
                .expect("orphan"),
            gossip: GossipEngine::with_limits_and_replacement(
                64,
                50,
                ReplacementRateLimit {
                    window_sec: 60,
                    max_replacements: 5,
                    penalty: 10,
                },
            )
            .expect("gossip"),
        };
        relay.gossip.connect_peer(1);
        relay
            .mempool
            .insert_with_fee(tx.clone(), 1_000)
            .expect("insert tx");
        let mut state = RelayServerState { runtime, relay };

        let out = process_relay_wire_message(
            &mut state,
            1,
            WireMessage::GetData {
                items: vec![InventoryItem::Tx(txid)],
            },
            1_000,
        )
        .expect("process getdata");
        assert!(
            out.iter()
                .any(|msg| matches!(msg, WireMessage::Tx { tx } if tx.txid() == txid))
        );
        assert!(
            !out.iter()
                .any(|msg| matches!(msg, WireMessage::NotFound { .. })),
            "known inventory must not generate notfound"
        );
    }

    #[test]
    fn relay_inv_path_keeps_only_messages_for_originating_peer() {
        let cfg: ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        cfg.validate().expect("config validate");
        let runtime = ChainRuntime::from_config(cfg.clone()).expect("runtime");
        let mut gossip = GossipEngine::with_limits_and_replacement(
            64,
            50,
            ReplacementRateLimit {
                window_sec: 60,
                max_replacements: 5,
                penalty: 10,
            },
        )
        .expect("gossip");
        gossip.connect_peer(10);
        let relay = RelayAdmissionState {
            mempool: Mempool::with_policy(cfg.max_mempool_txs as usize, cfg.min_relay_fee_per_kb)
                .expect("mempool"),
            orphan_pool: OrphanPool::new(cfg.max_orphan_txs as usize, cfg.orphan_ttl_sec)
                .expect("orphan"),
            gossip,
        };
        let mut state = RelayServerState { runtime, relay };

        let out = process_relay_wire_message(
            &mut state,
            10,
            WireMessage::Inv {
                items: vec![InventoryItem::Tx(Hash256([0xAB; 32]))],
            },
            1_000,
        )
        .expect("process inv");
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], WireMessage::GetData { .. }));
    }

    #[test]
    fn template_provider_service_roundtrip() {
        let _net_guard = network_test_guard();
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
        join_with_timeout(server, Duration::from_secs(5), "template provider").expect("ok");
    }

    #[test]
    fn job_declarator_service_roundtrip() {
        let _net_guard = network_test_guard();
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
        let request = super::JobDeclaratorRequest {
            channel_id: 1,
            template: super::mining_template_to_rpc(&template),
        };
        let first = super::call_json_role_service::<
            super::JobDeclaratorRequest,
            super::JobDeclaratorResponse,
        >(&addr, &request)
        .expect("first")
        .job_id;
        let second = super::call_json_role_service::<
            super::JobDeclaratorRequest,
            super::JobDeclaratorResponse,
        >(&addr, &request)
        .expect("second")
        .job_id;
        assert_eq!(first, 42);
        assert_eq!(second, 43);
        join_with_timeout(server, Duration::from_secs(5), "job declarator").expect("ok");
    }

    #[test]
    fn translator_service_roundtrip() {
        let _net_guard = network_test_guard();
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
        join_with_timeout(server, Duration::from_secs(5), "translator").expect("ok");
    }

    #[test]
    fn template_provider_entrypoint_rejects_invalid_bind_address() {
        let bind_err = run_sv2_template_provider(Sv2TemplateProviderArgs {
            bind: "not-an-addr".to_owned(),
            max_requests: 1,
            telemetry_out: None,
        })
        .expect_err("invalid bind must fail template provider startup");
        assert!(bind_err.to_string().contains("bind failed"));
    }

    #[test]
    fn translator_and_sv2_entrypoints_surface_connect_and_bind_failures() {
        let translation_err =
            translate_remote_job_with_service("127.0.0.1:0", Sv2Message::KeepAlive)
                .expect_err("unreachable translator endpoint must fail");
        assert!(
            translation_err
                .to_string()
                .contains("connect to role service")
        );

        let declarator_bind_err = run_sv2_job_declarator(Sv2JobDeclaratorArgs {
            bind: "not-an-addr".to_owned(),
            max_requests: 1,
            start_job_id: 1,
            telemetry_out: None,
        })
        .expect_err("invalid bind must fail declarator startup");
        assert!(declarator_bind_err.to_string().contains("bind failed"));

        let bind_err = run_sv2_translator(Sv2TranslatorArgs {
            bind: "not-an-addr".to_owned(),
            max_requests: 1,
            telemetry_out: None,
        })
        .expect_err("invalid bind must fail translator startup");
        assert!(bind_err.to_string().contains("bind failed"));

        let conformance_err = run_sv2_conformance(Sv2ConformanceArgs {
            pool: "127.0.0.1:0".to_owned(),
            user: "u".to_owned(),
            read_timeout_sec: 1,
            secure_transport: false,
            secure_transport_mode: None,
            secure_rekey_interval_messages: 10_000,
            secure_static_secret_key_hex: None,
            secure_expected_remote_static_pubkey_hex: None,
            corpus: None,
            out: None,
            stack_name: None,
        })
        .expect_err("unreachable conformance endpoint must fail");
        assert!(
            conformance_err
                .to_string()
                .contains("sv2 conformance connect failed")
        );
    }

    #[test]
    fn run_from_args_reports_parse_errors() {
        let err = super::run_from_args(["scam-node", "--definitely-invalid-flag"])
            .expect_err("invalid args must fail parse");
        assert!(err.to_string().contains("unexpected argument"));

        let missing_cfg = temp_dir("run-from-args-missing-config").join("missing.toml");
        let err = super::run_from_args([
            "scam-node",
            "status",
            "--network",
            "devnet",
            "--config",
            missing_cfg.to_str().expect("missing cfg path"),
        ])
        .expect_err("run_from_args must execute command dispatch");
        assert!(err.to_string().contains("config"));
    }
}
