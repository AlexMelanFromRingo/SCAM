use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use scam_chain::{BlockSubmissionOutcome, ChainError, ChainRuntime};
use scam_consensus::{TxValidationError, UtxoSet, validate_and_apply_block, validate_block_basic};
use scam_core::{
    ChainConfig, ChainConfigError, Hash256, OutPoint, Transaction, TxIn, TxOut, block_meets_pow,
    render_hash_bitmap_16x16,
};
use scam_miner::{BlockTemplate, mine_block};
use scam_p2p::{
    FramingConfig, GossipEngine, LocalHandshake, TransportError, WireMessage, build_block_locator,
    client_handshake, read_message, request_headers, select_headers_for_peer, send_message,
    server_handshake,
};
use scam_rpc::{StatusResponse, TxResponse, header_to_block_response, to_pretty_json};
use scam_storage::{ChainStateSnapshot, StorageError, load_snapshot, save_snapshot};
use scam_wallet::{
    AddressError, DeriveKeyError, MnemonicError, QrError, SchnorrError, WalletMnemonic,
    derive_wallet_key, new_mnemonic, parse_address, qr_for_payment_uri, sign_digest, to_address,
    verify_digest,
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
    #[arg(long, default_value_t = false)]
    print_genesis: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    Node(NodeArgs),
    Status(StatusArgs),
    GetBlock(GetBlockArgs),
    GetTx(GetTxArgs),
    AddPeer(AddPeerArgs),
    HashVisual(HashVisualArgs),
    Wallet(WalletArgs),
    MineOnce(MineOnceArgs),
    ChainDemo(ChainDemoArgs),
    SyncDemo(SyncDemoArgs),
    NetDemo(NetDemoArgs),
    ReorgDemo(ReorgDemoArgs),
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
    Show {
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
        #[arg(long, default_value = "scd")]
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
        #[arg(long, default_value = "scd")]
        hrp: String,
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
        #[arg(long, default_value = "scd")]
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

impl Network {
    fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }
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
    #[error("qr error: {0}")]
    Qr(#[from] QrError),
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

fn run_node(
    network: Network,
    config: Option<PathBuf>,
    print_genesis: bool,
) -> Result<(), NodeError> {
    let config_path =
        config.unwrap_or_else(|| PathBuf::from(format!("config/{}.toml", network.as_str())));

    let cfg = load_chain_config(&config_path)?;
    let genesis = cfg.build_genesis_block()?;
    let genesis_hash = genesis.header.block_hash();

    println!("Project: SCAM (Smart Computing Alternative Money)");
    println!("Network: {}", cfg.network_id);
    println!("Config: {}", config_path.display());
    println!("Genesis hash: {}", genesis_hash);
    println!("Genesis PoW valid: {}", block_meets_pow(&genesis));
    println!(
        "Genesis consensus-valid: {}",
        validate_block_basic(&genesis).is_ok()
    );
    let mut utxos = UtxoSet::new();
    let applied = validate_and_apply_block(
        &genesis,
        0,
        cfg.block_subsidy,
        cfg.coinbase_maturity as u64,
        &mut utxos,
    );
    println!("Genesis UTXO-apply valid: {}", applied.is_ok());
    println!("Block target: {}", genesis.header.target);

    if print_genesis {
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

fn run_add_peer(args: AddPeerArgs) -> Result<(), NodeError> {
    let network_name = args.network.as_str();
    let peers_path = args.peers_dir.join(format!("{network_name}.txt"));
    if let Some(parent) = peers_path.parent() {
        fs::create_dir_all(parent).map_err(|e| NodeError::Runtime(e.to_string()))?;
    }

    let mut existing = if peers_path.exists() {
        fs::read_to_string(&peers_path)
            .map_err(|e| NodeError::Runtime(e.to_string()))?
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    if !existing.iter().any(|entry| entry == &args.peer) {
        existing.push(args.peer.clone());
        existing.sort();
        existing.dedup();
        let content = format!("{}\n", existing.join("\n"));
        fs::write(&peers_path, content).map_err(|e| NodeError::Runtime(e.to_string()))?;
        println!("Peer added for {}: {}", network_name, args.peer);
    } else {
        println!("Peer already exists for {}: {}", network_name, args.peer);
    }
    println!("Peer book: {}", peers_path.display());
    println!("Total peers: {}", existing.len());
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
        } => {
            let mnemonic = WalletMnemonic::parse(&mnemonic)?;
            let seed = mnemonic.to_seed(&passphrase);
            let key = derive_wallet_key(&seed, account, index)?;
            let address = to_address(&hrp, key.pubkey_compressed())?;

            println!(
                "PubKey (compressed): {}",
                hex::encode(key.pubkey_compressed())
            );
            println!("Address: {address}");
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
        SnapshotCommand::Show { path } => {
            let snapshot = load_snapshot(&path)?;
            println!("Snapshot: {}", path.display());
            println!("Network: {}", snapshot.network_id);
            println!("Tip height: {}", snapshot.tip_height);
            println!("Tip hash: {}", snapshot.tip_hash);
            println!("Blocks tracked: {}", snapshot.block_hashes_by_height.len());
            println!("UTXO count: {}", snapshot.utxos.len());
        }
    }
    Ok(())
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

fn mine_blocks_on_runtime(
    runtime: &mut ChainRuntime,
    params: &MiningLoopParams,
) -> Result<(), NodeError> {
    let mut timestamp = runtime
        .tip_header()
        .timestamp
        .saturating_add(params.interval_sec);
    for step in 1..=params.count {
        let expected_target = runtime.expected_target_for_next_block()?;
        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp,
            target: expected_target,
            transactions: vec![build_coinbase_tx(
                format!("{}-{step}", params.label_prefix),
                params.subsidy,
                params.miner_key_hash,
            )],
        };

        let Some(block) = mine_block(&template, params.max_nonce) else {
            return Err(NodeError::Runtime(format!(
                "cannot mine height {} in nonce range 0..={}",
                runtime.tip_height() + 1,
                params.max_nonce
            )));
        };

        let applied = runtime.apply_next_block(block)?;
        if params.print_each {
            let tip = runtime.tip_header();
            println!(
                "h={} hash={} target={} fees={}",
                runtime.tip_height(),
                applied.block_hash,
                tip.target,
                applied.total_fees
            );
        }
        timestamp = runtime
            .tip_header()
            .timestamp
            .saturating_add(params.interval_sec);
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
    for hash in remote.block_hashes() {
        if let Some(header) = remote.header_by_hash(hash) {
            remote_headers.insert(*hash, header.clone());
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

    let locator = build_block_locator(local.block_hashes());
    let headers = request_headers(&mut client, &framing, locator.clone(), None)?;

    let server_result = server
        .join()
        .map_err(|_| NodeError::Runtime("server thread panicked".to_owned()))?;
    if let Err(err) = server_result {
        return Err(NodeError::Runtime(format!("server error: {err}")));
    }

    println!("Net demo (TCP + handshake + headers-first)");
    println!(
        "Client tip: h={} hash={}",
        local.tip_height(),
        local.tip_hash()
    );
    println!(
        "Server tip: h={} hash={}",
        remote.tip_height(),
        remote.tip_hash()
    );
    println!("Locator sent: {}", locator.len());
    println!("Headers received: {}", headers.len());
    if let Some(first) = headers.first() {
        println!("First header prev: {}", first.prev_block);
    }
    if let Some(last) = headers.last() {
        println!("Last header hash: {}", last.block_hash());
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
        Some(Command::Node(args)) => run_node(args.network, args.config, args.print_genesis),
        Some(Command::Status(args)) => run_status(args),
        Some(Command::GetBlock(args)) => run_get_block(args),
        Some(Command::GetTx(args)) => run_get_tx(args),
        Some(Command::AddPeer(args)) => run_add_peer(args),
        Some(Command::HashVisual(args)) => run_hash_visual(args),
        Some(Command::Wallet(args)) => run_wallet(args.command),
        Some(Command::MineOnce(args)) => run_mine_once(args),
        Some(Command::ChainDemo(args)) => run_chain_demo(args),
        Some(Command::SyncDemo(args)) => run_sync_demo(args),
        Some(Command::NetDemo(args)) => run_net_demo(args),
        Some(Command::ReorgDemo(args)) => run_reorg_demo(args),
        Some(Command::RpcServe(args)) => run_rpc_serve(args),
        Some(Command::Snapshot(args)) => run_snapshot(args.command),
        Some(Command::P2pDemo) => run_p2p_demo(),
        None => run_node(cli.network, cli.config, cli.print_genesis),
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
