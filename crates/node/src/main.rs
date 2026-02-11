use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use scam_consensus::{UtxoSet, validate_and_apply_block, validate_block_basic};
use scam_core::{ChainConfig, ChainConfigError, block_meets_pow};
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
    Wallet(WalletArgs),
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
struct WalletArgs {
    #[command(subcommand)]
    command: WalletCommand,
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

fn run() -> Result<(), NodeError> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Node(args)) => run_node(args.network, args.config, args.print_genesis),
        Some(Command::Wallet(args)) => run_wallet(args.command),
        None => run_node(cli.network, cli.config, cli.print_genesis),
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
