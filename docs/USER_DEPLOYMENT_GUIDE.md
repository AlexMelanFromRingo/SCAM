# SCAM User Deployment Guide

This guide is a practical, user-focused path: build binary, run node, create wallet, sync peers, and (optionally) mine.

## 1) Preconditions

- OS: Linux/macOS.
- Rust toolchain installed.
- Open ports as needed:
  - P2P relay: default `18444`
  - Stratum: default `3347`

Check toolchain:

```bash
rustc --version
cargo --version
```

## 2) Build Binary

From repo root:

```bash
cargo build --release -p scam-node
```

Binary path:

```text
target/release/scam-node
```

Optional install into PATH:

```bash
install -m 755 target/release/scam-node /usr/local/bin/scam-node
```

## 3) Choose Network Config

Presets:
- `config/devnet.toml`
- `config/testnet.toml`
- `config/mainnet.toml`

For your own fork/network use:

```bash
scam-node config-scaffold --network-id myfork --hrp sc --out config/myfork.toml
```

## 4) Start Node

```bash
scam-node node \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb
```

Check status in another terminal:

```bash
scam-node status --network devnet --config config/devnet.toml
```

## 5) Connect to Peers

If you know a peer endpoint:

```bash
scam-node add-peer --network devnet --peer 203.0.113.10:18444
scam-node sync-peer --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb --peer 203.0.113.10:18444
```

If you have peer book + seeds:

```bash
scam-node sync-book --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
```

### 5.1 Web Console (Explorer + Wallet GUI)

Run RPC server against runtime DB and serve UI files:

```bash
scam-node rpc-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 127.0.0.1:18080 \
  --ui-dir web \
  --relay-telemetry data/relay.telemetry.jsonl
```

Open:

```text
http://127.0.0.1:18080/
```

Wallet actions in the web UI call RPC endpoints (`/wallet/*`).
Mining operations should still use Stratum/SV2 commands.

## 6) Create Wallet (Secure Recommended)

Create encrypted vault:

```bash
scam-node wallet secure-new \
  --words 12 \
  --password "<strong-password>" \
  --out data/wallets/default.vault.json \
  --hrp sd
```

Get receive address:

```bash
scam-node wallet secure-address \
  --wallet data/wallets/default.vault.json \
  --password "<strong-password>" \
  --hrp sd
```

Rescan wallet range:

```bash
scam-node wallet secure-rescan \
  --network devnet \
  --config config/devnet.toml \
  --wallet data/wallets/default.vault.json \
  --password "<strong-password>" \
  --start-index 0 \
  --end-index 50
```

## 7) Send and Verify

Send transaction (mnemonic flow):

```bash
scam-node wallet send \
  --network devnet \
  --config config/devnet.toml \
  --mnemonic "<mnemonic words>" \
  --to <recipient_address> \
  --amount 1000 \
  --fee 1
```

Address decode:

```bash
scam-node wallet decode --address <address>
```

QR display:

```bash
scam-node wallet qr --address <address> --amount 1000 --label "Invoice #1"
```

## 8) Mining (Optional)

Run local pool:

```bash
scam-node stratum-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 127.0.0.1:3347
```

Run worker:

```bash
scam-node stratum-mine --pool 127.0.0.1:3347 --user miner01 --max-shares 100
```

## 9) Secure Stratum (`noise_xx`) Setup

Generate keypair:

```bash
scam-node stratum-keygen \
  --secret-out data/stratum-keys/server.secret.hex \
  --public-out data/stratum-keys/server.public.hex
```

Start secure server:

```bash
scam-node stratum-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 127.0.0.1:3347 \
  --secure-transport \
  --secure-transport-mode noise-xx \
  --secure-static-secret-key-hex <server_secret_hex32>
```

Secure worker:

```bash
scam-node stratum-mine \
  --pool 127.0.0.1:3347 \
  --user miner01 \
  --secure-transport \
  --secure-transport-mode noise-xx \
  --secure-static-secret-key-hex <client_secret_hex32>
```

Rotate keypair:

```bash
scam-node stratum-key-rotate \
  --secret-path data/stratum-keys/server.secret.hex \
  --public-path data/stratum-keys/server.public.hex \
  --archive-dir data/stratum-keys/archive
```

## 10) Backups and Recovery

Backup runtime DB:

```bash
cp data/devnet.runtime.redb data/devnet.runtime.redb.bak.$(date +%Y%m%d-%H%M%S)
```

Reindex runtime:

```bash
scam-node reindex-runtime --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
```

## 11) Service Deployment Example (systemd)

`/etc/systemd/system/scam-node.service`:

```ini
[Unit]
Description=SCAM Node
After=network-online.target

[Service]
User=scam
WorkingDirectory=/opt/scam
ExecStart=/opt/scam/scam-node node --network testnet --config /opt/scam/config/testnet.toml --runtime-db /var/lib/scam/testnet.runtime.redb
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Apply:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now scam-node
sudo systemctl status scam-node
```

## 12) Validation Before Public Use

Run baseline checks:

```bash
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Run durability and rehearsal scripts:

```bash
scripts/soak-24h.sh
scripts/chaos-crash-loop.sh
scripts/testnet-dress-rehearsal.sh
```
