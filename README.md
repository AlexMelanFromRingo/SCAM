# SCAM (Smart Computing Alternative Money)

SCAM is a Rust 2024 implementation of a PoW L1 blockchain with a configurable, production-style baseline.

Current repository status (2026-03-10, `RC3`):
- Release candidate baseline is marked as `RC3`.
- Full mutation closure is green on current code (`stage2` closure + full `stage3` with `0 missed`, `0 timeout`).
- Workspace quality gates are green: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Remaining deferred non-code gates: long-run soak, external audit, and the maximum-detail documentation pack.
- Codebase size (approx, excluding `target/` and vendor trees):
  - Total tracked LOC: ~79,237
  - Rust LOC: ~62,831

This README is written as an operator+developer manual: what the protocol does, how to build it, how to run node/wallet/mining, and how to validate deployments.

---

## 1) What SCAM Implements

### Consensus and chain
- PoW with **BLAKE3-256**.
- Valid block rule: `hash(block_header) <= target` (numeric compare, no “leading zero” shortcut logic).
- Target block interval: **120 sec**.
- Difficulty algorithms (config-selectable):
  - `windowed`
  - `lwma`
  - `asert`
- Longest-chain rule by **cumulative work** (not height only).
- Reorg handling with disconnect/connect logic.
- Fixed block subsidy (no hard supply cap by default).

### Crypto and addressing
- Signature scheme: **Schnorr (secp256k1, BIP340-style)**.
- Public key format on interfaces: compressed SEC33 (`02/03 + x`).
- Address format: **Bech32m**.
- Address payload: `RIPEMD160(BLAKE3(pubkey_compressed))`.
- Network replay protection in tx sighash via chain domain (`network_id`).

### Wallet
- BIP39 mnemonic create/restore.
- HD derivation (frozen derivation path in code).
- Encrypted vault at rest (`Argon2id + XChaCha20Poly1305`).
- Rescan over chain for address ranges.
- QR and payment URI generation.

### Transaction policy
- UTXO model.
- Structural checks: no duplicate inputs, no zero-value outputs, no coinbase in mempool.
- Mempool conflict policy: **fee-aware replacement** (no txid-grinding policy).
- Replacement limits include min fee delta + descendant guardrails.
- CPFP-aware miner selection.
- Orphan pool with bounded size + TTL.

### P2P and sync
- Wire primitives: `version/verack`, `ping/pong`, `inv/getdata`, `tx/block`, `getheaders/headers`, `getblocks`.
- Transport module exposes both blocking and async framing/handshake APIs.
- Headers-first sync + block download/apply.
- Peer book persistence (`redb`) + DNS seed ingestion.
- Outbound diversity and rotation for eclipse-risk reduction.
- The node process (`serve`): P2P relay with per-peer replacement-rate
  controls, plus in-process RPC/web console and stratum pool on one chain
  and mempool; it owns its data directory (stores opened once, locked).

### Stratum / SV2 subset
- Binary framing + typed message state machine.
- Pool endpoint (`serve --stratum`, or standalone `stratum-serve`) + worker
  client (`stratum-mine`).
- The pool uses async tokio socket I/O with bounded concurrent sessions.
- Role split services:
  - `sv2-template-provider`
  - `sv2-job-declarator`
  - `sv2-translator`
- Secure transport modes:
  - `legacy` (ECDH+AEAD baseline)
  - `noise_xx` (Noise `XX_25519_ChaChaPoly_BLAKE2s`)
- Key lifecycle commands:
  - `stratum-keygen`
  - `stratum-key-rotate`
- Conformance/corpus tooling:
  - `sv2-conformance`
  - `scripts/sv2-corpus-replay.sh`
  - `scripts/sv2-conformance-matrix.sh`

---

## 2) Workspace Layout

- `crates/core` – types, hashes, config, serialization.
- `crates/consensus` – block/tx validation, difficulty math.
- `crates/chain` – runtime, cumulative-work selection, reorg.
- `crates/mempool` – mempool/orphans/replacement/telemetry.
- `crates/p2p` – wire protocol, gossip, discovery, sync.
- `crates/miner` – templates, CPFP ordering, nonce loops.
- `crates/stratum` – SV2 subset protocol + secure transport.
- `crates/storage` – `redb` persistence for chain + peers.
- `crates/wallet` – mnemonic/HD/signing/vault/rescan/QR.
- `crates/node` – CLI orchestration.

---

## 3) Protocol Details (Operator-Facing)

### 3.1 Block structure
Header fields:
- `version`
- `prev_block`
- `merkle_root`
- `timestamp`
- `target`
- `nonce`

Validation baseline:
- merkle root matches tx list,
- PoW target check (`hash <= target`),
- coinbase first,
- subsidy+fees accounting,
- contextual timestamp checks:
  - median-time-past guard,
  - max-future-time guard.

### 3.2 Difficulty
Config controls algorithm and parameters.

`windowed` (classic N-block retarget):
- `expected = N * target_block_time_sec`
- `actual = time(last) - time(last-N)`
- `new_target = old_target * actual / expected`
- clamp up/down and min/max target bounds.

`lwma`:
- weighted solve-time model over recent window,
- smoother adaptation against hashrate swings.

`asert`:
- exponential target adjustment around anchor,
- configured by `asert_half_life_sec`.

### 3.3 Monetary policy
- Fixed subsidy per block (`block_subsidy`).
- Emission is perpetual unless policy is changed in config/protocol rules.
- Difficulty controls issuance timing stability, not market price.

### 3.4 Mempool policy
- Conflict handling is **fee policy**, not hash-order race.
- Replacement accepted only when policy constraints are satisfied.
- Peer-scoped replacement-rate controls exist in gossip/relay paths.

---

## 4) Build and Toolchain

### 4.1 Prerequisites
- Linux/macOS with `bash`.
- Rust stable toolchain (workspace currently validated on Rust 1.93.x stable).
- For fuzzing: nightly toolchain.

### 4.2 Build (debug)

```bash
cargo build --workspace
```

### 4.3 Build (release)

```bash
cargo build --workspace --release
```

Main binary:
- `target/release/scam-node`

### 4.4 Full quality gate

```bash
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

### 4.5 Release automation (GitHub Actions)

- Workflow: `.github/workflows/release-build.yml`
- Trigger:
  - push to `master` when `Cargo.toml` workspace version changes,
  - manual `workflow_dispatch`.
- Output:
  - creates/updates GitHub Release tag `v<workspace-version>`,
  - uploads raw binaries (no archive):
    - `scam-node-linux-x86_64`
    - `scam-node-windows-x86_64.exe`
    - `scam-node-macos-aarch64`

---

## 5) Configuration and Network Profiles

Preset configs:
- `config/devnet.toml`
- `config/testnet.toml`
- `config/mainnet.toml`

Important config groups:
- consensus: block interval, difficulty params, subsidy,
- tx/pool: size/fee/orphan/replacement parameters,
- p2p: DNS seeds, outbound bucket cap, ban thresholds,
- stratum: vardiff/share limits/timeouts/secure mode,
- wallet policy: `wallet_min_spendable_confirmations` for regular (non-coinbase) spendability,
- genesis: message/timestamp/target/nonce/reward script hash,
- address HRP.

Generate a new fork config:

```bash
cargo run -p scam-node -- config-scaffold \
  --network-id myfork \
  --hrp sc \
  --difficulty-algorithm lwma \
  --target-block-time-sec 120 \
  --difficulty-adjustment-window 20 \
  --stratum-secure-transport \
  --stratum-secure-transport-mode noise-xx \
  --out config/myfork.toml
```

---

## 6) Running a Node

### 6.0 Simple Launch Helpers

For default local usage (without long CLI flag lists), use:

```bash
scripts/scam-easy.sh help
scripts/scam-easy.sh node
scripts/scam-easy.sh relay
scripts/scam-easy.sh rpc
scripts/scam-easy.sh pool
scripts/scam-easy.sh miner
```

Dedicated single-purpose launchers:

```bash
# 1) Miner only (connect to remote/local pool, payout label = your address)
POOL_ADDR=127.0.0.1:3347 \
COINBASE_ADDRESS=sd1... \
scripts/run-miner.sh start

# 2) Node only (relay + RPC/UI, no local mining)
ADD_PEERS=203.0.113.10:18444,198.51.100.25:18444 \
scripts/run-node-only.sh start

# 3) Node + local miner (relay + RPC/UI + stratum + miner)
ADD_PEERS=203.0.113.10:18444,198.51.100.25:18444 \
COINBASE_ADDRESS=sd1... \
scripts/run-node-miner.sh start
```

Each script supports `start|stop|status|logs`.
`ADD_PEERS` is optional and applies only to scripts that run a node (`run-node-only.sh`, `run-node-miner.sh`).

Windows launcher equivalents (same commands, `.bat` wrappers over PowerShell):

```bat
:: 1) Miner only
set POOL_ADDR=127.0.0.1:3347
set COINBASE_ADDRESS=sd1...
scripts\run-miner.bat start

:: 2) Node only
set ADD_PEERS=203.0.113.10:18444,198.51.100.25:18444
scripts\run-node-only.bat start

:: 3) Node + local miner
set ADD_PEERS=203.0.113.10:18444,198.51.100.25:18444
set COINBASE_ADDRESS=sd1...
scripts\run-node-miner.bat start
```

The `.bat` launchers also support `start|stop|status|logs`.

For local multi-node verification:

```bash
scripts/local-multinode.sh up
scripts/local-multinode.sh status
scripts/local-multinode.sh down
```

For large clusters, run Stratum only on selected nodes (example: node `0` and `1`):

```bash
NODE_COUNT=50 RUN_STRATUM=true STRATUM_NODE_INDEXES=0,1 \
  BASE_P2P_PORT=44400 BASE_RPC_PORT=44000 BASE_STRATUM_PORT=45000 \
  scripts/local-multinode.sh up
```

By default `local-multinode` wires a bounded topology (`WIRE_PEERS_PER_NODE=8`) for faster startup on large clusters.
Set `WIRE_PEERS_PER_NODE=0` if you explicitly need full-mesh wiring.
Relay sessions run async read polling (`SCAM_RELAY_ASYNC_READ_POLL_MS`, default `250`) so tip/header propagation does not wait for long socket timeouts.

Binary-only run (outside repo, no cargo build step):

```bash
SCAM_NODE_BIN=./scam-node BUILD=false scripts/local-multinode.sh up
```

For a fuller local lab (2+ nodes + miner + demo wallets + UI):

```bash
scripts/local-test-lab.sh up
scripts/local-test-lab.sh status
scripts/local-test-lab.sh down
```

Scenario presets (single command profile loader):

```bash
scripts/run-preset.sh list
scripts/run-preset.sh lab-solo-local up
scripts/run-preset.sh lab-solo-local status
scripts/run-preset.sh lab-solo-local down
```

For quick sync-spread measurements on larger clusters:

```bash
CLUSTER_DIR=target/local-cluster50 NODE_COUNT=50 RUN_STRATUM=true STRATUM_NODE_INDEXES=0,1 \
  BASE_P2P_PORT=44400 BASE_RPC_PORT=44000 BASE_STRATUM_PORT=45000 \
  SCAM_NODE_BIN=target/release/scam-node BUILD=false \
  scripts/cluster-sync-sample.sh
```

Available preset files live in `scripts/presets/*.env` and can be copied/edited for custom operator flows.

Binary-only run:

```bash
SCAM_NODE_BIN=./scam-node BUILD=false scripts/local-test-lab.sh up
```

By default this lab uses live relay outbound auto-connect (`RELAY_OUTBOUND_CONNECT=true`) and does not run periodic `sync-book` loops (`RUN_SYNC_LOOP=false`). Miner payout defaults to `wallet-01` unless you override `MINER_USER`.

Automated local E2E transfer/mining/sync check (wallet-01 -> wallet-02 across node-0/node-1):

```bash
scripts/local-e2e-flow.sh
```

Expected result: `[e2e] success` plus JSON payload with `txid` and non-zero `receiver_spendable`, without enabling periodic `sync-book` loops.

### 6.1 Bootstrap node runtime

```bash
cargo run -p scam-node -- node \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb
```

### 6.2 Status and chain queries

```bash
cargo run -p scam-node -- status --network devnet --config config/devnet.toml
cargo run -p scam-node -- get-block --network devnet --config config/devnet.toml --height 1
cargo run -p scam-node -- get-tx --network devnet --config config/devnet.toml --height 1 --tx-index 0
```

### 6.3 Manual peer bootstrap

```bash
cargo run -p scam-node -- add-peer --network devnet --peer 203.0.113.10:18444
cargo run -p scam-node -- sync-peer \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --peer 203.0.113.10:18444
```

### 6.4 Peer-book fanout sync

```bash
cargo run -p scam-node -- sync-book \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb
```

### 6.5 The node process (`serve`)

A node is one process: the P2P relay plus, optionally, the RPC/web console
and the stratum pool, all on the same in-memory chain and mempool. The
process owns its data directory — every store is opened once and locked —
so a second process on the same files (another `serve`, `relay-serve`,
`rpc-serve`, `stratum-serve`, or a CLI tool that writes the stores) is
refused with "database ... is held by another running process". Talk to a
running node through its RPC instead.

```bash
cargo run -p scam-node -- serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --peers-dir data/peers \
  --bind 0.0.0.0:18444 \
  --outbound-connect \
  --telemetry-out data/relay.telemetry.jsonl \
  --rpc "--bind 127.0.0.1:18080 --ui-dir web" \
  --stratum "--bind 127.0.0.1:3347"
```

`--rpc` and `--stratum` take the options of `rpc-serve` / `stratum-serve` as
one string (quote values with spaces: `--ui-dir 'my web'`); network, config
and runtime DB are always the node's. A failing service stops the node.

`relay-serve`, `rpc-serve` and `stratum-serve` still exist for a process that
is alone on its data directory: a relay without services, an explorer over
a stopped node's data, or a test pool (as the SV2 conformance matrix uses).

### 6.6 RPC + Web Console (Explorer + Wallet UI)

Run it inside the node (`serve --rpc "..."`, above). Then open:

```text
http://127.0.0.1:18080/
```

RPC security model:
- Every state-changing request must be `POST` with `Content-Type: application/json`
  (blocks cross-site form posts); a browser `Origin` must be loopback.
- The `Host` header must be loopback (DNS-rebinding protection), so expose the
  RPC beyond the host only through a reverse proxy that you control.
- Binding to a non-loopback address requires a bearer token:
  `--auth-token-file <file>` (or `SCAM_RPC_AUTH_TOKEN`); clients then send
  `Authorization: Bearer <token>` on every `POST`.
- `--disable-wallet-rpc` turns off the routes that accept a mnemonic
  (`/wallet/new|address|balance|send-preview|send`). Use it for any shared,
  proxied or public deployment.

RPC endpoints used by the console:
- GET: `/health`, `/status`, `/block/<height>`, `/tx/<height>/<index>`, `/mempool`, `/events` (SSE snapshots)
- POST: `/wallet/new`, `/wallet/address`, `/wallet/decode`, `/wallet/balance`, `/wallet/balance-by-address`, `/wallet/balance-history-by-address`, `/wallet/send-preview`, `/wallet/send`, `/tx/submit`, `/wallet/qr`

---

## 7) Wallet User Flows

### 7.1 Simple mnemonic wallet

Create mnemonic:

```bash
cargo run -p scam-node -- wallet new --words 12 --hrp sd
```

Derive address from mnemonic:

```bash
cargo run -p scam-node -- wallet address --mnemonic "<words>" --hrp sd
```

Derive address by explicit derivation path:

```bash
cargo run -p scam-node -- wallet address \
  --mnemonic "<words>" \
  --path "m/44'/1337'/0'/0/12" \
  --hrp sd
```

Check balance:

```bash
cargo run -p scam-node -- wallet balance \
  --network devnet \
  --config config/devnet.toml \
  --mnemonic "<words>"
```

Check balance by explicit derivation path:

```bash
cargo run -p scam-node -- wallet balance \
  --network devnet \
  --config config/devnet.toml \
  --mnemonic "<words>" \
  --path "m/44'/1337'/0'/0/12"
```

Discover funded paths in account/index ranges (gap-limit scan):

```bash
cargo run -p scam-node -- wallet discover \
  --network devnet \
  --config config/devnet.toml \
  --mnemonic "<words>" \
  --start-account 0 \
  --end-account 5 \
  --gap-limit 20 \
  --max-index 500
```

Watch-only balance by address:

```bash
cargo run -p scam-node -- wallet balance-address \
  --network devnet \
  --config config/devnet.toml \
  --address <address>
```

Send (`--fee` is optional; without it the minimum relay fee for the
transaction size is paid). Secrets can be passed via `SCAM_WALLET_MNEMONIC`,
`SCAM_WALLET_PASSPHRASE` and `SCAM_WALLET_PASSWORD` instead of arguments, which
are visible to other users in `ps`:

```bash
SCAM_WALLET_MNEMONIC="<words>" cargo run -p scam-node -- wallet send \
  --network devnet \
  --config config/devnet.toml \
  --to <address> \
  --amount 1000
```

### 7.2 Encrypted wallet vault (recommended)

Create secure vault (refuses to overwrite an existing file; pass `--force` to
replace it — the old wallet is then gone unless its mnemonic is backed up).
The vault is written with owner-only permissions on Unix:

```bash
cargo run -p scam-node -- wallet secure-new \
  --words 12 \
  --password "<strong-password>" \
  --out data/wallets/default.vault.json \
  --hrp sd
```

Derive address from vault:

```bash
cargo run -p scam-node -- wallet secure-address \
  --wallet data/wallets/default.vault.json \
  --password "<strong-password>" \
  --hrp sd
```

Rescan vault:

```bash
cargo run -p scam-node -- wallet secure-rescan \
  --network devnet \
  --config config/devnet.toml \
  --wallet data/wallets/default.vault.json \
  --password "<strong-password>" \
  --start-index 0 \
  --end-index 50
```

### 7.3 QR/payment URI

```bash
cargo run -p scam-node -- wallet qr --address <address> --amount 12345 --label "Payment"
```

---

## 8) Mining and Stratum/SV2

### 8.1 Local pool server

Run the pool inside the node so it builds templates from the node's mempool
and its blocks reach peers at once (`serve --stratum "--bind 127.0.0.1:3347
--pool-payout-mode solo"`, see 6.5). Payout secrets come from the
environment (`SCAM_POOL_PAYOUT_MNEMONIC`, `SCAM_POOL_PAYOUT_PASSPHRASE`).

### 8.2 Worker

```bash
cargo run -p scam-node -- stratum-mine \
  --pool 127.0.0.1:3347 \
  --user <payout_address> \
  --max-shares 100
```

If `--user` is a valid SCAM address for the current network, that address is used as coinbase payout target for the channel.

### 8.3 External role services

```bash
cargo run -p scam-node -- sv2-template-provider --bind 127.0.0.1:3550
cargo run -p scam-node -- sv2-job-declarator --bind 127.0.0.1:3551
cargo run -p scam-node -- sv2-translator --bind 127.0.0.1:3552
```

Wire the node's pool to external roles:

```bash
cargo run -p scam-node -- serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 0.0.0.0:18444 \
  --stratum "--bind 127.0.0.1:3347 --template-provider-addr 127.0.0.1:3550 --job-declarator-addr 127.0.0.1:3551"
```

---

## 9) Secure Transport Modes and Keys

### 9.1 Key generation

```bash
cargo run -p scam-node -- stratum-keygen \
  --secret-out data/stratum-keys/server.secret.hex \
  --public-out data/stratum-keys/server.public.hex
```

### 9.2 Key rotation

```bash
cargo run -p scam-node -- stratum-key-rotate \
  --secret-path data/stratum-keys/server.secret.hex \
  --public-path data/stratum-keys/server.public.hex \
  --archive-dir data/stratum-keys/archive
```

### 9.3 `noise_xx` secure server

```bash
export SCAM_STRATUM_STATIC_SECRET_KEY_HEX=<server_secret_hex32>
cargo run -p scam-node -- serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 0.0.0.0:18444 \
  --stratum "--bind 127.0.0.1:3347 --secure-transport --secure-transport-mode noise-xx"
```

### 9.4 `noise_xx` secure worker

```bash
cargo run -p scam-node -- stratum-mine \
  --pool 127.0.0.1:3347 \
  --user <payout_address> \
  --secure-transport \
  --secure-transport-mode noise-xx \
  --secure-static-secret-key-hex <client_secret_hex32>
```

---

## 10) Storage, Backup, Recovery

Backup runtime DB:

```bash
cp data/devnet.runtime.redb data/devnet.runtime.redb.bak.$(date +%Y%m%d-%H%M%S)
```

Reindex runtime from archive:

```bash
cargo run -p scam-node -- reindex-runtime \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb
```

Snapshot tools:

```bash
cargo run -p scam-node -- snapshot --help
```

---

## 11) Soak, Chaos, Rehearsal

24h soak profile:

```bash
scripts/soak-24h.sh
```

Crash-loop durability:

```bash
scripts/chaos-crash-loop.sh
```

Telemetry threshold gate:

```bash
scripts/telemetry-alert-check.py --input data/soak.telemetry.jsonl
```

Public-testnet dress rehearsal:

```bash
scripts/testnet-dress-rehearsal.sh
```

Mainnet parameter freeze lock artifact:

```bash
scripts/mainnet-freeze-lock.sh
```

---

## 12) Fuzzing and Mutation Testing

### Fuzzing (requires nightly)

Install tools once:

```bash
cargo install cargo-fuzz
rustup toolchain install nightly --profile minimal
```

Run targets:

```bash
cargo +nightly fuzz run wire_decode --manifest-path fuzz/Cargo.toml
cargo +nightly fuzz run block_decode --manifest-path fuzz/Cargo.toml
cargo +nightly fuzz run tx_decode --manifest-path fuzz/Cargo.toml
```

### Mutation testing

Install tool:

```bash
cargo install cargo-mutants
```

Run baseline script:

```bash
scripts/mutation-baseline.sh
```

Run staged script (recommended for faster signal and lower flakiness):

```bash
scripts/mutation-staged.sh stage1
scripts/mutation-staged.sh stage2
scripts/mutation-staged.sh stage3
```

Package-scoped mutation is also available:

```bash
MUTATION_PACKAGES="scam-core scam-consensus" scripts/mutation-baseline.sh
```

---

## 13) Conformance and Interop Matrix

Single endpoint conformance:

```bash
cargo run -p scam-node -- sv2-conformance \
  --pool 127.0.0.1:3347 \
  --stack-name local \
  --corpus docs/sv2-corpus/default.json \
  --out target/sv2-conformance/local.json
```

Matrix + report generation:

```bash
scripts/sv2-conformance-matrix.sh
python3 scripts/sv2-conformance-report.py \
  --input-dir target/sv2-conformance \
  --summary-out target/sv2-conformance/summary.json \
  --matrix-out target/sv2-conformance/matrix.md
```

---

## 14) Production Notes and Limits

- This is a strong base implementation, but production operations still require:
  - infra hardening (monitoring, key custody, incident drills),
  - external peer ecosystem validation,
  - change-management discipline for protocol/config updates.
- Mining control/data plane should use Stratum/SV2; RPC is intentionally operator/wallet-facing API and web-console transport.
- Always run `testnet` + rehearsal workflows before any mainnet-facing change.

---

## 15) Documentation Index

- `docs/IMPLEMENTATION_TODO.md`
- `docs/RELEASE_STATUS.md`
- `docs/METHODICAL_MANUAL.md`
- `docs/USER_DEPLOYMENT_GUIDE.md`
- `docs/OPERATOR_RUNBOOK.md`
- `docs/STRATUM_SV2_NOTES.md`
- `docs/SV2_POOL_GRADE_GAP.md`
- `docs/SV2_ROLE_INTERFACES.md`
- `docs/SV2_ROLLOUT_POLICY.md`
- `docs/SV2_ROLE_INCIDENT_RUNBOOK.md`
- `docs/SV2_INTEROP_MATRIX.md`
- `docs/MEMPOOL_THREAT_MODEL.md`
- `docs/TESTING_STRATEGY.md`
- `docs/FORKING_GUIDE.md`
- `docs/WEB_CONSOLE.md`
