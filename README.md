# SCAM (Smart Computing Alternative Money)

SCAM is a Rust 2024 implementation of a PoW L1 blockchain with a configurable, production-style baseline.

Current repository status (2026-02-13):
- `IMPLEMENTATION_TODO` checklist is fully closed.
- `SV2_POOL_GRADE_GAP` checklist is fully closed.
- workspace `fmt/check/test/clippy` gates are green.

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
- Long-lived relay runtime (`relay-serve`) with per-peer replacement-rate controls.

### Stratum / SV2 subset
- Binary framing + typed message state machine.
- Pool endpoint (`stratum-serve`) + worker client (`stratum-mine`).
- `stratum-serve` uses async tokio socket I/O with bounded concurrent sessions.
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
- Rust stable toolchain (workspace currently validated on Rust 1.91.x stable).
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

For local multi-node verification:

```bash
scripts/local-multinode.sh up
scripts/local-multinode.sh status
scripts/local-multinode.sh down
```

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

### 6.5 Long-lived relay runtime

```bash
cargo run -p scam-node -- relay-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 0.0.0.0:18444 \
  --telemetry-out data/relay.telemetry.jsonl
```

### 6.6 RPC + Web Console (Explorer + Wallet UI)

Start RPC against persisted runtime state and serve web UI assets:

```bash
cargo run -p scam-node -- rpc-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 127.0.0.1:18080 \
  --ui-dir web \
  --relay-telemetry data/relay.telemetry.jsonl
```

Then open:

```text
http://127.0.0.1:18080/
```

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

Check balance:

```bash
cargo run -p scam-node -- wallet balance \
  --network devnet \
  --config config/devnet.toml \
  --mnemonic "<words>"
```

Watch-only balance by address:

```bash
cargo run -p scam-node -- wallet balance-address \
  --network devnet \
  --config config/devnet.toml \
  --address <address>
```

Send:

```bash
cargo run -p scam-node -- wallet send \
  --network devnet \
  --config config/devnet.toml \
  --mnemonic "<words>" \
  --to <address> \
  --amount 1000 \
  --fee 1
```

### 7.2 Encrypted wallet vault (recommended)

Create secure vault:

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

```bash
cargo run -p scam-node -- stratum-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 127.0.0.1:3347
```

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

Wire pool to external roles:

```bash
cargo run -p scam-node -- stratum-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 127.0.0.1:3347 \
  --template-provider-addr 127.0.0.1:3550 \
  --job-declarator-addr 127.0.0.1:3551
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
cargo run -p scam-node -- stratum-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 127.0.0.1:3347 \
  --secure-transport \
  --secure-transport-mode noise-xx \
  --secure-static-secret-key-hex <server_secret_hex32>
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
