# SCAM (Smart Computing Alternative Money)

SCAM is a Rust 2024 workspace implementing a PoW L1 cryptocurrency with a production-style minimal baseline:

- BLAKE3 PoW (`hash <= target` numeric compare),
- 2-minute block target,
- configurable DAA (`windowed`, `lwma`, `asert`),
- Schnorr signatures over secp256k1,
- compressed pubkeys + Bech32m addresses,
- wallet mnemonic/restore, encrypted vault, QR,
- mempool with fee-aware replacement + CPFP-aware mining selection,
- P2P inventory relay and headers-first sync,
- Stratum v2 subset pool endpoint and worker client with optional encrypted transport.

## Workspace

- `crates/core`: types, hashing, config, serialization.
- `crates/consensus`: block/tx validation, UTXO rules, difficulty math.
- `crates/chain`: chain runtime, reorg by cumulative work.
- `crates/mempool`: mempool + orphan pool + replacement policy + telemetry.
- `crates/p2p`: wire, transport, gossip, discovery.
- `crates/miner`: block templates, nonce loops, CPFP package selection.
- `crates/stratum`: SV2 subset framing/session/share validation.
- `crates/storage`: `redb` persistence for chain/archive/snapshots/peers.
- `crates/wallet`: mnemonic, derivation, signing, vault, rescan, QR.
- `crates/node`: CLI orchestration.

## Quick Start

Build and validate all modules:

```bash
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Run node bootstrap:

```bash
cargo run -p scam-node -- node run --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
```

Show status:

```bash
cargo run -p scam-node -- status --network devnet --config config/devnet.toml
```

## Mining

Start SV2 subset pool endpoint:

```bash
cargo run -p scam-node -- stratum-serve --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb --bind 0.0.0.0:3347
```

Connect worker using manual pool address (no DNS required):

```bash
cargo run -p scam-node -- stratum-mine --pool 127.0.0.1:3347 --user miner01 --max-shares 10
```

Enable encrypted transport on both sides:

```bash
cargo run -p scam-node -- stratum-serve --network devnet --config config/devnet.toml --secure-transport --secure-rekey-interval-messages 10000
cargo run -p scam-node -- stratum-mine --pool 127.0.0.1:3347 --user miner01 --secure-transport --secure-rekey-interval-messages 10000
```

## Manual Peer Connectivity

Add peer manually:

```bash
cargo run -p scam-node -- add-peer --network devnet --peer 203.0.113.10:18444
```

Sync directly from explicit peer endpoint:

```bash
cargo run -p scam-node -- sync-peer --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb --peer 203.0.113.10:18444
```

## Soak and Hardening

24h soak helper:

```bash
scripts/soak-24h.sh
```

Crash-loop durability:

```bash
scripts/chaos-crash-loop.sh
```

Public testnet dry-run:

```bash
scripts/testnet-dress-rehearsal.sh
```

Soak with persisted telemetry snapshots (JSONL):

```bash
cargo run -p scam-node -- soak \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --rounds 720 \
  --sleep-per-round-sec 120 \
  --txs-per-round 1 \
  --tx-amount 1000 \
  --tx-fee 1 \
  --telemetry-out data/soak.telemetry.jsonl \
  --telemetry-every-rounds 1
```

Check telemetry thresholds:

```bash
scripts/telemetry-alert-check.py --input data/soak.telemetry.jsonl
```

## Config-First Forking

Generate a new network config:

```bash
cargo run -p scam-node -- config-scaffold --network-id myfork --hrp sc --stratum-secure-transport --stratum-secure-rekey-interval-messages 10000 --out config/myfork.toml
```

See `docs/FORKING_GUIDE.md` for full constructor options.

## Current Status

MVP production-style baseline is implemented. Remaining major program item:

- final launch hardening + public testnet dress rehearsal.

## SV2 Scope Note

Current implementation is a robust SV2 subset suitable for local/integration mining flows.
A full pool-grade SV2 deployment still needs:

- external service deployment hardening for Template Provider / Job Declarator / Translator roles,
- full Noise-spec transport compatibility and key lifecycle hardening,
- exhaustive interoperability/conformance matrix against third-party SV2 stacks.

## Documentation

- `docs/IMPLEMENTATION_TODO.md`
- `docs/OPERATOR_RUNBOOK.md`
- `docs/STRATUM_SV2_NOTES.md`
- `docs/MEMPOOL_THREAT_MODEL.md`
- `docs/TESTING_STRATEGY.md`
- `docs/FORKING_GUIDE.md`
- `docs/SV2_POOL_GRADE_GAP.md`
