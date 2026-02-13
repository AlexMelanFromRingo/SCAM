# SCAM (Smart Computing Alternative Money)

SCAM is a Rust 2024 PoW L1 workspace with a production-style minimal base:

- BLAKE3 PoW (`hash <= target` numeric compare),
- 2-minute blocks,
- configurable DAA (`windowed`, `lwma`, `asert`),
- Schnorr signatures over secp256k1,
- compressed pubkeys + Bech32m addresses,
- wallet mnemonic/restore, encrypted vault, QR,
- mempool fee-aware replacement + CPFP mining policy,
- P2P inventory relay + headers-first sync,
- Stratum/SV2 subset with role split + secure transport modes.

## Workspace

- `crates/core`
- `crates/consensus`
- `crates/chain`
- `crates/mempool`
- `crates/p2p`
- `crates/miner`
- `crates/stratum`
- `crates/storage`
- `crates/wallet`
- `crates/node`

## Validate

```bash
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Quick Start

```bash
cargo run -p scam-node -- node --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
cargo run -p scam-node -- status --network devnet --config config/devnet.toml
```

## P2P Relay Runtime

Long-lived socket relay with live mempool admission and peer replacement quotas:

```bash
cargo run -p scam-node -- relay-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 0.0.0.0:18444 \
  --telemetry-out data/relay.telemetry.jsonl
```

## Stratum / SV2

Generate Noise static keys:

```bash
cargo run -p scam-node -- stratum-keygen \
  --secret-out data/stratum-keys/server.secret.hex \
  --public-out data/stratum-keys/server.public.hex
```

Start pool endpoint:

```bash
cargo run -p scam-node -- stratum-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 0.0.0.0:3347 \
  --secure-transport \
  --secure-transport-mode noise-xx \
  --secure-static-secret-key-hex <hex32>
```

Connect worker:

```bash
cargo run -p scam-node -- stratum-mine \
  --pool 127.0.0.1:3347 \
  --user miner01 \
  --secure-transport \
  --secure-transport-mode noise-xx \
  --secure-static-secret-key-hex <hex32>
```

External role services:

```bash
cargo run -p scam-node -- sv2-template-provider --bind 127.0.0.1:3550
cargo run -p scam-node -- sv2-job-declarator --bind 127.0.0.1:3551
cargo run -p scam-node -- sv2-translator --bind 127.0.0.1:3552
```

## Conformance / Interop

Single endpoint probe + corpus replay:

```bash
cargo run -p scam-node -- sv2-conformance \
  --pool 127.0.0.1:3347 \
  --stack-name local \
  --corpus docs/sv2-corpus/default.json \
  --out target/sv2-conformance/local.json
```

Matrix harness + artifact generation:

```bash
scripts/sv2-conformance-matrix.sh
```

## Hardening and Launch

```bash
scripts/soak-24h.sh
scripts/chaos-crash-loop.sh
scripts/testnet-dress-rehearsal.sh
scripts/mainnet-freeze-lock.sh
```

## Status

- MVP production-style baseline: complete.
- SV2 pool-grade gap plan tracker: closed (`docs/SV2_POOL_GRADE_GAP.md`).

## Documentation

- `docs/IMPLEMENTATION_TODO.md`
- `docs/OPERATOR_RUNBOOK.md`
- `docs/STRATUM_SV2_NOTES.md`
- `docs/SV2_ROLE_INTERFACES.md`
- `docs/SV2_ROLLOUT_POLICY.md`
- `docs/SV2_ROLE_INCIDENT_RUNBOOK.md`
- `docs/SV2_INTEROP_MATRIX.md`
- `docs/MEMPOOL_THREAT_MODEL.md`
- `docs/TESTING_STRATEGY.md`
- `docs/FORKING_GUIDE.md`
