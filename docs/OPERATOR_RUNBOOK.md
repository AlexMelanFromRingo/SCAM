# SCAM Operator Runbook

This runbook captures the minimum operations flow for testnet/mainnet-style node operation.

## 1) Start and Health

```bash
cargo run -p scam-node -- node run --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
cargo run -p scam-node -- status --network devnet --config config/devnet.toml
```

## 2) Manual Peer Bootstrap (No DNS Required)

```bash
cargo run -p scam-node -- add-peer --network devnet --peer 203.0.113.10:18444
cargo run -p scam-node -- sync-peer --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb --peer 203.0.113.10:18444
```

If DNS seeds are configured, `sync-book` can fan out over persisted peers + seeds:

```bash
cargo run -p scam-node -- sync-book --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
```

## 3) Stratum Pool and Worker

Pool server:

```bash
cargo run -p scam-node -- stratum-serve --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb --bind 0.0.0.0:3347
```

Worker client (manual pool endpoint):

```bash
cargo run -p scam-node -- stratum-mine --pool 127.0.0.1:3347 --user miner01 --max-shares 100
```

Encrypted transport mode:

```bash
cargo run -p scam-node -- stratum-serve --network devnet --config config/devnet.toml --secure-transport --secure-rekey-interval-messages 10000
cargo run -p scam-node -- stratum-mine --pool 127.0.0.1:3347 --user miner01 --secure-transport --secure-rekey-interval-messages 10000
```

## 4) Backup, Reindex, Recovery

Backup runtime DB before risky operations:

```bash
cp data/devnet.runtime.redb data/devnet.runtime.redb.bak.$(date +%Y%m%d-%H%M%S)
```

Rebuild archive/runtime index from persisted chain:

```bash
cargo run -p scam-node -- reindex-runtime --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
```

Validate startup and tip after restore/reindex:

```bash
cargo run -p scam-node -- node run --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
cargo run -p scam-node -- status --network devnet --config config/devnet.toml
```

## 5) Durability and Long-Run Testing

24h soak:

```bash
scripts/soak-24h.sh
```

Crash-loop durability:

```bash
scripts/chaos-crash-loop.sh
```

Soak with persisted telemetry snapshots:

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

Telemetry threshold check:

```bash
scripts/telemetry-alert-check.py --input data/soak.telemetry.jsonl
```

Public testnet dry-run (end-to-end checklist automation):

```bash
scripts/testnet-dress-rehearsal.sh
```

## 6) Hardening Signals

- Keep gossip replacement-rate limits enabled (default in current code path).
- Track mempool/orphan churn via telemetry snapshots in runtime integration.
- Keep stratum reject-budget and idle timeout bounded in network config (`stratum_*`).
