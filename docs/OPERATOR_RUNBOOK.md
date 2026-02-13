# SCAM Operator Runbook

This runbook covers minimum operations for node, P2P, Stratum, SV2 roles, and launch hardening.

## 1) Start and Health

```bash
cargo run -p scam-node -- node --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
cargo run -p scam-node -- status --network devnet --config config/devnet.toml
```

## 2) Manual Peer Bootstrap (No DNS Required)

```bash
cargo run -p scam-node -- add-peer --network devnet --peer 203.0.113.10:18444
cargo run -p scam-node -- sync-peer --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb --peer 203.0.113.10:18444
```

Peer-book fanout:

```bash
cargo run -p scam-node -- sync-book --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
```

## 3) Stratum Secure Setup

Generate keys:

```bash
cargo run -p scam-node -- stratum-keygen \
  --secret-out data/stratum-keys/server.secret.hex \
  --public-out data/stratum-keys/server.public.hex
```

Rotate keys:

```bash
cargo run -p scam-node -- stratum-key-rotate \
  --secret-path data/stratum-keys/server.secret.hex \
  --public-path data/stratum-keys/server.public.hex \
  --archive-dir data/stratum-keys/archive
```

Start pool server with secure noise mode:

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

Worker client:

```bash
cargo run -p scam-node -- stratum-mine \
  --pool 127.0.0.1:3347 \
  --user miner01 \
  --max-shares 100 \
  --secure-transport \
  --secure-transport-mode noise-xx \
  --secure-static-secret-key-hex <hex32>
```

## 4) External Role Services

Start services:

```bash
cargo run -p scam-node -- sv2-template-provider --bind 127.0.0.1:3550 --telemetry-out data/sv2-template.telemetry.jsonl
cargo run -p scam-node -- sv2-job-declarator --bind 127.0.0.1:3551 --telemetry-out data/sv2-job.telemetry.jsonl
cargo run -p scam-node -- sv2-translator --bind 127.0.0.1:3552 --telemetry-out data/sv2-translator.telemetry.jsonl
```

Wire pool server to external roles:

```bash
cargo run -p scam-node -- stratum-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 127.0.0.1:3347 \
  --template-provider-addr 127.0.0.1:3550 \
  --job-declarator-addr 127.0.0.1:3551
```

Role telemetry dashboard:

```bash
python3 scripts/role-telemetry-dashboard.py \
  --input data/sv2-template.telemetry.jsonl \
  --input data/sv2-job.telemetry.jsonl \
  --input data/sv2-translator.telemetry.jsonl \
  --out data/sv2-role-dashboard.md
```

## 5) Backup, Reindex, Recovery

```bash
cp data/devnet.runtime.redb data/devnet.runtime.redb.bak.$(date +%Y%m%d-%H%M%S)
cargo run -p scam-node -- reindex-runtime --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
```

## 6) Durability and Soak

```bash
scripts/soak-24h.sh
scripts/chaos-crash-loop.sh
```

Telemetry threshold check:

```bash
scripts/telemetry-alert-check.py --input data/soak.telemetry.jsonl
```

## 7) Conformance and Dress Rehearsal

SV2 conformance matrix:

```bash
scripts/sv2-conformance-matrix.sh
```

Direct corpus replay to a target endpoint:

```bash
POOL=203.0.113.20:3347 scripts/sv2-corpus-replay.sh
```

Public testnet dry run:

```bash
scripts/testnet-dress-rehearsal.sh
```

## 8) Policy and Incident Links

- rollout policy: `docs/SV2_ROLLOUT_POLICY.md`
- role incident runbook: `docs/SV2_ROLE_INCIDENT_RUNBOOK.md`
- role interface contract: `docs/SV2_ROLE_INTERFACES.md`
