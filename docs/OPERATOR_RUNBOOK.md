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

Start the node with its pool in secure noise mode (the pool runs inside the
node process, on the node's chain and mempool):

```bash
export SCAM_STRATUM_STATIC_SECRET_KEY_HEX=<hex32>
cargo run -p scam-node -- serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 0.0.0.0:18444 \
  --stratum "--bind 0.0.0.0:3347 --secure-transport --secure-transport-mode noise-xx"
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

Wire the node's pool to external roles:

```bash
cargo run -p scam-node -- serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db data/devnet.runtime.redb \
  --bind 0.0.0.0:18444 \
  --stratum "--bind 127.0.0.1:3347 --template-provider-addr 127.0.0.1:3550 --job-declarator-addr 127.0.0.1:3551"
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

## 5.1) Deep Forks and Resynchronisation

Fork choice is "the heaviest valid chain wins", at any depth:

- A reorg of up to 720 blocks (`MAX_REORG_DEPTH`, about a day at 2-minute
  blocks) disconnects blocks with stored undo data, as usual.
- A branch that forks deeper (a node or a part of the network was cut off
  for longer) is first proven by its headers alone: links, proof of work,
  the branch's own difficulty, median-time-past and the future limit, while
  its cumulative work is summed. Only one such branch is probed at a time,
  and it may be at most 4× as long as the local chain above the fork (plus
  10 000 blocks), so a long cheap branch from an old fork costs the node
  nothing but hashes.
- Once the headers show more work than the local chain, the node fetches
  the branch's blocks and rebuilds its state from genesis along the new
  chain, validating every block. This takes as long as a full sync and the
  node does not serve requests meanwhile. If any block is invalid, the node
  stays on its chain, marks the branch invalid and bans the peer.

Signals:

- Logs: `deep fork: peer … announces a branch from height …`, `deep fork:
  branch … carries more work …; fetching N blocks`, and
  `DEEP REORG: switched to the heavier branch from height … blocks
  disconnected, new tip … at height …` (or `… ends … without out-working the
  active chain; ignored`, `… probe stalled; dropped`).
- `GET /status` gains `deep_fork: {fork_height, branch_tip_height, stage,
  blocks_received}` while a branch is being proven (`proving-headers`) or
  fetched (`fetching-blocks`); the relay telemetry snapshot carries the same.

Manual resynchronisation (no peer on the heavier chain is reachable, or you
want to force a fresh copy):

1. Stop the node (`scripts/run-node-*.sh stop`, or stop `scam-node serve`).
2. Move the runtime DB aside (`mv data/devnet.runtime.redb{,.bak}`); keep the
   mempool and pool-ledger DBs and the peer book.
3. Add peers known to follow the right chain:
   `scam-node add-peer --network <net> --peers-dir <dir> --peer host:port`.
4. Start the node with `--outbound-connect`; it syncs from genesis.

To rebuild only the derived state (UTXO set, undo data) from the local block
archive, stop the node and run `scam-node reindex-runtime --network <net>
--runtime-db <path>`.

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

Strict full-spec style replay (submit-share path + observed-kind gates):

```bash
POOL=203.0.113.20:3347 \
CORPUS=docs/sv2-corpus/full-spec-submit.json \
SETUP_PROTOCOL=2 \
SETUP_MIN_VERSION=2 \
SETUP_MAX_VERSION=2 \
SETUP_FLAGS=0 \
MIN_JOB_MESSAGES=1 \
EXPECT_SET_TARGET=true \
REQUIRE_SETUP_VERSION=2 \
REQUIRE_SETUP_FLAGS_MASK=0 \
FORBID_SETUP_FLAGS_MASK=0 \
REQUIRE_OBSERVED_KINDS="SetupConnectionSuccess;OpenStandardMiningChannelSuccess;SubmitSharesSuccess;SetTarget" \
REQUIRE_OBSERVED_SEQUENCE="SetupConnectionSuccess,OpenStandardMiningChannelSuccess,SetTarget,SubmitSharesSuccess" \
FORBID_OBSERVED_KINDS="SetupConnectionError;OpenStandardMiningChannelError;SubmitSharesError" \
scripts/sv2-corpus-replay.sh
```

Strict release gate (local + optional external matrix expectations):

```bash
scripts/sv2-release-gate.sh
```

Release gate with golden baseline verification:

```bash
VERIFY_GOLDEN=true \
GOLDEN_EXPECTATIONS=docs/sv2-corpus/golden/expectations.json \
scripts/sv2-release-gate.sh
```

Require external targets during go/no-go gate:

```bash
REQUIRE_EXTERNAL=true \
SV2_EXTERNAL_TARGETS_FILE=docs/sv2-interop-targets.example.json \
scripts/sv2-release-gate.sh
```

Refresh local golden expectations after intentional protocol changes:

```bash
scripts/sv2-golden-freeze.sh
```

Public testnet dry run:

```bash
scripts/testnet-dress-rehearsal.sh
```

## 8) Policy and Incident Links

- rollout policy: `docs/SV2_ROLLOUT_POLICY.md`
- role incident runbook: `docs/SV2_ROLE_INCIDENT_RUNBOOK.md`
- role interface contract: `docs/SV2_ROLE_INTERFACES.md`
- full-spec checklist (SCAM profile): `docs/SV2_FULLSPEC_CHECKLIST.md`

## 9) Incident Thresholds (Default Ops Guardrails)

Baseline thresholds for `devnet/testnet` operations:

- `sync_lag_blocks > 6` for longer than `5m` -> investigate relay connectivity and peer health.
- `last_block_age > 3 * target_block_time_sec` for longer than `10m` -> investigate miner/pool liveliness.
- `relay_peer_count == 0` while node is expected online -> investigate bind/firewall/peer-book bootstrap.
- `orphan_pool_len > 500` or steady growth for `10m` -> investigate inbound malformed tx storm or missing-parent churn.
- `replacement_rate_limited_total` increasing continuously (`> 20/min`) -> investigate replacement spam source peers.
- `banned_peer_count` jump (`> 10` within `5m`) -> investigate coordinated bad-peer traffic.
- `stratum_rejected_share_ratio > 5%` over rolling `10m` -> investigate share target mismatch, stale jobs, clock skew.

## 10) Incident Playbook (Fast Triage)

1. Confirm node liveness and tip movement.

```bash
curl -s http://127.0.0.1:19080/status | jq .
curl -s http://127.0.0.1:19080/mempool | jq .
```

2. Check relay telemetry trend for churn/spam signatures.

```bash
tail -n 200 data/relay.telemetry.jsonl
scripts/telemetry-alert-check.py --input data/soak.telemetry.jsonl
```

3. Verify peer bootstrap and outbound dial path.

```bash
cargo run -p scam-node -- sync-book --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
```

4. If sync divergence persists, isolate and rehydrate runtime from archive.

```bash
cargo run -p scam-node -- reindex-runtime --network devnet --config config/devnet.toml --runtime-db data/devnet.runtime.redb
```

5. For SV2 instability, replay corpus against active endpoint and inspect matrix artifacts.

```bash
POOL=127.0.0.1:3347 scripts/sv2-corpus-replay.sh
scripts/sv2-conformance-matrix.sh
```

## 11) Alert Escalation Policy

1. `sev-3` (minor degradation): single threshold breach under `10m`, auto-recovering.
2. `sev-2` (service risk): repeated threshold breaches for `> 10m` or user-visible sync lag.
3. `sev-1` (critical): chain split, persistent invalid block acceptance, or sustained no-progress state.

Escalate to `sev-1` immediately when:

- two healthy relays disagree on best tip for `> 5m`,
- mempool admission rejects valid signed tx across multiple peers,
- Stratum workers cannot submit accepted shares after transport/channel setup.

## 12) Pending Mainnet WAN SLO Gate

Before declaring mainnet-grade readiness, run a dedicated WAN-emulation profile:

- duration: `2-6h`,
- topology: at least `50` relay nodes, `2+` active miners,
- network shaping: latency + jitter + packet loss + reorder via `tc netem`.

Proposed gate thresholds:

- `final_spread <= 1`,
- `max_spread <= 6` after initial warm-up window,
- `avg_bad == 0`.

Mutation release gate (for RC/mainnet candidate):

- Run full Stage 3 mutation without iterate:
  - `MUTATION_ITERATE=false scripts/mutation-staged.sh stage3`
- Accept only:
  - `missed = 0`,
  - `timeout = 0`.
