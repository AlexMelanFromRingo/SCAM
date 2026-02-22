# SCAM Pool/Payout Expansion Roadmap (2026-02-22)

Purpose: preserve current context and convert new requirements into an implementation backlog.

## Current state snapshot

- Stratum server supports many workers and validates shares (including vardiff).
- Block reward currently follows template coinbase payout key:
  - if worker `user` is a valid address, reward for found block goes to that address,
  - otherwise reward goes to configured default reward key.
- This is effectively `solo-pool` behavior (winner-takes-all per found block).
- There is no production payout engine yet (no PPS/PPLNS accounting + no payout transaction scheduler).

## Requested target state

- Production pool wrapper around current Stratum core.
- Shared mining payout modes:
  - PPLNS (window-based)
  - PPS (fixed pay-per-share)
- Payout engine primitives:
  - per-miner share ledger,
  - rounds,
  - PPLNS windows,
  - PPS accrual,
  - payout transactions.
- Launch presets for common operator/user flows:
  - full node only,
  - solo mining on own node,
  - solo mining on remote/public node,
  - shared pool mode,
  - local multi-node lab profiles.
- UI hashrate visibility:
  - miner hashrate,
  - pool aggregate hashrate,
  - network hashrate.

## Why node-0 looked "down" while mining continued

Observed behavior is consistent with process split:

- `rpc-serve` is a separate process from `relay-serve` and `stratum-serve`.
- If `rpc-serve` on node-0 exits, UI/API may be down while Stratum on node-0 still accepts miners and mines blocks.
- In local lab, miner is wired to node-0 Stratum by default, so block production can continue even when node-0 RPC is unavailable.

Action item:
- add explicit health summary in launcher/status (relay/rpc/stratum per node + miner target endpoint + last accepted share timestamp).

## Work packages

### WP1: Share ledger + persistence (mandatory)

- [x] Persistent pool accounting DB (redb) tables are implemented (`pool_meta`, `pool_workers`, `pool_shares`, `pool_rounds`, `pool_payout_pending`, `pool_payout_completed`).
- [x] Anti-duplication constraints are enforced via `share_key` dedup on load/save and in runtime admission.
- [x] Crash-safe replay/recovery is implemented by loading ledger snapshot on startup and persisting after share/round updates.
- Add persistent pool accounting DB (redb) tables:
  - workers
  - submitted shares (accepted/rejected, difficulty, timestamp)
  - round metadata (start/end height/hash)
  - per-worker accrual balance
- Add anti-duplication constraints (share identity + channel/job/nonce key).
- Add crash-safe replay/recovery on restart.

### WP2: Round model (mandatory)

- [x] Round lifecycle implemented: open at tip, close on accepted block, immediately open next round.
- [x] Reorg policy baseline implemented: closed rounds are marked `orphaned` when their closing block is no longer on active chain; open round is rebased to active tip if fork point moved.
- [x] Re-attribution policy for orphaned rounds is implemented (PPLNS accruals are recomputed from non-orphaned rounds; orphaned-round rewards are excluded from payable balances).
- Define round lifecycle:
  - round opens at current tip,
  - closes when pool finds/accepts a block,
  - starts next round immediately.
- Round boundary + chain reorg handling policy:
  - orphaned found block rollback,
  - share re-attribution strategy on disconnect/reorg.

### WP3: PPLNS engine (mandatory)

- [x] Implemented N-window selection over accepted shares.
- [x] Implemented difficulty-weighted share accounting.
- [x] Implemented per-worker reward split after pool fee.
- [x] Implemented deterministic payout snapshot recompute for closed rounds.

### WP4: PPS engine (mandatory)

- [x] Implemented fixed pay-per-share accrual.
- [x] Implemented solvency guardrails:
  - reserve checks,
  - max PPS liability checks,
  - guardrail alert counters.

### WP5: Payout transaction pipeline (mandatory)

- [x] Implemented payout batch creation from accrued balances.
- [x] Implemented payout threshold + payout interval scheduling.
- [x] Implemented payout submission through mempool path with telemetry/state updates.
- [x] Implemented payout lifecycle tracking (pending/submitted/confirmed with failure-safe retry readiness).

### WP6: API/UI for pool accounting + hashrate (mandatory)

- [x] RPC routes implemented: `/pool/status`, `/pool/worker/<label>`, `/pool/payouts/pending`, `/pool/payouts/completed`.
- [x] UI panels implemented for pool status, worker status, pending/completed payouts.
- [x] UI hashrate visibility implemented for network and pool hashrate cards (`/status` + stratum telemetry).
- Add RPC routes:
  - pool stats
  - worker stats
  - pending/completed payouts
- Add UI sections:
  - worker hashrate,
  - pool hashrate,
  - network hashrate (derived estimate from target + observed inter-block timing).

### WP7: Launcher presets (mandatory)

- [x] One-command preset wrapper implemented (`scripts/run-preset.sh` + `.env` profile files).
- [x] Profiles implemented: node-only, solo-local, solo-remote, pool-shared, two-node realtime lab.
- [x] Launcher status now includes miner endpoint and accepted-share summary for faster operator checks.
- Add profile files and wrappers for:
  - node-only,
  - solo-local,
  - solo-remote,
  - pool-shared,
  - two-node lab realtime sync.
- Ensure one-command startup with sensible defaults.

## Guardrails and regression checks

- E2E tests:
  - two nodes + miner + tx send + confirmation + peer visibility,
  - pool round closure and payout accrual,
  - payout tx creation and confirmation,
  - restart recovery of pool ledger,
  - reorg rollback/reapply for accounting.
- Non-flaky runtime checks for relay/rpc/stratum process split.

## Out of scope for this roadmap iteration

- Full third-party SV2 interop matrix completion.
- External security audit and long soak runs.
