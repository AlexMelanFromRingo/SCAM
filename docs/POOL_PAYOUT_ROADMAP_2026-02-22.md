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

- Add persistent pool accounting DB (redb) tables:
  - workers
  - submitted shares (accepted/rejected, difficulty, timestamp)
  - round metadata (start/end height/hash)
  - per-worker accrual balance
- Add anti-duplication constraints (share identity + channel/job/nonce key).
- Add crash-safe replay/recovery on restart.

### WP2: Round model (mandatory)

- Define round lifecycle:
  - round opens at current tip,
  - closes when pool finds/accepts a block,
  - starts next round immediately.
- Round boundary + chain reorg handling policy:
  - orphaned found block rollback,
  - share re-attribution strategy on disconnect/reorg.

### WP3: PPLNS engine (mandatory)

- Implement N-window selection over accepted shares.
- Weighting rule (difficulty-weighted shares).
- Per-worker reward split after pool fee.
- Deterministic payout snapshot for a closed round.

### WP4: PPS engine (mandatory)

- Implement fixed pay-per-share accrual.
- Solvency guardrails:
  - reserve checks,
  - max PPS liability,
  - operator alerts.

### WP5: Payout transaction pipeline (mandatory)

- Build payout transaction batches from accrued balances.
- Support payout thresholds + payout interval.
- Submit payouts through mempool path with retries and telemetry.
- Track payout transaction lifecycle (created/submitted/confirmed/failed).

### WP6: API/UI for pool accounting + hashrate (mandatory)

- Add RPC routes:
  - pool stats
  - worker stats
  - pending/completed payouts
- Add UI sections:
  - worker hashrate,
  - pool hashrate,
  - network hashrate (derived estimate from target + observed inter-block timing).

### WP7: Launcher presets (mandatory)

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

