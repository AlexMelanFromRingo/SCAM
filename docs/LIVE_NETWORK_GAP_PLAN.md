# SCAM Live Network Gap Plan (2026-02-19)

## Current factual status
- Consensus/UTXO/PoW validation: works.
- Stratum mining to local node: works (blocks produced).
- Node-to-node synchronization: realtime INV propagation works for active relay connections; relay has outbound peer auto-dial from peer-book (`--outbound-connect`) and now tolerates out-of-order block arrival via unknown-parent recovery + pending orphan promotion.
- Relay runtime model: async tokio accept/session loop with bounded concurrent permits (no runtime thread-per-connection growth in `relay-serve` path).
- P2P protocol baseline: now includes `getaddr/addr` exchange and compact-block negotiation/recovery (`sendcmpct/cmpctblock/getblocktxn/blocktxn`) in addition to legacy `inv/getdata`.
- Peer management hardening: outbound dialer now supports persisted anchor targets (`<network>.anchors.json`) and periodic feeler probes for liveness sampling without opening full long-lived sessions.
- Peer management hardening: outbound selection now uses addrman-like `tried/new` quotas plus per-network secret-salted diversity buckets (`<network>.bucket.key`) to reduce predictable eclipse slot targeting.
- Peer fanout hardening: outbound peer selection now applies per-node deterministic jitter (`bind_addr`-scoped) to equal-score candidates, reducing herd/hotspot dials to the same low-index peers in large local clusters.
- Catch-up hardening: relay periodic sync loop now emits both `GetHeaders` and rate-limited `GetBlocks` catch-up probes when a peer reports a higher tip, accelerating recovery after missed inventory bursts.
- Catch-up hardening: unknown block inventory and parent-gap header announcements now trigger immediate bounded `GetBlocks` catch-up alongside `GetHeaders`, reducing long-tail lag in dense local meshes.
- Catch-up hardening: peer-tip tracking from `inv` now scales with unknown block batch size (not only `+1`), so lag-driven aggressive catch-up cadence activates earlier on bursty peers.
- Outbound stability hardening: retry streak growth is now capped for transient I/O disconnect classes (`timeout/closed/refused/reset`) so relay workers redial faster under mesh churn instead of backing off too aggressively.
- Orphan tx hardening: relay now requests missing parent transactions from the source peer (`GetData`), de-duplicates parent requests with TTL, and penalizes oversized orphan-parent fanout.
- Anti-fingerprinting hardening: async relay send path supports bounded tx inventory diffusion jitter (`SCAM_RELAY_TX_DIFFUSION_BASE_MS`, `SCAM_RELAY_TX_DIFFUSION_MAX_MS`).
- Anonymity transport guards: outbound relay now supports policy-gated Tor/I2P SOCKS5 routing and CJDNS admission (`SCAM_P2P_ALLOW_ONION`, `SCAM_P2P_ALLOW_I2P`, `SCAM_P2P_ALLOW_CJDNS`, `SCAM_P2P_SOCKS5_PROXY`).
- Wallet UX transfer pipeline: live submit path (`wallet/send`, `tx/submit`) is wired to mempool DB admission and mined confirmation flow.
- UI: SSE push stream (`/events`) with polling fallback (5s) is active; dashboard now shows relay peers, relay mempool, sync lag, and last-block age.
- RPC lock-contended status fallback: `/status` now uses relay telemetry snapshots (tip/utxo/work/hashrate) when runtime DB refresh is blocked by redb lock contention, reducing stale-genesis readouts under relay+rpx concurrency.

## Why blocks often have `tx_count = 1`
- Blocks include only coinbase unless mempool has user transactions.
- End-to-end tx coverage is now available through `scripts/local-e2e-flow.sh` (submit -> mempool -> mine -> peer apply -> receiver balance).

## P0 (must-have for real testnet launch)
- [x] Add live RPC submit endpoint (`POST /wallet/send`) that:
  - [x] signs tx,
  - [x] validates tx context,
  - [x] submits to local relay/mempool (via shared mempool DB),
  - [x] returns txid + relay acceptance details.
- [x] Add raw tx endpoint (`POST /tx/submit`) for external wallets/tools (bincode-hex payload).
- [x] Add relay-local admission path usable by RPC without fragile process coupling (shared `mempool.redb` state).
- [x] Ensure locally mined blocks are announced to connected peers in near-realtime (timeout-driven INV on long-lived relay sessions).
- [x] Ensure relay workers refresh runtime tip consistently from runtime DB and persist accepted block updates.
- [x] Add mempool-to-block inclusion E2E tests:
  - [x] tx submit -> appears in mempool,
  - [x] mined block includes tx,
  - [x] peer node receives/applies block,
  - [x] receiver balance updates.

## P1 (required for operational usability)
- [x] Add realtime UI updates:
  - [x] SSE stream endpoint (`/events`) with status/tip/mempool deltas.
  - [x] frontend EventSource client with auto-reconnect + polling fallback indicator.
- [x] Keep polling fallback when SSE unavailable (UI now auto-refreshes every 5s).
- [x] Add explicit node health telemetry in UI (relay peers, sync lag, mempool size, last block age).
- [x] Add RPC endpoint to query balance by address + tx history in one call for wallet UX (`POST /wallet/balance-history-by-address`).

## P1 networking hardening
- [x] Verify relay thread model under sustained connections (no silent worker exits).
- [x] Add integration test: multi-node realtime propagation without `sync-book` assistance.
- [x] Add integration test: node restart + catch-up + mempool rebroadcast.
- [x] Add deterministic failure logs for peer disconnect reasons (protocol error, timeout, ban, io reset).
- [x] Remove runtime thread-per-connection in `relay-serve` by migrating to async tokio socket handling.
- [x] Add compact-block fallback path (request missing txs by index and reconstruct block before apply).
- [x] Add addr exchange path (`getaddr/addr`) for live peer discovery enrichment.
- [x] Add periodic `GetBlocks` catch-up requests alongside `GetHeaders` when peer tip is ahead (rate-limited, aggressive mode for large lag).
- [x] Add per-node outbound candidate jitter to avoid synchronized dial hotspots under high node counts.
- [x] Add Erlay/Minisketch mempool set-reconciliation path to reduce inv/getdata overhead at high peer counts.
  - Closure (`2026-03-01`): `SendRecon/ReqRecon/Sketch/ReqSketchExt/ReqTx/ReconcileDiff` wired through relay runtime; short-id reconciliation now uses negotiated capability (`version/bits/implementation/salt`) with `minisketch-rs`, collision fallback, and bounded per-peer round tracking.

## P2 (launch confidence)
- [ ] Soak test profile for 24h: 2-5 nodes + miner + tx spam profile.
- [ ] Mainnet-grade WAN profile run (2-6h) with synthetic latency/loss/reorder (`tc netem`) and explicit SLO gate:
  - `final_spread <= 1`,
  - `max_spread <= 6` after warm-up window,
  - `avg_bad == 0`.
- [ ] RC mutation gate: full non-iterative Stage 3 run (`scripts/mutation-staged.sh stage3`, `MUTATION_ITERATE=false`) with `0 missed` and `0 timeout`.
- [x] Mutation stage2/3 rerun after live submit/realtime changes.
  - Closure (`2026-02-28`): Stage 2 iterate closure (`0 missed/timeout`), Stage 3 full workspace (`0 missed/timeout`).
- [x] Fuzz target for relay wire parsing and tx submit route.
- [x] Operator runbook updates (incident handling, recovery, metrics thresholds).

## Required test additions (minimum)
- [x] `wallet/send` happy path integration test.
- [x] `wallet/send` rejects invalid hrp/negative amount/insufficient funds/double spend.
- [x] Reorg case: pending tx survives/reenters mempool when block disconnected.
- [x] Realtime propagation latency test between two relays.
- [x] UI events endpoint contract tests (schema + heartbeat).

## Definition of done for “testnet-ready”
- [x] No dependence on periodic `sync-book` loop for normal block propagation.
- [x] User tx can be created/submitted/propagated/mined/observed from another node.
- [x] UI reflects chain/mempool updates automatically (realtime stream) with clear fallback.
- [x] Full workspace: `fmt`, `clippy -D warnings`, tests, mutation stages (agreed thresholds).
  - Verified (`2026-02-28`): `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, staged mutation closure (`stage2/stage3`).
