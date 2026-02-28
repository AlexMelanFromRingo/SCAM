# SCAM Live Network Gap Plan (2026-02-19)

## Current factual status
- Consensus/UTXO/PoW validation: works.
- Stratum mining to local node: works (blocks produced).
- Node-to-node synchronization: realtime INV propagation works for active relay connections; relay has outbound peer auto-dial from peer-book (`--outbound-connect`) and now tolerates out-of-order block arrival via unknown-parent recovery + pending orphan promotion.
- Relay runtime model: async tokio accept/session loop with bounded concurrent permits (no runtime thread-per-connection growth in `relay-serve` path).
- P2P protocol baseline: now includes `getaddr/addr` exchange and compact-block negotiation/recovery (`sendcmpct/cmpctblock/getblocktxn/blocktxn`) in addition to legacy `inv/getdata`.
- Peer management hardening: outbound dialer now supports persisted anchor targets (`<network>.anchors.json`) and periodic feeler probes for liveness sampling without opening full long-lived sessions.
- Orphan tx hardening: relay now requests missing parent transactions from the source peer (`GetData`), de-duplicates parent requests with TTL, and penalizes oversized orphan-parent fanout.
- Wallet UX transfer pipeline: live submit path (`wallet/send`, `tx/submit`) is wired to mempool DB admission and mined confirmation flow.
- UI: SSE push stream (`/events`) with polling fallback (5s) is active; dashboard now shows relay peers, relay mempool, sync lag, and last-block age.

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

## P2 (launch confidence)
- [ ] Soak test profile for 24h: 2-5 nodes + miner + tx spam profile.
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
