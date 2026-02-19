# SCAM Live Network Gap Plan (2026-02-19)

## Current factual status
- Consensus/UTXO/PoW validation: works.
- Stratum mining to local node: works (blocks produced).
- Node-to-node synchronization: works in polling mode (`sync-book` loop), not full realtime gossip.
- Wallet UX E2E transfer pipeline: incomplete (only `send-preview`, no live submit+broadcast route).
- UI: request/refresh based, no realtime push stream.

## Why blocks often have `tx_count = 1`
- Blocks include only coinbase unless mempool has user transactions.
- Current UX does not expose a production-ready `wallet/send` path that submits a signed tx into relay mempool and propagates it across peers.

## P0 (must-have for real testnet launch)
- [ ] Add live RPC submit endpoint (`POST /wallet/send`) that:
  - [ ] signs tx,
  - [ ] validates tx context,
  - [ ] submits to local relay/mempool,
  - [ ] returns txid + relay acceptance details.
- [ ] Add raw tx endpoint (`POST /tx/submit`) for external wallets/tools.
- [ ] Add relay-local admission API/command path usable by RPC without fragile process coupling.
- [ ] Ensure locally mined blocks are announced to connected peers in realtime (INV/GETDATA/BLOCK path), not only discovered by periodic sync.
- [ ] Ensure relay workers refresh runtime tip consistently or share a single runtime source of truth.
- [ ] Add mempool-to-block inclusion E2E tests:
  - [ ] tx submit -> appears in mempool,
  - [ ] mined block includes tx,
  - [ ] peer node receives/applies block,
  - [ ] receiver balance updates.

## P1 (required for operational usability)
- [ ] Add realtime UI updates:
  - [ ] SSE stream endpoint (`/events`) with status/tip/mempool deltas,
  - [ ] frontend EventSource client with auto-reconnect and stale-state indicator.
- [ ] Keep polling fallback when SSE unavailable.
- [ ] Add explicit node health telemetry in UI (relay peers, sync lag, mempool size, last block age).
- [ ] Add RPC endpoint to query balance by address + tx history in one call for wallet UX.

## P1 networking hardening
- [ ] Verify relay thread model under sustained connections (no silent worker exits).
- [ ] Add integration test: multi-node realtime propagation without `sync-book` assistance.
- [ ] Add integration test: node restart + catch-up + mempool rebroadcast.
- [ ] Add deterministic failure logs for peer disconnect reasons (protocol error, timeout, ban, io reset).

## P2 (launch confidence)
- [ ] Soak test profile for 24h: 2-5 nodes + miner + tx spam profile.
- [ ] Mutation stage2/3 rerun after live submit/realtime changes.
- [ ] Fuzz target for relay wire parsing and tx submit route.
- [ ] Operator runbook updates (incident handling, recovery, metrics thresholds).

## Required test additions (minimum)
- [ ] `wallet/send` happy path integration test.
- [ ] `wallet/send` rejects invalid hrp/negative amount/insufficient funds/double spend.
- [ ] Reorg case: pending tx survives/reenters mempool when block disconnected.
- [ ] Realtime propagation latency test between two relays.
- [ ] UI events endpoint contract tests (schema + heartbeat).

## Definition of done for “testnet-ready”
- [ ] No dependence on periodic `sync-book` loop for normal block propagation.
- [ ] User tx can be created/submitted/propagated/mined/observed from another node.
- [ ] UI reflects chain/mempool updates automatically (realtime stream) with clear fallback.
- [ ] Full workspace: `fmt`, `clippy -D warnings`, tests, mutation stages (agreed thresholds).
