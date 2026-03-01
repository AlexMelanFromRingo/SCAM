# Agent Autonomous TODO

## Scope
- Close mutation stage2 misses (`scam-stratum`, `scam-p2p`, `scam-node`) without regressions.
- Keep battle-tested migration track active: `SOCKS5`, `HTTP`, `wire/codec`.
- Gate every phase with `cargo fmt`, `cargo check`, `cargo test`, `cargo clippy`.

## Phase Plan

### Phase A: Stage2 mutation stabilization
- [x] Group current stage2 misses by function/module.
- [x] Strengthen unit tests for `p2p::discovery` and `p2p::gossip` (boundaries + branch behavior).
- [x] Strengthen `node` tests for env/policy/socks/diffusion/relay boundaries and flaky paths.
- [x] Run targeted mutation loop for `scam-p2p` discovery/gossip until zero misses.
- [ ] Run full stage2 mutation (`scam-stratum`, `scam-p2p`, `scam-node`) and close remaining misses.
- [ ] Re-run stage2 mutation after fixes to confirm stable zero-miss/no-timeout state.

### Phase B: Battle-tested transport/protocol migration
- [x] Migrate async SOCKS5 connect path to `tokio-socks` (remove hand-rolled async dial logic).
- [x] Migrate `rpc-serve` HTTP path to `hyper`/`axum` while preserving existing route contracts/tests.
  - `axum` backend now implements full route parity for RPC GET/POST endpoints, SSE `/events`, pool routes, and UI asset fallback behavior.
  - `SCAM_RPC_HTTP_BACKEND=axum` remains available for rollout control; legacy path is retained only as compatibility backend.
- [x] Move wire framing onto battle-tested codec path (`tokio-util` codec) with strict size limits (async path).
- [ ] Keep compatibility tests for version/handshake/frame boundary behavior.

### Phase C: Verification gates (mandatory after each sub-phase)
- [x] `cargo fmt --all`
- [x] `cargo check --workspace`
- [x] `cargo test --workspace`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] Mutation gate re-check for stage2.

### Phase D: Local commit policy (no push)
- [ ] Commit 1: Stage2 mutation fixes (`p2p/node`).
- [x] Commit 2: HTTP migration (`hyper`/`axum`) + route tests.
- [ ] Commit 3: wire/codec migration + framing tests.
- [ ] Commit 4: final verification gate + docs status update.

## Current status snapshot
- `p2p` targeted mutation loop for `discovery/gossip`: closed (0 misses in scoped run).
- `rpc-serve` axum path: full route parity done, SSE and UI fallback included.
- `p2p::transport` async frame path now uses `tokio-util` codec + strict magic/size checks.
- Full stage2 mutation: pending final rerun after latest node/http changes.
