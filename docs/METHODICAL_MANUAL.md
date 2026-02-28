# SCAM Methodical Manual (WIP)

Status: in progress (started after RC1 stabilization).
Goal: produce a maximum-detail implementation manual per crate and protocol flow.

This file is the canonical entry-point for the deferred “full documentation pack” from:
- `docs/IMPLEMENTATION_TODO.md:345`

---

## 1) Scope and completion policy

Target crates:
- `core`
- `consensus`
- `chain`
- `mempool`
- `wallet`
- `p2p`
- `stratum`
- `storage`
- `rpc`
- `node`
- `miner`

Planned content per crate:
- architecture role in the system,
- module map and main data structures,
- function-level behavior notes (inputs, outputs, invariants, side effects, errors),
- cross-links to tests/fuzz/mutation coverage.

Completion policy:
- this manual is finalized only after code freeze for the relevant release branch.

---

## 2) System data-flow map (top level)

Primary runtime loops:
1. `relay-serve`:
   - receives `tx/block/inv/getdata` on P2P wire,
   - validates admission and contextual constraints,
   - updates mempool/runtime persistence,
   - rebroadcasts inventory.
2. `stratum-serve`:
   - handles worker sessions and share submission,
   - builds templates from runtime + mempool,
   - updates telemetry and optional pool payout ledger,
   - submits solved blocks into runtime.
3. `rpc-serve`:
   - read APIs for status/explorer/pool views,
   - wallet tx creation + submit APIs,
   - SSE event stream for UI.

Core object boundaries:
- `core`: wire-independent types/hash/target/config.
- `consensus`: block/tx/utxo validity + difficulty math.
- `chain`: canonical runtime, reorg, cumulative-work chain selection.
- `mempool`: policy layer before block inclusion.
- `p2p`: transport, wire messages, gossip, sync/discovery helpers.
- `miner`: template packing + PoW search.
- `stratum`: SV2 message model and secure framing.
- `storage`: `redb` persistence wrappers.
- `wallet`: mnemonic/keys/signing/vault/rescan/qr.
- `node`: orchestration/CLI/service loops (integration crate).

---

## 3) Crate by crate

## 3.1 `crates/core`

Files:
- `crates/core/src/lib.rs`
- `crates/core/src/types.rs`
- `crates/core/src/hash.rs`
- `crates/core/src/target.rs`
- `crates/core/src/pow.rs`
- `crates/core/src/merkle.rs`
- `crates/core/src/codec.rs`
- `crates/core/src/config.rs`
- `crates/core/src/visual.rs`

Responsibility:
- immutable protocol primitives and serialization contracts.

Primary structs/types:
- block/tx/outpoint family in `types.rs`,
- `Hash256` and hash helpers in `hash.rs`,
- numeric target type and comparison in `target.rs`,
- chain/network config in `config.rs`.

Key invariants:
- block hash compare is numeric (`hash <= target`),
- tx/block IDs are deterministic hashes over canonical serialization,
- config validation enforces cross-field constraints before runtime start.

Notes:
- `visual.rs` provides optional 16x16 hash bitmap helper.
- `config.rs` is the fork-constructor pivot: genesis, difficulty mode, HRP, networking knobs.

## 3.2 `crates/consensus`

Files:
- `crates/consensus/src/lib.rs`
- `crates/consensus/src/validate.rs`
- `crates/consensus/src/utxo.rs`
- `crates/consensus/src/difficulty.rs`

Responsibility:
- deterministic block/tx correctness independent of networking.

Main components:
- `validate.rs`: structural + contextual block checks,
- `utxo.rs`: transaction application and spend rules,
- `difficulty.rs`: `windowed`, `lwma`, `asert` target evolution.

Key invariants:
- no overspend, no duplicate input spend in same tx,
- coinbase maturity and fee accounting are enforced,
- difficulty function output is bounded and non-zero.

## 3.3 `crates/chain`

Files:
- `crates/chain/src/lib.rs`

Responsibility:
- canonical runtime state, branch tracking, reorg/connect/disconnect workflow.

Main behaviors:
- applies validated blocks in-order,
- tracks cumulative work per branch tip,
- reorgs to heavier chain with guardrails against invalid disconnect/replay loops,
- restores runtime from persisted ordered blocks.

Key invariants:
- active tip always belongs to max cumulative-work branch,
- reorg path must preserve UTXO consistency after disconnect+connect,
- persistence snapshots must round-trip into identical runtime tip.

## 3.4 `crates/mempool`

Files:
- `crates/mempool/src/lib.rs`

Responsibility:
- pre-consensus transaction staging with policy and anti-abuse controls.

Main behaviors:
- fee-aware insert,
- conflict replacement under policy constraints,
- bounded orphan pool with ttl/eviction,
- telemetry for replace/orphan churn.

Key invariants:
- no duplicate inputs inside a tx,
- coinbase and zero-value outputs rejected,
- replacement cannot violate configured fee delta / descendant limits.

## 3.5 `crates/wallet`

Files:
- `crates/wallet/src/lib.rs`
- `crates/wallet/src/mnemonic.rs`
- `crates/wallet/src/address.rs`
- `crates/wallet/src/signer.rs`
- `crates/wallet/src/vault.rs`
- `crates/wallet/src/rescan.rs`
- `crates/wallet/src/qr.rs`

Responsibility:
- user key material lifecycle and transaction signing support.

Main behaviors:
- BIP39 create/parse + seed derivation,
- deterministic key derivation and address encoding/decoding,
- encrypted vault read/write,
- chain rescan for balances/history,
- QR/payment URI rendering.

## 3.6 `crates/p2p`

Files:
- `crates/p2p/src/lib.rs`
- `crates/p2p/src/wire.rs`
- `crates/p2p/src/transport.rs`
- `crates/p2p/src/gossip.rs`
- `crates/p2p/src/sync.rs`
- `crates/p2p/src/discovery.rs`

Responsibility:
- peer protocol messages + transport framing + gossip/sync helper logic.

Main behaviors:
- handshake and message framing,
- inventory tracking for blocks/tx,
- sync helpers (`headers/getblocks/getdata`),
- peer discovery/addr exchange.

## 3.7 `crates/stratum`

Files:
- `crates/stratum/src/lib.rs`

Responsibility:
- SV2 message model, session state transitions, secure transport framing.

Main behaviors:
- setup/channel/open/submit message serialization,
- session event/state machine validation,
- `legacy` secure mode and `noise_xx` mode support.

## 3.8 `crates/storage`

Files:
- `crates/storage/src/lib.rs`

Responsibility:
- `redb` persistence integration for runtime artifacts.

Main behaviors:
- save/load ordered block archive,
- save/load peer book,
- consistency checks for network id and persisted payload format.

## 3.9 `crates/rpc`

Files:
- `crates/rpc/src/lib.rs`

Responsibility:
- rpc response types + encoding helpers.

Main behaviors:
- shared JSON shaping used by node rpc endpoints.

## 3.10 `crates/miner`

Files:
- `crates/miner/src/lib.rs`

Responsibility:
- template assembly and PoW search loop primitives.

Main behaviors:
- block template construction from mempool,
- package/ancestor handling for CPFP-aware ordering,
- nonce/extra-nonce search helpers.

## 3.11 `crates/node`

Files:
- `crates/node/src/main.rs`

Responsibility:
- integration/orchestration binary:
  - command-line interface,
  - relay runtime,
  - rpc server,
  - wallet command entrypoints,
  - stratum server/client and SV2 conformance tooling.

Note:
- this crate is intentionally large because it hosts integration glue.
- subsequent manual passes split this section into command-by-command and function-by-function tables.

---

## 4) Protocol walkthroughs to expand next

Planned deep dives:
1. P2P relay path:
   - inbound `tx` -> mempool admission -> inventory delta -> rebroadcast.
2. Block sync path:
   - locator -> headers -> inv/getdata -> block apply.
3. Stratum path:
   - setup -> channel open -> job issue -> share submit -> block submit.
4. Wallet send path:
   - mnemonic/vault -> utxo selection -> sign -> submit -> mempool -> mined.
5. Reorg path:
   - disconnect old branch -> restore tx to mempool -> connect heavier branch.

---

## 5) Coverage cross-link map (initial)

Mutation:
- staged runner: `scripts/mutation-staged.sh`
- baseline runner: `scripts/mutation-baseline.sh`
- latest closure artifacts:
  - `target/mutants-stage-j2c/stage2/mutants.out/outcomes.json`
  - `target/mutants-stage-j2c-full/stage3/mutants.out/outcomes.json`

Fuzz:
- targets under `fuzz/` (wire, tx decode, block decode + relay/submit coverage).

Integration/e2e scripts:
- `scripts/local-test-lab.sh`
- `scripts/local-e2e-flow.sh`
- `scripts/local-multinode.sh`

---

## 6) Next pass checklist for this manual

- add function inventory tables per file (`fn`, purpose, input/output, side effects),
- add error taxonomy table (`NodeError`/crate-specific errors),
- add persistence schema notes (`redb` keys/tables per subsystem),
- add operator scenario recipes with expected outputs and failure triage,
- add explicit links from each manual section to tests validating that behavior.
