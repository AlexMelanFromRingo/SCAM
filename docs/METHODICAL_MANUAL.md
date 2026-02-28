# SCAM Methodical Manual (RC1)

Status: active reference for `master` (RC1).

This document is the maximum-detail implementation manual requested in `docs/IMPLEMENTATION_TODO.md` section 20.
It is split by crate and paired with a generated function index in `docs/manual/FUNCTION_INVENTORY.md`.

## 1) How To Read This Manual

1. Start with section 2 (system architecture + runtime loops).
2. Use section 3 (crate-by-crate) for code ownership and invariants.
3. Use section 4 for protocol walkthroughs.
4. Use section 5 for operator recipes.
5. Use section 6 for verification links (tests/fuzz/mutation).

Primary source files:
- `docs/manual/FUNCTION_INVENTORY.md` (full function list with line numbers)
- `docs/OPERATOR_RUNBOOK.md` (operations + incidents)
- `docs/SV2_INTEROP_MATRIX.md` (interop results and expectations)

## 2) System Architecture (Top-Level)

### 2.1 Process Roles

- `scam-node node`: initializes runtime DB from config/genesis and exits after persistence bootstrap.
- `scam-node relay-serve`: long-running P2P relay loop (handshake, INV/GETDATA, tx/block admission, gossip).
- `scam-node rpc-serve`: explorer + wallet RPC/HTTP + SSE + static Web UI.
- `scam-node stratum-serve`: SV2 pool endpoint, share validation, template updates, optional payout accounting.
- `scam-node stratum-mine`: miner client (solo/remote pool modes through Stratum).

### 2.2 Data Planes

- Consensus plane:
  - `core` defines canonical bytes/hashes/types.
  - `consensus` validates block/tx and mutates UTXO.
  - `chain` decides active tip via cumulative work and performs reorg.
- Networking plane:
  - `p2p` provides wire, transport, gossip logic, sync/discovery helpers.
  - `stratum` provides SV2 messages/session logic/secure transports.
- Wallet plane:
  - `wallet` handles mnemonic -> key derivation -> signing -> scan.
- Persistence plane:
  - `storage` wraps `redb` for runtime archive, peer book, mempool snapshot, pool ledger.
- Integration plane:
  - `node` wires all planes, defines CLI commands, runtime services, and RPC routes.

### 2.3 Runtime Storage Contracts

- Runtime archive DB: ordered blocks by height + hash indexes.
- Runtime state DB: network id, tip, UTXO snapshot, height->hash vector.
- Peer book DB: deduped peer records keyed by address.
- Mempool DB: txid-keyed tx + fee snapshot.
- Pool ledger DB: rounds, shares, worker accruals, pending/completed payouts.

### 2.4 High-Level Data Flows

- Block validation flow: `wire/block` -> `chain::submit_block` -> contextual checks -> UTXO apply or reorg -> persist -> relay INV.
- Tx admission flow: `wire/tx` or `rpc /tx/submit` -> mempool policy + UTXO context -> orphan/mempool updates -> relay INV.
- Mining flow: runtime tip + mempool revision -> template build (CPFP-aware) -> nonce search -> solved block submission.
- Wallet flow: mnemonic/vault -> derive key hash -> rescan UTXO ownership -> sign/send -> mempool -> mined/confirmed.

## 3) Crate-By-Crate Manual

## 3.1 `core`

Role: protocol primitives and canonical serialization/hashing used by all crates.

Modules:
- `codec.rs`: deterministic encoder + varint rules.
- `types.rs`: `OutPoint`, `Transaction`, `BlockHeader`, `Block` with hash/signing helpers.
- `hash.rs`: BLAKE3-based hash helpers and hex decoding.
- `target.rs`: numeric target representation and `hash <= target` evaluation.
- `pow.rs`: PoW checks against header hash.
- `merkle.rs`: merkle root builder.
- `config.rs`: network/fork constructor config + validation + genesis construction.
- `visual.rs`: optional 16x16 hash bitmap rendering.

Public function notes (API surface, see full signatures in `docs/manual/FUNCTION_INVENTORY.md`):
- `hash::hash256`, `tagged_hash256`, `hash160_blake3`:
  - Deterministic BLAKE3 wrappers.
  - `tagged_hash256` is domain separator for signatures and protocol contexts.
- `target::allows_hash`:
  - Numeric big-endian comparison (`hash <= target`), not leading-zero counting.
- `pow::header_meets_pow`, `block_meets_pow`:
  - Enforce target-based validity on computed header hash.
- `types::Transaction::signing_digest_with_chain_domain`:
  - Enforces input index bounds.
  - Includes chain-domain bytes to prevent cross-network replay.
  - Hashes canonical signing preimage (selected input pubkey + all outputs + lock_time + input index).
- `types::Block::has_valid_merkle_root`:
  - Recomputes txid merkle root from serialized tx set.
- `config::validate`:
  - Cross-field gatekeeper for chain params, limits, difficulty clamps, address prefix, Stratum settings.
- `config::build_genesis_block`:
  - Constructs genesis from config constants (including reward address and genesis message/tag).

Invariants and error paths:
- Canonical bytes are the only hash source (no alternate encodings).
- Invalid hex/size is rejected early by `ParseHexError`.
- Invalid config cannot enter runtime (`ChainConfigError`).

Coverage links:
- Unit tests in `crates/core/src/*.rs`.
- Mutation coverage from staged/full runs (`scripts/mutation-staged.sh`, `scripts/mutation-baseline.sh`).

## 3.2 `consensus`

Role: deterministic consensus validation independent of transport/UI.

Modules:
- `validate.rs`: block-structure checks (coinbase position/count, merkle consistency, tx list non-empty).
- `utxo.rs`: PoW check, tx signature validation (Schnorr), maturity rules, fee/subsidy enforcement, UTXO mutation.
- `difficulty.rs`: windowed retarget, LWMA, ASERT and chainwork math.

Public function notes:
- `validate_block_basic`:
  - Structural gate only; does not mutate state.
- `validate_and_apply_block`:
  - Full block execution against mutable UTXO set.
  - Checks:
    - PoW match.
    - Exactly-first coinbase semantics.
    - Input existence and no in-block double-spend.
    - Schnorr signature validity against compressed pubkey/x-only verify.
    - Pubkey hash ownership match.
    - Coinbase maturity.
    - Non-final tx lock-time/sequence policy (`tx_is_final_for_block`).
    - `sum(inputs) >= sum(outputs)` and coinbase reward <= subsidy + fees.
- `tx_is_final_for_block`:
  - Locktime threshold semantics (`height` vs `timestamp`) and final-sequence shortcut.
- Difficulty functions:
  - `retarget_next`: bounded timespan clamp + scaled target update.
  - `lwma_next`: weighted solve-time averaging with solve-time caps.
  - `asert_next`: exponential target adjustment around half-life.
  - `chainwork_for_target`: cumulative work metric used by chain fork choice.

Invariants:
- Consensus-level rejection on any malformed signature/pubkey/overspend/maturity violation.
- Difficulty outputs are clamped to non-zero and bounded by max target.

Coverage links:
- Unit tests in `crates/consensus/src/difficulty.rs`, `crates/consensus/src/utxo.rs`, `crates/consensus/src/validate.rs`.

## 3.3 `chain`

Role: active-chain state machine with heavy-chain selection and reorg.

Primary structures:
- `ChainRuntime`: config, UTXO map, block/header maps, cumulative-work map, active-chain vector, per-block undo data.
- `BlockUndo`: spent entries + created outpoints for disconnect.

Public function notes:
- Constructors:
  - `from_config`: validates config + builds genesis.
  - `from_ordered_blocks`: restores runtime from archive and verifies expected genesis hash.
  - `new`: initializes runtime from explicit genesis block.
- Accessors:
  - tip/hash/header/height, block hash at height, block lookup, UTXO view, cumulative work.
- Difficulty interface:
  - `expected_target_for_next_block` chooses algorithm (`Windowed`, `Lwma`, `Asert`) from config.
- Connect path:
  - `apply_next_block` requires prev = current tip and exact expected target.
  - Executes contextual timestamp checks (MTP > parent median, <= now + 2h).
- Submission path:
  - `submit_block` accepts side-branch storage for known parent.
  - Promotes candidate branch only if cumulative work exceeds current tip.
  - Performs disconnect/connect reorg using undo data, rollback on failure.

Key internal mechanisms (production-critical):
- `collect_chain_to_genesis`: walks candidate branch to anchor.
- `find_fork_height`: identifies common ancestor with active chain.
- `reorganize_to_chain`: bounded disconnect guard + reconnect loop.
- `connect_known_block` and `disconnect_tip_block`: incremental reorg, avoids replay-from-genesis DoS behavior.

Invariants:
- Active tip always the highest cumulative-work known branch.
- Reorg never mutates state partially on failure (rollback backups restored).
- Genesis cannot be disconnected.

Coverage links:
- Unit tests in `crates/chain/src/lib.rs`.
- Integration tests in `crates/chain/tests/runtime_sync.rs`.

## 3.4 `mempool`

Role: policy staging area between signed tx submission and block inclusion.

Primary structures:
- `Mempool`: tx map, spent-outpoint index, feerate index, policy constants, telemetry.
- `OrphanPool`: missing-parent tx staging with TTL and bounded size.
- Telemetry structs for replacement/orphan churn.

Public function notes:
- Constructors:
  - `new`, `with_policy`, `with_policy_and_replacement` with strict non-zero limits.
- Query/mutation:
  - `len`, `is_empty`, `revision`, `telemetry`, `contains`, `get`, `fee`, `get_with_fee`.
  - `remove_confirmed_txids`: deterministic removal and telemetry updates.
- Admission:
  - `insert` (default fee=0), `insert_with_fee` (main policy path), `min_required_fee`.
  - `txids_by_feerate_desc`: independent tx ranking.
- Replacement policy details (`insert_with_fee`):
  - Detects input conflicts via `spent_outpoints`.
  - Rejects multi-conflict replacements.
  - Requires strictly higher feerate than conflicting root.
  - Builds replacement set (root + descendants), enforces descendant cap.
  - Requires incoming fee >= total replaced fees + `min_replacement_fee_delta`.
- Full pool behavior:
  - Evicts lowest-feerate entry (with descendants) only when incoming feerate is better.
- Orphans:
  - `OrphanPool::insert`, `expire`, `resolve_outpoint`, `telemetry`.

Internal performance/safety details:
- Feerate eviction uses `BTreeSet` index (`lowest_feerate_txid`) instead of full scan.
- Replacement descendant discovery is bounded by configurable scan limit.

Invariants:
- Rejects coinbase tx, invalid compressed pubkey prefixes, duplicate inputs, zero outputs, under-fee tx.
- Revision increments only on state-changing operations.

Coverage links:
- Unit tests in `crates/mempool/src/lib.rs` include replacement policy, orphan lifecycle, telemetry, eviction.

## 3.5 `wallet`

Role: user-key lifecycle, address encoding, signing, scanning, vault encryption, QR.

Modules and function notes:

- `mnemonic.rs`
  - `new_mnemonic(words)`: BIP39 English mnemonic generation.
  - `WalletMnemonic::parse`: normalized phrase validation.
  - `WalletMnemonic::to_seed(passphrase)`: deterministic 64-byte seed.

- `signer.rs`
  - `derivation_path(account,index)`: frozen path `m/44'/1337'/account'/0/index`.
  - `derive_wallet_key(seed, account, index)`: BIP32 derivation to secp256k1 key.
  - `sign_digest` / `verify_digest`: Schnorr signing and x-only verification.
  - `WalletKey::pubkey_compressed` / `secret_key_bytes`: exportors for runtime usage.

- `address.rs`
  - `key_hash20_from_compressed_pubkey`: validates secp256k1 compressed key then hashes.
  - `to_address(hrp, pubkey)`: Bech32m encode with enforced HRP prefix rule (`s*`).
  - `parse_address`: decode + variant + payload length checks.

- `rescan.rs`
  - `derive_watched_keys`: derive watched key hashes over index range.
  - `rescan_blocks`: computes received/spent/unspent, spendable vs immature (coinbase maturity).

- `vault.rs`
  - `new_encrypted_wallet_vault`: Argon2id key derivation + XChaCha20Poly1305 encryption.
  - `decrypt_wallet_vault`: full integrity/decryption checks + mnemonic parse validation.
  - `save_wallet_vault` / `load_wallet_vault`: JSON persistence.

- `qr.rs`
  - `qr_for_text`: ASCII QR rendering for arbitrary payload.
  - `qr_for_payment_uri`: `coin:<address>?amount=&label=` wrapper.

Invariants:
- Empty seed/empty mnemonic/empty encryption password are rejected.
- Address parse rejects wrong HRP, wrong Bech32 variant, invalid payload length.
- Vault decode rejects unsupported version/kdf.

Coverage links:
- Unit tests in `crates/wallet/src/*.rs` (BIP39 vector, Schnorr roundtrip, address invariants, vault roundtrip, QR rendering).

## 3.6 `p2p`

Role: P2P protocol definitions + framing + gossip state machine + sync/discovery helpers.

Module notes:
- `wire.rs`:
  - `WireMessage` includes handshake, inv/getdata, headers/blocks, addr, compact-block primitives.
  - `encode_message` / `decode_message` with max-size checks.
- `transport.rs`:
  - Sync + async frame I/O: `send_message[_async]`, `read_message[_async]`.
  - Sync + async handshake: `client_handshake[_async]`, `server_handshake[_async]`.
  - Header/block request helpers: `request_headers[_async]`, `request_blocks[_async]`.
- `gossip.rs`:
  - Peer state, ban-score model, replacement rate limiting.
  - Local inventory tracking and fanout.
  - Bounded tx/block stores with FIFO pruning (`max_*_store_items`) to avoid unbounded RAM growth.
- `sync.rs`:
  - `build_block_locator`, `select_headers_for_peer`, `select_block_hashes_for_peer`.
- `discovery.rs`:
  - `select_outbound_peers` with diversity buckets + failure-aware ranking.

Key gossip behaviors:
- INV over-limit penalizes and can ban peers.
- GetData replies from local stores; missing items returned via `NotFound`.
- Tx replacement events from peers are rate-limited and telemetry-accounted.

Coverage links:
- Unit tests in `crates/p2p/src/*`.
- Integration test in `crates/p2p/tests/gossip_propagation.rs`.
- Fuzz target: `fuzz/fuzz_targets/wire_decode.rs`.

## 3.7 `stratum`

Role: SV2 protocol modeling, session-state enforcement, share validation, secure transport.

Primary exported entities:
- `Sv2Message`: all setup/channel/job/submit/target/keepalive message variants.
- `Sv2Session`: state machine (`AwaitSetup` -> `AwaitOpenChannel` -> `Active` -> `Closed`).
- `SecureSv2Transport` (legacy secure framing) and `NoiseSv2Transport` (Noise XX secure framing).
- `JobDeclarator`, `SequentialJobDeclarator`, `Translator`, `IdentityTranslator`.

Function-path notes:
- Session initialization and config validation:
  - `Sv2Session::new` validates limits, vardiff bounds, setup flag constraints.
- Session processing:
  - `handle_message` / `handle_message_at` routes each incoming message through state-specific handlers.
  - `install_job` inserts bounded active job set and emits `NewMiningJob`.
  - `set_new_prev_hash`, `set_target_message` emit coordinator updates.
- Secure transport:
  - `SecureSv2Transport::handshake_*`, `read_message*`, `write_message*`.
  - `NoiseSv2Transport::handshake_*`, `read_message*`, `write_message*`.
  - `write_frame*` / `read_frame*` for plaintext framing utilities.
- Share validation:
  - `validate_share` checks job binding, channel, target relation, and derives block/share acceptance.

Invariants:
- Protocol version/flags negotiation must pass before channel open.
- Submit before setup/channel produces protocol-state error.
- Share target is always clamped to configured bounds.

Coverage links:
- Unit tests inside `crates/stratum/src/lib.rs`.
- Node-level conformance tests and scripts:
  - `scripts/sv2-conformance-matrix.sh`
  - `scripts/sv2-corpus-replay.sh`

## 3.8 `storage`

Role: `redb` persistence for chain state, archive, peer book, mempool, pool ledger.

Primary records:
- Chain: `ChainStateSnapshot`, `ChainArchive`, `UtxoRecord`.
- Networking: `PeerAddressBook`, `PeerAddressRecord`.
- Mempool: `MempoolSnapshot`, `MempoolTxRecord`.
- Pool ledger: `PoolLedgerSnapshot`, `PoolShareRecord`, `PoolRoundRecord`, `PoolWorkerAccrualRecord`, `PoolPayoutRecord`.

Public function notes:
- Snapshot API:
  - `save_snapshot` / `load_snapshot` for file+bincode.
  - `save_snapshot_db` / `load_snapshot_db` for redb (atomic replace using temp file).
- Archive API:
  - `save_chain_archive_db`, `load_chain_archive_db`, `load_block_by_hash_db`.
  - Enforces index continuity and header/body consistency.
- Peer/mempool API:
  - `save_peer_book_db`, `load_peer_book_db` with dedup/sort and key consistency checks.
  - `save_mempool_db`, `load_mempool_db` with txid recomputation validation.
- Pool ledger API:
  - `save_pool_ledger_db`, `load_pool_ledger_db` with per-table dedup, sorting, key consistency checks.

Safety and durability behavior:
- Every DB write path uses temp DB then atomic replace.
- All load paths validate metadata presence and field sizes before decode.

Coverage links:
- Unit tests in `crates/storage/src/lib.rs` for roundtrip and corruption checks.

## 3.9 `rpc`

Role: shared RPC payload shaping and tx-submit decoding.

Public function notes:
- `parse_tx_submit_json`, `decode_tx_submit_request`:
  - parse JSON request, decode tx hex payload via bincode, return `(Transaction, fee)`.
- `to_pretty_json`:
  - shared pretty serializer for CLI and response formatting.
- `BlockResponse::from_block`, `TxResponse::from_tx`, `header_to_block_response`:
  - explorer payload helpers.

Errors:
- `TxSubmitError` for malformed JSON, empty tx hex, invalid hex, invalid transaction payload.

Coverage links:
- Unit tests in `crates/rpc/src/lib.rs`.

## 3.10 `miner`

Role: template construction + CPFP package selection + nonce/extra-nonce search.

Primary APIs:
- `build_template_from_mempool`:
  - Gathers candidate tx graph from mempool.
  - Builds CPFP packages with dependency ordering and package score.
  - Enforces `max_txs`, produces `TemplateBuildSummary`.
  - Computes coinbase reward = subsidy + included fees.
- `TemplateManager::build_or_reuse`:
  - Cache key is `(tip_hash, mempool_revision)`.
- `mine_block_with_extra_nonce`:
  - Iterates extra nonce outer loop, nonce inner loop; returns first valid PoW.
- `mine_block`:
  - Convenience wrapper with fixed extra nonce range (`0`).

Key internal algorithms:
- `build_cpfp_package`:
  - Closure expansion over descendants whose parents are in package or already included.
  - Topological ordering (parents before children) with ranked tie-breaking.
- `package_beats_current`:
  - Selects better package by score key then total fee then deterministic root tie-break.

Coverage links:
- Unit tests in `crates/miner/src/lib.rs` include CPFP ordering, cyclic guard, template cache behavior.

## 3.11 `node`

Role: integration/orchestration binary and largest crate.

Important note:
- `crates/node/src/main.rs` intentionally centralizes CLI and service glue.
- Full top-level function inventory is in `docs/manual/FUNCTION_INVENTORY.md`.

### 3.11.1 CLI/Command Dispatch Layer

Core entrypoints:
- `run_from_args` -> `run_command` -> selected `run_*` handler.
- `main` wraps `run_from_args` and exits non-zero on errors.

Primary command handlers (operator-facing):
- chain/runtime/read APIs:
  - `run_node`, `run_status`, `run_get_block`, `run_get_tx`, `run_snapshot`, `run_reindex_runtime`.
- config/network bootstrap:
  - `run_config_scaffold`, `run_add_peer`, `run_sync_peer`, `run_sync_book`, `run_net_demo`, `run_p2p_demo`.
- wallet/mining flows:
  - `run_wallet`, `run_mine_once`, `run_chain_demo`, `run_sync_demo`, `run_reorg_demo`, `run_soak`.
- long-running services:
  - `run_relay_serve`, `run_rpc_serve`, `run_stratum_serve`, `run_stratum_mine`.
- SV2 role/conformance tools:
  - `run_sv2_template_provider`, `run_sv2_job_declarator`, `run_sv2_translator`, `run_sv2_conformance`.
- key management:
  - `run_stratum_keygen`, `run_stratum_key_rotate`.

### 3.11.2 Runtime/DB Helpers

Key functions:
- `load_chain_config`, `default_*_db_path` helpers.
- `load_runtime_from_db_or_genesis`, `persist_runtime_db_with_retry`.
- `load_mempool_from_db_or_empty_with_retry`, `persist_mempool_db_with_retry`.
- `load_pool_ledger_from_db_or_new`, `persist_pool_ledger_db_with_retry`.
- `persist_with_retry`, `load_with_retry`, lock-conflict helpers.

Behavior notes:
- Retry wrappers are used for transient DB lock contention.
- Runtime and mempool DBs are synchronized on service critical transitions.

### 3.11.3 P2P Relay Runtime (`relay-serve`)

Main orchestration:
- `run_relay_serve`:
  - binds listener,
  - initializes relay state and gossip engine,
  - launches inbound accept loop,
  - optional outbound supervisor for peer book dialing,
  - spawns telemetry snapshot thread.

Inbound/outbound session paths:
- `run_relay_peer_session` handles per-connection handshake, message loop, and peer-scoped policy accounting.
- `run_relay_outbound_worker` dials a single target and runs same session path.
- `run_relay_outbound_supervisor` maintains dial targets from peer book with redial policy.

Wire processing:
- `process_relay_wire_message_inner` is the core dispatcher for tx/block/inv/getdata/addr/headers paths.
- `process_relay_wire_message_with_archive` extends getdata behavior with runtime archive fallback reads.
- `relay_collect_getdata_from_memory` handles local in-memory retrieval fast path.

Compact-block path:
- `relay_compact_block_from_block`, `relay_lookup_mempool_tx_by_short_txid`,
  `relay_reconstruct_compact_transactions`, `relay_try_build_block_from_compact`.

Mempool/chain integration:
- `admit_peer_tx_into_relay` validates tx against runtime+mempool.
- `relay_submit_incoming_block` hands blocks into chain runtime and updates deltas.
- Orphan-recovery helpers:
  - `relay_store_pending_orphan_block`, `relay_try_apply_pending_orphans`, `relay_recovery_messages_for_unknown_parent`.

Policy and anti-DoS helpers:
- message/read limits: `should_stop_after_seen_messages`, read-result mappers.
- replacement throttling: `relay_mark_peer_replacement_rate_limited` and quota guards.
- reputation persistence: `load_peer_reputation_book`, `update_peer_reputation_store`, `save_peer_reputation_book`.

### 3.11.4 RPC + UI (`rpc-serve`)

Core server loop:
- `run_rpc_serve_inner` accepts HTTP, routes requests, serves JSON or static assets, and can stream SSE snapshots.

Routing and parsing helpers:
- `read_http_request`, `parse_content_length`, timeout/closed classifiers.
- route matchers:
  - `rpc_block_height_path`, `rpc_tx_path_parts`, `rpc_txid_path`, `rpc_exact_route_matches`, `is_pool_worker_route`.
- response writers:
  - `write_http_response`, `write_http_json_response`, `write_http_sse_headers`, `write_http_sse_event`.

Explorer/wallet payload helpers:
- `block_lookup_response`, `tx_lookup_response`.
- `wallet_address_response`, `wallet_balance_response`, `wallet_tx_history_for_key_hash`.
- UI asset helpers:
  - `sanitize_ui_path`, `guess_content_type`, `try_serve_ui_asset`.

Realtime event stream:
- `build_rpc_event_snapshot`, `run_rpc_events_worker`, worker lifecycle helpers.

### 3.11.5 Stratum/SV2/Pool Paths

Stratum service:
- `run_stratum_serve`:
  - config validation,
  - template generation from runtime+mempool,
  - worker session handling,
  - share acceptance/rejection accounting,
  - optional payout tick execution.

Miner client:
- `run_stratum_mine` and helper `try_find_share_for_job`.

SV2 conformance:
- corpus loading/materialization/evaluation helpers:
  - `load_sv2_corpus`, `materialize_sv2_conformance_message`, `update_sv2_conformance_state`,
    `evaluate_sv2_conformance_requirements`, `ensure_sv2_conformance_pass`.

Pool payout helpers:
- ledger updates:
  - `record_pool_share_accepted`, `record_pool_share_rejected`, `record_pool_round_closed`.
- reconciliation/payout:
  - `reconcile_pool_ledger_with_runtime`, `maybe_process_pool_payouts`, `run_pool_payout_tick_with_warning`.

### 3.11.6 Wallet + Tx Construction Helpers

Key functions:
- `select_utxos_for_amount`, `collect_spendable_utxos`, `detect_missing_outpoints`.
- `build_signed_transfer_tx` (signing + change output behavior + fee handling).
- `submit_tx_via_mempool_db` local admission/persistence path.

### 3.11.7 Node Error Taxonomy

`NodeError` wraps:
- config parse/validation,
- IO/network errors,
- transport/wire protocol errors,
- storage and serialization errors,
- chain/mempool/stratum/wallet-specific failures.

Error mapping helpers (`map_*_result`, `*_io_error_is_*`) are used to normalize retry/close semantics across relay, RPC, and SV2 loops.

Coverage links for `node`:
- Extensive unit + integration tests in `crates/node/src/main.rs` and `crates/node/tests/cli_main.rs`.
- Fuzz target `fuzz/fuzz_targets/relay_tx_submit.rs`.

## 4) Protocol Walkthroughs

## 4.1 P2P Relay + Sync Walkthrough

1. Peer handshake (`Version`/`Verack`) via `p2p::transport`.
2. Remote peer sends `Inv`.
3. Relay computes unknown inventory and requests via `GetData`.
4. On `Tx`:
   - decode + context validation,
   - mempool admission,
   - inventory update,
   - outbound fanout to other peers.
5. On `Block`:
   - submit to `ChainRuntime` (`ExtendedTip`, `StoredSideBranch`, or `Reorged`),
   - remove confirmed mempool entries,
   - announce block inventory.
6. For initial sync:
   - build locator with exponential backoff,
   - request headers (`GetHeaders`),
   - request blocks (`GetBlocks` / `GetData`),
   - apply in order.

## 4.2 Stratum (SV2) Walkthrough

1. Setup: client sends `SetupConnection`.
2. Server verifies version/flags and replies success/error.
3. Client opens channel (`OpenStandardMiningChannel`).
4. Server replies channel success and `SetTarget`.
5. Server emits `NewMiningJob` (or `SetNewPrevHash` when tip shifts).
6. Client submits share (`SubmitSharesStandard`/`Extended`).
7. Server validates against job + target and replies `SubmitSharesSuccess` or `SubmitSharesError`.
8. Accepted block-share path triggers block submission into runtime.

## 4.3 Wallet Tx Flow

1. Mnemonic parse/generate (`wallet::mnemonic`).
2. Derive key (`wallet::signer`) and address (`wallet::address`).
3. Query spendable UTXO set from runtime.
4. Build unsigned tx with outputs + optional change.
5. Compute per-input signing digest with chain domain.
6. Schnorr-sign each input and fill signature/pubkey.
7. Submit through mempool admission path.
8. Relay gossip propagates tx; miner template eventually includes it in block.

## 5) Operator Runbook Recipes (Practical Scenarios)

All recipes can be launched via presets:
- `scripts/run-preset.sh --list`
- Preset files under `scripts/presets/*.env`.

### 5.1 Node-only (no mining)

- Preset: `scripts/presets/lab-node-only.env`
- Start:
  - `scripts/run-preset.sh scripts/presets/lab-node-only.env up`
- Validate:
  - `/status`, `/mempool`, relay logs.

### 5.2 Solo mining on own node

- Preset: `scripts/presets/lab-solo-local.env`
- Start lab:
  - `scripts/run-preset.sh scripts/presets/lab-solo-local.env up`
- Miner connects local Stratum endpoint and rewards target local miner key.

### 5.3 Solo mining on remote/shared node (solo-pool mode)

- Preset: `scripts/presets/lab-solo-remote.env`
- Miner points to remote pool endpoint, but payout semantics remain per-user (no shared payout split).

### 5.4 Shared pool mode (share-accounted payout)

- Base preset: `scripts/presets/lab-shared-pool-base.env`
- Convenience preset: `scripts/presets/lab-pool-shared.env`
- Workflow:
  - start pool node,
  - attach multiple workers (distinct `--user`),
  - inspect pool ledger endpoints and payout records.

Operational docs:
- `docs/OPERATOR_RUNBOOK.md`
- `docs/SV2_ROLE_INCIDENT_RUNBOOK.md`
- `docs/SV2_INTEROP_MATRIX.md`

## 6) Verification And Coverage Links

Rust tests:
- `cargo test --workspace`

Lint/format gates:
- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`

Fuzz:
- `fuzz/fuzz_targets/wire_decode.rs`
- `fuzz/fuzz_targets/tx_decode.rs`
- `fuzz/fuzz_targets/block_decode.rs`
- `fuzz/fuzz_targets/relay_tx_submit.rs`

Mutation:
- staged: `scripts/mutation-staged.sh`
- baseline: `scripts/mutation-baseline.sh`
- current run summaries: `docs/MUTATION_REPORT_ACTIONS_2026-02-13.md`

SV2 conformance/interop:
- `scripts/sv2-corpus-replay.sh`
- `scripts/sv2-conformance-matrix.sh`
- `docs/SV2_INTEROP_MATRIX.md`
- `docs/FUTURE_SV2_FULLSPEC_PLAN.md`

## 7) Function-Level Cross-Reference Index

- Full public API inventory by crate + top-level node function inventory:
  - `docs/manual/FUNCTION_INVENTORY.md`

Use this index together with section 3 for behavior notes and with source files for implementation details.
