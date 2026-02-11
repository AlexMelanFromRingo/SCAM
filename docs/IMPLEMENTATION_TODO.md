# SCAM Implementation TODO (MVP but Production-Style Base)

Status: draft v1 (frozen decisions from user session on 2026-02-11)

## 1) Frozen Design Decisions

- Consensus: PoW.
- Hash algorithm: BLAKE3, 32-byte output (`Hash256`).
- Block validity rule: interpret block hash and target as unsigned 256-bit integers; valid when `hash <= target`.
- Target block time: `120` seconds.
- Difficulty adjustment window: `20` blocks (configurable constant).
- Reward model: fixed block subsidy (no hard cap by default).
- Double-spend mempool policy: for conflicting tx spending same outpoint, keep tx with lower numeric `txid` (BLAKE3 hash).
- Public key format at interfaces: compressed secp256k1 pubkey (33 bytes, `02/03 + x`).
- Signature scheme: Schnorr over secp256k1 (BIP340 style, x-only verification key internally).
- Address format: Bech32m, payload is `blake3(compressed_pubkey)[0..20]` (20-byte key hash), HRP by network.
- Genesis message/string is network-configurable (`genesis_message`), so new networks can be generated from config.
- Smart contracts: not included.

## 2) Important Notes and Tradeoffs

- Schnorr is a good default if we use a mature library (`secp256k1`) and strict message/domain separation.
- Fixed subsidy means perpetual emission (inflation never goes to zero). Difficulty does not set price directly; market demand does.
- "Leading zeros" and "hash <= target" are equivalent views; this project uses explicit numeric target comparison only.
- BLAKE3 256-bit hash can also be visualized as a 16x16 bitmap (256 bits), optional utility.

## 3) Repo Structure TODO

- [ ] Create Cargo workspace members:
- [ ] `crates/core` (types, serialization, hash wrappers).
- [ ] `crates/consensus` (tx/block validation, PoW, retarget).
- [ ] `crates/storage` (DB adapters and chainstate).
- [ ] `crates/mempool` (tx pool, conflict handling).
- [ ] `crates/p2p` (protocol, peers, sync).
- [ ] `crates/node` (orchestrator, startup, config).
- [ ] `crates/miner` (template builder, nonce loop).
- [ ] `crates/wallet` (mnemonic, HD keys, sign/send).
- [ ] `crates/rpc` (CLI/RPC surface).
- [ ] Keep `src/main.rs` as thin bootstrap only.

## 4) Configuration TODO

- [ ] Add `config/chain.toml`:
- [ ] `network_id`
- [ ] `target_block_time_sec = 120`
- [ ] `difficulty_adjustment_window = 20`
- [ ] `difficulty_clamp_up` and `difficulty_clamp_down`
- [ ] `max_block_weight` or `max_block_size`
- [ ] `max_tx_size`
- [ ] `max_mempool_txs`
- [ ] `coinbase_maturity`
- [ ] `block_subsidy`
- [ ] `hrp` for addresses
- [ ] `genesis_*` fields
- [ ] `genesis_message` (human-readable string embedded in genesis coinbase/script)
- [ ] Add separate presets: `devnet.toml`, `testnet.toml`, `mainnet.toml`.

## 5) Cryptography TODO

- [ ] Add hash API:
- [ ] `hash256(data) -> [u8; 32]` using BLAKE3.
- [ ] Define canonical transaction and block serialization for hashing.
- [ ] Integrate secp256k1 Schnorr signing and verification.
- [ ] Enforce canonical signatures and strict pubkey parsing.
- [ ] Implement compressed pubkey encode/decode (SEC33).
- [ ] Add domain-separated signing tags (prevent cross-context replay).

## 6) Wallet and Key Management TODO

- [ ] Implement BIP39 mnemonic generation (12/24 words).
- [ ] Implement wallet restore from mnemonic.
- [ ] Implement BIP32 HD derivation.
- [ ] Freeze derivation path in config/constants.
- [ ] Derive compressed pubkeys for address generation.
- [ ] Derive address payload from `blake3(pubkey_compressed)[0..20]`.
- [ ] Add encrypted at-rest key storage.
- [ ] Add wallet rescan (rebuild UTXO ownership from chain).

## 7) Address and QR TODO

- [ ] Implement Bech32m address encode/decode with network HRP.
- [ ] Implement payment URI: `coin:<address>?amount=<n>&label=<text>`.
- [ ] Implement QR generation for payment URI (PNG + terminal ASCII optional).
- [ ] Add CLI:
- [ ] `wallet address`
- [ ] `wallet address --qr`
- [ ] `wallet decode <address>`

## 8) Transaction Model TODO (UTXO)

- [ ] Define tx structures:
- [ ] `TxIn { prev_out, signature, pubkey_compressed, sequence }`
- [ ] `TxOut { value, key_hash20 }`
- [ ] Define `txid = hash256(serialized_tx_without_witness_mutable_fields)` (freeze exact rule).
- [ ] Validate:
- [ ] inputs exist in UTXO
- [ ] signatures valid
- [ ] `sum(inputs) >= sum(outputs)`
- [ ] no overflow / no negative amounts
- [ ] coinbase special rules enforced
- [ ] Fee policy:
- [ ] min relay fee
- [ ] mempool sorting by fee rate

## 9) Mempool TODO (Conflict Rule)

- [ ] Keep index `spent_outpoint -> txid`.
- [ ] On incoming tx:
- [ ] if no conflict, validate then insert.
- [ ] if conflict exists, compare numeric `new_txid` vs `old_txid`.
- [ ] if `new_txid < old_txid`, replace old tx and evict descendants.
- [ ] else reject new tx.
- [ ] Broadcast replacement/eviction events to peers as inventory updates.
- [ ] Add orphan tx pool with size/time limits.
- [ ] Add eviction policy for full mempool.

## 10) Block and Chain TODO

- [ ] Define block header:
- [ ] `version, prev_hash, merkle_root, timestamp, target, nonce`.
- [ ] Compute and validate merkle root.
- [ ] Validate PoW with numeric target compare (`hash <= target`).
- [ ] Validate block tx ordering and coinbase position.
- [ ] Validate subsidy + fees in coinbase output total.
- [ ] Implement chain selection by cumulative work (not height only).
- [ ] Implement reorg: disconnect old branch, connect new branch.

## 11) Difficulty Retarget TODO

- [ ] Every `N=20` blocks recompute target:
- [ ] `expected = N * target_block_time_sec`
- [ ] `actual = time(last) - time(last-N)`
- [ ] `new_target = old_target * actual / expected`
- [ ] Clamp change per window (for stability).
- [ ] Enforce min/max target bounds.
- [ ] Add protections for timestamp abuse:
- [ ] median-time-past check
- [ ] max future block time

## 12) Storage TODO

- [ ] Pick DB engine (`redb` recommended for simple embedded start).
- [ ] Buckets/tables:
- [ ] blocks by hash
- [ ] headers by hash
- [ ] block index (height, work, parent)
- [ ] UTXO set
- [ ] chain tip metadata
- [ ] mempool persistence (optional, bounded)
- [ ] peer address book
- [ ] Atomic commit for block connect/disconnect state updates.
- [ ] Recovery and reindex mode.

## 13) P2P TODO (Reliable Minimal Gossip)

- [ ] Define protocol messages:
- [ ] `version`, `verack`
- [ ] `ping`, `pong`
- [ ] `inv`, `getdata`, `tx`, `block`
- [ ] `getheaders`, `headers`
- [ ] `getblocks` (optional if headers-first + getdata is enough)
- [ ] Use inventory-first propagation:
- [ ] announce hashes via `inv`
- [ ] request unknown objects via `getdata`
- [ ] send full object only on request
- [ ] Maintain per-peer `known_inventory` to avoid duplicate sends.
- [ ] Keep local dedup cache for recently seen object IDs.
- [ ] Implement headers-first sync for new nodes.
- [ ] Implement peer scoring and ban for invalid data spam.
- [ ] Add rate limits and max message size guards.

## 14) Mining TODO

- [ ] Build block template from mempool by fee rate.
- [ ] Insert coinbase with fixed subsidy + collected fees.
- [ ] Implement nonce search loop.
- [ ] Add extra nonce in coinbase to extend search space.
- [ ] Rebuild template on new best block or mempool updates.
- [ ] Add CPU miner mode for devnet/testnet.

## 15) Node and RPC TODO

- [ ] Node CLI:
- [ ] `node run --network <devnet|testnet|mainnet>`
- [ ] `node status`
- [ ] `node add-peer <addr>`
- [ ] `node get-block <hash>`
- [ ] `node get-tx <txid>`
- [ ] Wallet CLI:
- [ ] `wallet new`
- [ ] `wallet restore`
- [ ] `wallet balance`
- [ ] `wallet send`
- [ ] `wallet address --qr`
- [ ] Add JSON-RPC or REST facade for automation.

## 16) Test Plan TODO

- [ ] Unit tests:
- [ ] hash determinism and serialization compatibility
- [ ] signature verification and pubkey parsing
- [ ] merkle root generation
- [ ] target math and retarget formula
- [ ] mempool replacement by lower txid rule
- [ ] Integration tests:
- [ ] 3+ node tx propagation via inv/getdata
- [ ] block propagation and dedup behavior
- [ ] initial sync from genesis to tip
- [ ] fork + reorg correctness
- [ ] difficulty update every 20 blocks
- [ ] wallet mnemonic restore and deterministic addresses
- [ ] Soak test:
- [ ] local devnet running for 24h with mining and tx flow

## 17) Launch Strategy TODO

- [ ] Phase 1: single-node consensus correctness (no P2P).
- [ ] Phase 2: mempool + mining + persistent chainstate.
- [ ] Phase 3: P2P gossip and headers-first sync.
- [ ] Phase 4: wallet, mnemonic, QR, send/receive UX.
- [ ] Phase 5: hardening, tests, docs, public testnet.
- [ ] Phase 6: mainnet parameter freeze and genesis lock-in.

## 18) Open Constants to Revisit Later

- [ ] `coinbase_maturity` (suggest `100`).
- [ ] `min_relay_fee` baseline.
- [ ] `max_block_size`.
- [ ] retarget clamp factors.
- [ ] mempool max size and orphan limits.

## 19) Optional Utility: 16x16 Hash Visualizer

- [ ] Input: 32-byte hash.
- [ ] Convert bytes to 256 bits (MSB-first, freeze exact bit order in code docs).
- [ ] Render 16x16 matrix where `1 = white`, `0 = black`.
- [ ] Provide CLI command: `util hash-visual <hex>`.
