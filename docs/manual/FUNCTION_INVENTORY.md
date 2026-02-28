# SCAM Function Inventory (RC1)

This file is an index of production-facing functions and top-level integration helpers.
Line numbers are from current `master` at generation time.

## crates/core

```text
crates/core/src/visual.rs:5:pub fn hash_to_bitmap_16x16(hash: Hash256) -> HashBitmap16 {
crates/core/src/visual.rs:20:pub fn render_hash_bitmap_16x16(hash: Hash256) -> String {
crates/core/src/config.rs:107:    pub fn validate(&self) -> Result<(), ChainConfigError> {
crates/core/src/config.rs:323:    pub fn genesis_target(&self) -> Result<Target, ChainConfigError> {
crates/core/src/config.rs:333:    pub fn genesis_reward_key_hash20(&self) -> Result<[u8; 20], ChainConfigError> {
crates/core/src/config.rs:337:    pub fn stratum_share_target(&self) -> Result<Target, ChainConfigError> {
crates/core/src/config.rs:341:    pub fn stratum_min_share_target(&self) -> Result<Target, ChainConfigError> {
crates/core/src/config.rs:345:    pub fn stratum_max_share_target(&self) -> Result<Target, ChainConfigError> {
crates/core/src/config.rs:349:    pub fn build_genesis_block(&self) -> Result<Block, ChainConfigError> {
crates/core/src/merkle.rs:3:pub fn merkle_root(txids: &[Hash256]) -> Hash256 {
crates/core/src/codec.rs:7:    pub fn with_capacity(capacity: usize) -> Self {
crates/core/src/codec.rs:13:    pub fn write_u8(&mut self, value: u8) {
crates/core/src/codec.rs:17:    pub fn write_u32(&mut self, value: u32) {
crates/core/src/codec.rs:21:    pub fn write_u64(&mut self, value: u64) {
crates/core/src/codec.rs:25:    pub fn write_bytes(&mut self, bytes: &[u8]) {
crates/core/src/codec.rs:29:    pub fn write_varint(&mut self, value: usize) {
crates/core/src/codec.rs:49:    pub fn write_len_prefixed_bytes(&mut self, data: &[u8]) {
crates/core/src/codec.rs:54:    pub fn into_bytes(self) -> Vec<u8> {
crates/core/src/pow.rs:4:pub fn header_pow_hash(header: &BlockHeader) -> Hash256 {
crates/core/src/pow.rs:8:pub fn header_meets_pow(header: &BlockHeader) -> bool {
crates/core/src/pow.rs:13:pub fn block_meets_pow(block: &Block) -> bool {
crates/core/src/types.rs:20:    pub fn coinbase() -> Self {
crates/core/src/types.rs:27:    pub fn is_coinbase(&self) -> bool {
crates/core/src/types.rs:55:    pub fn is_coinbase(&self) -> bool {
crates/core/src/types.rs:59:    pub fn txid(&self) -> Hash256 {
crates/core/src/types.rs:63:    pub fn signing_digest(&self, input_index: usize) -> Result<Hash256, TxSigningError> {
crates/core/src/types.rs:67:    pub fn signing_digest_with_chain_domain(
crates/core/src/types.rs:84:    pub fn encode_for_hash(&self) -> Vec<u8> {
crates/core/src/types.rs:150:    pub fn encode(&self) -> Vec<u8> {
crates/core/src/types.rs:161:    pub fn block_hash(&self) -> Hash256 {
crates/core/src/types.rs:173:    pub fn computed_merkle_root(&self) -> Hash256 {
crates/core/src/types.rs:178:    pub fn has_valid_merkle_root(&self) -> bool {
crates/core/src/target.rs:14:    pub fn from_hex(raw: &str) -> Result<Self, ParseHexError> {
crates/core/src/target.rs:18:    pub fn to_hex(self) -> String {
crates/core/src/target.rs:22:    pub fn allows_hash(&self, hash: &Hash256) -> bool {
crates/core/src/hash.rs:13:    pub fn from_hex(raw: &str) -> Result<Self, ParseHexError> {
crates/core/src/hash.rs:17:    pub fn to_hex(self) -> String {
crates/core/src/hash.rs:28:pub fn hash256(data: &[u8]) -> Hash256 {
crates/core/src/hash.rs:33:pub fn tagged_hash256(tag: &[u8], data: &[u8]) -> Hash256 {
crates/core/src/hash.rs:42:pub fn hash160_blake3(data: &[u8]) -> [u8; 20] {
crates/core/src/hash.rs:53:pub fn decode_hex_array<const N: usize>(raw: &str) -> Result<[u8; N], ParseHexError> {
```

## crates/consensus

```text
crates/consensus/src/difficulty.rs:6:pub fn retarget_next(
crates/consensus/src/difficulty.rs:48:pub fn chainwork_for_target(target: Target) -> BigUint {
crates/consensus/src/difficulty.rs:58:pub fn lwma_next(
crates/consensus/src/difficulty.rs:111:pub fn asert_next(
crates/consensus/src/utxo.rs:33:pub fn validate_and_apply_block(
crates/consensus/src/utxo.rs:264:pub fn tx_is_final_for_block(tx: &Transaction, block_height: u64, block_time: u64) -> bool {
crates/consensus/src/validate.rs:6:pub fn validate_block_basic(block: &Block) -> Result<(), BlockValidationError> {
```

## crates/chain

```text
crates/chain/src/lib.rs:51:    pub fn from_config(config: ChainConfig) -> Result<Self, ChainError> {
crates/chain/src/lib.rs:57:    pub fn from_ordered_blocks(
crates/chain/src/lib.rs:84:    pub fn new(config: ChainConfig, genesis: Block) -> Result<Self, ChainError> {
crates/chain/src/lib.rs:115:    pub fn config(&self) -> &ChainConfig {
crates/chain/src/lib.rs:119:    pub fn tip_height(&self) -> u64 {
crates/chain/src/lib.rs:123:    pub fn tip_hash(&self) -> Hash256 {
crates/chain/src/lib.rs:127:    pub fn tip_header(&self) -> &BlockHeader {
crates/chain/src/lib.rs:133:    pub fn block_hashes(&self) -> &[Hash256] {
crates/chain/src/lib.rs:137:    pub fn block_hash_at_height(&self, height: u64) -> Option<Hash256> {
crates/chain/src/lib.rs:141:    pub fn block_by_hash(&self, hash: &Hash256) -> Option<&Block> {
crates/chain/src/lib.rs:145:    pub fn main_chain_blocks(&self) -> Result<Vec<Block>, ChainError> {
crates/chain/src/lib.rs:157:    pub fn utxo_set(&self) -> &UtxoSet {
crates/chain/src/lib.rs:161:    pub fn utxo_len(&self) -> usize {
crates/chain/src/lib.rs:165:    pub fn cumulative_work(&self) -> &BigUint {
crates/chain/src/lib.rs:171:    pub fn header_by_hash(&self, hash: &Hash256) -> Option<&BlockHeader> {
crates/chain/src/lib.rs:228:    pub fn expected_target_for_next_block(&self) -> Result<Target, ChainError> {
crates/chain/src/lib.rs:318:    pub fn apply_next_block(&mut self, block: Block) -> Result<BlockApplySummary, ChainError> {
crates/chain/src/lib.rs:361:    pub fn submit_block(&mut self, block: Block) -> Result<BlockSubmissionOutcome, ChainError> {
```

## crates/mempool

```text
crates/mempool/src/lib.rs:83:    pub fn new(max_txs: usize) -> Result<Self, MempoolError> {
crates/mempool/src/lib.rs:87:    pub fn with_policy(max_txs: usize, min_relay_fee_per_kb: u64) -> Result<Self, MempoolError> {
crates/mempool/src/lib.rs:96:    pub fn with_policy_and_replacement(
crates/mempool/src/lib.rs:126:    pub fn len(&self) -> usize {
crates/mempool/src/lib.rs:130:    pub fn is_empty(&self) -> bool {
crates/mempool/src/lib.rs:134:    pub fn revision(&self) -> u64 {
crates/mempool/src/lib.rs:138:    pub fn telemetry(&self) -> MempoolTelemetry {
crates/mempool/src/lib.rs:142:    pub fn get(&self, txid: &Hash256) -> Option<&Transaction> {
crates/mempool/src/lib.rs:146:    pub fn contains(&self, txid: &Hash256) -> bool {
crates/mempool/src/lib.rs:150:    pub fn fee(&self, txid: &Hash256) -> Option<u64> {
crates/mempool/src/lib.rs:154:    pub fn get_with_fee(&self, txid: &Hash256) -> Option<(&Transaction, u64)> {
crates/mempool/src/lib.rs:158:    pub fn remove_confirmed_txids(&mut self, txids: &[Hash256]) -> Vec<Hash256> {
crates/mempool/src/lib.rs:184:    pub fn insert(&mut self, tx: Transaction) -> Result<InsertOutcome, MempoolError> {
crates/mempool/src/lib.rs:188:    pub fn min_required_fee(&self, tx: &Transaction) -> Result<u64, MempoolError> {
crates/mempool/src/lib.rs:195:    pub fn txids_by_feerate_desc(&self) -> Vec<Hash256> {
crates/mempool/src/lib.rs:210:    pub fn insert_with_fee(
crates/mempool/src/lib.rs:470:    pub fn new(max_txs: usize, ttl_secs: u64) -> Result<Self, MempoolError> {
crates/mempool/src/lib.rs:491:    pub fn len(&self) -> usize {
crates/mempool/src/lib.rs:495:    pub fn is_empty(&self) -> bool {
crates/mempool/src/lib.rs:499:    pub fn contains(&self, txid: &Hash256) -> bool {
crates/mempool/src/lib.rs:503:    pub fn telemetry(&self) -> OrphanPoolTelemetry {
crates/mempool/src/lib.rs:507:    pub fn insert(
crates/mempool/src/lib.rs:565:    pub fn expire(&mut self, now_unix_sec: u64) -> usize {
crates/mempool/src/lib.rs:588:    pub fn resolve_outpoint(&mut self, outpoint: &OutPoint) -> Vec<ReadyOrphanTx> {
crates/mempool/src/lib.rs:752:    pub fn inventory_delta(&self) -> MempoolInventoryDelta {
```

## crates/wallet

```text
crates/wallet/src/vault.rs:48:pub fn new_encrypted_wallet_vault(
crates/wallet/src/vault.rs:95:pub fn decrypt_wallet_vault(
crates/wallet/src/vault.rs:138:pub fn save_wallet_vault(
crates/wallet/src/vault.rs:156:pub fn load_wallet_vault(path: &Path) -> Result<EncryptedWalletVault, WalletVaultError> {
crates/wallet/src/signer.rs:18:    pub fn pubkey_compressed(&self) -> [u8; 33] {
crates/wallet/src/signer.rs:22:    pub fn secret_key_bytes(&self) -> [u8; 32] {
crates/wallet/src/signer.rs:27:pub fn derivation_path(account: u32, index: u32) -> Result<DerivationPath, DeriveKeyError> {
crates/wallet/src/signer.rs:41:pub fn derivation_path_string(account: u32, index: u32) -> Result<String, DeriveKeyError> {
crates/wallet/src/signer.rs:45:pub fn derive_wallet_key(
crates/wallet/src/signer.rs:71:pub fn sign_digest(wallet_key: &WalletKey, digest32: [u8; 32]) -> Result<[u8; 64], SchnorrError> {
crates/wallet/src/signer.rs:81:pub fn verify_digest(
crates/wallet/src/rescan.rs:54:pub fn derive_watched_keys(
crates/wallet/src/rescan.rs:82:pub fn rescan_blocks<'a, I>(
crates/wallet/src/mnemonic.rs:10:    pub fn parse(phrase: &str) -> Result<Self, MnemonicError> {
crates/wallet/src/mnemonic.rs:23:    pub fn phrase(&self) -> &str {
crates/wallet/src/mnemonic.rs:27:    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
crates/wallet/src/mnemonic.rs:34:pub fn new_mnemonic(words: usize) -> Result<WalletMnemonic, MnemonicError> {
crates/wallet/src/qr.rs:4:pub fn qr_for_payment_uri(
crates/wallet/src/qr.rs:26:pub fn qr_for_text(text: &str) -> Result<String, QrError> {
crates/wallet/src/address.rs:12:pub fn key_hash20_from_compressed_pubkey(
crates/wallet/src/address.rs:19:pub fn to_address(hrp: &str, pubkey_compressed: [u8; 33]) -> Result<String, AddressError> {
crates/wallet/src/address.rs:33:pub fn parse_address(address: &str) -> Result<DecodedAddress, AddressError> {
```

## crates/p2p

```text
crates/p2p/src/discovery.rs:11:pub fn select_outbound_peers(
crates/p2p/src/sync.rs:9:pub fn build_block_locator(main_chain: &[Hash256]) -> Vec<Hash256> {
crates/p2p/src/sync.rs:37:pub fn select_headers_for_peer(
crates/p2p/src/sync.rs:72:pub fn select_block_hashes_for_peer(
crates/p2p/src/gossip.rs:65:    pub fn new(max_inv_items: usize) -> Result<Self, GossipError> {
crates/p2p/src/gossip.rs:69:    pub fn with_limits(max_inv_items: usize, ban_threshold: u32) -> Result<Self, GossipError> {
crates/p2p/src/gossip.rs:77:    pub fn with_limits_and_replacement(
crates/p2p/src/gossip.rs:124:    pub fn connect_peer(&mut self, peer_id: PeerId) {
crates/p2p/src/gossip.rs:131:    pub fn disconnect_peer(&mut self, peer_id: PeerId) {
crates/p2p/src/gossip.rs:135:    pub fn peer_count(&self) -> usize {
crates/p2p/src/gossip.rs:139:    pub fn peer_score(&self, peer_id: PeerId) -> Option<u32> {
crates/p2p/src/gossip.rs:143:    pub fn is_banned(&self, peer_id: PeerId) -> bool {
crates/p2p/src/gossip.rs:147:    pub fn has_inventory(&self, item: &InventoryItem) -> bool {
crates/p2p/src/gossip.rs:151:    pub fn telemetry(&self) -> GossipTelemetry {
crates/p2p/src/gossip.rs:155:    pub fn announce_tx(&mut self, tx: Transaction) -> Vec<OutboundMessage> {
crates/p2p/src/gossip.rs:162:    pub fn announce_block(&mut self, block: Block) -> Vec<OutboundMessage> {
crates/p2p/src/gossip.rs:169:    pub fn apply_mempool_inventory_delta(
crates/p2p/src/gossip.rs:177:    pub fn apply_mempool_inventory_delta_from_peer(
crates/p2p/src/gossip.rs:224:    pub fn on_message(
crates/p2p/src/transport.rs:40:pub fn send_message<W: Write>(
crates/p2p/src/transport.rs:61:pub async fn send_message_async<S: AsyncWrite + Unpin>(
crates/p2p/src/transport.rs:89:pub fn read_message<R: Read>(
crates/p2p/src/transport.rs:118:pub async fn read_message_async<S: AsyncRead + Unpin>(
crates/p2p/src/transport.rs:151:pub fn client_handshake<IO: Read + Write>(
crates/p2p/src/transport.rs:180:pub async fn client_handshake_async<S: AsyncRead + AsyncWrite + Unpin>(
crates/p2p/src/transport.rs:210:pub fn server_handshake<IO: Read + Write>(
crates/p2p/src/transport.rs:238:pub async fn server_handshake_async<S: AsyncRead + AsyncWrite + Unpin>(
crates/p2p/src/transport.rs:267:pub fn request_headers<IO: Read + Write>(
crates/p2p/src/transport.rs:284:pub async fn request_headers_async<S: AsyncRead + AsyncWrite + Unpin>(
crates/p2p/src/transport.rs:301:pub fn request_blocks<IO: Read + Write>(
crates/p2p/src/transport.rs:332:pub async fn request_blocks_async<S: AsyncRead + AsyncWrite + Unpin>(
crates/p2p/src/wire.rs:94:pub fn encode_message(message: &WireMessage) -> Result<Vec<u8>, WireError> {
crates/p2p/src/wire.rs:98:pub fn decode_message(data: &[u8], max_message_size: usize) -> Result<WireMessage, WireError> {
```

## crates/stratum

```text
crates/stratum/src/lib.rs:44:    pub fn as_str(self) -> &'static str {
crates/stratum/src/lib.rs:232:    pub fn new(start_job_id: u32) -> Self {
crates/stratum/src/lib.rs:409:    pub fn new(cfg: SessionConfig) -> Result<Self, StratumError> {
crates/stratum/src/lib.rs:475:    pub fn channel_id(&self) -> u32 {
crates/stratum/src/lib.rs:479:    pub fn is_active(&self) -> bool {
crates/stratum/src/lib.rs:483:    pub fn stats(&self) -> &SessionStats {
crates/stratum/src/lib.rs:487:    pub fn share_target(&self) -> Target {
crates/stratum/src/lib.rs:491:    pub fn negotiated_setup_version(&self) -> Option<u16> {
crates/stratum/src/lib.rs:495:    pub fn negotiated_setup_flags(&self) -> u32 {
crates/stratum/src/lib.rs:499:    pub fn close(&mut self) {
crates/stratum/src/lib.rs:503:    pub fn handle_message(&mut self, message: Sv2Message) -> Result<SessionResponse, StratumError> {
crates/stratum/src/lib.rs:507:    pub fn handle_message_at(
crates/stratum/src/lib.rs:576:    pub fn install_job(&mut self, job: MiningJob) -> Result<Sv2Message, StratumError> {
crates/stratum/src/lib.rs:612:    pub fn set_new_prev_hash(&self, job: &MiningJob) -> Result<Sv2Message, StratumError> {
crates/stratum/src/lib.rs:628:    pub fn set_target_message(&self) -> Sv2Message {
crates/stratum/src/lib.rs:635:    pub fn job(&self, job_id: u32) -> Option<&MiningJob> {
crates/stratum/src/lib.rs:988:    pub fn handshake_client<IO: Read + Write>(io: &mut IO) -> Result<Self, StratumError> {
crates/stratum/src/lib.rs:1008:    pub async fn handshake_client_async<IO: AsyncRead + AsyncWrite + Unpin>(
crates/stratum/src/lib.rs:1031:    pub fn handshake_server<IO: Read + Write>(io: &mut IO) -> Result<Self, StratumError> {
crates/stratum/src/lib.rs:1052:    pub async fn handshake_server_async<IO: AsyncRead + AsyncWrite + Unpin>(
crates/stratum/src/lib.rs:1076:    pub fn set_rekey_interval_messages(&mut self, interval: u64) -> Result<(), StratumError> {
crates/stratum/src/lib.rs:1086:    pub fn write_message<W: Write>(
crates/stratum/src/lib.rs:1113:    pub async fn write_message_async<W: AsyncWrite + Unpin>(
crates/stratum/src/lib.rs:1144:    pub fn read_message<R: Read>(
crates/stratum/src/lib.rs:1178:    pub async fn read_message_async<R: AsyncRead + Unpin>(
crates/stratum/src/lib.rs:1286:pub fn generate_noise_static_keypair() -> Result<NoiseStaticKeypair, StratumError> {
crates/stratum/src/lib.rs:1298:    pub fn handshake_client<IO: Read + Write>(
crates/stratum/src/lib.rs:1339:    pub async fn handshake_client_async<IO: AsyncRead + AsyncWrite + Unpin>(
crates/stratum/src/lib.rs:1380:    pub fn handshake_server<IO: Read + Write>(
crates/stratum/src/lib.rs:1421:    pub async fn handshake_server_async<IO: AsyncRead + AsyncWrite + Unpin>(
crates/stratum/src/lib.rs:1462:    pub fn set_rekey_interval_messages(&mut self, interval: u64) -> Result<(), StratumError> {
crates/stratum/src/lib.rs:1472:    pub fn write_message<W: Write>(
crates/stratum/src/lib.rs:1500:    pub async fn write_message_async<W: AsyncWrite + Unpin>(
crates/stratum/src/lib.rs:1532:    pub fn read_message<R: Read>(
crates/stratum/src/lib.rs:1574:    pub async fn read_message_async<R: AsyncRead + Unpin>(
crates/stratum/src/lib.rs:1863:pub fn write_frame<W: Write>(writer: &mut W, message: &Sv2Message) -> Result<(), StratumError> {
crates/stratum/src/lib.rs:1888:pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Sv2Message>, StratumError> {
crates/stratum/src/lib.rs:1937:pub async fn write_frame_async<W: AsyncWrite + Unpin>(
crates/stratum/src/lib.rs:1967:pub async fn read_frame_async<R: AsyncRead + Unpin>(
crates/stratum/src/lib.rs:2022:pub fn validate_share(
```

## crates/storage

```text
crates/storage/src/lib.rs:145:    pub fn from_utxo_set(
crates/storage/src/lib.rs:175:    pub fn to_utxo_set(&self) -> UtxoSet {
crates/storage/src/lib.rs:184:pub fn save_snapshot(path: &Path, snapshot: &ChainStateSnapshot) -> Result<(), StorageError> {
crates/storage/src/lib.rs:199:pub fn load_snapshot(path: &Path) -> Result<ChainStateSnapshot, StorageError> {
crates/storage/src/lib.rs:207:pub fn save_snapshot_db(path: &Path, snapshot: &ChainStateSnapshot) -> Result<(), StorageError> {
crates/storage/src/lib.rs:261:pub fn load_snapshot_db(path: &Path) -> Result<ChainStateSnapshot, StorageError> {
crates/storage/src/lib.rs:349:pub fn save_chain_archive_db(path: &Path, archive: &ChainArchive) -> Result<(), StorageError> {
crates/storage/src/lib.rs:425:pub fn load_chain_archive_db(path: &Path) -> Result<ChainArchive, StorageError> {
crates/storage/src/lib.rs:506:pub fn load_block_by_hash_db(path: &Path, hash: Hash256) -> Result<Option<Block>, StorageError> {
crates/storage/src/lib.rs:531:pub fn save_peer_book_db(path: &Path, peer_book: &PeerAddressBook) -> Result<(), StorageError> {
crates/storage/src/lib.rs:587:pub fn load_peer_book_db(path: &Path) -> Result<PeerAddressBook, StorageError> {
crates/storage/src/lib.rs:630:pub fn save_mempool_db(path: &Path, snapshot: &MempoolSnapshot) -> Result<(), StorageError> {
crates/storage/src/lib.rs:695:pub fn load_mempool_db(path: &Path) -> Result<MempoolSnapshot, StorageError> {
crates/storage/src/lib.rs:743:pub fn save_pool_ledger_db(path: &Path, snapshot: &PoolLedgerSnapshot) -> Result<(), StorageError> {
crates/storage/src/lib.rs:899:pub fn load_pool_ledger_db(path: &Path) -> Result<PoolLedgerSnapshot, StorageError> {
```

## crates/rpc

```text
crates/rpc/src/lib.rs:53:pub fn decode_tx_submit_request(
crates/rpc/src/lib.rs:65:pub fn parse_tx_submit_json(body: &[u8]) -> Result<(Transaction, u64), TxSubmitError> {
crates/rpc/src/lib.rs:83:pub fn to_pretty_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
crates/rpc/src/lib.rs:88:    pub fn from_block(height: u64, block: &Block) -> Self {
crates/rpc/src/lib.rs:101:    pub fn from_tx(block_height: u64, tx_index: usize, tx: &Transaction) -> Self {
crates/rpc/src/lib.rs:112:pub fn header_to_block_response(
```

## crates/miner

```text
crates/miner/src/lib.rs:62:    pub fn build_with_nonce(&self, nonce: u64) -> Block {
crates/miner/src/lib.rs:79:pub fn build_template_from_mempool(
crates/miner/src/lib.rs:364:    pub fn new() -> Self {
crates/miner/src/lib.rs:368:    pub fn build_or_reuse(
crates/miner/src/lib.rs:396:    pub fn invalidate(&mut self) {
crates/miner/src/lib.rs:427:pub fn mine_block_with_extra_nonce(
crates/miner/src/lib.rs:447:pub fn mine_block(template: &BlockTemplate, max_nonce: u64) -> Option<Block> {
```

## crates/node (top-level production functions in `main.rs`)

```text
1166:fn accepted_hrps_for_network(network: Network, configured_hrp: &str) -> Vec<String> {
1181:fn parse_secure_transport_mode(value: &str) -> Result<SecureTransportMode, NodeError> {
1248:fn load_chain_config(path: &Path) -> Result<ChainConfig, NodeError> {
1261:fn default_runtime_db_path(network: Network) -> PathBuf {
1265:fn default_mempool_db_path(runtime_db_path: &Path) -> PathBuf {
1269:fn default_pool_ledger_db_path(runtime_db_path: &Path) -> PathBuf {
1273:fn runtime_to_archive(runtime: &ChainRuntime) -> Result<ChainArchive, NodeError> {
1281:fn load_runtime_from_db_or_genesis(
1302:fn persist_runtime_db(runtime: &ChainRuntime, runtime_db_path: &Path) -> Result<(), NodeError> {
1308:fn mempool_snapshot_from_pool(cfg: &ChainConfig, mempool: &Mempool) -> MempoolSnapshot {
1329:fn persist_mempool_db(
1339:fn load_mempool_from_db_or_empty(
1360:fn load_mempool_from_db_or_empty_with_retry(
1371:fn load_mempool_with_retry_inner<F>(
1405:fn remove_confirmed_txids_from_mempool_db(
1422:fn is_runtime_db_lock_conflict(err: &NodeError) -> bool {
1427:fn is_mempool_db_lock_conflict(err: &NodeError) -> bool {
1432:fn is_pool_ledger_db_lock_conflict(err: &NodeError) -> bool {
1437:fn load_pool_ledger_from_db_or_new(
1476:fn persist_pool_ledger_db(
1485:fn persist_with_retry<F>(
1513:fn load_with_retry<T, F>(
1539:fn persist_runtime_db_with_retry(
1554:fn persist_mempool_db_with_retry(
1570:fn persist_pool_ledger_db_with_retry(
1585:fn next_stratum_job_timestamp(runtime: &ChainRuntime, _cfg: &ChainConfig) -> u64 {
1595:fn handle_runtime_persist_result(
1612:fn run_node(
1656:fn loopback_pool_from_bind(bind: &str) -> Result<String, NodeError> {
1663:fn build_run_mode_plan(args: &RunModeArgs) -> Result<RunModePlan, NodeError> {
1718:fn spawn_mode_service<F>(
1731:fn run_mode(args: RunModeArgs) -> Result<(), NodeError> {
1909:fn should_mine_query_blocks(mine_blocks: u32) -> bool {
1913:fn build_runtime_for_query(
1942:fn decode_fixed_hex<const N: usize>(field: &'static str, raw: &str) -> Result<[u8; N], NodeError> {
1959:fn decode_optional_hex32(
1969:fn run_status(args: StatusArgs) -> Result<(), NodeError> {
2009:fn run_get_block(args: GetBlockArgs) -> Result<(), NodeError> {
2050:fn run_get_tx(args: GetTxArgs) -> Result<(), NodeError> {
2095:fn run_config_scaffold(args: ConfigScaffoldArgs) -> Result<(), NodeError> {
2184:fn peer_book_paths(peers_dir: &Path, network_name: &str) -> (PathBuf, PathBuf) {
2191:fn peer_reputation_path(peers_dir: &Path, network_name: &str) -> PathBuf {
2230:fn load_peer_reputation_book(
2265:fn save_peer_reputation_book(path: &Path, book: &PeerReputationBook) -> Result<(), NodeError> {
2296:fn reputation_failure_weight(events: u64, last_unix_sec: u64, now_unix_sec: u64) -> u32 {
2311:fn load_peer_reputation_weights(
2333:fn update_peer_reputation_store(
2370:fn load_or_init_peer_book(
2414:fn current_unix_sec() -> Result<u64, NodeError> {
2423:fn resolve_dns_seed(seed: &str) -> Vec<SocketAddr> {
2442:fn peer_diversity_bucket(addr: SocketAddr) -> String {
2455:fn apply_bucket_cap(addrs: Vec<SocketAddr>, max_per_bucket: u32) -> Vec<SocketAddr> {
2473:fn run_add_peer(args: AddPeerArgs) -> Result<(), NodeError> {
2504:fn run_hash_visual(args: HashVisualArgs) -> Result<(), NodeError> {
2514:fn run_wallet(command: WalletCommand) -> Result<(), NodeError> {
2966:fn run_p2p_demo() -> Result<P2pDemoSummary, NodeError> {
3019:fn run_snapshot(command: SnapshotCommand) -> Result<(), NodeError> {
3119:fn select_utxos_for_amount(
3178:fn collect_spendable_utxos(
3206:fn build_signed_transfer_tx(
3287:fn build_coinbase_tx(tag: String, subsidy: u64, key_hash20: [u8; 20]) -> Transaction {
3317:fn mine_block_with_transactions(
3359:fn mine_blocks_on_runtime(
3386:fn run_mine_once(args: MineOnceArgs) -> Result<(), NodeError> {
3447:fn run_chain_demo(args: ChainDemoArgs) -> Result<(), NodeError> {
3483:fn run_sync_demo(args: SyncDemoArgs) -> Result<(), NodeError> {
3551:fn configure_stream_timeouts_with_ops<SetRead, SetWrite>(
3570:fn ensure_network_id_match(expected: &str, got: &str, context: &str) -> Result<(), NodeError> {
3579:fn ensure_expected_hash(expected: Hash256, got: Hash256, context: &str) -> Result<(), NodeError> {
3588:fn has_unknown_hashes(hashes: &[Hash256]) -> bool {
3592:fn run_net_demo(args: NetDemoArgs) -> Result<(), NodeError> {
3898:fn sync_runtime_with_peer(
3991:fn peer_book_contains_address(peer_book: &PeerAddressBook, address: &str) -> bool {
3995:fn sort_and_dedup_peer_book(peer_book: &mut PeerAddressBook) {
4000:fn find_peer_record_mut<'a>(
4010:fn sync_book_has_success(success_count: u32) -> bool {
4014:fn run_sync_peer(args: SyncPeerArgs) -> Result<(), NodeError> {
4053:fn run_sync_book(args: SyncBookArgs) -> Result<(), NodeError> {
5030:fn relay_fee_hint(tx: &Transaction) -> u64 {
5037:fn relay_mark_outbound_worker_start(state: &Arc<Mutex<RelayServerState>>) {
5043:fn relay_mark_outbound_supervisor_start(state: &Arc<Mutex<RelayServerState>>) {
5050:fn relay_forget_pending_orphan_block(state: &mut RelayServerState, hash: Hash256) {
5057:fn relay_store_pending_orphan_block(state: &mut RelayServerState, block: scam_core::Block) {
5071:fn relay_apply_main_chain_transition(
5142:fn relay_should_request_parent_sync(
5161:fn relay_recovery_messages_for_unknown_parent(
5181:fn relay_try_apply_pending_orphans(state: &mut RelayServerState, now_unix_sec: u64) {
5226:fn nonempty_parent_dir(path: &Path) -> Option<&Path> {
5235:fn relay_server_snapshot(
5262:fn append_relay_telemetry_snapshot(
5301:fn append_jsonl_record<T: Serialize>(
5346:fn append_role_service_telemetry(
5363:fn compact_short_txid(txid: Hash256) -> u64 {
5369:fn relay_compact_block_from_block(block: &scam_core::Block) -> CompactBlock {
5394:fn relay_lookup_mempool_tx_by_short_txid(
5410:fn relay_reconstruct_compact_transactions(
5457:fn relay_try_build_block_from_compact(
5473:fn relay_compact_announcement_enabled(state: &RelayServerState, peer_id: u64) -> bool {
5481:fn relay_inventory_messages_for_peer(
5516:fn relay_messages_for_peer(
5533:fn relay_timeout_streak_reached_limit(timeout_streak: u32) -> bool {
5537:fn relay_startup_send_failed(startup_sent: bool) -> bool {
5541:fn should_persist_peer_reputation(delta: RuntimePeerReputation) -> bool {
5545:fn relay_known_peer_addresses(state: &RelayServerState, max_items: usize) -> Vec<PeerAddress> {
5554:fn relay_merge_known_peer_addresses(state: &mut RelayServerState, incoming: &[PeerAddress]) {
5581:fn relay_submit_incoming_block(
5609:fn relay_collect_getdata_from_memory(
5639:fn process_relay_wire_message_with_archive(
5671:fn process_relay_wire_message(
5720:fn process_relay_wire_message_inner(
5932:fn push_inv_batches(out: &mut Vec<WireMessage>, items: Vec<InventoryItem>, max_inv_items: usize) {
5943:fn relay_proactive_inventory_messages(
5969:fn relay_mark_peer_replacement_rate_limited(
5979:fn relay_take_peer_runtime_reputation(
5995:fn load_relay_outbound_targets(
6009:fn load_relay_known_peer_addresses(
6031:fn load_relay_outbound_targets_selected(
6070:fn relay_target_matches_bind(bind_addr: &str, target: &str) -> bool {
6091:fn relay_disconnect_reason(err: &NodeError) -> &'static str {
6124:fn relay_session_error_is_fatal(err: &NodeError) -> bool {
6133:fn run_relay_outbound_worker(
6212:fn run_relay_outbound_supervisor(
6479:fn relay_runtime_or_mempool_changed(
6488:fn relay_max_active_sessions(max_clients: u32) -> usize {
6498:fn run_relay_peer_session<IO: Read + Write>(
6997:fn run_relay_serve(args: RelayServeArgs) -> Result<(), NodeError> {
7313:fn run_reindex_runtime(args: ReindexRuntimeArgs) -> Result<(), NodeError> {
7372:fn derive_soak_flow_keys() -> Result<(WalletKey, [u8; 20]), NodeError> {
7410:fn append_soak_telemetry_snapshot(
7449:fn detect_missing_outpoints(
7467:fn admit_peer_tx_into_relay(
7531:fn execute_soak_rounds<F>(
7570:fn run_soak(args: SoakArgs) -> Result<(), NodeError> {
7853:fn run_reorg_demo(args: ReorgDemoArgs) -> Result<(), NodeError> {
8008:fn mining_template_to_rpc(template: &MiningTemplate) -> RpcMiningTemplate {
8018:fn mining_template_from_rpc(template: RpcMiningTemplate) -> Result<MiningTemplate, NodeError> {
8031:fn role_service_response_is_empty(bytes_read: usize) -> bool {
8035:fn call_json_role_service<Req, Resp>(addr: &str, request: &Req) -> Result<Resp, NodeError>
8074:fn request_template_from_provider(
8091:fn translate_remote_job_with_service(
8197:fn sv2_io_error_is_timeout_like(err: &std::io::Error) -> bool {
8206:fn sv2_io_error_is_closed_like(err: &std::io::Error) -> bool {
8217:fn read_sv2_message(
8295:fn lock_runtime<'a>(
8408:fn load_runtime_tip_hash(ctx: &StratumServerContext) -> Result<Hash256, NodeError> {
8801:fn read_role_request<T: DeserializeOwned, R: Read>(stream: &mut R) -> Result<T, NodeError> {
8816:fn write_role_response<T: Serialize, W: Write>(
8833:fn max_requests_reached(max_requests: u32, served: u32) -> bool {
8837:fn relay_inbound_accept_rate_limited(
8861:fn rpc_accept_error_should_retry(shutdown_enabled: bool, err_kind: std::io::ErrorKind) -> bool {
8869:fn map_rpc_accept_result(
8880:fn map_sv2_read_result(
8896:fn protocol_violation_response(
8938:fn has_inventory_delta_changes(announced_len: usize, removed_len: usize) -> bool {
8942:fn relay_telemetry_thread_running(stop_flag: &AtomicBool) -> bool {
8946:fn should_stop_after_seen_messages(read_limit: u32, seen: u32) -> bool {
8957:fn relay_io_error_is_timeout_like(err: &std::io::Error) -> bool {
8966:fn relay_io_error_is_closed_like(err: &std::io::Error) -> bool {
8977:fn ensure_relay_peer_network(
8991:fn map_relay_read_result(
9007:fn relay_send_message_or_closed<IO: Write>(
9020:fn relay_send_messages_until_closed<IO: Write>(
9085:fn should_require_noise_static_key(
9093:fn should_apply_set_new_prev_hash(active_channel: Option<u32>, incoming_channel: u32) -> bool {
9097:fn should_apply_set_target(active_channel: Option<u32>, incoming_channel: u32) -> bool {
9101:fn tip_changed(current: Hash256, previous: Hash256) -> bool {
9105:fn should_process_share_as_block(is_block: bool) -> bool {
9109:fn should_reissue_job_for_channel(channel_id: u32, active_channel_id: u32) -> bool {
9113:fn expected_hashes_for_target(target: Target) -> f64 {
9120:fn estimate_network_hashrate_hps_from_target(target: Target, target_block_time_sec: u64) -> f64 {
9125:fn estimate_network_hashrate_hps(runtime: &ChainRuntime) -> f64 {
9132:fn record_stratum_share_accepted(
9146:fn record_stratum_share_rejected(ctx: &StratumServerContext, worker: &str) {
9153:fn persist_pool_ledger_with_warning(ctx: &StratumServerContext) {
9167:fn record_pool_share_accepted(
9206:fn record_pool_share_rejected(ctx: &StratumServerContext, worker: &str) {
9221:fn record_pool_round_closed(
9251:fn reconcile_pool_ledger_with_runtime(ctx: &StratumServerContext, fallback_unix_sec: u64) {
9275:fn runtime_spendable_balance_for_key_hash(runtime: &ChainRuntime, key_hash20: [u8; 20]) -> u128 {
9290:fn runtime_contains_txid(runtime: &ChainRuntime, needle_txid: Hash256) -> bool {
9298:fn pool_payout_amount_from_atomic(amount_atomic: u128) -> Option<u64> {
9305:fn maybe_process_pool_payouts(ctx: &StratumServerContext) -> Result<(), NodeError> {
9413:fn run_pool_payout_tick_with_warning(ctx: &StratumServerContext) {
9419:fn stratum_user_payout_key_hash20(user: &str) -> Option<[u8; 20]> {
9423:fn stratum_coinbase_label(channel_id: u32, user_hint: &str) -> String {
9437:fn stratum_coinbase_tag(base_label: &str, prev_hash: Hash256) -> String {
9442:fn should_send_open_standard_channel(open_sent: bool) -> bool {
9446:fn should_emit_miner_keepalive(elapsed_sec: u64) -> bool {
9450:fn wallet_send_preview_has_invalid_amount(amount: u64) -> bool {
9462:fn resolve_prevout_for_admission(
9485:fn validate_tx_for_local_admission(
9620:fn coinbase_prevout_is_immature(tip_height: u64, created_height: u64, maturity: u64) -> bool {
9624:fn mempool_outcome_label(outcome: &InsertOutcome) -> &'static str {
9639:fn submit_tx_via_mempool_db(
9666:fn share_target_in_bounds(
9674:fn nonzero_limit_reached(limit: u64, observed: u64) -> bool {
9678:fn protocol_violations_reached_limit(violations: u32, max_protocol_violations: u32) -> bool {
9682:fn stratum_telemetry_thread_running(stop_requested: bool) -> bool {
9686:fn reconnect_attempts_exhausted(max_reconnect_attempts: u32, attempts: u32) -> bool {
9690:fn should_break_reconnect_loop(reconnect_requested: bool) -> bool {
9694:fn should_retry_connect_attempt(attempt: u32, attempts_total: u32) -> bool {
9698:fn pool_status_sources_missing(telemetry_present: bool, ledger_present: bool) -> bool {
9702:fn pool_worker_sources_missing(
9709:fn pool_worker_name_matches(worker: &str, normalized: &str) -> bool {
9713:fn should_emit_periodic_round(round: u32, every_rounds: u32) -> bool {
9717:fn blocks_per_second(blocks_mined: u64, elapsed_sec: u64) -> f64 {
9725:fn reorg_min_difficulty_window(window: u32) -> u32 {
9729:fn is_tx_flow_enabled(txs_per_round: u32) -> bool {
9733:fn soak_recipient_key_hash(
9745:fn soak_tx_fee_for_index(base_fee: u64, tx_index: u32) -> u64 {
9749:fn soak_peer_id_for_round(round: u32, tx_index: u32, simulated_peers: u32) -> u64 {
9753:fn should_persist_round(round: u32, persist_every_rounds: u32) -> bool {
9757:fn run_sv2_template_provider(args: Sv2TemplateProviderArgs) -> Result<(), NodeError> {
9839:fn run_sv2_job_declarator(args: Sv2JobDeclaratorArgs) -> Result<(), NodeError> {
9903:fn run_sv2_translator(args: Sv2TranslatorArgs) -> Result<(), NodeError> {
9972:fn validate_pool_payout_config(payout_cfg: &PoolPayoutConfig) -> Result<(), NodeError> {
9986:fn run_stratum_serve(args: StratumServeArgs) -> Result<(), NodeError> {
10421:fn try_find_share_for_job(
10458:fn run_stratum_mine(args: StratumMineArgs) -> Result<(), NodeError> {
10864:fn run_stratum_keygen(args: StratumKeygenArgs) -> Result<(), NodeError> {
10922:fn run_stratum_key_rotate(args: StratumKeyRotateArgs) -> Result<(), NodeError> {
11020:fn sv2_message_kind(message: &Sv2Message) -> &'static str {
11042:fn default_sv2_conformance_corpus(user: &str) -> Vec<Sv2Message> {
11074:fn update_sv2_conformance_state(
11122:fn materialize_sv2_conformance_message(
11156:fn missing_observed_sequence(required_sequence: &[String], observed: &[String]) -> Vec<String> {
11177:fn evaluate_sv2_conformance_requirements(
11252:fn sv2_conformance_pass(
11273:fn ensure_sv2_conformance_pass(pass: bool) -> Result<(), NodeError> {
11283:fn load_sv2_corpus(path: &Path, user: &str) -> Result<Vec<Sv2Message>, NodeError> {
11315:fn apply_sv2_setup_overrides(
11340:fn normalize_observed_kind_filters(values: &[String]) -> Vec<String> {
11349:fn read_next_sv2_message_with<F>(
11366:fn connect_tcp_with_timeout(endpoint: &str, timeout: Duration) -> Result<TcpStream, NodeError> {
11394:fn connect_tcp_with_retry(
11418:fn run_sv2_conformance(args: Sv2ConformanceArgs) -> Result<(), NodeError> {
11682:fn json_error_body(message: &str) -> String {
11997:fn tx_lookup_response(block_height: u64, tx_index: usize, tx: &Transaction) -> TxLookupRpcResponse {
12030:fn block_lookup_response(height: u64, block: &scam_core::Block) -> BlockLookupRpcResponse {
12054:fn wallet_address_response(
12075:fn wallet_balance_response(
12125:fn wallet_tx_history_for_key_hash(
12196:fn mempool_tx_count_from_db(mempool_db_path: &Path) -> Result<(bool, usize), NodeError> {
12204:fn build_rpc_event_snapshot(
12269:fn load_pool_ledger_snapshot_with_retry(
12280:fn pool_ledger_status_from_snapshot(
12328:fn pool_worker_status_from_snapshot(
12349:fn write_http_response<W: Write>(
12371:fn write_http_json_response<W: Write>(
12384:fn write_http_sse_headers<W: Write>(stream: &mut W) -> Result<(), NodeError> {
12401:fn write_http_sse_event<W: Write>(
12416:fn write_http_sse_comment<W: Write>(stream: &mut W, comment: &str) -> Result<(), NodeError> {
12427:fn find_http_header_terminator(buffer: &[u8]) -> Option<usize> {
12431:fn parse_content_length(headers: &str) -> Result<usize, NodeError> {
12452:fn http_io_error_is_timeout_like(err: &std::io::Error) -> bool {
12461:fn http_io_error_is_closed_like(err: &std::io::Error) -> bool {
12472:fn read_http_request<R: Read>(stream: &mut R) -> Result<Option<HttpRequest>, NodeError> {
12568:fn parse_json_body<T: DeserializeOwned>(request: &HttpRequest) -> Result<T, NodeError> {
12577:fn load_latest_jsonl_record<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, NodeError> {
12602:fn sanitize_ui_path(path: &str) -> Option<PathBuf> {
12617:fn guess_content_type(path: &Path) -> &'static str {
12631:fn ui_dir_is_servable(ui_dir: &Path) -> bool {
12635:fn file_mtime(path: &Path) -> Option<SystemTime> {
12639:fn runtime_db_mtime(path: &Path) -> Option<SystemTime> {
12643:fn mempool_db_mtime(path: &Path) -> Option<SystemTime> {
12647:fn refresh_runtime_from_db_if_changed(
12667:fn refresh_mempool_from_db_if_changed(
12687:fn try_serve_ui_asset<W: Write>(
12725:fn rpc_exact_route_matches(
12734:fn is_get_method(method: &str) -> bool {
12738:fn is_pool_worker_route(method: &str, path: &str) -> bool {
12742:fn rpc_block_height_path<'a>(method: &str, path: &'a str) -> Option<&'a str> {
12750:fn rpc_tx_path_parts<'a>(method: &str, path: &'a str) -> Option<(&'a str, &'a str, bool)> {
12762:fn rpc_txid_path<'a>(method: &str, path: &'a str) -> Option<&'a str> {
12770:fn rpc_txid_path_is_invalid(txid_raw: &str) -> bool {
12774:fn rpc_tx_path_is_invalid(height_raw: &str, index_raw: &str, has_extra: bool) -> bool {
12778:fn parse_tx_height_and_index(height_raw: &str, index_raw: &str) -> Option<(u64, usize)> {
12785:fn find_tx_by_txid(
12796:fn address_hrp_is_accepted(accepted_hrps: &[String], hrp: &str) -> bool {
12800:fn should_reject_send_preview_hrp(accepted_hrps: &[String], hrp: &str) -> bool {
12804:fn should_attempt_ui_asset_serve(method: &str) -> bool {
12808:fn should_serve_ui_asset_for_route(method: &str, ui_served: bool) -> bool {
12812:fn should_reply_bad_http_request(err: &NodeError) -> bool {
12822:fn rpc_sse_write_error_is_closed_like(err: &NodeError) -> bool {
12835:fn rpc_events_worker_should_continue(stop_flag: &AtomicBool) -> bool {
12839:fn reap_finished_rpc_event_workers(handles: &mut Vec<thread::JoinHandle<()>>) {
12853:fn run_rpc_events_worker(
12912:fn run_rpc_serve_inner(
13951:fn run_rpc_serve(args: RpcServeArgs) -> Result<(), NodeError> {
13956:fn run_rpc_serve_with_shutdown(
13963:fn run_command(cli: Cli) -> Result<(), NodeError> {
14004:fn run_from_args<I, T>(args: I) -> Result<(), NodeError>
14013:fn main() {
```
