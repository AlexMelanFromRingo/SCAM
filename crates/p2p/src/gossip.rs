use std::collections::{HashMap, HashSet, VecDeque};

use scam_core::{Block, Hash256, Transaction};
use thiserror::Error;

use crate::wire::{InventoryItem, WireMessage};

pub type PeerId = u64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundMessage {
    pub peer_id: PeerId,
    pub message: WireMessage,
}

#[derive(Default)]
struct PeerState {
    known_inventory: HashSet<InventoryItem>,
    score: u32,
    replacement_events: VecDeque<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplacementRateLimit {
    pub window_sec: u64,
    pub max_replacements: usize,
    pub penalty: u32,
}

impl Default for ReplacementRateLimit {
    fn default() -> Self {
        Self {
            window_sec: 60,
            max_replacements: 20,
            penalty: 25,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GossipTelemetry {
    pub announced_txs_total: u64,
    pub removed_txs_total: u64,
    pub inbound_replacement_events_total: u64,
    pub replacement_rate_limited_total: u64,
}

pub struct GossipEngine {
    max_inv_items: usize,
    ban_threshold: u32,
    peers: HashMap<PeerId, PeerState>,
    banned_peers: HashSet<PeerId>,
    local_inventory: HashSet<InventoryItem>,
    tx_store: HashMap<Hash256, Transaction>,
    block_store: HashMap<Hash256, Block>,
    tx_store_order: VecDeque<Hash256>,
    block_store_order: VecDeque<Hash256>,
    max_tx_store_items: usize,
    max_block_store_items: usize,
    replacement_rate_limit: ReplacementRateLimit,
    telemetry: GossipTelemetry,
}

impl GossipEngine {
    pub fn new(max_inv_items: usize) -> Result<Self, GossipError> {
        Self::with_limits_and_replacement(max_inv_items, 100, ReplacementRateLimit::default())
    }

    pub fn with_limits(max_inv_items: usize, ban_threshold: u32) -> Result<Self, GossipError> {
        Self::with_limits_and_replacement(
            max_inv_items,
            ban_threshold,
            ReplacementRateLimit::default(),
        )
    }

    pub fn with_limits_and_replacement(
        max_inv_items: usize,
        ban_threshold: u32,
        replacement_rate_limit: ReplacementRateLimit,
    ) -> Result<Self, GossipError> {
        if max_inv_items == 0 {
            return Err(GossipError::InvalidConfig(
                "max_inv_items must be greater than zero".to_owned(),
            ));
        }
        if ban_threshold == 0 {
            return Err(GossipError::InvalidConfig(
                "ban_threshold must be greater than zero".to_owned(),
            ));
        }
        if replacement_rate_limit.window_sec == 0 {
            return Err(GossipError::InvalidConfig(
                "replacement window must be greater than zero".to_owned(),
            ));
        }
        if replacement_rate_limit.max_replacements == 0 {
            return Err(GossipError::InvalidConfig(
                "replacement max_replacements must be greater than zero".to_owned(),
            ));
        }
        if replacement_rate_limit.penalty == 0 {
            return Err(GossipError::InvalidConfig(
                "replacement penalty must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            max_inv_items,
            ban_threshold,
            peers: HashMap::new(),
            banned_peers: HashSet::new(),
            local_inventory: HashSet::new(),
            tx_store: HashMap::new(),
            block_store: HashMap::new(),
            tx_store_order: VecDeque::new(),
            block_store_order: VecDeque::new(),
            max_tx_store_items: max_inv_items.saturating_mul(8).max(max_inv_items),
            max_block_store_items: max_inv_items.saturating_mul(8).max(max_inv_items),
            replacement_rate_limit,
            telemetry: GossipTelemetry::default(),
        })
    }

    pub fn connect_peer(&mut self, peer_id: PeerId) {
        if self.banned_peers.contains(&peer_id) {
            return;
        }
        self.peers.entry(peer_id).or_default();
    }

    pub fn disconnect_peer(&mut self, peer_id: PeerId) {
        self.peers.remove(&peer_id);
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn peer_score(&self, peer_id: PeerId) -> Option<u32> {
        self.peers.get(&peer_id).map(|state| state.score)
    }

    pub fn is_banned(&self, peer_id: PeerId) -> bool {
        self.banned_peers.contains(&peer_id)
    }

    pub fn has_inventory(&self, item: &InventoryItem) -> bool {
        self.local_inventory.contains(item)
    }

    pub fn telemetry(&self) -> GossipTelemetry {
        self.telemetry
    }

    pub fn announce_tx(&mut self, tx: Transaction) -> Vec<OutboundMessage> {
        let txid = self.store_tx(tx);
        let item = InventoryItem::Tx(txid);
        self.insert_local_inventory(item.clone());
        self.fanout_inv(None, item)
    }

    pub fn announce_block(&mut self, block: Block) -> Vec<OutboundMessage> {
        let block_hash = self.store_block(block);
        let item = InventoryItem::Block(block_hash);
        self.insert_local_inventory(item.clone());
        self.fanout_inv(None, item)
    }

    pub fn apply_mempool_inventory_delta(
        &mut self,
        announced_txs: Vec<Transaction>,
        removed_txids: &[Hash256],
    ) -> Vec<OutboundMessage> {
        self.apply_mempool_inventory_delta_inner(announced_txs, removed_txids)
    }

    pub fn apply_mempool_inventory_delta_from_peer(
        &mut self,
        from_peer: PeerId,
        announced_txs: Vec<Transaction>,
        removed_txids: &[Hash256],
        now_unix_sec: u64,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        if self.banned_peers.contains(&from_peer) {
            return Err(GossipError::BannedPeer { peer_id: from_peer });
        }
        if !self.peers.contains_key(&from_peer) {
            return Err(GossipError::UnknownPeer { peer_id: from_peer });
        }

        if !removed_txids.is_empty() {
            self.enforce_replacement_rate(from_peer, now_unix_sec)?;
            self.telemetry.inbound_replacement_events_total = self
                .telemetry
                .inbound_replacement_events_total
                .saturating_add(1);
        }

        Ok(self.apply_mempool_inventory_delta_inner(announced_txs, removed_txids))
    }

    fn apply_mempool_inventory_delta_inner(
        &mut self,
        announced_txs: Vec<Transaction>,
        removed_txids: &[Hash256],
    ) -> Vec<OutboundMessage> {
        for txid in removed_txids {
            self.forget_tx(*txid);
        }
        self.telemetry.removed_txs_total = self
            .telemetry
            .removed_txs_total
            .saturating_add(removed_txids.len() as u64);

        let mut outbound = Vec::<OutboundMessage>::new();
        for tx in announced_txs {
            outbound.extend(self.announce_tx(tx));
            self.telemetry.announced_txs_total =
                self.telemetry.announced_txs_total.saturating_add(1);
        }
        outbound
    }

    pub fn on_message(
        &mut self,
        from_peer: PeerId,
        message: WireMessage,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        if self.banned_peers.contains(&from_peer) {
            return Err(GossipError::BannedPeer { peer_id: from_peer });
        }
        if !self.peers.contains_key(&from_peer) {
            return Err(GossipError::UnknownPeer { peer_id: from_peer });
        }

        match message {
            WireMessage::Version { .. } => Ok(vec![OutboundMessage {
                peer_id: from_peer,
                message: WireMessage::Verack,
            }]),
            WireMessage::Ping { nonce } => Ok(vec![OutboundMessage {
                peer_id: from_peer,
                message: WireMessage::Pong { nonce },
            }]),
            WireMessage::Inv { items } => self.handle_inv(from_peer, items),
            WireMessage::GetData { items } => self.handle_getdata(from_peer, items),
            WireMessage::Tx { tx } => self.handle_tx(from_peer, tx),
            WireMessage::Block { block } => self.handle_block(from_peer, block),
            WireMessage::Verack
            | WireMessage::Pong { .. }
            | WireMessage::NotFound { .. }
            | WireMessage::GetHeaders { .. }
            | WireMessage::GetBlocks { .. }
            | WireMessage::Headers { .. }
            | WireMessage::GetAddr
            | WireMessage::Addr { .. }
            | WireMessage::SendCmpct { .. }
            | WireMessage::CmpctBlock { .. }
            | WireMessage::GetBlockTxn { .. }
            | WireMessage::BlockTxn { .. } => Ok(Vec::new()),
        }
    }

    fn handle_inv(
        &mut self,
        from_peer: PeerId,
        items: Vec<InventoryItem>,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        if items.len() > self.max_inv_items {
            self.penalize_peer(from_peer, 25);
            return Err(GossipError::TooManyInventoryItems {
                limit: self.max_inv_items,
                got: items.len(),
            });
        }

        let mut unknown = Vec::new();
        if let Some(peer_state) = self.peers.get_mut(&from_peer) {
            for item in items {
                peer_state.known_inventory.insert(item.clone());
                if !self.local_inventory.contains(&item) {
                    unknown.push(item);
                }
            }
        }

        if unknown.is_empty() {
            return Ok(Vec::new());
        }

        Ok(vec![OutboundMessage {
            peer_id: from_peer,
            message: WireMessage::GetData { items: unknown },
        }])
    }

    fn handle_getdata(
        &mut self,
        from_peer: PeerId,
        items: Vec<InventoryItem>,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        if items.len() > self.max_inv_items {
            self.penalize_peer(from_peer, 25);
            return Err(GossipError::TooManyInventoryItems {
                limit: self.max_inv_items,
                got: items.len(),
            });
        }

        let mut out = Vec::new();
        let mut not_found = Vec::new();
        for item in items {
            match item.clone() {
                InventoryItem::Tx(txid) => {
                    if let Some(tx) = self.tx_store.get(&txid) {
                        out.push(OutboundMessage {
                            peer_id: from_peer,
                            message: WireMessage::Tx { tx: tx.clone() },
                        });
                    } else {
                        not_found.push(item);
                    }
                }
                InventoryItem::Block(block_hash) => {
                    if let Some(block) = self.block_store.get(&block_hash) {
                        out.push(OutboundMessage {
                            peer_id: from_peer,
                            message: WireMessage::Block {
                                block: block.clone(),
                            },
                        });
                    } else {
                        not_found.push(item);
                    }
                }
            }
        }

        if !not_found.is_empty() {
            out.push(OutboundMessage {
                peer_id: from_peer,
                message: WireMessage::NotFound { items: not_found },
            });
        }
        Ok(out)
    }

    fn handle_tx(
        &mut self,
        from_peer: PeerId,
        tx: Transaction,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        let txid = self.store_tx(tx);
        let item = InventoryItem::Tx(txid);
        let was_new = self.insert_local_inventory(item.clone());

        if let Some(peer_state) = self.peers.get_mut(&from_peer) {
            peer_state.known_inventory.insert(item.clone());
        }
        if !was_new {
            return Ok(Vec::new());
        }
        Ok(self.fanout_inv(Some(from_peer), item))
    }

    fn handle_block(
        &mut self,
        from_peer: PeerId,
        block: Block,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        let block_hash = self.store_block(block);
        let item = InventoryItem::Block(block_hash);
        let was_new = self.insert_local_inventory(item.clone());

        if let Some(peer_state) = self.peers.get_mut(&from_peer) {
            peer_state.known_inventory.insert(item.clone());
        }
        if !was_new {
            return Ok(Vec::new());
        }
        Ok(self.fanout_inv(Some(from_peer), item))
    }

    fn insert_local_inventory(&mut self, item: InventoryItem) -> bool {
        self.local_inventory.insert(item)
    }

    fn fanout_inv(
        &mut self,
        except_peer: Option<PeerId>,
        item: InventoryItem,
    ) -> Vec<OutboundMessage> {
        let mut out = Vec::new();
        for (peer_id, state) in &mut self.peers {
            if except_peer == Some(*peer_id) {
                continue;
            }
            if state.known_inventory.insert(item.clone()) {
                out.push(OutboundMessage {
                    peer_id: *peer_id,
                    message: WireMessage::Inv {
                        items: vec![item.clone()],
                    },
                });
            }
        }
        out
    }

    fn forget_tx(&mut self, txid: Hash256) {
        self.tx_store.remove(&txid);
        self.tx_store_order.retain(|hash| *hash != txid);
        let item = InventoryItem::Tx(txid);
        self.forget_inventory_item(&item);
    }

    fn forget_block(&mut self, block_hash: Hash256) {
        self.block_store.remove(&block_hash);
        self.block_store_order.retain(|hash| *hash != block_hash);
        let item = InventoryItem::Block(block_hash);
        self.forget_inventory_item(&item);
    }

    fn forget_inventory_item(&mut self, item: &InventoryItem) {
        self.local_inventory.remove(item);
        for peer in self.peers.values_mut() {
            peer.known_inventory.remove(item);
        }
    }

    fn store_tx(&mut self, tx: Transaction) -> Hash256 {
        let txid = tx.txid();
        let is_new = self.tx_store.insert(txid, tx).is_none();
        if is_new {
            self.tx_store_order.push_back(txid);
        }
        self.prune_tx_store();
        txid
    }

    fn store_block(&mut self, block: Block) -> Hash256 {
        let block_hash = block.header.block_hash();
        let is_new = self.block_store.insert(block_hash, block).is_none();
        if is_new {
            self.block_store_order.push_back(block_hash);
        }
        self.prune_block_store();
        block_hash
    }

    fn prune_tx_store(&mut self) {
        while self.tx_store.len() > self.max_tx_store_items {
            let Some(oldest) = self.tx_store_order.pop_front() else {
                break;
            };
            if self.tx_store.contains_key(&oldest) {
                self.forget_tx(oldest);
            }
        }
    }

    fn prune_block_store(&mut self) {
        while self.block_store.len() > self.max_block_store_items {
            let Some(oldest) = self.block_store_order.pop_front() else {
                break;
            };
            if self.block_store.contains_key(&oldest) {
                self.forget_block(oldest);
            }
        }
    }

    fn penalize_peer(&mut self, peer_id: PeerId, penalty: u32) {
        if let Some(state) = self.peers.get_mut(&peer_id) {
            state.score = state.score.saturating_add(penalty);
            if state.score >= self.ban_threshold {
                self.peers.remove(&peer_id);
                self.banned_peers.insert(peer_id);
            }
        }
    }

    fn enforce_replacement_rate(
        &mut self,
        peer_id: PeerId,
        now_unix_sec: u64,
    ) -> Result<(), GossipError> {
        let window_sec = self.replacement_rate_limit.window_sec;
        let max_replacements = self.replacement_rate_limit.max_replacements;
        let penalty = self.replacement_rate_limit.penalty;

        let Some(state) = self.peers.get_mut(&peer_id) else {
            return Err(GossipError::UnknownPeer { peer_id });
        };
        while let Some(ts) = state.replacement_events.front().copied() {
            if now_unix_sec.saturating_sub(ts) > window_sec {
                state.replacement_events.pop_front();
            } else {
                break;
            }
        }

        if state.replacement_events.len() >= max_replacements {
            self.telemetry.replacement_rate_limited_total = self
                .telemetry
                .replacement_rate_limited_total
                .saturating_add(1);
            self.penalize_peer(peer_id, penalty);
            return Err(GossipError::ReplacementRateLimited {
                peer_id,
                max_replacements,
                window_sec,
            });
        }

        if let Some(state) = self.peers.get_mut(&peer_id) {
            state.replacement_events.push_back(now_unix_sec);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum GossipError {
    #[error("unknown peer: {peer_id}")]
    UnknownPeer { peer_id: PeerId },
    #[error("peer is banned: {peer_id}")]
    BannedPeer { peer_id: PeerId },
    #[error(
        "replacement rate limit exceeded for peer={peer_id}: max={max_replacements} within {window_sec}s"
    )]
    ReplacementRateLimited {
        peer_id: PeerId,
        max_replacements: usize,
        window_sec: u64,
    },
    #[error("too many inventory items: limit={limit}, got={got}")]
    TooManyInventoryItems { limit: usize, got: usize },
    #[error("{0}")]
    InvalidConfig(String),
}

#[cfg(test)]
mod tests {
    use super::{GossipEngine, OutboundMessage, ReplacementRateLimit};
    use crate::wire::{InventoryItem, WireMessage};
    use scam_core::{Hash256, OutPoint, Transaction, TxIn, TxOut};

    fn sample_tx(seed: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: scam_core::hash::hash256(&[seed]),
                    vout: 0,
                },
                signature: vec![seed; 64],
                pubkey_compressed: vec![2u8; 33],
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [seed; 20],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn receiving_new_tx_fanouts_inventory() {
        let mut engine = GossipEngine::new(256).expect("engine");
        engine.connect_peer(1);
        engine.connect_peer(2);
        engine.connect_peer(3);

        let tx = sample_tx(7);
        let txid = tx.txid();
        let out = engine
            .on_message(1, WireMessage::Tx { tx })
            .expect("handle should work");

        assert_eq!(out.len(), 2);
        for msg in out {
            match msg {
                OutboundMessage {
                    peer_id: 2 | 3,
                    message: WireMessage::Inv { items },
                } => assert_eq!(items, vec![InventoryItem::Tx(txid)]),
                _ => panic!("unexpected message"),
            }
        }
    }

    #[test]
    fn inv_for_unknown_object_requests_getdata() {
        let mut engine = GossipEngine::new(256).expect("engine");
        engine.connect_peer(9);
        let unknown = InventoryItem::Block(scam_core::hash::hash256(b"unknown"));

        let out = engine
            .on_message(
                9,
                WireMessage::Inv {
                    items: vec![unknown.clone()],
                },
            )
            .expect("inv should be handled");

        assert_eq!(
            out,
            vec![OutboundMessage {
                peer_id: 9,
                message: WireMessage::GetData {
                    items: vec![unknown],
                },
            }]
        );
    }

    #[test]
    fn duplicate_object_is_not_rebroadcast() {
        let mut engine = GossipEngine::new(256).expect("engine");
        engine.connect_peer(1);
        engine.connect_peer(2);

        let tx = sample_tx(2);
        let first = engine
            .on_message(1, WireMessage::Tx { tx: tx.clone() })
            .expect("first");
        assert_eq!(first.len(), 1);

        let second = engine
            .on_message(1, WireMessage::Tx { tx })
            .expect("second");
        assert!(second.is_empty());
    }

    #[test]
    fn peer_connect_disconnect_and_ban_tracking_are_consistent() {
        let mut engine = GossipEngine::new(256).expect("engine");
        engine.connect_peer(1);
        engine.connect_peer(2);
        assert_eq!(engine.peer_count(), 2);
        assert!(!engine.is_banned(1));

        engine.disconnect_peer(2);
        assert_eq!(engine.peer_count(), 1);
        assert_eq!(engine.peer_score(2), None);
    }

    #[test]
    fn announce_block_fanouts_inventory_to_connected_peers() {
        let mut engine = GossipEngine::new(256).expect("engine");
        engine.connect_peer(10);
        engine.connect_peer(11);
        let block = scam_core::Block {
            header: scam_core::BlockHeader {
                version: 1,
                prev_block: scam_core::Hash256::ZERO,
                merkle_root: scam_core::hash::hash256(b"mrkl"),
                timestamp: 1_770_763_200,
                target: scam_core::Target::MAX,
                nonce: 1,
            },
            transactions: Vec::new(),
        };
        let block_hash = block.header.block_hash();
        let out = engine.announce_block(block);
        assert_eq!(out.len(), 2);
        assert!(engine.has_inventory(&InventoryItem::Block(block_hash)));
    }

    #[test]
    fn block_store_prunes_old_entries_and_inventory_when_capacity_is_exceeded() {
        let mut engine = GossipEngine::new(2).expect("engine");
        engine.connect_peer(1);

        let limit = engine.max_block_store_items;
        let mut hashes = Vec::<Hash256>::new();
        for idx in 0..(limit + 4) {
            let block = scam_core::Block {
                header: scam_core::BlockHeader {
                    version: 1,
                    prev_block: scam_core::Hash256::ZERO,
                    merkle_root: scam_core::hash::hash256(format!("merkle-{idx}").as_bytes()),
                    timestamp: 1_770_763_200 + idx as u64,
                    target: scam_core::Target::MAX,
                    nonce: idx as u64,
                },
                transactions: Vec::new(),
            };
            hashes.push(block.header.block_hash());
            let _ = engine.announce_block(block);
        }

        assert_eq!(engine.block_store.len(), limit);
        let oldest = hashes[0];
        let newest = *hashes.last().expect("newest hash");
        assert!(!engine.has_inventory(&InventoryItem::Block(oldest)));
        assert!(engine.has_inventory(&InventoryItem::Block(newest)));
    }

    #[test]
    fn tx_store_prunes_old_entries_and_inventory_when_capacity_is_exceeded() {
        let mut engine = GossipEngine::new(2).expect("engine");
        engine.connect_peer(1);

        let limit = engine.max_tx_store_items;
        let mut txids = Vec::<Hash256>::new();
        for idx in 0..(limit + 4) {
            let tx = sample_tx(idx as u8);
            let txid = tx.txid();
            txids.push(txid);
            let _ = engine.announce_tx(tx);
        }

        assert_eq!(engine.tx_store.len(), limit);
        let oldest = txids[0];
        let newest = *txids.last().expect("newest txid");
        assert!(!engine.has_inventory(&InventoryItem::Tx(oldest)));
        assert!(engine.has_inventory(&InventoryItem::Tx(newest)));
    }

    #[test]
    fn oversized_inventory_is_penalized_and_banned() {
        let mut engine = GossipEngine::with_limits(2, 50).expect("engine");
        engine.connect_peer(42);

        let oversized = vec![
            InventoryItem::Tx(scam_core::hash::hash256(b"a")),
            InventoryItem::Tx(scam_core::hash::hash256(b"b")),
            InventoryItem::Tx(scam_core::hash::hash256(b"c")),
        ];

        let _ = engine.on_message(
            42,
            WireMessage::Inv {
                items: oversized.clone(),
            },
        );
        assert_eq!(engine.peer_score(42), Some(25));

        let _ = engine.on_message(42, WireMessage::Inv { items: oversized });
        assert!(engine.is_banned(42));

        let err = engine
            .on_message(42, WireMessage::Inv { items: vec![] })
            .expect_err("banned peer must be rejected");
        assert!(matches!(
            err,
            super::GossipError::BannedPeer { peer_id: 42 }
        ));
    }

    #[test]
    fn mempool_delta_broadcasts_announced_txs() {
        let mut engine = GossipEngine::new(256).expect("engine");
        engine.connect_peer(1);
        engine.connect_peer(2);

        let tx = sample_tx(77);
        let txid = tx.txid();
        let outbound = engine.apply_mempool_inventory_delta(vec![tx], &[]);

        assert_eq!(outbound.len(), 2);
        for msg in outbound {
            match msg {
                OutboundMessage {
                    peer_id: 1 | 2,
                    message: WireMessage::Inv { items },
                } => assert_eq!(items, vec![InventoryItem::Tx(txid)]),
                _ => panic!("unexpected outbound message"),
            }
        }
    }

    #[test]
    fn mempool_delta_forgets_removed_txs_from_store() {
        let mut engine = GossipEngine::new(256).expect("engine");
        engine.connect_peer(1);
        engine.connect_peer(2);

        let tx = sample_tx(88);
        let txid = tx.txid();
        let _ = engine
            .on_message(1, WireMessage::Tx { tx })
            .expect("insert tx");
        assert!(engine.has_inventory(&InventoryItem::Tx(txid)));

        let _ = engine.apply_mempool_inventory_delta(vec![], &[txid]);
        assert!(!engine.has_inventory(&InventoryItem::Tx(txid)));

        let response = engine
            .on_message(
                2,
                WireMessage::GetData {
                    items: vec![InventoryItem::Tx(txid)],
                },
            )
            .expect("handle getdata");
        assert_eq!(
            response,
            vec![OutboundMessage {
                peer_id: 2,
                message: WireMessage::NotFound {
                    items: vec![InventoryItem::Tx(txid)],
                },
            }]
        );
    }

    #[test]
    fn per_peer_replacement_rate_limit_penalizes_sender() {
        let mut engine = GossipEngine::with_limits_and_replacement(
            256,
            50,
            ReplacementRateLimit {
                window_sec: 60,
                max_replacements: 1,
                penalty: 60,
            },
        )
        .expect("engine");
        engine.connect_peer(1);
        engine.connect_peer(2);

        let first_tx = sample_tx(100);
        let _ = engine
            .apply_mempool_inventory_delta_from_peer(
                1,
                vec![first_tx],
                &[scam_core::hash::hash256(b"old-a")],
                1_000,
            )
            .expect("first replacement accepted");

        let second_tx = sample_tx(101);
        let err = engine
            .apply_mempool_inventory_delta_from_peer(
                1,
                vec![second_tx],
                &[scam_core::hash::hash256(b"old-b")],
                1_010,
            )
            .expect_err("second replacement in window must be rate limited");
        assert!(matches!(
            err,
            super::GossipError::ReplacementRateLimited { peer_id: 1, .. }
        ));
        assert!(engine.is_banned(1));
    }

    #[test]
    fn replacement_rate_limit_window_allows_later_replacement() {
        let mut engine = GossipEngine::with_limits_and_replacement(
            256,
            100,
            ReplacementRateLimit {
                window_sec: 5,
                max_replacements: 1,
                penalty: 5,
            },
        )
        .expect("engine");
        engine.connect_peer(1);

        let _ = engine
            .apply_mempool_inventory_delta_from_peer(
                1,
                vec![sample_tx(120)],
                &[scam_core::hash::hash256(b"old")],
                1_000,
            )
            .expect("first replacement accepted");
        let _ = engine
            .apply_mempool_inventory_delta_from_peer(
                1,
                vec![sample_tx(121)],
                &[scam_core::hash::hash256(b"old2")],
                1_010,
            )
            .expect("window elapsed, replacement accepted");
    }

    #[test]
    fn replacement_rate_window_boundary_is_inclusive() {
        let mut engine = GossipEngine::with_limits_and_replacement(
            256,
            100,
            ReplacementRateLimit {
                window_sec: 5,
                max_replacements: 1,
                penalty: 5,
            },
        )
        .expect("engine");
        engine.connect_peer(1);

        let _ = engine
            .apply_mempool_inventory_delta_from_peer(
                1,
                vec![sample_tx(140)],
                &[scam_core::hash::hash256(b"old-a")],
                1_000,
            )
            .expect("first replacement accepted");
        let err = engine
            .apply_mempool_inventory_delta_from_peer(
                1,
                vec![sample_tx(141)],
                &[scam_core::hash::hash256(b"old-b")],
                1_005,
            )
            .expect_err("exact boundary should still count inside window");
        assert!(matches!(
            err,
            super::GossipError::ReplacementRateLimited { peer_id: 1, .. }
        ));
    }

    #[test]
    fn inv_and_getdata_accept_exact_max_inv_items_boundary() {
        let mut engine = GossipEngine::with_limits(2, 100).expect("engine");
        engine.connect_peer(7);

        let inv_items = vec![
            InventoryItem::Tx(scam_core::hash::hash256(b"tx-a")),
            InventoryItem::Tx(scam_core::hash::hash256(b"tx-b")),
        ];
        let response = engine
            .on_message(
                7,
                WireMessage::Inv {
                    items: inv_items.clone(),
                },
            )
            .expect("exact boundary for inv should pass");
        assert_eq!(
            response,
            vec![OutboundMessage {
                peer_id: 7,
                message: WireMessage::GetData { items: inv_items },
            }]
        );

        let getdata_items = vec![
            InventoryItem::Tx(scam_core::hash::hash256(b"missing-1")),
            InventoryItem::Tx(scam_core::hash::hash256(b"missing-2")),
        ];
        let response = engine
            .on_message(
                7,
                WireMessage::GetData {
                    items: getdata_items.clone(),
                },
            )
            .expect("exact boundary for getdata should pass");
        assert_eq!(
            response,
            vec![OutboundMessage {
                peer_id: 7,
                message: WireMessage::NotFound {
                    items: getdata_items
                },
            }]
        );
    }

    #[test]
    fn telemetry_counts_replacements_and_delta_activity() {
        let mut engine = GossipEngine::new(256).expect("engine");
        engine.connect_peer(1);

        let _ = engine
            .apply_mempool_inventory_delta_from_peer(
                1,
                vec![sample_tx(130)],
                &[scam_core::hash::hash256(b"remove-a")],
                2_000,
            )
            .expect("accepted");
        let _ = engine.apply_mempool_inventory_delta(vec![sample_tx(131)], &[]);

        let telemetry = engine.telemetry();
        assert_eq!(telemetry.inbound_replacement_events_total, 1);
        assert_eq!(telemetry.announced_txs_total, 2);
        assert_eq!(telemetry.removed_txs_total, 1);
    }
}
