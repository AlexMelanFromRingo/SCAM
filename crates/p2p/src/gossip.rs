use std::collections::{HashMap, HashSet};

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
}

pub struct GossipEngine {
    max_inv_items: usize,
    ban_threshold: u32,
    peers: HashMap<PeerId, PeerState>,
    banned_peers: HashSet<PeerId>,
    local_inventory: HashSet<InventoryItem>,
    tx_store: HashMap<Hash256, Transaction>,
    block_store: HashMap<Hash256, Block>,
}

impl GossipEngine {
    pub fn new(max_inv_items: usize) -> Result<Self, GossipError> {
        Self::with_limits(max_inv_items, 100)
    }

    pub fn with_limits(max_inv_items: usize, ban_threshold: u32) -> Result<Self, GossipError> {
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
        Ok(Self {
            max_inv_items,
            ban_threshold,
            peers: HashMap::new(),
            banned_peers: HashSet::new(),
            local_inventory: HashSet::new(),
            tx_store: HashMap::new(),
            block_store: HashMap::new(),
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

    pub fn announce_tx(&mut self, tx: Transaction) -> Vec<OutboundMessage> {
        let txid = tx.txid();
        self.tx_store.insert(txid, tx);
        let item = InventoryItem::Tx(txid);
        self.insert_local_inventory(item.clone());
        self.fanout_inv(None, item)
    }

    pub fn announce_block(&mut self, block: Block) -> Vec<OutboundMessage> {
        let block_hash = block.header.block_hash();
        self.block_store.insert(block_hash, block);
        let item = InventoryItem::Block(block_hash);
        self.insert_local_inventory(item.clone());
        self.fanout_inv(None, item)
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
            | WireMessage::Headers { .. } => Ok(Vec::new()),
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
        let txid = tx.txid();
        self.tx_store.insert(txid, tx);
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
        let block_hash = block.header.block_hash();
        self.block_store.insert(block_hash, block);
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

    fn penalize_peer(&mut self, peer_id: PeerId, penalty: u32) {
        if let Some(state) = self.peers.get_mut(&peer_id) {
            state.score = state.score.saturating_add(penalty);
            if state.score >= self.ban_threshold {
                self.peers.remove(&peer_id);
                self.banned_peers.insert(peer_id);
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum GossipError {
    #[error("unknown peer: {peer_id}")]
    UnknownPeer { peer_id: PeerId },
    #[error("peer is banned: {peer_id}")]
    BannedPeer { peer_id: PeerId },
    #[error("too many inventory items: limit={limit}, got={got}")]
    TooManyInventoryItems { limit: usize, got: usize },
    #[error("{0}")]
    InvalidConfig(String),
}

#[cfg(test)]
mod tests {
    use super::{GossipEngine, OutboundMessage};
    use crate::wire::{InventoryItem, WireMessage};
    use scam_core::{OutPoint, Transaction, TxIn, TxOut};

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
}
