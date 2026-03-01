use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hasher;

use minisketch_rs::Minisketch;
use scam_core::{Block, Hash256, Transaction};
use siphasher::sip::SipHasher24;
use thiserror::Error;

use crate::wire::{InventoryItem, WireMessage};

pub type PeerId = u64;
const RECON_VERSION: u16 = 1;
const RECON_BITS: u32 = 32;
const RECON_MAX_TRACKED_ROUNDS_PER_PEER: usize = 8;
const RECON_MIN_REQUEST_INTERVAL_SEC: u64 = 15;
const RECON_MAX_EXTENSION_REQUESTS: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundMessage {
    pub peer_id: PeerId,
    pub message: WireMessage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconRoundRole {
    Initiator,
    Responder,
}

#[derive(Clone, Debug, Default)]
struct ReconSnapshot {
    txids: Vec<Hash256>,
    unique_short_ids: Vec<u64>,
    short_to_txids: HashMap<u64, Vec<Hash256>>,
    collision_txids: Vec<Hash256>,
}

#[derive(Clone, Debug)]
struct ReconRound {
    role: ReconRoundRole,
    capacity: usize,
    implementation: u32,
    snapshot: ReconSnapshot,
    extension_requests: u8,
}

#[derive(Default)]
struct PeerState {
    known_inventory: HashSet<InventoryItem>,
    score: u32,
    replacement_events: VecDeque<u64>,
    recon_enabled: bool,
    recon_version: u16,
    recon_short_id_bits: u8,
    recon_implementation: u32,
    recon_local_salt: u64,
    recon_remote_salt: u64,
    recon_max_sketch_items: usize,
    recon_max_diff_items: usize,
    last_recon_request_unix_sec: u64,
    recon_round_nonce: u64,
    recon_rounds: HashMap<u64, ReconRound>,
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
    recon_max_sketch_items: usize,
    recon_max_diff_items: usize,
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
    recon_short_id_bits: u8,
    recon_implementation: u32,
    recon_salt_key0: u64,
    recon_salt_key1: u64,
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
        Minisketch::try_new(RECON_BITS, 0, 1)
            .map_err(|err| GossipError::Recon(format!("minisketch unsupported: {err}")))?;
        Ok(Self {
            max_inv_items,
            ban_threshold,
            recon_max_sketch_items: max_inv_items.max(1),
            recon_max_diff_items: max_inv_items.max(1),
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
            recon_short_id_bits: RECON_BITS as u8,
            recon_implementation: 0,
            recon_salt_key0: 0x7265_636f_6e5f_6b30u64
                ^ (max_inv_items as u64)
                ^ ((ban_threshold as u64) << 32),
            recon_salt_key1: 0x7265_636f_6e5f_6b31u64
                ^ replacement_rate_limit.window_sec
                ^ ((replacement_rate_limit.max_replacements as u64) << 32),
        })
    }

    pub fn connect_peer(&mut self, peer_id: PeerId) {
        if self.banned_peers.contains(&peer_id) {
            return;
        }
        let local_salt = self.local_recon_salt_for_peer(peer_id);
        self.peers.entry(peer_id).or_insert_with(|| PeerState {
            recon_local_salt: local_salt,
            ..PeerState::default()
        });
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

    pub fn tx_inventory_len(&self) -> usize {
        self.tx_store.len()
    }

    pub fn peer_supports_reconciliation(&self, peer_id: PeerId) -> bool {
        let Some(state) = self.peers.get(&peer_id) else {
            return false;
        };
        if !state.recon_enabled {
            return false;
        }
        if state.recon_version == 0 || state.recon_version > RECON_VERSION {
            return false;
        }
        if state.recon_short_id_bits as u32 != RECON_BITS {
            return false;
        }
        if state.recon_implementation != self.recon_implementation {
            return false;
        }
        state.recon_remote_salt != 0
    }

    pub fn build_send_recon(&self, peer_id: PeerId) -> Result<WireMessage, GossipError> {
        let Some(peer_state) = self.peers.get(&peer_id) else {
            return Err(GossipError::UnknownPeer { peer_id });
        };
        Ok(WireMessage::SendRecon {
            enabled: true,
            version: RECON_VERSION,
            short_id_bits: self.recon_short_id_bits,
            implementation: self.recon_implementation,
            salt: peer_state.recon_local_salt,
            max_sketch_items: self.recon_max_sketch_items as u32,
            max_diff_items: self.recon_max_diff_items as u32,
        })
    }

    pub fn maybe_start_reconciliation(
        &mut self,
        peer_id: PeerId,
        now_unix_sec: u64,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        let Some(peer_state) = self.peers.get(&peer_id) else {
            return Err(GossipError::UnknownPeer { peer_id });
        };
        if !self.peer_supports_reconciliation(peer_id) {
            return Ok(Vec::new());
        }
        let elapsed = now_unix_sec.saturating_sub(peer_state.last_recon_request_unix_sec);
        if elapsed < RECON_MIN_REQUEST_INTERVAL_SEC {
            return Ok(Vec::new());
        }
        if peer_state.recon_rounds.len() >= RECON_MAX_TRACKED_ROUNDS_PER_PEER {
            return Ok(Vec::new());
        }

        let nonce = peer_state.recon_round_nonce;
        let negotiated_capacity = peer_state
            .recon_max_sketch_items
            .max(1)
            .min(self.recon_max_sketch_items);
        let implementation = peer_state.recon_implementation;
        let salt = self.recon_round_salt(
            peer_id,
            now_unix_sec,
            nonce,
            peer_state.recon_local_salt,
            peer_state.recon_remote_salt,
            implementation,
        );
        let snapshot = self.build_recon_snapshot(salt, negotiated_capacity, implementation)?;

        if let Some(peer_state) = self.peers.get_mut(&peer_id) {
            peer_state.last_recon_request_unix_sec = now_unix_sec;
            peer_state.recon_round_nonce = peer_state.recon_round_nonce.saturating_add(1);
            if peer_state.recon_rounds.len() >= RECON_MAX_TRACKED_ROUNDS_PER_PEER
                && let Some(oldest) = peer_state.recon_rounds.keys().next().copied()
            {
                peer_state.recon_rounds.remove(&oldest);
            }
            peer_state.recon_rounds.insert(
                salt,
                ReconRound {
                    role: ReconRoundRole::Initiator,
                    capacity: negotiated_capacity,
                    implementation,
                    snapshot,
                    extension_requests: 0,
                },
            );
        }

        Ok(vec![OutboundMessage {
            peer_id,
            message: WireMessage::ReqRecon {
                salt,
                set_size: negotiated_capacity as u32,
            },
        }])
    }

    pub fn penalize_peer(&mut self, peer_id: PeerId, penalty: u32) -> Result<(), GossipError> {
        if self.banned_peers.contains(&peer_id) {
            return Err(GossipError::BannedPeer { peer_id });
        }
        if !self.peers.contains_key(&peer_id) {
            return Err(GossipError::UnknownPeer { peer_id });
        }
        self.apply_penalty(peer_id, penalty);
        Ok(())
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
            WireMessage::SendRecon {
                enabled,
                version,
                short_id_bits,
                implementation,
                salt,
                max_sketch_items,
                max_diff_items,
            } => self.handle_send_recon(
                from_peer,
                enabled,
                version,
                short_id_bits,
                implementation,
                salt,
                max_sketch_items,
                max_diff_items,
            ),
            WireMessage::ReqRecon { salt, set_size } => {
                self.handle_req_recon(from_peer, salt, set_size)
            }
            WireMessage::Sketch {
                salt,
                bits,
                capacity,
                implementation,
                bytes,
            } => self.handle_sketch(from_peer, salt, bits, capacity, implementation, bytes),
            WireMessage::ReqSketchExt { salt, capacity } => {
                self.handle_req_sketch_ext(from_peer, salt, capacity)
            }
            WireMessage::ReqTx { salt, short_ids } => {
                self.handle_req_tx(from_peer, salt, short_ids)
            }
            WireMessage::ReconcileDiff {
                salt,
                announce_txids,
                request_txids,
            } => self.handle_reconcile_diff(from_peer, salt, announce_txids, request_txids),
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

    #[allow(clippy::too_many_arguments)]
    fn handle_send_recon(
        &mut self,
        from_peer: PeerId,
        enabled: bool,
        version: u16,
        short_id_bits: u8,
        implementation: u32,
        salt: u64,
        max_sketch_items: u32,
        max_diff_items: u32,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        if enabled && version == 0 {
            self.apply_penalty(from_peer, 10);
            return Err(GossipError::InvalidConfig(
                "reconciliation cannot be enabled with version=0".to_owned(),
            ));
        }
        if version > RECON_VERSION {
            self.apply_penalty(from_peer, 10);
            return Err(GossipError::InvalidConfig(format!(
                "unsupported recon protocol version: {version}"
            )));
        }
        if enabled && short_id_bits as u32 != RECON_BITS {
            self.apply_penalty(from_peer, 10);
            return Err(GossipError::InvalidConfig(format!(
                "unsupported recon short_id_bits: expected {RECON_BITS}, got {short_id_bits}"
            )));
        }
        if enabled && implementation != self.recon_implementation {
            self.apply_penalty(from_peer, 10);
            return Err(GossipError::InvalidConfig(format!(
                "unsupported recon implementation: expected {}, got {implementation}",
                self.recon_implementation
            )));
        }
        if enabled && salt == 0 {
            self.apply_penalty(from_peer, 10);
            return Err(GossipError::InvalidConfig(
                "reconciliation salt must be non-zero when enabled".to_owned(),
            ));
        }
        let negotiated_sketch = self
            .recon_capacity_from_requested(max_sketch_items)
            .min(self.recon_max_sketch_items);
        let negotiated_diff = self
            .recon_capacity_from_requested(max_diff_items)
            .min(self.recon_max_diff_items);
        if let Some(peer_state) = self.peers.get_mut(&from_peer) {
            peer_state.recon_enabled = enabled;
            peer_state.recon_version = if enabled { version } else { 0 };
            peer_state.recon_short_id_bits = if enabled { short_id_bits } else { 0 };
            peer_state.recon_implementation = if enabled { implementation } else { 0 };
            peer_state.recon_remote_salt = if enabled { salt } else { 0 };
            peer_state.recon_max_sketch_items = if enabled { negotiated_sketch } else { 0 };
            peer_state.recon_max_diff_items = if enabled { negotiated_diff } else { 0 };
            if !enabled {
                peer_state.recon_rounds.clear();
            }
        }
        Ok(Vec::new())
    }

    fn handle_req_recon(
        &mut self,
        from_peer: PeerId,
        salt: u64,
        set_size: u32,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        if !self.peer_supports_reconciliation(from_peer) {
            self.apply_penalty(from_peer, 10);
            return Err(GossipError::Recon(
                "peer requested reconciliation before negotiation".to_owned(),
            ));
        }
        let Some(peer_state) = self.peers.get(&from_peer) else {
            return Err(GossipError::UnknownPeer { peer_id: from_peer });
        };
        let requested = self
            .recon_capacity_from_requested(set_size)
            .min(peer_state.recon_max_sketch_items.max(1))
            .min(self.recon_max_sketch_items);
        let implementation = peer_state.recon_implementation;
        let snapshot = self.build_recon_snapshot(salt, requested, implementation)?;
        let collisions = snapshot.collision_txids.clone();
        let short_ids = snapshot.unique_short_ids.clone();
        if let Some(peer_state) = self.peers.get_mut(&from_peer) {
            if peer_state.recon_rounds.len() >= RECON_MAX_TRACKED_ROUNDS_PER_PEER
                && let Some(oldest) = peer_state.recon_rounds.keys().next().copied()
            {
                peer_state.recon_rounds.remove(&oldest);
            }
            peer_state.recon_rounds.insert(
                salt,
                ReconRound {
                    role: ReconRoundRole::Responder,
                    capacity: requested,
                    implementation,
                    snapshot,
                    extension_requests: 0,
                },
            );
        }

        let bytes = self.build_recon_sketch(salt, requested, implementation, &short_ids)?;
        let mut out = vec![OutboundMessage {
            peer_id: from_peer,
            message: WireMessage::Sketch {
                salt,
                bits: RECON_BITS,
                capacity: requested as u32,
                implementation,
                bytes,
            },
        }];
        if !collisions.is_empty() {
            let diff_limit = self
                .peers
                .get(&from_peer)
                .map(|state| state.recon_max_diff_items.max(1))
                .unwrap_or(self.recon_max_diff_items)
                .min(self.recon_max_diff_items);
            out.push(OutboundMessage {
                peer_id: from_peer,
                message: WireMessage::ReconcileDiff {
                    salt,
                    announce_txids: collisions.into_iter().take(diff_limit).collect(),
                    request_txids: Vec::new(),
                },
            });
        }
        Ok(out)
    }

    fn handle_req_sketch_ext(
        &mut self,
        from_peer: PeerId,
        salt: u64,
        capacity: u32,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        let requested = self.recon_capacity_from_requested(capacity);
        let (capacity, implementation, unique_short_ids, collision_txids, diff_limit) = {
            let Some(peer_state) = self.peers.get_mut(&from_peer) else {
                return Err(GossipError::UnknownPeer { peer_id: from_peer });
            };
            let Some(round) = peer_state.recon_rounds.get_mut(&salt) else {
                return Err(GossipError::Recon(format!(
                    "unknown reconciliation round salt={salt}"
                )));
            };
            if round.role != ReconRoundRole::Responder {
                self.apply_penalty(from_peer, 5);
                return Err(GossipError::Recon(format!(
                    "reqsketchext for non-responder round salt={salt}"
                )));
            }
            let capped_capacity = requested
                .min(peer_state.recon_max_sketch_items.max(1))
                .min(self.recon_max_sketch_items);
            round.capacity = round.capacity.max(capped_capacity);
            (
                round.capacity,
                round.implementation,
                round.snapshot.unique_short_ids.clone(),
                round.snapshot.collision_txids.clone(),
                peer_state.recon_max_diff_items.max(1),
            )
        };
        let bytes = self.build_recon_sketch(salt, capacity, implementation, &unique_short_ids)?;

        let mut out = vec![OutboundMessage {
            peer_id: from_peer,
            message: WireMessage::Sketch {
                salt,
                bits: RECON_BITS,
                capacity: capacity as u32,
                implementation,
                bytes,
            },
        }];
        if !collision_txids.is_empty() {
            out.push(OutboundMessage {
                peer_id: from_peer,
                message: WireMessage::ReconcileDiff {
                    salt,
                    announce_txids: collision_txids.into_iter().take(diff_limit).collect(),
                    request_txids: Vec::new(),
                },
            });
        }
        Ok(out)
    }

    fn handle_sketch(
        &mut self,
        from_peer: PeerId,
        salt: u64,
        bits: u32,
        capacity: u32,
        implementation: u32,
        bytes: Vec<u8>,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        if bits != RECON_BITS {
            self.apply_penalty(from_peer, 10);
            return Err(GossipError::Recon(format!(
                "unsupported recon bits: expected {RECON_BITS}, got {bits}"
            )));
        }
        let requested_capacity = self.recon_capacity_from_requested(capacity);
        let (peer_max_sketch_items, peer_max_diff_items, round) = {
            let Some(peer_state) = self.peers.get(&from_peer) else {
                return Err(GossipError::UnknownPeer { peer_id: from_peer });
            };
            let Some(round) = peer_state.recon_rounds.get(&salt).cloned() else {
                return Err(GossipError::Recon(format!(
                    "received sketch for unknown round salt={salt}"
                )));
            };
            (
                peer_state.recon_max_sketch_items.max(1),
                peer_state.recon_max_diff_items.max(1),
                round,
            )
        };
        let capacity = requested_capacity.min(peer_max_sketch_items);
        if implementation != round.implementation {
            self.apply_penalty(from_peer, 10);
            return Err(GossipError::Recon(format!(
                "recon sketch implementation mismatch: expected {}, got {implementation}",
                round.implementation
            )));
        }
        let max_serialized_len = (((RECON_BITS as usize).saturating_mul(capacity)) / 8).max(1);
        if bytes.len() > max_serialized_len.saturating_mul(2) {
            self.apply_penalty(from_peer, 25);
            return Err(GossipError::TooManyInventoryItems {
                limit: self.max_inv_items,
                got: bytes.len(),
            });
        }
        let local_short_ids = round.snapshot.unique_short_ids.clone();
        let local_set = local_short_ids.iter().copied().collect::<HashSet<_>>();

        let mut local_sketch = Minisketch::try_new(RECON_BITS, implementation, capacity)
            .map_err(|err| GossipError::Recon(format!("local minisketch create failed: {err}")))?;
        local_sketch.set_seed(salt);
        for short_id in &local_short_ids {
            local_sketch.add(*short_id);
        }

        let mut remote_sketch = Minisketch::try_new(RECON_BITS, implementation, capacity)
            .map_err(|err| GossipError::Recon(format!("remote minisketch create failed: {err}")))?;
        remote_sketch.set_seed(salt);
        remote_sketch.deserialize(&bytes);
        local_sketch
            .merge(&remote_sketch)
            .map_err(|err| GossipError::Recon(format!("minisketch merge failed: {err}")))?;

        let mut decoded = vec![0u64; capacity];
        let decoded_count = match local_sketch.decode(&mut decoded) {
            Ok(count) => count,
            Err(err) => {
                self.remove_recon_round(from_peer, salt);
                if round.snapshot.txids.is_empty() {
                    return Err(GossipError::Recon(format!(
                        "minisketch decode failed and no fallback txids available: {err}"
                    )));
                }
                return Ok(vec![OutboundMessage {
                    peer_id: from_peer,
                    message: WireMessage::ReconcileDiff {
                        salt,
                        announce_txids: round
                            .snapshot
                            .txids
                            .iter()
                            .copied()
                            .take(peer_max_diff_items.min(self.recon_max_diff_items))
                            .collect(),
                        request_txids: Vec::new(),
                    },
                }]);
            }
        };
        if decoded_count == capacity && round.role == ReconRoundRole::Initiator {
            let at_extension_limit = round.extension_requests >= RECON_MAX_EXTENSION_REQUESTS;
            let at_capacity_limit = capacity >= peer_max_sketch_items;
            if at_extension_limit {
                // Fall through to deterministic diff fallback below.
            } else if !at_capacity_limit {
                let next_capacity = (capacity.saturating_mul(2))
                    .max(capacity.saturating_add(1))
                    .min(peer_max_sketch_items);
                if let Some(peer_state) = self.peers.get_mut(&from_peer)
                    && let Some(round_state) = peer_state.recon_rounds.get_mut(&salt)
                {
                    round_state.capacity = round_state.capacity.max(next_capacity);
                    round_state.extension_requests =
                        round_state.extension_requests.saturating_add(1);
                }
                return Ok(vec![OutboundMessage {
                    peer_id: from_peer,
                    message: WireMessage::ReqSketchExt {
                        salt,
                        capacity: next_capacity as u32,
                    },
                }]);
            }
            self.remove_recon_round(from_peer, salt);
            if round.snapshot.txids.is_empty() {
                return Err(GossipError::Recon(
                    "minisketch decode saturated at capacity and no fallback txids available"
                        .to_owned(),
                ));
            }
            return Ok(vec![OutboundMessage {
                peer_id: from_peer,
                message: WireMessage::ReconcileDiff {
                    salt,
                    announce_txids: round
                        .snapshot
                        .txids
                        .iter()
                        .copied()
                        .take(peer_max_diff_items.min(self.recon_max_diff_items))
                        .collect(),
                    request_txids: Vec::new(),
                },
            }]);
        }
        decoded.truncate(decoded_count);

        let mut missing = Vec::<u64>::new();
        for short_id in decoded {
            if short_id == 0 {
                continue;
            }
            if local_set.contains(&short_id) {
                continue;
            }
            missing.push(short_id);
        }
        missing.sort_unstable();
        missing.dedup();
        missing.truncate(self.max_inv_items);
        let mut out = Vec::<OutboundMessage>::new();
        if !missing.is_empty() {
            out.push(OutboundMessage {
                peer_id: from_peer,
                message: WireMessage::ReqTx {
                    salt,
                    short_ids: missing,
                },
            });
        }
        if !round.snapshot.collision_txids.is_empty() {
            out.push(OutboundMessage {
                peer_id: from_peer,
                message: WireMessage::ReconcileDiff {
                    salt,
                    announce_txids: round
                        .snapshot
                        .collision_txids
                        .iter()
                        .copied()
                        .take(peer_max_diff_items.min(self.recon_max_diff_items))
                        .collect(),
                    request_txids: Vec::new(),
                },
            });
        }
        self.remove_recon_round(from_peer, salt);
        Ok(out)
    }

    fn handle_req_tx(
        &mut self,
        from_peer: PeerId,
        salt: u64,
        short_ids: Vec<u64>,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        if short_ids.len() > self.max_inv_items {
            self.apply_penalty(from_peer, 25);
            return Err(GossipError::TooManyInventoryItems {
                limit: self.max_inv_items,
                got: short_ids.len(),
            });
        }
        let requested_set = short_ids.into_iter().collect::<HashSet<_>>();
        let (short_to_txids, diff_limit) = if let Some(peer_state) = self.peers.get(&from_peer) {
            if let Some(round) = peer_state.recon_rounds.get(&salt) {
                (
                    round.snapshot.short_to_txids.clone(),
                    peer_state.recon_max_diff_items.max(1),
                )
            } else {
                let implementation = self.recon_implementation;
                let snapshot = self.build_recon_snapshot(
                    salt,
                    self.max_inv_items.min(self.tx_store.len().max(1)),
                    implementation,
                )?;
                (snapshot.short_to_txids, self.recon_max_diff_items)
            }
        } else {
            return Err(GossipError::UnknownPeer { peer_id: from_peer });
        };

        let mut out = Vec::<OutboundMessage>::new();
        let mut collisions = Vec::<Hash256>::new();
        for short_id in requested_set {
            if let Some(txids) = short_to_txids.get(&short_id) {
                if txids.len() == 1 {
                    if let Some(tx) = self.tx_store.get(&txids[0]).cloned() {
                        out.push(OutboundMessage {
                            peer_id: from_peer,
                            message: WireMessage::Tx { tx },
                        });
                    }
                } else {
                    collisions.extend(txids.iter().copied());
                }
            }
        }
        collisions.sort_unstable();
        collisions.dedup();
        if !collisions.is_empty() {
            out.push(OutboundMessage {
                peer_id: from_peer,
                message: WireMessage::ReconcileDiff {
                    salt,
                    announce_txids: collisions.into_iter().take(diff_limit).collect(),
                    request_txids: Vec::new(),
                },
            });
        }
        Ok(out)
    }

    fn handle_reconcile_diff(
        &mut self,
        from_peer: PeerId,
        salt: u64,
        announce_txids: Vec<Hash256>,
        request_txids: Vec<Hash256>,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        let diff_limit = self
            .peers
            .get(&from_peer)
            .map(|state| state.recon_max_diff_items.max(1))
            .unwrap_or(self.recon_max_diff_items)
            .min(self.recon_max_diff_items);
        if announce_txids.len() > diff_limit || request_txids.len() > diff_limit {
            self.apply_penalty(from_peer, 25);
            return Err(GossipError::TooManyInventoryItems {
                limit: diff_limit,
                got: announce_txids.len().max(request_txids.len()),
            });
        }

        let mut out = Vec::<OutboundMessage>::new();
        let mut wanted = Vec::<InventoryItem>::new();
        for txid in announce_txids {
            let item = InventoryItem::Tx(txid);
            if !self.local_inventory.contains(&item) {
                wanted.push(item);
            }
        }
        if !wanted.is_empty() {
            out.push(OutboundMessage {
                peer_id: from_peer,
                message: WireMessage::GetData { items: wanted },
            });
        }

        for txid in request_txids {
            if let Some(tx) = self.tx_store.get(&txid).cloned() {
                out.push(OutboundMessage {
                    peer_id: from_peer,
                    message: WireMessage::Tx { tx },
                });
            }
        }
        self.remove_recon_round(from_peer, salt);
        Ok(out)
    }

    fn handle_inv(
        &mut self,
        from_peer: PeerId,
        items: Vec<InventoryItem>,
    ) -> Result<Vec<OutboundMessage>, GossipError> {
        if items.len() > self.max_inv_items {
            self.apply_penalty(from_peer, 25);
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
            self.apply_penalty(from_peer, 25);
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

    fn apply_penalty(&mut self, peer_id: PeerId, penalty: u32) {
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
            self.apply_penalty(peer_id, penalty);
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

    fn recon_capacity_from_requested(&self, requested: u32) -> usize {
        let requested = if requested == 0 {
            self.max_inv_items
        } else {
            requested as usize
        };
        requested.min(self.max_inv_items).max(1)
    }

    fn build_recon_sketch(
        &self,
        salt: u64,
        capacity: usize,
        implementation: u32,
        short_ids: &[u64],
    ) -> Result<Vec<u8>, GossipError> {
        let mut sketch = Minisketch::try_new(RECON_BITS, implementation, capacity)
            .map_err(|err| GossipError::Recon(format!("minisketch create failed: {err}")))?;
        sketch.set_seed(salt);
        for short_id in short_ids {
            sketch.add(*short_id);
        }
        let mut bytes = vec![0u8; sketch.serialized_size()];
        sketch
            .serialize(&mut bytes)
            .map_err(|err| GossipError::Recon(format!("minisketch serialize failed: {err}")))?;
        Ok(bytes)
    }

    fn build_recon_snapshot(
        &self,
        salt: u64,
        max_items: usize,
        implementation: u32,
    ) -> Result<ReconSnapshot, GossipError> {
        if max_items == 0 {
            return Err(GossipError::Recon(
                "reconciliation snapshot requires max_items > 0".to_owned(),
            ));
        }
        let limit = max_items.min(self.max_inv_items).max(1);
        let mut out = Vec::<(u64, Hash256)>::new();
        let mut mapping = HashMap::<u64, Vec<Hash256>>::new();
        let mut txids = self.tx_store.keys().copied().collect::<Vec<_>>();
        txids.sort_unstable();
        for txid in txids {
            let short_id = recon_short_id(txid, salt, implementation);
            if short_id == 0 {
                continue;
            }
            out.push((short_id, txid));
            mapping.entry(short_id).or_default().push(txid);
            if out.len() >= limit {
                break;
            }
        }
        let mut unique_short_ids = Vec::<u64>::new();
        let mut collision_txids = Vec::<Hash256>::new();
        for (short_id, ids) in &mapping {
            if ids.len() == 1 {
                unique_short_ids.push(*short_id);
            } else {
                collision_txids.extend(ids.iter().copied());
            }
        }
        unique_short_ids.sort_unstable();
        unique_short_ids.dedup();
        collision_txids.sort_unstable();
        collision_txids.dedup();

        Ok(ReconSnapshot {
            txids: out.iter().map(|(_, txid)| *txid).collect(),
            unique_short_ids,
            short_to_txids: mapping,
            collision_txids,
        })
    }

    fn recon_round_salt(
        &self,
        peer_id: PeerId,
        now_unix_sec: u64,
        nonce: u64,
        local_salt: u64,
        remote_salt: u64,
        implementation: u32,
    ) -> u64 {
        let mut hasher = SipHasher24::new_with_keys(
            self.recon_salt_key0 ^ (implementation as u64),
            self.recon_salt_key1 ^ peer_id,
        );
        hasher.write_u64(now_unix_sec);
        hasher.write_u64(peer_id);
        hasher.write_u64(nonce);
        hasher.write_u64(local_salt);
        hasher.write_u64(remote_salt);
        let salt = hasher.finish();
        if salt == 0 { 1 } else { salt }
    }

    fn local_recon_salt_for_peer(&self, peer_id: PeerId) -> u64 {
        let mut hasher = SipHasher24::new_with_keys(self.recon_salt_key0, self.recon_salt_key1);
        hasher.write_u64(peer_id);
        hasher.write_u8(self.recon_short_id_bits);
        hasher.write_u32(self.recon_implementation);
        let salt = hasher.finish();
        if salt == 0 { 1 } else { salt }
    }

    fn remove_recon_round(&mut self, peer_id: PeerId, salt: u64) {
        if let Some(peer_state) = self.peers.get_mut(&peer_id) {
            peer_state.recon_rounds.remove(&salt);
        }
    }
}

fn recon_short_id(txid: Hash256, salt: u64, implementation: u32) -> u64 {
    let key0 = salt ^ ((implementation as u64) << 32);
    let key1 = !salt ^ 0x9E37_79B9_7F4A_7C15u64;
    let mut hasher = SipHasher24::new_with_keys(key0, key1);
    hasher.write(&txid.0);
    let value = hasher.finish();
    let mask = if RECON_BITS == 64 {
        u64::MAX
    } else {
        (1u64 << RECON_BITS) - 1
    };
    value & mask
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
    #[error("recon error: {0}")]
    Recon(String),
    #[error("{0}")]
    InvalidConfig(String),
}

#[cfg(test)]
mod tests {
    use minisketch_rs::Minisketch;

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
    fn explicit_penalty_api_bans_peer_after_threshold() {
        let mut engine = GossipEngine::with_limits(256, 50).expect("engine");
        engine.connect_peer(9);
        assert!(!engine.is_banned(9));

        engine.penalize_peer(9, 25).expect("first penalty");
        assert_eq!(engine.peer_score(9), Some(25));
        assert!(!engine.is_banned(9));

        engine.penalize_peer(9, 25).expect("second penalty");
        assert!(engine.is_banned(9));
        assert_eq!(engine.peer_score(9), None);
    }

    #[test]
    fn explicit_penalty_api_rejects_unknown_peer() {
        let mut engine = GossipEngine::new(32).expect("engine");
        let err = engine
            .penalize_peer(42, 10)
            .expect_err("unknown peer must fail");
        assert!(matches!(
            err,
            super::GossipError::UnknownPeer { peer_id: 42 }
        ));
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
    fn forget_tx_and_block_keep_unrelated_entries_in_order_indexes() {
        let mut engine = GossipEngine::new(32).expect("engine");
        engine.connect_peer(1);
        engine.connect_peer(2);

        let tx_a = sample_tx(31);
        let tx_b = sample_tx(32);
        let txid_a = tx_a.txid();
        let txid_b = tx_b.txid();
        let _ = engine
            .on_message(1, WireMessage::Tx { tx: tx_a })
            .expect("insert tx a");
        let _ = engine
            .on_message(1, WireMessage::Tx { tx: tx_b })
            .expect("insert tx b");
        assert_eq!(engine.tx_store_order.len(), 2);
        assert_eq!(engine.tx_store_order.front().copied(), Some(txid_a));
        assert_eq!(engine.tx_store_order.back().copied(), Some(txid_b));

        engine.forget_tx(txid_a);
        assert!(!engine.tx_store.contains_key(&txid_a));
        assert!(engine.tx_store.contains_key(&txid_b));
        assert_eq!(engine.tx_store_order.len(), 1);
        assert_eq!(engine.tx_store_order.front().copied(), Some(txid_b));

        let block_a = scam_core::Block {
            header: scam_core::BlockHeader {
                version: 1,
                prev_block: scam_core::Hash256::ZERO,
                merkle_root: scam_core::hash::hash256(b"blk-a"),
                timestamp: 1_770_763_300,
                target: scam_core::Target::MAX,
                nonce: 1,
            },
            transactions: Vec::new(),
        };
        let block_b = scam_core::Block {
            header: scam_core::BlockHeader {
                version: 1,
                prev_block: scam_core::Hash256::ZERO,
                merkle_root: scam_core::hash::hash256(b"blk-b"),
                timestamp: 1_770_763_301,
                target: scam_core::Target::MAX,
                nonce: 2,
            },
            transactions: Vec::new(),
        };
        let block_hash_a = block_a.header.block_hash();
        let block_hash_b = block_b.header.block_hash();
        let _ = engine.announce_block(block_a);
        let _ = engine.announce_block(block_b);
        assert_eq!(engine.block_store_order.len(), 2);
        assert_eq!(
            engine.block_store_order.front().copied(),
            Some(block_hash_a)
        );
        assert_eq!(engine.block_store_order.back().copied(), Some(block_hash_b));

        engine.forget_block(block_hash_a);
        assert!(!engine.block_store.contains_key(&block_hash_a));
        assert!(engine.block_store.contains_key(&block_hash_b));
        assert_eq!(engine.block_store_order.len(), 1);
        assert_eq!(
            engine.block_store_order.front().copied(),
            Some(block_hash_b)
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

    #[test]
    fn recon_request_returns_sketch_of_local_mempool() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(7);
        engine
            .on_message(
                7,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 7,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("sendrecon");
        engine.announce_tx(sample_tx(1));
        engine.announce_tx(sample_tx(2));
        let out = engine
            .on_message(
                7,
                WireMessage::ReqRecon {
                    salt: 42,
                    set_size: 16,
                },
            )
            .expect("req recon");
        assert_eq!(out.len(), 1);
        match &out[0].message {
            WireMessage::Sketch {
                salt,
                bits,
                capacity,
                implementation,
                bytes,
            } => {
                assert_eq!(*salt, 42);
                assert_eq!(*bits, super::RECON_BITS);
                assert_eq!(*capacity, 16);
                assert_eq!(*implementation, 0);
                assert!(!bytes.is_empty());
            }
            other => panic!("unexpected recon response: {other:?}"),
        }
    }

    #[test]
    fn recon_sketch_and_reqtx_flow_requests_and_serves_missing_entries() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(5);
        engine
            .on_message(
                5,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 5,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("sendrecon");
        let local_tx = sample_tx(10);
        let local_txid = local_tx.txid();
        engine.announce_tx(local_tx);
        let remote_txid = sample_tx(11).txid();
        let round = engine
            .maybe_start_reconciliation(5, 1_000)
            .expect("start recon");
        assert_eq!(round.len(), 1);
        let (salt, capacity) = match &round[0].message {
            WireMessage::ReqRecon { salt, set_size } => (*salt, *set_size as usize),
            other => panic!("expected reqrecon start, got {other:?}"),
        };
        let mut remote_sketch =
            Minisketch::try_new(super::RECON_BITS, 0, capacity).expect("remote sketch create");
        remote_sketch.set_seed(salt);
        remote_sketch.add(super::recon_short_id(local_txid, salt, 0));
        remote_sketch.add(super::recon_short_id(remote_txid, salt, 0));
        let mut remote_bytes = vec![0u8; remote_sketch.serialized_size()];
        remote_sketch
            .serialize(&mut remote_bytes)
            .expect("remote sketch serialize");

        let out = engine
            .on_message(
                5,
                WireMessage::Sketch {
                    salt,
                    bits: super::RECON_BITS,
                    capacity: capacity as u32,
                    implementation: 0,
                    bytes: remote_bytes,
                },
            )
            .expect("recon sketch");
        assert_eq!(out.len(), 1);
        let missing_short_ids = match &out[0].message {
            WireMessage::ReqTx {
                salt: got_salt,
                short_ids,
            } => {
                assert_eq!(*got_salt, salt);
                short_ids.clone()
            }
            other => panic!("expected req tx, got {other:?}"),
        };
        assert_eq!(
            missing_short_ids,
            vec![super::recon_short_id(remote_txid, salt, 0)]
        );

        let out = engine
            .on_message(
                5,
                WireMessage::ReqTx {
                    salt,
                    short_ids: vec![super::recon_short_id(local_txid, salt, 0)],
                },
            )
            .expect("req tx");
        assert_eq!(out.len(), 1);
        match &out[0] {
            OutboundMessage {
                peer_id: 5,
                message: WireMessage::Tx { tx },
            } => assert_eq!(tx.txid(), local_txid),
            other => panic!("unexpected reqtx response: {other:?}"),
        }
    }

    #[test]
    fn oversized_recon_payloads_are_rate_limited_like_inventory_abuse() {
        let mut engine = GossipEngine::with_limits(2, 50).expect("engine");
        engine.connect_peer(9);
        engine
            .on_message(
                9,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 9,
                    max_sketch_items: 2,
                    max_diff_items: 2,
                },
            )
            .expect("sendrecon");
        let start = engine
            .maybe_start_reconciliation(9, 1_000)
            .expect("start recon");
        let salt = match &start[0].message {
            WireMessage::ReqRecon { salt, .. } => *salt,
            other => panic!("expected reqrecon, got {other:?}"),
        };
        let err = engine
            .on_message(
                9,
                WireMessage::Sketch {
                    salt,
                    bits: super::RECON_BITS,
                    capacity: 2,
                    implementation: 0,
                    bytes: vec![0u8; 128],
                },
            )
            .expect_err("oversized sketch");
        assert!(matches!(
            err,
            super::GossipError::TooManyInventoryItems { .. }
        ));
        assert_eq!(engine.peer_score(9), Some(25));
    }

    #[test]
    fn maybe_start_reconciliation_requires_negotiation_and_interval() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(77);
        assert!(
            engine
                .maybe_start_reconciliation(77, 1_000)
                .expect("no recon without negotiation")
                .is_empty()
        );
        engine
            .on_message(
                77,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 77,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("sendrecon");
        assert!(
            !engine
                .maybe_start_reconciliation(77, 1_000)
                .expect("start after negotiation")
                .is_empty()
        );
        assert!(
            engine
                .maybe_start_reconciliation(77, 1_001)
                .expect("interval guard")
                .is_empty()
        );
        assert!(
            !engine
                .maybe_start_reconciliation(77, 1_015)
                .expect("exact interval boundary should permit request")
                .is_empty()
        );
    }

    #[test]
    fn maybe_start_reconciliation_respects_tracked_round_limit_boundary() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(78);
        engine
            .on_message(
                78,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 78,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("sendrecon");
        {
            let peer_state = engine.peers.get_mut(&78).expect("peer");
            for idx in 0..super::RECON_MAX_TRACKED_ROUNDS_PER_PEER {
                peer_state.recon_rounds.insert(
                    (idx + 1) as u64,
                    super::ReconRound {
                        role: super::ReconRoundRole::Initiator,
                        capacity: 1,
                        implementation: 0,
                        snapshot: super::ReconSnapshot::default(),
                        extension_requests: 0,
                    },
                );
            }
            assert_eq!(
                peer_state.recon_rounds.len(),
                super::RECON_MAX_TRACKED_ROUNDS_PER_PEER
            );
        }
        let out = engine
            .maybe_start_reconciliation(78, 2_000)
            .expect("round limit should not error");
        assert!(
            out.is_empty(),
            "initiator must not start new round when tracked-round cache is at limit"
        );
    }

    #[test]
    fn maybe_start_reconciliation_does_not_evict_rounds_below_limit() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(79);
        engine
            .on_message(
                79,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 79,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("sendrecon");
        {
            let peer_state = engine.peers.get_mut(&79).expect("peer");
            peer_state.recon_rounds.insert(
                1,
                super::ReconRound {
                    role: super::ReconRoundRole::Initiator,
                    capacity: 1,
                    implementation: 0,
                    snapshot: super::ReconSnapshot::default(),
                    extension_requests: 0,
                },
            );
        }
        let out = engine
            .maybe_start_reconciliation(79, 2_000)
            .expect("new round should start below cap");
        assert_eq!(out.len(), 1);
        let peer_state = engine.peers.get(&79).expect("peer");
        assert!(
            peer_state.recon_rounds.contains_key(&1),
            "existing round must remain when cache is below cap"
        );
        assert_eq!(peer_state.recon_rounds.len(), 2);
    }

    #[test]
    fn build_send_recon_exposes_nonzero_peer_salt() {
        let mut engine = GossipEngine::new(8).expect("engine");
        engine.connect_peer(3);
        let msg = engine.build_send_recon(3).expect("build sendrecon");
        match msg {
            WireMessage::SendRecon {
                enabled,
                version,
                short_id_bits,
                implementation,
                salt,
                max_sketch_items,
                max_diff_items,
            } => {
                assert!(enabled);
                assert_eq!(version, 1);
                assert_eq!(short_id_bits, super::RECON_BITS as u8);
                assert_eq!(implementation, 0);
                assert_ne!(salt, 0);
                assert!(max_sketch_items >= 1);
                assert!(max_diff_items >= 1);
            }
            other => panic!("unexpected recon message: {other:?}"),
        }
    }

    #[test]
    fn send_recon_rejects_unsupported_short_id_bits_and_implementation() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(44);
        let bad_bits = engine
            .on_message(
                44,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: 16,
                    implementation: 0,
                    salt: 11,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect_err("must reject unsupported short-id bits");
        assert!(matches!(bad_bits, super::GossipError::InvalidConfig(_)));

        let bad_impl = engine
            .on_message(
                44,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 99,
                    salt: 11,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect_err("must reject unsupported implementation");
        assert!(matches!(bad_impl, super::GossipError::InvalidConfig(_)));
    }

    #[test]
    fn reqsketchext_returns_larger_responder_sketch() {
        let mut engine = GossipEngine::new(32).expect("engine");
        engine.connect_peer(13);
        engine
            .on_message(
                13,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 13,
                    max_sketch_items: 32,
                    max_diff_items: 32,
                },
            )
            .expect("sendrecon");
        engine.announce_tx(sample_tx(1));
        engine.announce_tx(sample_tx(2));

        let first = engine
            .on_message(
                13,
                WireMessage::ReqRecon {
                    salt: 99,
                    set_size: 2,
                },
            )
            .expect("reqrecon");
        let first_bytes_len = first
            .iter()
            .find_map(|msg| match &msg.message {
                WireMessage::Sketch { bytes, .. } => Some(bytes.len()),
                _ => None,
            })
            .expect("first sketch");

        let ext = engine
            .on_message(
                13,
                WireMessage::ReqSketchExt {
                    salt: 99,
                    capacity: 16,
                },
            )
            .expect("reqsketchext");
        let ext_bytes_len = ext
            .iter()
            .find_map(|msg| match &msg.message {
                WireMessage::Sketch { bytes, .. } => Some(bytes.len()),
                _ => None,
            })
            .expect("extended sketch");
        assert!(
            ext_bytes_len >= first_bytes_len,
            "extended sketch should be at least as large"
        );
        assert!(
            !ext.iter()
                .any(|msg| matches!(msg.message, WireMessage::ReconcileDiff { .. })),
            "no collision diff should be emitted when snapshot has no short-id collisions"
        );
    }

    #[test]
    fn send_recon_disable_clears_cached_rounds() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(93);
        engine
            .on_message(
                93,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 93,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("enable recon");
        let req = engine
            .maybe_start_reconciliation(93, 1_000)
            .expect("start recon");
        let salt = match req[0].message {
            WireMessage::ReqRecon { salt, .. } => salt,
            ref other => panic!("expected reqrecon, got {other:?}"),
        };
        assert!(
            engine
                .peers
                .get(&93)
                .and_then(|state| state.recon_rounds.get(&salt))
                .is_some()
        );
        engine
            .on_message(
                93,
                WireMessage::SendRecon {
                    enabled: false,
                    version: 0,
                    short_id_bits: 0,
                    implementation: 0,
                    salt: 0,
                    max_sketch_items: 0,
                    max_diff_items: 0,
                },
            )
            .expect("disable recon");
        assert!(
            engine
                .peers
                .get(&93)
                .is_some_and(|state| state.recon_rounds.is_empty())
        );
    }

    #[test]
    fn req_recon_replaces_oldest_round_when_tracking_limit_reached() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(94);
        engine
            .on_message(
                94,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 94,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("enable");
        for idx in 1..=super::RECON_MAX_TRACKED_ROUNDS_PER_PEER {
            engine
                .on_message(
                    94,
                    WireMessage::ReqRecon {
                        salt: idx as u64,
                        set_size: 8,
                    },
                )
                .expect("seed rounds");
        }
        assert_eq!(
            engine.peers.get(&94).expect("peer").recon_rounds.len(),
            super::RECON_MAX_TRACKED_ROUNDS_PER_PEER
        );
        engine
            .on_message(
                94,
                WireMessage::ReqRecon {
                    salt: 999,
                    set_size: 8,
                },
            )
            .expect("extra round");
        let rounds = &engine.peers.get(&94).expect("peer").recon_rounds;
        assert_eq!(rounds.len(), super::RECON_MAX_TRACKED_ROUNDS_PER_PEER);
        assert!(rounds.contains_key(&999));
    }

    #[test]
    fn req_sketch_ext_rejects_non_responder_rounds() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(95);
        engine
            .on_message(
                95,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 95,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("enable");
        let req = engine
            .maybe_start_reconciliation(95, 1_000)
            .expect("start recon");
        let salt = match req[0].message {
            WireMessage::ReqRecon { salt, .. } => salt,
            ref other => panic!("expected reqrecon, got {other:?}"),
        };
        let err = engine
            .on_message(95, WireMessage::ReqSketchExt { salt, capacity: 16 })
            .expect_err("initiator round must reject reqsketchext");
        assert!(matches!(err, super::GossipError::Recon(_)));
    }

    #[test]
    fn handle_sketch_accepts_payload_at_exact_serialized_limit() {
        let mut engine = GossipEngine::new(8).expect("engine");
        engine.connect_peer(96);
        engine
            .on_message(
                96,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 96,
                    max_sketch_items: 8,
                    max_diff_items: 8,
                },
            )
            .expect("enable");
        let req = engine
            .maybe_start_reconciliation(96, 1_000)
            .expect("start recon");
        let (salt, capacity) = match req[0].message {
            WireMessage::ReqRecon { salt, set_size } => (salt, set_size as usize),
            ref other => panic!("expected reqrecon, got {other:?}"),
        };
        let max_serialized_len =
            (((super::RECON_BITS as usize).saturating_mul(capacity)) / 8).max(1);
        let payload = vec![0u8; max_serialized_len.saturating_mul(2)];
        let out = engine
            .on_message(
                96,
                WireMessage::Sketch {
                    salt,
                    bits: super::RECON_BITS,
                    capacity: capacity as u32,
                    implementation: 0,
                    bytes: payload,
                },
            )
            .expect("exact payload boundary should pass");
        assert!(
            out.iter().all(|msg| matches!(
                msg.message,
                WireMessage::ReqTx { .. } | WireMessage::ReconcileDiff { .. }
            )),
            "payload boundary should not trigger size rejection"
        );
    }

    #[test]
    fn handle_sketch_decode_failure_requests_extension_then_falls_back() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(97);
        engine
            .on_message(
                97,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 97,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("enable");
        let req = engine
            .maybe_start_reconciliation(97, 1_000)
            .expect("start recon");
        let salt = match req[0].message {
            WireMessage::ReqRecon { salt, .. } => salt,
            ref other => panic!("expected reqrecon, got {other:?}"),
        };

        {
            let round = engine
                .peers
                .get_mut(&97)
                .and_then(|state| state.recon_rounds.get_mut(&salt))
                .expect("round");
            round.snapshot.txids = vec![scam_core::hash::hash256(b"fallback")];
            round.snapshot.unique_short_ids.clear();
            round.snapshot.short_to_txids.clear();
            round.snapshot.collision_txids.clear();
            round.capacity = 1;
        }
        let mut remote = Minisketch::try_new(super::RECON_BITS, 0, 1).expect("remote sketch");
        remote.set_seed(salt);
        remote.add(123_456_789);
        let mut bad_payload = vec![0u8; remote.serialized_size()];
        remote
            .serialize(&mut bad_payload)
            .expect("serialize remote sketch");
        let first = engine
            .on_message(
                97,
                WireMessage::Sketch {
                    salt,
                    bits: super::RECON_BITS,
                    capacity: 1,
                    implementation: 0,
                    bytes: bad_payload.clone(),
                },
            )
            .expect("first saturated sketch should request extension");
        assert!(
            first
                .iter()
                .any(|msg| matches!(msg.message, WireMessage::ReqSketchExt { .. }))
        );

        {
            let round = engine
                .peers
                .get_mut(&97)
                .and_then(|state| state.recon_rounds.get_mut(&salt))
                .expect("round");
            round.extension_requests = super::RECON_MAX_EXTENSION_REQUESTS;
        }
        let second = engine
            .on_message(
                97,
                WireMessage::Sketch {
                    salt,
                    bits: super::RECON_BITS,
                    capacity: 1,
                    implementation: 0,
                    bytes: bad_payload,
                },
            )
            .expect("extension limit should force fallback");
        assert!(
            second
                .iter()
                .any(|msg| matches!(msg.message, WireMessage::ReconcileDiff { .. }))
        );
    }

    #[test]
    fn handle_sketch_ignores_zero_and_local_short_ids_in_missing_requests() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(98);
        engine
            .on_message(
                98,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 98,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("enable");
        let req = engine
            .maybe_start_reconciliation(98, 1_000)
            .expect("start recon");
        let (salt, capacity) = match req[0].message {
            WireMessage::ReqRecon { salt, set_size } => (salt, set_size as usize),
            ref other => panic!("expected reqrecon, got {other:?}"),
        };

        let local_short = 42u64;
        {
            let round = engine
                .peers
                .get_mut(&98)
                .and_then(|state| state.recon_rounds.get_mut(&salt))
                .expect("round");
            round.snapshot.unique_short_ids = vec![local_short];
            round.snapshot.short_to_txids.clear();
            round.snapshot.collision_txids.clear();
            round.snapshot.txids.clear();
        }

        let mut remote = Minisketch::try_new(super::RECON_BITS, 0, capacity).expect("remote");
        remote.set_seed(salt);
        remote.add(0);
        remote.add(local_short);
        remote.add(77);
        let mut payload = vec![0u8; remote.serialized_size()];
        remote.serialize(&mut payload).expect("serialize");

        let out = engine
            .on_message(
                98,
                WireMessage::Sketch {
                    salt,
                    bits: super::RECON_BITS,
                    capacity: capacity as u32,
                    implementation: 0,
                    bytes: payload,
                },
            )
            .expect("handle sketch");
        let req_tx = out
            .iter()
            .find_map(|msg| match &msg.message {
                WireMessage::ReqTx { short_ids, .. } => Some(short_ids.clone()),
                _ => None,
            })
            .expect("expected reqtx");
        assert_eq!(req_tx, vec![77], "must ignore zero and local short IDs");
    }

    #[test]
    fn reconcile_diff_can_request_and_announce_txids() {
        let mut engine = GossipEngine::new(32).expect("engine");
        engine.connect_peer(55);
        let local = sample_tx(42);
        let local_txid = local.txid();
        engine.announce_tx(local);
        let unknown_txid = scam_core::hash::hash256(b"recon-unknown");

        let out = engine
            .on_message(
                55,
                WireMessage::ReconcileDiff {
                    salt: 123,
                    announce_txids: vec![unknown_txid],
                    request_txids: vec![local_txid],
                },
            )
            .expect("reconcile diff");

        assert!(
            out.iter()
                .any(|msg| matches!(msg.message, WireMessage::GetData { .. })),
            "announce path should request unknown tx"
        );
        assert!(
            out.iter()
                .any(|msg| matches!(msg.message, WireMessage::Tx { .. })),
            "request path should serve local tx"
        );
    }

    #[test]
    fn with_limits_and_replacement_derives_nontrivial_recon_salt_keys() {
        let replacement = ReplacementRateLimit {
            window_sec: 7,
            max_replacements: 5,
            penalty: 9,
        };
        let engine =
            GossipEngine::with_limits_and_replacement(16, 33, replacement).expect("engine config");

        let expected_key0 = 0x7265_636f_6e5f_6b30u64 ^ 16u64 ^ ((33u64) << 32);
        let expected_key1 = 0x7265_636f_6e5f_6b31u64 ^ 7u64 ^ ((5u64) << 32);
        assert_eq!(engine.recon_salt_key0, expected_key0);
        assert_eq!(engine.recon_salt_key1, expected_key1);
        assert_ne!(engine.recon_salt_key0, 0);
        assert_ne!(engine.recon_salt_key1, 0);
    }

    #[test]
    fn tx_inventory_len_tracks_announced_transactions() {
        let mut engine = GossipEngine::new(32).expect("engine");
        assert_eq!(engine.tx_inventory_len(), 0);
        engine.announce_tx(sample_tx(1));
        assert_eq!(engine.tx_inventory_len(), 1);
        engine.announce_tx(sample_tx(2));
        assert_eq!(engine.tx_inventory_len(), 2);
    }

    #[test]
    fn peer_supports_reconciliation_requires_full_negotiation_state() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(91);
        assert!(!engine.peer_supports_reconciliation(91));

        engine
            .on_message(
                91,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 91,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("negotiate recon");
        assert!(engine.peer_supports_reconciliation(91));

        engine
            .on_message(
                91,
                WireMessage::SendRecon {
                    enabled: false,
                    version: 0,
                    short_id_bits: 0,
                    implementation: 0,
                    salt: 0,
                    max_sketch_items: 0,
                    max_diff_items: 0,
                },
            )
            .expect("disable recon");
        assert!(!engine.peer_supports_reconciliation(91));
    }

    #[test]
    fn peer_supports_reconciliation_rejects_each_missing_requirement() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(92);
        engine
            .on_message(
                92,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 92,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("negotiate");
        assert!(engine.peer_supports_reconciliation(92));

        {
            let state = engine.peers.get_mut(&92).expect("peer state");
            state.recon_enabled = false;
        }
        assert!(!engine.peer_supports_reconciliation(92));
        {
            let state = engine.peers.get_mut(&92).expect("peer state");
            state.recon_enabled = true;
            state.recon_version = 0;
        }
        assert!(!engine.peer_supports_reconciliation(92));
        {
            let state = engine.peers.get_mut(&92).expect("peer state");
            state.recon_version = super::RECON_VERSION + 1;
        }
        assert!(!engine.peer_supports_reconciliation(92));
        {
            let state = engine.peers.get_mut(&92).expect("peer state");
            state.recon_version = 1;
            state.recon_short_id_bits = 16;
        }
        assert!(!engine.peer_supports_reconciliation(92));
        {
            let state = engine.peers.get_mut(&92).expect("peer state");
            state.recon_short_id_bits = super::RECON_BITS as u8;
            state.recon_implementation = 1;
        }
        assert!(!engine.peer_supports_reconciliation(92));
        {
            let state = engine.peers.get_mut(&92).expect("peer state");
            state.recon_implementation = 0;
            state.recon_remote_salt = 0;
        }
        assert!(!engine.peer_supports_reconciliation(92));
    }

    #[test]
    fn recon_capacity_zero_maps_to_max_inv_and_nonzero_is_clamped() {
        let engine = GossipEngine::new(17).expect("engine");
        assert_eq!(engine.recon_capacity_from_requested(0), 17);
        assert_eq!(engine.recon_capacity_from_requested(1), 1);
        assert_eq!(engine.recon_capacity_from_requested(500), 17);
    }

    #[test]
    fn build_recon_sketch_roundtrip_decodes_same_short_ids() {
        let engine = GossipEngine::new(32).expect("engine");
        let salt = 0x1234_5678_9abc_def0;
        let short_ids = vec![1u64, 7u64, 13u64];
        let bytes = engine
            .build_recon_sketch(salt, 8, 0, &short_ids)
            .expect("build sketch");
        assert!(!bytes.is_empty(), "serialized sketch must not be empty");

        let mut sketch = Minisketch::try_new(super::RECON_BITS, 0, 8).expect("sketch");
        sketch.set_seed(salt);
        sketch.deserialize(&bytes);

        let mut expected = Minisketch::try_new(super::RECON_BITS, 0, 8).expect("expected sketch");
        expected.set_seed(salt);
        for id in short_ids {
            expected.add(id);
        }
        sketch.merge(&expected).expect("merge");
        let mut decoded = vec![0u64; 8];
        let count = sketch.decode(&mut decoded).expect("decode");
        assert_eq!(
            count, 0,
            "identical sketches should reconcile to empty diff"
        );
    }

    #[test]
    fn build_recon_snapshot_respects_max_items_cap() {
        let mut engine = GossipEngine::new(32).expect("engine");
        for seed in 0u8..10u8 {
            engine.announce_tx(sample_tx(seed));
        }
        let snapshot = engine
            .build_recon_snapshot(0x55aa55aa55aa55aa, 3, 0)
            .expect("snapshot");
        assert_eq!(
            snapshot.txids.len(),
            3,
            "snapshot should respect caller max_items"
        );
        assert!(
            snapshot.unique_short_ids.len() <= snapshot.txids.len(),
            "unique short ids cannot exceed snapshot txids"
        );
    }

    #[test]
    fn recon_round_salt_is_deterministic_and_changes_with_nonce() {
        let engine = GossipEngine::new(16).expect("engine");
        let implementation = 0x0102_0304u32;
        let salt_a = engine.recon_round_salt(7, 1_000, 1, 11, 22, implementation);
        let salt_b = engine.recon_round_salt(7, 1_000, 1, 11, 22, implementation);
        let salt_c = engine.recon_round_salt(7, 1_000, 2, 11, 22, implementation);
        let mut expected = siphasher::sip::SipHasher24::new_with_keys(
            engine.recon_salt_key0 ^ (implementation as u64),
            engine.recon_salt_key1 ^ 7,
        );
        use std::hash::Hasher;
        expected.write_u64(1_000);
        expected.write_u64(7);
        expected.write_u64(1);
        expected.write_u64(11);
        expected.write_u64(22);
        let expected = expected.finish();
        assert_eq!(salt_a, salt_b);
        assert_eq!(salt_a, expected);
        assert_ne!(salt_a, 0);
        assert_ne!(salt_a, salt_c);
    }

    #[test]
    fn local_recon_salt_is_nonzero_and_peer_specific() {
        let engine = GossipEngine::new(16).expect("engine");
        let a = engine.local_recon_salt_for_peer(1);
        let b = engine.local_recon_salt_for_peer(1);
        let c = engine.local_recon_salt_for_peer(2);
        assert_eq!(a, b);
        assert_ne!(a, 0);
        assert_ne!(a, c);
    }

    #[test]
    fn remove_recon_round_actually_removes_cached_round() {
        let mut engine = GossipEngine::new(16).expect("engine");
        engine.connect_peer(5);
        engine
            .on_message(
                5,
                WireMessage::SendRecon {
                    enabled: true,
                    version: 1,
                    short_id_bits: super::RECON_BITS as u8,
                    implementation: 0,
                    salt: 5,
                    max_sketch_items: 16,
                    max_diff_items: 16,
                },
            )
            .expect("sendrecon");
        let req = engine
            .maybe_start_reconciliation(5, 1_000)
            .expect("start recon");
        let salt = match req[0].message {
            WireMessage::ReqRecon { salt, .. } => salt,
            ref other => panic!("expected reqrecon, got {other:?}"),
        };
        assert!(
            engine
                .peers
                .get(&5)
                .and_then(|state| state.recon_rounds.get(&salt))
                .is_some()
        );
        engine.remove_recon_round(5, salt);
        assert!(
            engine
                .peers
                .get(&5)
                .and_then(|state| state.recon_rounds.get(&salt))
                .is_none()
        );
    }

    #[test]
    fn req_tx_accepts_exact_max_inv_boundary() {
        let mut engine = GossipEngine::with_limits(2, 100).expect("engine");
        engine.connect_peer(70);
        engine.announce_tx(sample_tx(1));
        engine.announce_tx(sample_tx(2));
        let salt = 0x7777_1111_2222_3333u64;
        let snapshot = engine.build_recon_snapshot(salt, 2, 0).expect("snapshot");
        let short_ids = snapshot
            .unique_short_ids
            .iter()
            .copied()
            .take(2)
            .collect::<Vec<_>>();
        let out = engine
            .on_message(70, WireMessage::ReqTx { salt, short_ids })
            .expect("reqtx exact max should pass");
        assert!(!out.is_empty(), "reqtx should emit tx responses");
    }

    #[test]
    fn reconcile_diff_enforces_limit_for_each_direction_independently() {
        let mut engine = GossipEngine::new(2).expect("engine");
        engine.connect_peer(88);

        let too_many_announce = engine
            .on_message(
                88,
                WireMessage::ReconcileDiff {
                    salt: 1,
                    announce_txids: vec![
                        scam_core::hash::hash256(b"a"),
                        scam_core::hash::hash256(b"b"),
                        scam_core::hash::hash256(b"c"),
                    ],
                    request_txids: vec![],
                },
            )
            .expect_err("announce side over diff limit should fail");
        assert!(matches!(
            too_many_announce,
            super::GossipError::TooManyInventoryItems { .. }
        ));

        let too_many_request = engine
            .on_message(
                88,
                WireMessage::ReconcileDiff {
                    salt: 2,
                    announce_txids: vec![],
                    request_txids: vec![
                        scam_core::hash::hash256(b"ra"),
                        scam_core::hash::hash256(b"rb"),
                        scam_core::hash::hash256(b"rc"),
                    ],
                },
            )
            .expect_err("request side over diff limit should fail");
        assert!(matches!(
            too_many_request,
            super::GossipError::TooManyInventoryItems { .. }
        ));
    }

    #[test]
    fn recon_short_id_is_stable_and_matches_known_vector() {
        let txid = scam_core::hash::hash256(b"recon-short-id-vector");
        let salt = 0x1234_5678_9abc_def0u64;
        let implementation = 0x0102_0304u32;
        let id = super::recon_short_id(txid, salt, implementation);
        let key0 = salt ^ ((implementation as u64) << 32);
        let key1 = !salt ^ 0x9E37_79B9_7F4A_7C15u64;
        let mut hasher = siphasher::sip::SipHasher24::new_with_keys(key0, key1);
        use std::hash::Hasher;
        hasher.write(&txid.0);
        let expected = hasher.finish() & ((1u64 << super::RECON_BITS) - 1);
        assert_eq!(id, expected);
        assert_eq!(id, super::recon_short_id(txid, salt, implementation));
        assert_ne!(id, super::recon_short_id(txid, salt ^ 1, implementation));
    }
}
