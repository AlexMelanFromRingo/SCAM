#![cfg_attr(not(test), deny(clippy::unwrap_used))]
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use num_bigint::BigUint;
use scam_consensus::{
    BlockApplyContext, BlockApplySummary, BlockSizeLimits, BlockUndoData, BlockValidationError,
    UndoError, UtxoSet, asert_next, chainwork_for_target, lwma_next, retarget_next,
    revert_block_undo, validate_and_apply_block_with_undo, validate_block_basic,
};
use scam_core::{Block, BlockHeader, ChainConfig, DifficultyAlgorithm, Hash256, Target};
use thiserror::Error;

const MEDIAN_TIME_PAST_WINDOW: usize = 11;
const MAX_FUTURE_BLOCK_TIME_SEC: u64 = 2 * 60 * 60;
/// Deepest reorganization the runtime performs automatically. Side
/// branches forking below `tip - MAX_REORG_DEPTH` are refused and pruned,
/// and undo data older than that is dropped. This bounds memory for
/// side-branch storage and undo records; a deeper reorg requires an
/// operator to resync from a trusted peer.
pub const MAX_REORG_DEPTH: u64 = 720;
/// Prune side branches / undo data every this many tip changes.
const PRUNE_INTERVAL_BLOCKS: u64 = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockSubmissionOutcome {
    AlreadyKnown {
        block_hash: Hash256,
    },
    StoredSideBranch {
        block_hash: Hash256,
    },
    ExtendedTip {
        new_tip: Hash256,
        new_height: u64,
    },
    Reorged {
        old_tip: Hash256,
        new_tip: Hash256,
        new_height: u64,
    },
}

pub struct ChainRuntime {
    config: ChainConfig,
    utxos: UtxoSet,
    blocks: HashMap<Hash256, Block>,
    headers: HashMap<Hash256, BlockHeader>,
    heights: HashMap<Hash256, u64>,
    cumulative_work: HashMap<Hash256, BigUint>,
    main_chain: Vec<Hash256>,
    undo_data: HashMap<Hash256, BlockUndoData>,
    /// Blocks that passed proof-of-work at the expected target but failed
    /// full validation. Descendants are rejected without revalidation.
    invalid_blocks: HashSet<Hash256>,
    max_reorg_depth: u64,
    tip_changes: u64,
}

impl ChainRuntime {
    pub fn from_config(config: ChainConfig) -> Result<Self, ChainError> {
        config.validate()?;
        let genesis = config.build_genesis_block()?;
        Self::new(config, genesis)
    }

    /// Rebuild a runtime from a locally stored, height-ordered main chain.
    ///
    /// Every block is fully revalidated, except for the wall-clock
    /// "too far in the future" rule: these blocks were accepted earlier,
    /// and a host whose clock is behind must still be able to restart.
    pub fn from_ordered_blocks(
        config: ChainConfig,
        blocks_by_height: Vec<Block>,
    ) -> Result<Self, ChainError> {
        let Some(first) = blocks_by_height.first() else {
            return Err(ChainError::InvalidRuntime(
                "ordered chain blocks cannot be empty".to_owned(),
            ));
        };
        config.validate()?;
        let expected_genesis = config.build_genesis_block()?;
        let expected_hash = expected_genesis.header.block_hash();
        let got_hash = first.header.block_hash();
        if got_hash != expected_hash {
            return Err(ChainError::UnexpectedGenesis {
                expected: expected_hash,
                got: got_hash,
            });
        }

        let mut runtime = Self::new(config, first.clone())?;
        for block in blocks_by_height.into_iter().skip(1) {
            runtime.apply_next_block_inner(block, false)?;
        }
        Ok(runtime)
    }

    pub fn new(config: ChainConfig, genesis: Block) -> Result<Self, ChainError> {
        let mut utxos = UtxoSet::new();
        let limits = BlockSizeLimits::from_chain_config(&config);
        // Subsidy at height 0 — `subsidy_at_height(0)` is by definition
        // `block_subsidy` for any valid config, but routing through the
        // helper keeps the rule in one place.
        // Genesis MTP: no predecessors, so the only available clock is
        // the genesis header timestamp itself. Any CSV time-lock against
        // genesis would be unsatisfiable in the height-since-genesis<11
        // window regardless of MTP semantics, so this fallback is safe.
        let ctx = BlockApplyContext {
            current_height: 0,
            block_subsidy: config.subsidy_at_height(0),
            coinbase_maturity: config.coinbase_maturity as u64,
            chain_domain: config.network_id.as_bytes(),
            limits,
            median_time_past: Some(genesis.header.timestamp),
        };
        let (applied, _) = validate_and_apply_block_with_undo(&genesis, ctx, &mut utxos)?;

        let genesis_hash = applied.block_hash;
        let genesis_header = genesis.header.clone();
        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash, genesis);
        let mut headers = HashMap::new();
        headers.insert(genesis_hash, genesis_header.clone());
        let mut heights = HashMap::new();
        heights.insert(genesis_hash, 0);
        let mut cumulative_work = HashMap::new();
        cumulative_work.insert(genesis_hash, chainwork_for_target(genesis_header.target));

        Ok(Self {
            config,
            utxos,
            blocks,
            headers,
            heights,
            cumulative_work,
            main_chain: vec![genesis_hash],
            undo_data: HashMap::new(),
            invalid_blocks: HashSet::new(),
            max_reorg_depth: MAX_REORG_DEPTH,
            tip_changes: 0,
        })
    }

    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    pub fn tip_height(&self) -> u64 {
        (self.main_chain.len() - 1) as u64
    }

    pub fn tip_hash(&self) -> Hash256 {
        *self.main_chain.last().expect("chain always has genesis")
    }

    pub fn tip_header(&self) -> &BlockHeader {
        self.headers
            .get(&self.tip_hash())
            .expect("tip header must exist")
    }

    pub fn block_hashes(&self) -> &[Hash256] {
        &self.main_chain
    }

    pub fn block_hash_at_height(&self, height: u64) -> Option<Hash256> {
        self.main_chain.get(height as usize).copied()
    }

    pub fn block_by_hash(&self, hash: &Hash256) -> Option<&Block> {
        self.blocks.get(hash)
    }

    pub fn main_chain_blocks(&self) -> Result<Vec<Block>, ChainError> {
        let mut blocks = Vec::with_capacity(self.main_chain.len());
        for hash in &self.main_chain {
            let block = self
                .blocks
                .get(hash)
                .ok_or(ChainError::MissingBlock { block_hash: *hash })?;
            blocks.push(block.clone());
        }
        Ok(blocks)
    }

    pub fn utxo_set(&self) -> &UtxoSet {
        &self.utxos
    }

    pub fn utxo_len(&self) -> usize {
        self.utxos.len()
    }

    pub fn cumulative_work(&self) -> &BigUint {
        self.cumulative_work
            .get(&self.tip_hash())
            .expect("tip work must exist")
    }

    pub fn header_by_hash(&self, hash: &Hash256) -> Option<&BlockHeader> {
        self.headers.get(hash)
    }

    /// Height of any stored block (main chain or side branch).
    pub fn height_of(&self, hash: &Hash256) -> Option<u64> {
        self.heights.get(hash).copied()
    }

    pub fn is_known_invalid(&self, hash: &Hash256) -> bool {
        self.invalid_blocks.contains(hash)
    }

    pub fn median_time_past_for_tip(&self) -> Result<u64, ChainError> {
        self.median_time_past(self.tip_hash())
    }
    /// Evaluate a single BIP9-style deployment against the current main
    /// chain. Walks retarget windows from genesis forward, tallying
    /// signaling bit-count per window and stepping the state machine.
    /// Returns the state observable at the tip.
    ///
    /// O(tip_height) and recomputed every call. For production hot
    /// paths cache the result keyed by (deployment.bit, window_index of
    /// tip). For audit / RPC / TUI display this is fine.
    pub fn versionbits_state(
        &self,
        deployment: &scam_core::Deployment,
    ) -> Result<scam_core::DeploymentState, ChainError> {
        let window = self.config.versionbits_window_blocks;
        let threshold = self.config.versionbits_threshold;
        if window == 0 || threshold == 0 {
            return Ok(scam_core::DeploymentState::Defined);
        }

        let tip_h = self.tip_height();
        let mut state = scam_core::DeploymentState::Defined;
        let mut window_start: u64 = 0;
        while window_start + window <= tip_h.saturating_add(1) {
            // Count signaling headers in the just-completed window
            // [window_start, window_start + window).
            let mut signal_count: u32 = 0;
            for h in window_start..(window_start + window) {
                let Some(hash) = self.block_hash_at_height(h) else {
                    return Err(ChainError::MissingHeader {
                        block_hash: scam_core::Hash256::ZERO,
                    });
                };
                let header = self
                    .headers
                    .get(&hash)
                    .ok_or(ChainError::MissingHeader { block_hash: hash })?;
                if scam_core::deployment_bit_signaled(header.version, deployment.bit) {
                    signal_count = signal_count.saturating_add(1);
                }
            }
            // MTP at the boundary block (last block of the window).
            let boundary_hash = self.block_hash_at_height(window_start + window - 1).ok_or(
                ChainError::MissingHeader {
                    block_hash: scam_core::Hash256::ZERO,
                },
            )?;
            let boundary_mtp = self.median_time_past(boundary_hash)?;
            state = scam_core::next_state(
                state,
                signal_count,
                boundary_mtp,
                deployment,
                threshold,
                window,
            );
            window_start += window;
        }
        Ok(state)
    }

    fn median_time_past(&self, parent_hash: Hash256) -> Result<u64, ChainError> {
        let mut timestamps = Vec::with_capacity(MEDIAN_TIME_PAST_WINDOW);
        let mut cursor = Some(parent_hash);

        for _ in 0..MEDIAN_TIME_PAST_WINDOW {
            let Some(hash) = cursor else {
                break;
            };
            let header = self
                .headers
                .get(&hash)
                .ok_or(ChainError::MissingHeader { block_hash: hash })?;
            timestamps.push(header.timestamp);

            if header.prev_block == Hash256::ZERO {
                break;
            }
            cursor = Some(header.prev_block);
        }

        if timestamps.is_empty() {
            return Err(ChainError::InvalidRuntime(
                "cannot compute median-time-past without headers".to_owned(),
            ));
        }
        timestamps.sort_unstable();
        Ok(timestamps[timestamps.len() / 2])
    }

    fn validate_contextual_timestamps(
        &self,
        block: &Block,
        check_future: bool,
    ) -> Result<(), ChainError> {
        let block_hash = block.header.block_hash();
        let median_time_past = self.median_time_past(block.header.prev_block)?;
        if block.header.timestamp <= median_time_past {
            return Err(ChainError::TimestampTooOld {
                block_hash,
                median_time_past,
                got: block.header.timestamp,
            });
        }

        if check_future {
            let now = current_unix_timestamp()?;
            let max_allowed = now.saturating_add(MAX_FUTURE_BLOCK_TIME_SEC);
            if block.header.timestamp > max_allowed {
                return Err(ChainError::TimestampTooFarInFuture {
                    block_hash,
                    got: block.header.timestamp,
                    max_allowed,
                });
            }
        }

        Ok(())
    }

    pub fn expected_target_for_next_block(&self) -> Result<Target, ChainError> {
        self.expected_target_for_child_of(self.tip_hash())
    }

    /// Difficulty a child of `parent_hash` must carry, evaluated on the
    /// parent's own branch (main chain or side branch).
    pub fn expected_target_for_child_of(&self, parent_hash: Hash256) -> Result<Target, ChainError> {
        let window = self.config.difficulty_adjustment_window as u64;
        if window == 0 {
            return Err(ChainError::InvalidRuntime(
                "difficulty_adjustment_window must be > 0".to_owned(),
            ));
        }
        let parent_height = self
            .height_of(&parent_hash)
            .ok_or(ChainError::MissingHeader {
                block_hash: parent_hash,
            })?;
        let parent = self
            .headers
            .get(&parent_hash)
            .ok_or(ChainError::MissingHeader {
                block_hash: parent_hash,
            })?;
        let next_height = parent_height + 1;
        let max_target = self.config.genesis_target()?;

        match self.config.difficulty_algorithm {
            DifficultyAlgorithm::Windowed => {
                if !next_height.is_multiple_of(window) {
                    return Ok(parent.target);
                }

                // Windows overlap by one block: the timespan is measured
                // from the *last* block of the previous window. With
                // disjoint windows the gap between a window's last block
                // and the next window's first block is never measured,
                // which is the classic timewarp hole.
                let start_height = next_height.saturating_sub(window + 1);
                let start_hash = self.ancestor_hash(parent_hash, parent_height, start_height)?;
                let start_header =
                    self.headers
                        .get(&start_hash)
                        .ok_or(ChainError::MissingHeader {
                            block_hash: start_hash,
                        })?;
                let intervals = (parent_height - start_height).max(1);
                let actual_timespan = parent
                    .timestamp
                    .saturating_sub(start_header.timestamp)
                    .max(1);
                let expected_timespan = intervals * self.config.target_block_time_sec;

                retarget_next(
                    parent.target,
                    actual_timespan,
                    expected_timespan,
                    self.config.difficulty_clamp_down,
                    self.config.difficulty_clamp_up,
                    max_target,
                )
                .map_err(ChainError::Difficulty)
            }
            DifficultyAlgorithm::Lwma => {
                let history = parent_height + 1;
                if history < window + 1 {
                    return Ok(parent.target);
                }
                let mut targets = Vec::with_capacity(window as usize + 1);
                let mut timestamps = Vec::with_capacity(window as usize + 1);
                let mut cursor = parent_hash;
                for _ in 0..=window {
                    let header = self
                        .headers
                        .get(&cursor)
                        .ok_or(ChainError::MissingHeader { block_hash: cursor })?;
                    targets.push(header.target);
                    timestamps.push(header.timestamp);
                    cursor = header.prev_block;
                }
                targets.reverse();
                timestamps.reverse();

                lwma_next(
                    &targets,
                    &timestamps,
                    self.config.target_block_time_sec,
                    max_target,
                )
                .map_err(ChainError::Difficulty)
            }
            DifficultyAlgorithm::Asert => {
                if parent_height == 0 {
                    return Ok(parent.target);
                }
                let grandparent =
                    self.headers
                        .get(&parent.prev_block)
                        .ok_or(ChainError::MissingHeader {
                            block_hash: parent.prev_block,
                        })?;
                let observed = parent
                    .timestamp
                    .saturating_sub(grandparent.timestamp)
                    .max(1);
                asert_next(
                    parent.target,
                    observed,
                    self.config.target_block_time_sec,
                    self.config.asert_half_life_sec,
                    max_target,
                )
                .map_err(ChainError::Difficulty)
            }
        }
    }

    /// Hash of the ancestor of `from` (at `from_height`) at `target_height`.
    fn ancestor_hash(
        &self,
        from: Hash256,
        from_height: u64,
        target_height: u64,
    ) -> Result<Hash256, ChainError> {
        if self.is_on_main_chain(&from, from_height) {
            return self
                .block_hash_at_height(target_height)
                .ok_or(ChainError::MissingHeader { block_hash: from });
        }
        let mut cursor = from;
        for _ in target_height..from_height {
            cursor = self
                .headers
                .get(&cursor)
                .ok_or(ChainError::MissingHeader { block_hash: cursor })?
                .prev_block;
        }
        Ok(cursor)
    }

    fn is_on_main_chain(&self, hash: &Hash256, height: u64) -> bool {
        self.main_chain.get(height as usize) == Some(hash)
    }

    /// Append a block on top of the current tip. The block must extend the
    /// tip; it is fully validated before anything is stored.
    pub fn apply_next_block(&mut self, block: Block) -> Result<BlockApplySummary, ChainError> {
        self.apply_next_block_inner(block, true)
    }

    fn apply_next_block_inner(
        &mut self,
        block: Block,
        check_future: bool,
    ) -> Result<BlockApplySummary, ChainError> {
        if block.header.prev_block != self.tip_hash() {
            return Err(ChainError::PrevBlockMustBeTip {
                expected_tip: self.tip_hash(),
                got_prev: block.header.prev_block,
            });
        }
        let (summary, undo) = self.validate_and_connect(&block, check_future)?;
        let block_hash = summary.block_hash;
        let prev_work = self
            .cumulative_work
            .get(&block.header.prev_block)
            .expect("tip work must exist")
            .clone();
        let work = prev_work + chainwork_for_target(block.header.target);
        self.cumulative_work.insert(block_hash, work);
        self.heights.insert(block_hash, self.tip_height() + 1);
        self.headers.insert(block_hash, block.header.clone());
        self.blocks.insert(block_hash, block);
        self.main_chain.push(block_hash);
        self.undo_data.insert(block_hash, undo);
        self.on_tip_changed();
        Ok(summary)
    }

    /// Contextual checks + UTXO application for a block whose parent is the
    /// current tip. Mutates only the UTXO set, and only on success.
    fn validate_and_connect(
        &mut self,
        block: &Block,
        check_future: bool,
    ) -> Result<(BlockApplySummary, BlockUndoData), ChainError> {
        self.validate_contextual_timestamps(block, check_future)?;
        let expected_target = self.expected_target_for_next_block()?;
        if block.header.target != expected_target {
            return Err(ChainError::UnexpectedTarget {
                expected: expected_target,
                got: block.header.target,
            });
        }

        let height = self.tip_height() + 1;
        // BIP68: time-locked sequences compare against MTP of the
        // prior-11-headers. The new block isn't applied yet, so MTP
        // is computed from the parent (current tip).
        let mtp = self.median_time_past(self.tip_hash())?;
        let ctx = BlockApplyContext {
            current_height: height,
            block_subsidy: self.config.subsidy_at_height(height),
            coinbase_maturity: self.config.coinbase_maturity as u64,
            chain_domain: self.config.network_id.as_bytes(),
            limits: BlockSizeLimits::from_chain_config(&self.config),
            median_time_past: Some(mtp),
        };
        Ok(validate_and_apply_block_with_undo(
            block,
            ctx,
            &mut self.utxos,
        )?)
    }

    pub fn submit_block(&mut self, block: Block) -> Result<BlockSubmissionOutcome, ChainError> {
        validate_block_basic(&block, BlockSizeLimits::from_chain_config(&self.config))
            .map_err(ChainError::InvalidBlockStructure)?;

        let block_hash = block.header.block_hash();
        if self.headers.contains_key(&block_hash) {
            return Ok(BlockSubmissionOutcome::AlreadyKnown { block_hash });
        }
        if self.invalid_blocks.contains(&block_hash) {
            return Err(ChainError::KnownInvalid { block_hash });
        }
        let parent_hash = block.header.prev_block;
        if self.invalid_blocks.contains(&parent_hash) {
            self.invalid_blocks.insert(block_hash);
            return Err(ChainError::InvalidAncestor {
                block_hash,
                ancestor: parent_hash,
            });
        }
        let Some(parent_height) = self.height_of(&parent_hash) else {
            return Err(ChainError::UnknownParent {
                block_hash,
                parent: parent_hash,
            });
        };
        let height = parent_height + 1;
        let tip_height = self.tip_height();
        if height.saturating_add(self.max_reorg_depth) <= tip_height {
            return Err(ChainError::ForkTooDeep {
                block_hash,
                fork_height: parent_height,
                tip_height,
                max_reorg_depth: self.max_reorg_depth,
            });
        }
        self.validate_contextual_timestamps(&block, true)?;
        // The claimed target must be the one this branch requires; otherwise
        // a side-branch block could carry `Target::MAX` and cost nothing.
        let expected_target = self.expected_target_for_child_of(parent_hash)?;
        if block.header.target != expected_target {
            return Err(ChainError::UnexpectedTarget {
                expected: expected_target,
                got: block.header.target,
            });
        }

        let parent_work = self
            .cumulative_work
            .get(&parent_hash)
            .expect("parent work must exist")
            .clone();
        let candidate_work = parent_work + chainwork_for_target(block.header.target);
        let current_tip = self.tip_hash();
        let current_work = self.cumulative_work().clone();

        self.headers.insert(block_hash, block.header.clone());
        self.heights.insert(block_hash, height);
        self.blocks.insert(block_hash, block);
        self.cumulative_work
            .insert(block_hash, candidate_work.clone());

        if candidate_work <= current_work {
            // Side-branch blocks are not part of the active chain yet.
            return Ok(BlockSubmissionOutcome::StoredSideBranch { block_hash });
        }

        if parent_hash == current_tip {
            if let Err(err) = self.connect_known_block(block_hash) {
                self.reject_blocks(&[block_hash], &err);
                return Err(err);
            }
            self.on_tip_changed();
            return Ok(BlockSubmissionOutcome::ExtendedTip {
                new_tip: block_hash,
                new_height: self.tip_height(),
            });
        }

        let (fork_height, branch) = self.branch_from_main_chain(block_hash)?;
        let depth = tip_height - fork_height;
        if depth > self.max_reorg_depth {
            return Err(ChainError::ForkTooDeep {
                block_hash,
                fork_height,
                tip_height,
                max_reorg_depth: self.max_reorg_depth,
            });
        }
        self.reorganize(fork_height, &branch)?;
        self.on_tip_changed();

        Ok(BlockSubmissionOutcome::Reorged {
            old_tip: current_tip,
            new_tip: self.tip_hash(),
            new_height: self.tip_height(),
        })
    }

    /// Walk back from `tip_hash` until the main chain. Returns the fork
    /// height and the side-branch hashes above it, oldest first.
    fn branch_from_main_chain(&self, tip_hash: Hash256) -> Result<(u64, Vec<Hash256>), ChainError> {
        let mut branch = Vec::new();
        let mut cursor = tip_hash;
        loop {
            let height = self
                .height_of(&cursor)
                .ok_or(ChainError::MissingHeader { block_hash: cursor })?;
            if self.is_on_main_chain(&cursor, height) {
                branch.reverse();
                return Ok((height, branch));
            }
            if height == 0 {
                return Err(ChainError::InvalidRuntime(
                    "candidate chain does not share local genesis".to_owned(),
                ));
            }
            branch.push(cursor);
            cursor = self
                .headers
                .get(&cursor)
                .ok_or(ChainError::MissingHeader { block_hash: cursor })?
                .prev_block;
        }
    }

    /// Disconnect down to `fork_height`, then connect `branch`. If any branch
    /// block fails, the original chain is restored and the failing block and
    /// its stored descendants on `branch` are marked invalid.
    fn reorganize(&mut self, fork_height: u64, branch: &[Hash256]) -> Result<(), ChainError> {
        let mut disconnected = Vec::new();
        while self.tip_height() > fork_height {
            disconnected.push(self.disconnect_tip_block()?);
        }

        let mut failure = None;
        for (idx, hash) in branch.iter().enumerate() {
            if let Err(err) = self.connect_known_block(*hash) {
                failure = Some((idx, err));
                break;
            }
        }
        let Some((failed_idx, err)) = failure else {
            return Ok(());
        };

        for _ in 0..failed_idx {
            self.disconnect_tip_block()?;
        }
        for hash in disconnected.into_iter().rev() {
            self.connect_known_block(hash).map_err(|restore_err| {
                ChainError::InvalidRuntime(format!(
                    "failed to restore block {hash} after aborted reorg: {restore_err}"
                ))
            })?;
        }
        self.reject_blocks(&branch[failed_idx..], &err);
        Err(err)
    }

    /// Forget blocks that failed to connect. Consensus failures are also
    /// remembered as invalid so descendants are refused cheaply.
    fn reject_blocks(&mut self, hashes: &[Hash256], err: &ChainError) {
        let consensus_invalid = matches!(
            err,
            ChainError::Validation(_)
                | ChainError::InvalidBlockStructure(_)
                | ChainError::UnexpectedTarget { .. }
                | ChainError::TimestampTooOld { .. }
        );
        for hash in hashes {
            self.forget_block(hash);
            if consensus_invalid {
                self.invalid_blocks.insert(*hash);
            }
        }
    }

    fn forget_block(&mut self, hash: &Hash256) {
        self.blocks.remove(hash);
        self.headers.remove(hash);
        self.heights.remove(hash);
        self.cumulative_work.remove(hash);
        self.undo_data.remove(hash);
    }

    fn connect_known_block(&mut self, block_hash: Hash256) -> Result<(), ChainError> {
        // Take the body out while validating to avoid cloning it.
        let block = self
            .blocks
            .remove(&block_hash)
            .ok_or(ChainError::MissingBlock { block_hash })?;
        let result = if block.header.prev_block != self.tip_hash() {
            Err(ChainError::PrevBlockMustBeTip {
                expected_tip: self.tip_hash(),
                got_prev: block.header.prev_block,
            })
        } else {
            self.validate_and_connect(&block, false)
        };
        self.blocks.insert(block_hash, block);
        let (_, undo) = result?;
        self.main_chain.push(block_hash);
        self.undo_data.insert(block_hash, undo);
        Ok(())
    }

    fn disconnect_tip_block(&mut self) -> Result<Hash256, ChainError> {
        if self.main_chain.len() <= 1 {
            return Err(ChainError::InvalidRuntime(
                "cannot disconnect genesis block".to_owned(),
            ));
        }
        let tip_hash = self.tip_hash();
        let undo = self
            .undo_data
            .remove(&tip_hash)
            .ok_or(ChainError::MissingUndoData {
                block_hash: tip_hash,
            })?;
        if let Err(err) = revert_block_undo(&undo, &mut self.utxos) {
            self.undo_data.insert(tip_hash, undo);
            return Err(ChainError::Undo {
                block_hash: tip_hash,
                source: err,
            });
        }
        self.main_chain.pop();
        Ok(tip_hash)
    }

    /// Periodically drop state that can no longer matter: undo records and
    /// side branches deeper than `max_reorg_depth`.
    fn on_tip_changed(&mut self) {
        self.tip_changes = self.tip_changes.wrapping_add(1);
        if !self.tip_changes.is_multiple_of(PRUNE_INTERVAL_BLOCKS) {
            return;
        }
        self.prune_below_reorg_horizon();
    }

    fn prune_below_reorg_horizon(&mut self) {
        let tip_height = self.tip_height();
        let Some(horizon) = tip_height.checked_sub(self.max_reorg_depth) else {
            return;
        };
        let stale = self
            .heights
            .iter()
            .filter(|(hash, height)| **height <= horizon && !self.is_on_main_chain(hash, **height))
            .map(|(hash, _)| *hash)
            .collect::<Vec<_>>();
        for hash in stale {
            self.forget_block(&hash);
        }
        let heights = &self.heights;
        self.undo_data.retain(|hash, _| {
            heights
                .get(hash)
                .is_some_and(|height| height.saturating_add(self.max_reorg_depth) > tip_height)
        });
    }
}

fn current_unix_timestamp() -> Result<u64, ChainError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ChainError::InvalidRuntime(format!("system clock before unix epoch: {e}")))?;
    Ok(now.as_secs())
}

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("chain config error: {0}")]
    Config(#[from] scam_core::ChainConfigError),
    #[error("tx/block validation error: {0}")]
    Validation(#[from] scam_consensus::TxValidationError),
    #[error("difficulty retarget error: {0}")]
    Difficulty(#[source] scam_consensus::difficulty::DifficultyError),
    #[error("invalid block structure: {0}")]
    InvalidBlockStructure(#[from] BlockValidationError),
    #[error("block prev hash must point to current tip: expected {expected_tip}, got {got_prev}")]
    PrevBlockMustBeTip {
        expected_tip: Hash256,
        got_prev: Hash256,
    },
    #[error("unknown parent for block {block_hash}: parent={parent}")]
    UnknownParent {
        block_hash: Hash256,
        parent: Hash256,
    },
    #[error("missing header for block {block_hash}")]
    MissingHeader { block_hash: Hash256 },
    #[error("missing block body for block {block_hash}")]
    MissingBlock { block_hash: Hash256 },
    #[error("missing undo data for connected block {block_hash}")]
    MissingUndoData { block_hash: Hash256 },
    #[error("cannot disconnect block {block_hash}: {source}")]
    Undo {
        block_hash: Hash256,
        #[source]
        source: UndoError,
    },
    #[error("block {block_hash} was already found invalid")]
    KnownInvalid { block_hash: Hash256 },
    #[error("block {block_hash} descends from invalid block {ancestor}")]
    InvalidAncestor {
        block_hash: Hash256,
        ancestor: Hash256,
    },
    #[error(
        "block {block_hash} forks at height {fork_height}, deeper than the max reorg depth {max_reorg_depth} below tip {tip_height}"
    )]
    ForkTooDeep {
        block_hash: Hash256,
        fork_height: u64,
        tip_height: u64,
        max_reorg_depth: u64,
    },
    #[error("unexpected block target: expected {expected}, got {got}")]
    UnexpectedTarget { expected: Target, got: Target },
    #[error("unexpected genesis block hash: expected {expected}, got {got}")]
    UnexpectedGenesis { expected: Hash256, got: Hash256 },
    #[error("block {block_hash} timestamp too old: got={got}, median-time-past={median_time_past}")]
    TimestampTooOld {
        block_hash: Hash256,
        median_time_past: u64,
        got: u64,
    },
    #[error("block {block_hash} timestamp too far in future: got={got}, max_allowed={max_allowed}")]
    TimestampTooFarInFuture {
        block_hash: Hash256,
        got: u64,
        max_allowed: u64,
    },
    #[error("{0}")]
    InvalidRuntime(String),
}

#[cfg(test)]
mod tests {
    use scam_core::{Hash256, OutPoint, Transaction, TxIn, TxOut};
    use scam_miner::{BlockTemplate, mine_block};

    use super::{
        PRUNE_INTERVAL_BLOCKS, asert_next, chainwork_for_target, lwma_next, retarget_next,
    };
    use crate::{BlockSubmissionOutcome, ChainError, ChainRuntime};

    fn coinbase(value: u64, key_hash20: [u8; 20], tag: &[u8]) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: tag.to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut { value, key_hash20 }],
            lock_time: 0,
        }
    }

    fn devnet_config() -> scam_core::ChainConfig {
        toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse")
    }

    /// Mine a coinbase-only block on `parent` with the target the runtime
    /// expects for that branch.
    fn mine_on(
        runtime: &ChainRuntime,
        parent: Hash256,
        timestamp: u64,
        tag: &str,
        extra: Vec<Transaction>,
    ) -> scam_core::Block {
        let config = runtime.config().clone();
        let mut txs = vec![coinbase(
            config.block_subsidy,
            config.genesis_reward_key_hash20().expect("key"),
            tag.as_bytes(),
        )];
        txs.extend(extra);
        let template = BlockTemplate {
            version: 1,
            prev_block: parent,
            timestamp,
            target: runtime
                .expected_target_for_child_of(parent)
                .expect("branch target"),
            transactions: txs,
        };
        mine_block(&template, 2_000_000).expect("mine")
    }

    fn signing_key(seed: u8) -> (secp256k1::Keypair, Vec<u8>, [u8; 20]) {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[seed; 32]).expect("secret");
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret);
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret)
            .serialize()
            .to_vec();
        let hash = scam_core::hash160_blake3(&pubkey);
        (keypair, pubkey, hash)
    }

    fn signed_spend(
        prev: OutPoint,
        value: u64,
        to: [u8; 20],
        keypair: &secp256k1::Keypair,
        pubkey: &[u8],
        chain_domain: &[u8],
    ) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: prev,
                signature: vec![],
                pubkey_compressed: pubkey.to_vec(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value,
                key_hash20: to,
            }],
            lock_time: 0,
        };
        let digest = tx
            .signing_digest_with_chain_domain(0, chain_domain)
            .expect("digest");
        let message = secp256k1::Message::from_digest_slice(&digest.0).expect("msg");
        let sig = secp256k1::Secp256k1::new().sign_schnorr_no_aux_rand(&message, keypair);
        tx.inputs[0].signature = sig.as_ref().to_vec();
        tx
    }

    /// C2: a side-branch block must carry the target its branch requires.
    /// Before the fix a `Target::MAX` side block was stored for free.
    #[test]
    fn side_branch_block_with_easier_than_expected_target_is_rejected() {
        let mut config = devnet_config();
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Windowed;
        config.difficulty_adjustment_window = 2;
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let genesis_ts = runtime.tip_header().timestamp;
        // Fast block ⇒ retarget at height 2 makes the next target harder.
        let b1 = mine_on(&runtime, runtime.tip_hash(), genesis_ts + 1, "b1", vec![]);
        let b1_hash = b1.header.block_hash();
        runtime.apply_next_block(b1).expect("b1");
        let required = runtime.expected_target_for_child_of(b1_hash).expect("t");
        assert!(required < scam_core::Target::MAX, "retarget must tighten");
        let b2 = mine_on(&runtime, b1_hash, genesis_ts + 2, "b2", vec![]);
        runtime.apply_next_block(b2).expect("b2");

        let cheap = BlockTemplate {
            version: 1,
            prev_block: b1_hash,
            timestamp: genesis_ts + 3,
            target: scam_core::Target::MAX,
            transactions: vec![coinbase(
                config.block_subsidy,
                config.genesis_reward_key_hash20().expect("key"),
                b"cheap-side",
            )],
        };
        let cheap = mine_block(&cheap, 10).expect("free block");
        let cheap_hash = cheap.header.block_hash();
        let err = runtime.submit_block(cheap).expect_err("must reject");
        assert!(
            matches!(err, ChainError::UnexpectedTarget { .. }),
            "{err:?}"
        );
        assert!(runtime.block_by_hash(&cheap_hash).is_none(), "not stored");
    }

    /// C3: a tx spending an output created earlier in the same block must
    /// connect, and disconnecting it (reorg) must restore the UTXO set.
    #[test]
    fn in_block_parent_child_spend_connects_and_reorgs_cleanly() {
        let mut config = devnet_config();
        config.coinbase_maturity = 1;
        let (keypair, pubkey, key_hash) = signing_key(7);
        let (_, _, other_hash) = signing_key(8);
        let domain = config.network_id.as_bytes().to_vec();
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let ts = runtime.tip_header().timestamp;

        let cb1 = coinbase(config.block_subsidy, key_hash, b"b1-pay-me");
        assert!(cb1.is_coinbase());
        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: ts + 30,
            target: runtime.expected_target_for_next_block().expect("t"),
            transactions: vec![cb1.clone()],
        };
        runtime
            .apply_next_block(mine_block(&template, 200_000).expect("mine"))
            .expect("b1");
        let b1_hash = runtime.tip_hash();
        let after_b1 = runtime.utxo_set().clone();
        // The miner appends an extra-nonce to the coinbase, so read the
        // final txid back from the stored block.
        let cb1_txid = runtime.block_by_hash(&b1_hash).expect("b1").transactions[0].txid();

        let parent = signed_spend(
            OutPoint {
                txid: cb1_txid,
                vout: 0,
            },
            config.block_subsidy - 10,
            key_hash,
            &keypair,
            &pubkey,
            &domain,
        );
        let child = signed_spend(
            OutPoint {
                txid: parent.txid(),
                vout: 0,
            },
            config.block_subsidy - 20,
            other_hash,
            &keypair,
            &pubkey,
            &domain,
        );
        let b2 = mine_on(&runtime, b1_hash, ts + 60, "b2", vec![parent, child]);
        runtime
            .apply_next_block(b2)
            .expect("CPFP-shaped block must connect");
        assert_eq!(runtime.tip_height(), 2);

        // Heavier fork from b1 disconnects b2.
        let f2 = mine_on(&runtime, b1_hash, ts + 61, "f2", vec![]);
        let f2_hash = f2.header.block_hash();
        runtime.submit_block(f2).expect("f2 side");
        let f3 = mine_on(&runtime, f2_hash, ts + 62, "f3", vec![]);
        let outcome = runtime.submit_block(f3).expect("f3 reorg");
        assert!(matches!(outcome, BlockSubmissionOutcome::Reorged { .. }));
        for (outpoint, entry) in &after_b1 {
            assert_eq!(runtime.utxo_set().get(outpoint), Some(entry), "restored");
        }
        assert_eq!(
            runtime.utxo_len(),
            after_b1.len() + 2,
            "plus f2/f3 coinbases"
        );
    }

    /// C11: a failing reorg restores the old chain, and the bad block and its
    /// descendants are remembered as invalid.
    #[test]
    fn failed_reorg_restores_chain_and_marks_branch_invalid() {
        let config = devnet_config();
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let genesis = runtime.tip_hash();
        let ts = runtime.tip_header().timestamp;
        for i in 0..2u64 {
            let block = mine_on(
                &runtime,
                runtime.tip_hash(),
                ts + 30 * (i + 1),
                &format!("m{i}"),
                vec![],
            );
            runtime.apply_next_block(block).expect("main");
        }
        let main_tip = runtime.tip_hash();
        let utxo_before = runtime.utxo_set().clone();

        let f1 = mine_on(&runtime, genesis, ts + 31, "f1", vec![]);
        let f1_hash = f1.header.block_hash();
        runtime.submit_block(f1).expect("f1 side");
        // f2 pays itself more than the subsidy ⇒ consensus-invalid.
        let mut f2_template = BlockTemplate {
            version: 1,
            prev_block: f1_hash,
            timestamp: ts + 62,
            target: runtime.expected_target_for_child_of(f1_hash).expect("t"),
            transactions: vec![coinbase(
                config.block_subsidy + 1,
                config.genesis_reward_key_hash20().expect("key"),
                b"f2-greedy",
            )],
        };
        let f2 = mine_block(&f2_template, 200_000).expect("mine f2");
        let f2_hash = f2.header.block_hash();
        runtime
            .submit_block(f2)
            .expect("f2 stored as side branch (equal work)");
        f2_template.prev_block = f2_hash;
        f2_template.timestamp = ts + 93;
        f2_template.transactions = vec![coinbase(
            config.block_subsidy,
            config.genesis_reward_key_hash20().expect("key"),
            b"f3",
        )];
        let f3 = mine_block(&f2_template, 200_000).expect("mine f3");
        let f3_hash = f3.header.block_hash();
        let err = runtime.submit_block(f3).expect_err("reorg must fail");
        assert!(matches!(err, ChainError::Validation(_)), "{err:?}");

        assert_eq!(runtime.tip_hash(), main_tip, "old chain restored");
        assert_eq!(runtime.utxo_set(), &utxo_before, "UTXO set restored");
        assert!(runtime.is_known_invalid(&f2_hash));
        assert!(runtime.is_known_invalid(&f3_hash));
        assert!(runtime.block_by_hash(&f2_hash).is_none());

        f2_template.prev_block = f3_hash;
        f2_template.timestamp = ts + 124;
        let f4 = mine_block(&f2_template, 200_000).expect("mine f4");
        let err = runtime.submit_block(f4).expect_err("descendant of invalid");
        assert!(
            matches!(
                err,
                ChainError::UnknownParent { .. } | ChainError::InvalidAncestor { .. }
            ),
            "{err:?}"
        );
    }

    /// C12/C10: forks deeper than the reorg limit are refused, and stale
    /// side branches are pruned.
    #[test]
    fn deep_forks_are_refused_and_stale_side_branches_pruned() {
        let config = devnet_config();
        let mut runtime = ChainRuntime::from_config(config).expect("runtime");
        runtime.max_reorg_depth = 3;
        let genesis = runtime.tip_hash();
        let ts = runtime.tip_header().timestamp;
        let spacing = runtime.config().target_block_time_sec;

        let side = mine_on(&runtime, genesis, ts + spacing - 1, "early-side", vec![]);
        let side_hash = side.header.block_hash();
        let b1 = mine_on(&runtime, genesis, ts + spacing, "b1", vec![]);
        runtime.apply_next_block(b1).expect("b1");
        runtime.submit_block(side).expect("side within depth");
        assert!(runtime.block_by_hash(&side_hash).is_some());

        for i in 0..3u64 {
            let block = mine_on(
                &runtime,
                runtime.tip_hash(),
                ts + spacing * (2 + i),
                &format!("m{i}"),
                vec![],
            );
            runtime.apply_next_block(block).expect("main");
        }
        let deep = mine_on(&runtime, genesis, ts + spacing + 1, "deep", vec![]);
        let err = runtime.submit_block(deep).expect_err("too deep");
        assert!(matches!(err, ChainError::ForkTooDeep { .. }), "{err:?}");

        for i in 0..PRUNE_INTERVAL_BLOCKS {
            let block = mine_on(
                &runtime,
                runtime.tip_hash(),
                ts + spacing * (10 + i),
                &format!("p{i}"),
                vec![],
            );
            runtime.apply_next_block(block).expect("main");
        }
        assert!(runtime.block_by_hash(&side_hash).is_none(), "side pruned");
        assert!(runtime.undo_data.len() as u64 <= runtime.max_reorg_depth + PRUNE_INTERVAL_BLOCKS);
        assert!(runtime.undo_data.contains_key(&runtime.tip_hash()));
    }

    /// C13: replaying locally stored blocks must not apply the wall-clock
    /// future-time rule (a host whose clock is behind could not restart).
    #[test]
    fn local_replay_ignores_wall_clock_future_rule() {
        let config = devnet_config();
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let far_future = super::current_unix_timestamp().expect("now") + 10 * 3_600;
        let block = mine_on(&runtime, runtime.tip_hash(), far_future, "future", vec![]);
        let err = runtime
            .apply_next_block(block.clone())
            .expect_err("live path checks clock");
        assert!(matches!(err, ChainError::TimestampTooFarInFuture { .. }));

        let genesis = config.build_genesis_block().expect("genesis");
        let replayed =
            ChainRuntime::from_ordered_blocks(config, vec![genesis, block]).expect("replay");
        assert_eq!(replayed.tip_height(), 1);
    }

    #[test]
    fn runtime_initializes_from_config() {
        let config_raw = include_str!("../../../config/devnet.toml");
        let config: scam_core::ChainConfig = toml::from_str(config_raw).expect("config parse");
        let runtime = ChainRuntime::from_config(config).expect("runtime init");
        assert_eq!(runtime.tip_height(), 0);
        assert_eq!(runtime.block_hashes().len(), 1);
        assert_eq!(runtime.utxo_len(), 1);
        assert_eq!(runtime.utxo_set().len(), runtime.utxo_len());
    }

    #[test]
    fn runtime_accessors_track_height_and_cumulative_work() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let prev_work = runtime.cumulative_work().clone();
        let target = runtime.expected_target_for_next_block().expect("target");

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp + 30,
            target,
            transactions: vec![coinbase(config.block_subsidy, reward, b"accessor-work")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime.apply_next_block(block).expect("apply");

        assert_eq!(runtime.tip_height(), 1);
        assert_eq!(runtime.utxo_set().len(), runtime.utxo_len());
        assert!(
            runtime
                .utxo_set()
                .values()
                .any(|entry| entry.created_height == runtime.tip_height()),
            "new outputs should be tagged with current block height"
        );
        let expected_work = prev_work + chainwork_for_target(target);
        assert_eq!(*runtime.cumulative_work(), expected_work);
    }

    #[test]
    fn expected_target_windowed_returns_tip_target_between_boundaries() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Windowed;
        config.difficulty_adjustment_window = 20;
        let runtime = ChainRuntime::from_config(config).expect("runtime");
        let expected = runtime.expected_target_for_next_block().expect("target");
        assert_eq!(expected, runtime.tip_header().target);
    }

    #[test]
    fn expected_target_windowed_uses_retarget_math_at_boundary() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Windowed;
        config.difficulty_adjustment_window = 2;
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp.saturating_add(30),
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"w1")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime.apply_next_block(block).expect("apply");

        let tip_hash = runtime.tip_hash();
        let overridden_tip_target = scam_core::Target::from_hex(
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("target parse");
        runtime
            .headers
            .get_mut(&tip_hash)
            .expect("tip header")
            .target = overridden_tip_target;

        // First boundary (next height 2, window 2): windows overlap, so the
        // span starts at genesis and covers exactly one interval.
        let start_hash = runtime.block_hash_at_height(0).expect("genesis");
        let start_ts = runtime
            .headers
            .get(&start_hash)
            .expect("genesis header")
            .timestamp;
        let tip_ts = runtime.tip_header().timestamp;
        let expected = retarget_next(
            overridden_tip_target,
            tip_ts.saturating_sub(start_ts).max(1),
            config.target_block_time_sec,
            config.difficulty_clamp_down,
            config.difficulty_clamp_up,
            config.genesis_target().expect("max target"),
        )
        .expect("retarget");

        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            expected
        );
    }

    #[test]
    fn expected_target_lwma_uses_tip_target_until_history_is_ready() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Lwma;
        config.difficulty_adjustment_window = 20;
        let runtime = ChainRuntime::from_config(config).expect("runtime");
        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            runtime.tip_header().target
        );
    }

    #[test]
    fn expected_target_lwma_matches_formula_when_history_available() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Lwma;
        config.difficulty_adjustment_window = 3;
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        for i in 0..3 {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp: runtime.tip_header().timestamp + (i + 1) as u64 * 15,
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    reward,
                    format!("lwma-{i}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 200_000).expect("mine");
            runtime.apply_next_block(block).expect("apply");
        }

        let window = config.difficulty_adjustment_window as usize;
        let history = runtime.main_chain.len();
        let start = history - (window + 1);
        let target_override = scam_core::Target::from_hex(
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("target parse");
        let base_ts = 1_700_000_000u64;
        for (idx, height) in (start..history).enumerate() {
            let hash = runtime.main_chain[height];
            let header = runtime.headers.get_mut(&hash).expect("header");
            header.target = target_override;
            header.timestamp = base_ts + (idx as u64) * 30;
        }

        let mut targets = Vec::with_capacity(window + 1);
        let mut timestamps = Vec::with_capacity(window + 1);
        for height in start..history {
            let hash = runtime.main_chain[height];
            let header = runtime.headers.get(&hash).expect("header");
            targets.push(header.target);
            timestamps.push(header.timestamp);
        }
        let expected = lwma_next(
            &targets,
            &timestamps,
            config.target_block_time_sec,
            config.genesis_target().expect("max target"),
        )
        .expect("lwma");
        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            expected
        );
    }

    #[test]
    fn expected_target_asert_matches_formula_after_first_block() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Asert;
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp.saturating_add(45),
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"asert-1")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime.apply_next_block(block).expect("apply");

        let tip_hash = runtime.tip_hash();
        let override_target = scam_core::Target::from_hex(
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("target parse");
        runtime
            .headers
            .get_mut(&tip_hash)
            .expect("tip header")
            .target = override_target;

        let tip_header = runtime.tip_header().clone();
        let parent = runtime
            .headers
            .get(&tip_header.prev_block)
            .expect("parent header");
        let expected = asert_next(
            override_target,
            tip_header.timestamp.saturating_sub(parent.timestamp).max(1),
            config.target_block_time_sec,
            config.asert_half_life_sec,
            config.genesis_target().expect("max target"),
        )
        .expect("asert");
        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            expected
        );
    }

    #[test]
    fn validate_contextual_timestamps_rejects_unknown_parent() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let block = scam_core::Block {
            header: scam_core::BlockHeader {
                version: 1,
                prev_block: scam_core::Hash256([9u8; 32]),
                merkle_root: scam_core::Hash256::ZERO,
                timestamp: runtime.tip_header().timestamp.saturating_add(1),
                target: config.genesis_target().expect("target"),
                nonce: 0,
            },
            transactions: vec![coinbase(
                config.block_subsidy,
                config.genesis_reward_key_hash20().expect("key"),
                b"unknown-parent",
            )],
        };
        let err = runtime
            .validate_contextual_timestamps(&block, true)
            .expect_err("must reject unknown parent");
        assert!(matches!(err, ChainError::MissingHeader { .. }));
    }

    #[test]
    fn apply_next_block_rejects_unexpected_target_and_accepts_expected_target() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let expected_target = runtime.expected_target_for_next_block().expect("target");
        let wrong_target = scam_core::Target::from_hex(
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("target parse");
        assert_ne!(wrong_target, expected_target);

        let wrong_block = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp.saturating_add(30),
            target: wrong_target,
            transactions: vec![coinbase(config.block_subsidy, reward, b"wrong-target")],
        }
        .build_with_nonce(0);
        let err = runtime
            .apply_next_block(wrong_block)
            .expect_err("must reject unexpected target");
        assert!(matches!(err, ChainError::UnexpectedTarget { .. }));

        let ok_block = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp.saturating_add(30),
            target: expected_target,
            transactions: vec![coinbase(config.block_subsidy, reward, b"right-target")],
        };
        let mined = mine_block(&ok_block, 200_000).expect("mine");
        runtime.apply_next_block(mined).expect("accept block");
    }

    #[test]
    fn runtime_mines_and_applies_sequential_blocks() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_adjustment_window = 2;
        config.difficulty_clamp_up = 4.0;
        config.difficulty_clamp_down = 0.25;
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let mut timestamp = runtime.tip_header().timestamp + 10;
        for i in 0..3 {
            let target = runtime
                .expected_target_for_next_block()
                .expect("expected target");
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp,
                target,
                transactions: vec![coinbase(
                    config.block_subsidy,
                    config.genesis_reward_key_hash20().expect("key"),
                    format!("b{i}").as_bytes(),
                )],
            };
            let mined = mine_block(&template, 200_000).expect("block mined");
            runtime.apply_next_block(mined).expect("apply");
            timestamp += if i == 0 { 10 } else { 120 };
        }

        assert_eq!(runtime.tip_height(), 3);
        assert_eq!(runtime.block_hashes().len(), 4);
    }

    #[test]
    fn side_branch_with_more_work_triggers_reorg() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_adjustment_window = 50;
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let mut timestamp = runtime.tip_header().timestamp + 30;
        for i in 0..4 {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp,
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    config.genesis_reward_key_hash20().expect("key"),
                    format!("main-{i}").as_bytes(),
                )],
            };
            let mined = mine_block(&template, 300_000).expect("main mined");
            runtime.apply_next_block(mined).expect("main apply");
            timestamp += 30;
        }
        let old_tip = runtime.tip_hash();
        let fork_point = runtime.block_hash_at_height(1).expect("fork height exists");
        let fork_target = runtime
            .header_by_hash(&fork_point)
            .expect("fork header")
            .target;
        let mut fork_prev = fork_point;
        let mut fork_ts = runtime
            .header_by_hash(&fork_point)
            .expect("fork header")
            .timestamp
            + 20;

        let mut saw_reorg = false;
        for i in 0..6 {
            let template = BlockTemplate {
                version: 1,
                prev_block: fork_prev,
                timestamp: fork_ts,
                target: fork_target,
                transactions: vec![coinbase(
                    config.block_subsidy,
                    config.genesis_reward_key_hash20().expect("key"),
                    format!("fork-{i}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 300_000).expect("fork mined");
            fork_prev = block.header.block_hash();
            let outcome = runtime.submit_block(block).expect("submit");
            if matches!(outcome, BlockSubmissionOutcome::Reorged { .. }) {
                saw_reorg = true;
            }
            fork_ts += 20;
        }

        assert!(saw_reorg, "expected at least one reorg event");
        assert_ne!(runtime.tip_hash(), old_tip);
    }

    #[test]
    fn branch_from_main_chain_resolves_fork_point() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let reward = config.genesis_reward_key_hash20().expect("key");

        let mut timestamp = runtime.tip_header().timestamp + 30;
        for i in 0..2 {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp,
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    reward,
                    format!("fork-height-{i}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 200_000).expect("mine");
            runtime.apply_next_block(block).expect("apply");
            timestamp += 30;
        }

        let tip = runtime.tip_hash();
        let (fork_height, branch) = runtime
            .branch_from_main_chain(tip)
            .expect("main-chain tip is its own fork point");
        assert_eq!(fork_height, runtime.tip_height());
        assert!(branch.is_empty());

        let err = runtime
            .branch_from_main_chain(Hash256([0xEE; 32]))
            .expect_err("unknown block must fail");
        assert!(matches!(err, ChainError::MissingHeader { .. }));
    }

    #[test]
    fn disconnect_tip_block_must_reduce_height() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let reward = config.genesis_reward_key_hash20().expect("key");

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp + 30,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"disconnect-tip")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime.apply_next_block(block).expect("apply");

        let tip_before = runtime.tip_hash();
        let height_before = runtime.tip_height();
        runtime.disconnect_tip_block().expect("disconnect");
        assert_eq!(runtime.tip_height(), height_before.saturating_sub(1));
        assert_ne!(runtime.tip_hash(), tip_before);
    }

    #[test]
    fn block_timestamp_must_be_greater_than_median_time_past() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_adjustment_window = 50;
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let reward = config.genesis_reward_key_hash20().expect("key");

        let mut timestamp = runtime.tip_header().timestamp + 30;
        for i in 0..11 {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp,
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    reward,
                    format!("mtp-main-{i}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 200_000).expect("mine");
            runtime.apply_next_block(block).expect("apply");
            timestamp += 30;
        }

        let mtp = runtime
            .median_time_past(runtime.tip_hash())
            .expect("median-time-past");
        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: mtp,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"mtp-reject")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        let err = runtime.apply_next_block(block).expect_err("must reject");
        assert!(matches!(err, ChainError::TimestampTooOld { .. }));
    }

    #[test]
    fn median_time_past_for_tip_matches_internal_median_and_is_not_zero_for_recent_timestamps() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_adjustment_window = 50;
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let reward = config.genesis_reward_key_hash20().expect("key");

        let base = runtime.tip_header().timestamp.saturating_add(10_000);
        let offsets = [5_u64, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41];
        for (idx, delta) in offsets.iter().copied().enumerate() {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp: base.saturating_add(delta),
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    reward,
                    format!("mtp-tip-{idx}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 200_000).expect("mine");
            runtime.apply_next_block(block).expect("apply");
        }

        let mut expected = offsets
            .iter()
            .map(|delta| base.saturating_add(*delta))
            .collect::<Vec<_>>();
        expected.sort_unstable();
        let expected_median = expected[expected.len() / 2];
        let tip_mtp = runtime
            .median_time_past_for_tip()
            .expect("median-time-past-for-tip");
        let direct_mtp = runtime
            .median_time_past(runtime.tip_hash())
            .expect("direct median-time-past");

        assert_eq!(tip_mtp, expected_median);
        assert_eq!(direct_mtp, expected_median);
        assert!(
            tip_mtp > 1,
            "mtp should reflect mined timestamps, got={tip_mtp}"
        );
    }

    #[test]
    fn block_timestamp_too_far_in_future_is_rejected() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let now = super::current_unix_timestamp().expect("now");
        let future_timestamp = now + super::MAX_FUTURE_BLOCK_TIME_SEC + 1;

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: future_timestamp,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(
                config.block_subsidy,
                config.genesis_reward_key_hash20().expect("key"),
                b"future-reject",
            )],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        let err = runtime.apply_next_block(block).expect_err("must reject");
        assert!(matches!(err, ChainError::TimestampTooFarInFuture { .. }));
    }

    #[test]
    fn block_timestamp_within_future_window_is_accepted() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let now = super::current_unix_timestamp().expect("now");

        // Keep this comfortably below the 2-hour guard so tiny clock drift during validation
        // does not make the test flaky.
        let near_future_timestamp = now + 4_000;
        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: near_future_timestamp,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"within-future")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime
            .apply_next_block(block)
            .expect("timestamp below future window should pass");
    }

    #[test]
    fn block_timestamp_at_future_window_boundary_is_accepted() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
        let now = super::current_unix_timestamp().expect("now");

        let boundary_timestamp = now + super::MAX_FUTURE_BLOCK_TIME_SEC;
        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: boundary_timestamp,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"future-boundary")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime
            .apply_next_block(block)
            .expect("timestamp on future boundary should pass");
    }

    #[test]
    fn expected_target_windowed_uses_subtraction_index_at_boundary() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Windowed;
        config.difficulty_adjustment_window = 3;
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        for i in 0..5 {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp: runtime.tip_header().timestamp + 30 + i as u64,
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    reward,
                    format!("window-boundary-{i}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 200_000).expect("mine");
            runtime.apply_next_block(block).expect("apply");
        }
        assert_eq!(runtime.tip_height(), 5);

        let tip_hash = runtime.tip_hash();
        let height2 = runtime.block_hash_at_height(2).expect("h2 hash");
        let height3 = runtime.block_hash_at_height(3).expect("h3 hash");
        let target_override = scam_core::Target::from_hex(
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("target parse");
        runtime
            .headers
            .get_mut(&tip_hash)
            .expect("tip header")
            .target = target_override;
        runtime
            .headers
            .get_mut(&tip_hash)
            .expect("tip header")
            .timestamp = 10_000;
        runtime
            .headers
            .get_mut(&height2)
            .expect("height2 header")
            .timestamp = 1_000;
        runtime
            .headers
            .get_mut(&height3)
            .expect("height3 header")
            .timestamp = 9_000;

        let expected = retarget_next(
            target_override,
            10_000u64.saturating_sub(9_000),
            3 * config.target_block_time_sec,
            config.difficulty_clamp_down,
            config.difficulty_clamp_up,
            config.genesis_target().expect("max target"),
        )
        .expect("retarget");
        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            expected
        );
    }

    #[test]
    fn expected_target_lwma_uses_history_window_offset_formula() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Lwma;
        config.difficulty_adjustment_window = 3;
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        for i in 0..7 {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp: runtime.tip_header().timestamp + 40 + i as u64,
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    reward,
                    format!("lwma-window-{i}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 200_000).expect("mine");
            runtime.apply_next_block(block).expect("apply");
        }

        let history = runtime.main_chain.len();
        let window = config.difficulty_adjustment_window as usize;
        assert_eq!(history, 8);
        let start = history - (window + 1);
        let timestamps = [1_000u64, 1_020, 1_060, 1_100, 1_400, 1_450, 1_470, 1_900];
        for (idx, hash) in runtime.main_chain.iter().enumerate() {
            let header = runtime.headers.get_mut(hash).expect("header");
            header.timestamp = timestamps[idx];
            let mut target = [0xffu8; 32];
            target[0] = 0;
            target[1] = 0xffu8.saturating_sub((idx as u8) * 16);
            header.target = scam_core::Target(target);
        }

        let mut targets = Vec::with_capacity(window + 1);
        let mut sampled_timestamps = Vec::with_capacity(window + 1);
        for height in start..history {
            let hash = runtime.main_chain[height];
            let header = runtime.headers.get(&hash).expect("header");
            targets.push(header.target);
            sampled_timestamps.push(header.timestamp);
        }
        let expected = lwma_next(
            &targets,
            &sampled_timestamps,
            config.target_block_time_sec,
            config.genesis_target().expect("max target"),
        )
        .expect("lwma");
        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            expected
        );
    }

    #[test]
    fn expected_target_windowed_boundary_measures_from_previous_window_last_block() {
        let mut config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        config.difficulty_algorithm = scam_core::DifficultyAlgorithm::Windowed;
        config.difficulty_adjustment_window = 4;
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        for i in 0..7 {
            let template = BlockTemplate {
                version: 1,
                prev_block: runtime.tip_hash(),
                timestamp: runtime.tip_header().timestamp + 20 + i as u64,
                target: runtime.expected_target_for_next_block().expect("target"),
                transactions: vec![coinbase(
                    config.block_subsidy,
                    reward,
                    format!("window-start-{i}").as_bytes(),
                )],
            };
            let block = mine_block(&template, 200_000).expect("mine");
            runtime.apply_next_block(block).expect("apply");
        }
        assert_eq!(runtime.tip_height(), 7);

        let tip_hash = runtime.tip_hash();
        let h2 = runtime.block_hash_at_height(2).expect("h2 hash");
        let h3 = runtime.block_hash_at_height(3).expect("h3 hash");
        let h4 = runtime.block_hash_at_height(4).expect("h4 hash");
        let target_override = scam_core::Target::from_hex(
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("target parse");

        runtime
            .headers
            .get_mut(&tip_hash)
            .expect("tip header")
            .target = target_override;
        runtime
            .headers
            .get_mut(&tip_hash)
            .expect("tip header")
            .timestamp = 5_000;
        runtime.headers.get_mut(&h2).expect("h2 header").timestamp = 4_500;
        runtime.headers.get_mut(&h3).expect("h3 header").timestamp = 4_700;
        runtime.headers.get_mut(&h4).expect("h4 header").timestamp = 4_900;

        // Next height 8 closes window [4..=7]; the span is measured from
        // h3 (last block of the previous window), i.e. 4 full intervals.
        let expected = retarget_next(
            target_override,
            5_000u64.saturating_sub(4_700),
            4 * config.target_block_time_sec,
            config.difficulty_clamp_down,
            config.difficulty_clamp_up,
            config.genesis_target().expect("max target"),
        )
        .expect("retarget");

        assert_eq!(
            runtime.expected_target_for_next_block().expect("target"),
            expected
        );
    }

    #[test]
    fn submit_block_extending_tip_reports_extended_tip_outcome() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let reward = config.genesis_reward_key_hash20().expect("key");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp + 30,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(config.block_subsidy, reward, b"submit-extend")],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        let submitted_hash = block.header.block_hash();
        let outcome = runtime.submit_block(block).expect("submit");
        match outcome {
            BlockSubmissionOutcome::ExtendedTip {
                new_tip,
                new_height,
            } => {
                assert_eq!(new_tip, submitted_hash);
                assert_eq!(new_height, 1);
            }
            other => panic!("expected ExtendedTip, got {other:?}"),
        }
    }

    #[test]
    fn runtime_can_restore_from_ordered_blocks() {
        let config: scam_core::ChainConfig =
            toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse");
        let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp: runtime.tip_header().timestamp + 30,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(
                config.block_subsidy,
                config.genesis_reward_key_hash20().expect("key"),
                b"restore-1",
            )],
        };
        let block = mine_block(&template, 200_000).expect("mine");
        runtime.apply_next_block(block).expect("apply");

        let ordered = runtime.main_chain_blocks().expect("export");
        let restored = ChainRuntime::from_ordered_blocks(config, ordered).expect("restore");
        assert_eq!(restored.tip_height(), runtime.tip_height());
        assert_eq!(restored.tip_hash(), runtime.tip_hash());
        assert_eq!(restored.utxo_len(), runtime.utxo_len());
    }
}
