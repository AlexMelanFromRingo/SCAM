use std::collections::HashMap;

use scam_chain::{BlockSubmissionOutcome, ChainRuntime};
use scam_core::{
    ChainConfig, DifficultyAlgorithm, Hash256, OutPoint, Target, Transaction, TxIn, TxOut,
};
use scam_miner::{BlockTemplate, mine_block};
use scam_p2p::{build_block_locator, select_block_hashes_for_peer, select_headers_for_peer};

fn load_devnet_config() -> ChainConfig {
    toml::from_str(include_str!("../../../config/devnet.toml")).expect("config parse")
}

fn coinbase(height: u64, value: u64, key_hash20: [u8; 20], tag: &[u8]) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint::coinbase(),
            signature: scam_core::coinbase_script(height, tag),
            pubkey_compressed: vec![],
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut { value, key_hash20 }],
        lock_time: 0,
    }
}

fn mine_blocks(
    runtime: &mut ChainRuntime,
    config: &ChainConfig,
    count: u32,
    interval_sec: u64,
    max_nonce: u64,
    tag: &str,
) {
    let miner_key_hash = config.genesis_reward_key_hash20().expect("miner key hash");
    let mut timestamp = runtime.tip_header().timestamp.saturating_add(interval_sec);

    for i in 0..count {
        let template = BlockTemplate {
            version: 1,
            prev_block: runtime.tip_hash(),
            timestamp,
            target: runtime.expected_target_for_next_block().expect("target"),
            transactions: vec![coinbase(
                runtime.tip_height() + 1,
                config.block_subsidy,
                miner_key_hash,
                format!("{tag}-{i}").as_bytes(),
            )],
        };
        let block = mine_block(&template, max_nonce).expect("mine block");
        runtime.apply_next_block(block).expect("apply block");
        timestamp = runtime.tip_header().timestamp.saturating_add(interval_sec);
    }
}

fn mine_branch_block(
    height: u64,
    prev: Hash256,
    timestamp: u64,
    target: Target,
    config: &ChainConfig,
    max_nonce: u64,
    tag: &[u8],
) -> scam_core::Block {
    let template = BlockTemplate {
        version: 1,
        prev_block: prev,
        timestamp,
        target,
        transactions: vec![coinbase(
            height,
            config.block_subsidy,
            config.genesis_reward_key_hash20().expect("miner key hash"),
            tag,
        )],
    };
    mine_block(&template, max_nonce).expect("mine branch block")
}

#[test]
fn initial_sync_from_genesis_to_tip_works_on_runtime() {
    let config = load_devnet_config();
    let mut local = ChainRuntime::from_config(config.clone()).expect("local runtime");
    let mut remote = ChainRuntime::from_config(config.clone()).expect("remote runtime");

    mine_blocks(&mut remote, &config, 35, 30, 500_000, "remote");
    assert!(remote.tip_height() > local.tip_height());

    for _ in 0..32 {
        let locator = build_block_locator(local.block_hashes());
        let remote_headers_by_hash = remote
            .block_hashes()
            .iter()
            .filter_map(|hash| {
                remote
                    .header_by_hash(hash)
                    .map(|header| (*hash, header.clone()))
            })
            .collect::<HashMap<_, _>>();

        let headers = select_headers_for_peer(
            remote.block_hashes(),
            &remote_headers_by_hash,
            &locator,
            None,
            8,
        );
        if headers.is_empty() {
            break;
        }

        let hashes = select_block_hashes_for_peer(remote.block_hashes(), &locator, None, 8);
        let mut progressed = false;
        for hash in hashes {
            if local.block_by_hash(&hash).is_some() {
                continue;
            }
            let block = remote
                .block_by_hash(&hash)
                .expect("announced block exists on remote")
                .clone();
            let outcome = local.submit_block(block).expect("sync submit succeeds");
            if matches!(
                outcome,
                BlockSubmissionOutcome::ExtendedTip { .. } | BlockSubmissionOutcome::Reorged { .. }
            ) {
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }

    assert_eq!(local.tip_height(), remote.tip_height());
    assert_eq!(local.tip_hash(), remote.tip_hash());
    assert_eq!(local.utxo_len(), remote.utxo_len());
}

#[test]
fn fork_reorg_switches_to_heavier_chain() {
    let mut config = load_devnet_config();
    config.difficulty_adjustment_window = 50;

    let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");
    mine_blocks(&mut runtime, &config, 4, 30, 500_000, "main");

    let old_tip = runtime.tip_hash();
    let fork_point = runtime.block_hash_at_height(1).expect("fork point");
    let fork_header = runtime
        .header_by_hash(&fork_point)
        .expect("fork point header");
    let fork_target = fork_header.target;

    let mut fork_prev = fork_point;
    let mut fork_timestamp = fork_header.timestamp.saturating_add(20);
    let mut reorgs = 0usize;

    for i in 0..6 {
        let block = mine_branch_block(
            2 + i,
            fork_prev,
            fork_timestamp,
            fork_target,
            &config,
            500_000,
            format!("fork-{i}").as_bytes(),
        );
        fork_prev = block.header.block_hash();
        fork_timestamp = fork_timestamp.saturating_add(20);

        let outcome = runtime.submit_block(block).expect("submit side block");
        if matches!(outcome, BlockSubmissionOutcome::Reorged { .. }) {
            reorgs = reorgs.saturating_add(1);
        }
    }

    assert!(reorgs > 0, "expected at least one reorg event");
    assert_ne!(runtime.tip_hash(), old_tip);
}

#[test]
fn difficulty_retargets_at_20_block_boundaries() {
    let mut config = load_devnet_config();
    config.difficulty_algorithm = DifficultyAlgorithm::Windowed;
    config.difficulty_adjustment_window = 20;
    let mut runtime = ChainRuntime::from_config(config.clone()).expect("runtime");

    // Mine 19 fast blocks to force a lower target at height 20.
    mine_blocks(&mut runtime, &config, 19, 30, 500_000, "fast");
    assert_eq!(runtime.tip_height(), 19);

    let prev_target = runtime.tip_header().target;
    let retarget_target = runtime
        .expected_target_for_next_block()
        .expect("retarget target");
    assert!(
        retarget_target < prev_target,
        "target should get harder (numerically smaller) after fast window"
    );

    let block20 = mine_branch_block(
        runtime.tip_height() + 1,
        runtime.tip_hash(),
        runtime.tip_header().timestamp.saturating_add(30),
        retarget_target,
        &config,
        500_000,
        b"retarget-20",
    );
    runtime.apply_next_block(block20).expect("apply block #20");

    assert_eq!(runtime.tip_height(), 20);
    assert_eq!(runtime.tip_header().target, retarget_target);
    // Block 21 should keep the same target until next retarget window.
    assert_eq!(
        runtime
            .expected_target_for_next_block()
            .expect("next target"),
        retarget_target
    );
}
