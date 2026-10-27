use std::collections::HashMap;

use scam_core::{BlockHeader, Hash256};

pub const MAX_HEADERS_PER_MESSAGE: usize = 2000;
pub const MAX_BLOCK_HASHES_PER_MESSAGE: usize = 2000;
pub const LOCATOR_SOFT_LIMIT: usize = 32;

pub fn build_block_locator(main_chain: &[Hash256]) -> Vec<Hash256> {
    if main_chain.is_empty() {
        return Vec::new();
    }

    let mut locator = Vec::new();
    let mut step = 1usize;
    let mut height = main_chain.len() - 1;

    loop {
        locator.push(main_chain[height]);
        if height == 0 {
            break;
        }

        if locator.len() >= LOCATOR_SOFT_LIMIT {
            step = step.saturating_mul(2);
        }
        height = height.saturating_sub(step);
    }

    if locator.last().copied() != Some(main_chain[0]) {
        locator.push(main_chain[0]);
    }

    locator
}

pub fn select_headers_for_peer(
    main_chain: &[Hash256],
    headers_by_hash: &HashMap<Hash256, BlockHeader>,
    locator: &[Hash256],
    stop: Option<Hash256>,
    max_headers: usize,
) -> Vec<BlockHeader> {
    if main_chain.is_empty() {
        return Vec::new();
    }

    let max_headers = max_headers.min(MAX_HEADERS_PER_MESSAGE);
    let height_by_hash = build_height_index(main_chain);
    let fork_height = fork_height_from_locator(locator, &height_by_hash);
    let mut start = fork_height.saturating_add(1);
    if start >= main_chain.len() {
        return Vec::new();
    }

    let mut out = Vec::new();
    while start < main_chain.len() && out.len() < max_headers {
        let hash = main_chain[start];
        if Some(hash) == stop {
            break;
        }
        if let Some(header) = headers_by_hash.get(&hash) {
            out.push(header.clone());
        } else {
            break;
        }
        start += 1;
    }
    out
}

pub fn select_block_hashes_for_peer(
    main_chain: &[Hash256],
    locator: &[Hash256],
    stop: Option<Hash256>,
    max_hashes: usize,
) -> Vec<Hash256> {
    if main_chain.is_empty() {
        return Vec::new();
    }

    let max_hashes = max_hashes.min(MAX_BLOCK_HASHES_PER_MESSAGE);
    let height_by_hash = build_height_index(main_chain);
    let fork_height = fork_height_from_locator(locator, &height_by_hash);
    let mut start = fork_height.saturating_add(1);
    if start >= main_chain.len() {
        return Vec::new();
    }

    let mut out = Vec::new();
    while start < main_chain.len() && out.len() < max_hashes {
        let hash = main_chain[start];
        if Some(hash) == stop {
            break;
        }
        out.push(hash);
        start += 1;
    }
    out
}

/// [`select_headers_for_peer`] backed by the caller's existing indexes:
/// `main_chain_height(hash)` returns the height of a *main-chain* block and
/// `header(hash)` its header. Avoids building a whole-chain map for every
/// `GetHeaders` (the relay did that under its global lock).
pub fn select_headers_with_lookup(
    main_chain: &[Hash256],
    main_chain_height: impl Fn(&Hash256) -> Option<usize>,
    header: impl Fn(&Hash256) -> Option<BlockHeader>,
    locator: &[Hash256],
    stop: Option<Hash256>,
    max_headers: usize,
) -> Vec<BlockHeader> {
    let max_headers = max_headers.min(MAX_HEADERS_PER_MESSAGE);
    let fork_height = locator
        .iter()
        .find_map(&main_chain_height)
        .unwrap_or(0);
    let mut out = Vec::new();
    for hash in main_chain.iter().skip(fork_height.saturating_add(1)) {
        if out.len() >= max_headers || Some(*hash) == stop {
            break;
        }
        match header(hash) {
            Some(header) => out.push(header),
            None => break,
        }
    }
    out
}

/// [`select_block_hashes_for_peer`] backed by a main-chain height lookup.
pub fn select_block_hashes_with_lookup(
    main_chain: &[Hash256],
    main_chain_height: impl Fn(&Hash256) -> Option<usize>,
    locator: &[Hash256],
    stop: Option<Hash256>,
    max_hashes: usize,
) -> Vec<Hash256> {
    let max_hashes = max_hashes.min(MAX_BLOCK_HASHES_PER_MESSAGE);
    let fork_height = locator
        .iter()
        .find_map(&main_chain_height)
        .unwrap_or(0);
    main_chain
        .iter()
        .skip(fork_height.saturating_add(1))
        .take_while(|hash| Some(**hash) != stop)
        .take(max_hashes)
        .copied()
        .collect()
}

fn build_height_index(main_chain: &[Hash256]) -> HashMap<Hash256, usize> {
    let mut height_by_hash = HashMap::<Hash256, usize>::with_capacity(main_chain.len());
    for (height, hash) in main_chain.iter().copied().enumerate() {
        height_by_hash.insert(hash, height);
    }
    height_by_hash
}

fn fork_height_from_locator(
    locator: &[Hash256],
    height_by_hash: &HashMap<Hash256, usize>,
) -> usize {
    locator
        .iter()
        .find_map(|hash| height_by_hash.get(hash).copied())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use scam_core::{BlockHeader, Hash256, Target, hash::hash256};

    use crate::sync::{
        build_block_locator, select_block_hashes_for_peer, select_block_hashes_with_lookup,
        select_headers_for_peer, select_headers_with_lookup,
    };

    /// P9: the lookup-based selectors return exactly what the map-based
    /// ones do, for every locator shape.
    #[test]
    fn lookup_selectors_match_map_based_selectors() {
        let (chain, headers) = chain_headers(300);
        let height = |hash: &Hash256| chain.iter().position(|h| h == hash);
        let header = |hash: &Hash256| headers.get(hash).cloned();
        let locators = [
            build_block_locator(&chain[..120]),
            build_block_locator(&chain),
            vec![Hash256([0xEE; 32])],
            Vec::new(),
        ];
        for locator in &locators {
            for stop in [None, Some(chain[150]), Some(chain[0])] {
                for max in [0, 1, 7, 2_000, 10_000] {
                    assert_eq!(
                        select_headers_with_lookup(&chain, height, header, locator, stop, max),
                        select_headers_for_peer(&chain, &headers, locator, stop, max),
                    );
                    assert_eq!(
                        select_block_hashes_with_lookup(&chain, height, locator, stop, max),
                        select_block_hashes_for_peer(&chain, locator, stop, max),
                    );
                }
            }
        }
    }

    fn chain_headers(count: usize) -> (Vec<Hash256>, HashMap<Hash256, BlockHeader>) {
        let mut chain = Vec::new();
        let mut headers = HashMap::new();
        let mut prev = Hash256::ZERO;
        for i in 0..count {
            let header = BlockHeader {
                version: 1,
                prev_block: prev,
                merkle_root: hash256(format!("mrkl-{i}").as_bytes()),
                timestamp: 1_770_763_200 + i as u64,
                target: Target::MAX,
                nonce: i as u64,
            };
            let hash = header.block_hash();
            prev = hash;
            chain.push(hash);
            headers.insert(hash, header);
        }
        (chain, headers)
    }

    #[test]
    fn locator_includes_tip_and_genesis() {
        let (chain, _) = chain_headers(100);
        let locator = build_block_locator(&chain);
        assert_eq!(locator[0], *chain.last().expect("tip"));
        assert_eq!(locator.last().copied(), Some(chain[0]));
    }

    #[test]
    fn locator_is_empty_for_empty_chain() {
        let locator = build_block_locator(&[]);
        assert!(locator.is_empty());
    }

    #[test]
    fn locator_soft_limit_keeps_genesis_and_compresses_history() {
        let (chain, _) = chain_headers(300);
        let locator = build_block_locator(&chain);
        assert_eq!(locator[0], *chain.last().expect("tip"));
        assert_eq!(locator.last().copied(), Some(chain[0]));
        assert!(locator.len() < chain.len());
    }

    #[test]
    fn locator_for_short_chain_is_strictly_consecutive_without_duplicates() {
        let (chain, _) = chain_headers(4);
        let locator = build_block_locator(&chain);
        assert_eq!(locator, vec![chain[3], chain[2], chain[1], chain[0]]);
    }

    #[test]
    fn locator_before_soft_limit_advances_by_single_step() {
        let (chain, _) = chain_headers(64);
        let locator = build_block_locator(&chain);
        assert!(locator.len() > 10);
        for i in 1..10 {
            assert_eq!(locator[i], chain[63 - i]);
        }
    }

    #[test]
    fn select_headers_after_common_fork() {
        let (chain, headers) = chain_headers(50);
        let locator = vec![chain[20], chain[10], chain[0]];

        let selected = select_headers_for_peer(&chain, &headers, &locator, None, 5);
        assert_eq!(selected.len(), 5);
        assert_eq!(selected[0].prev_block, chain[20]);
    }

    #[test]
    fn select_headers_respects_stop_hash() {
        let (chain, headers) = chain_headers(50);
        let locator = vec![chain[10], chain[0]];
        let stop = Some(chain[15]);

        let selected = select_headers_for_peer(&chain, &headers, &locator, stop, 100);
        assert_eq!(selected.len(), 4);
        assert_eq!(selected.last().expect("last").block_hash(), chain[14]);
    }

    #[test]
    fn select_block_hashes_respects_stop_hash() {
        let (chain, _) = chain_headers(30);
        let locator = vec![chain[5], chain[0]];
        let stop = Some(chain[9]);
        let hashes = select_block_hashes_for_peer(&chain, &locator, stop, 100);
        assert_eq!(hashes, vec![chain[6], chain[7], chain[8]]);
    }

    #[test]
    fn select_block_hashes_is_limited() {
        let (chain, _) = chain_headers(40);
        let locator = vec![chain[10], chain[0]];
        let hashes = select_block_hashes_for_peer(&chain, &locator, None, 3);
        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0], chain[11]);
        assert_eq!(hashes[2], chain[13]);
    }

    #[test]
    fn select_headers_and_hashes_return_empty_for_zero_limits_or_empty_chain() {
        let (chain, headers) = chain_headers(10);
        let locator = vec![chain[0]];
        assert!(select_headers_for_peer(&chain, &headers, &locator, None, 0).is_empty());
        assert!(select_block_hashes_for_peer(&chain, &locator, None, 0).is_empty());

        let empty_chain = Vec::<Hash256>::new();
        let empty_headers = HashMap::<Hash256, BlockHeader>::new();
        assert!(
            select_headers_for_peer(&empty_chain, &empty_headers, &locator, None, 8).is_empty()
        );
        assert!(select_block_hashes_for_peer(&empty_chain, &locator, None, 8).is_empty());
    }

    #[test]
    fn select_headers_without_common_locator_starts_after_genesis() {
        let (chain, headers) = chain_headers(12);
        let locator = vec![hash256(b"unknown-locator")];
        let selected = select_headers_for_peer(&chain, &headers, &locator, None, 2);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].prev_block, chain[0]);
    }
}
