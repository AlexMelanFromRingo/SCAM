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
    if main_chain.is_empty() || max_headers == 0 {
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
    if main_chain.is_empty() || max_hashes == 0 {
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

    use crate::sync::{build_block_locator, select_block_hashes_for_peer, select_headers_for_peer};

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
}
