use crate::hash::{Hash256, hash256};

pub fn merkle_root(txids: &[Hash256]) -> Hash256 {
    if txids.is_empty() {
        return Hash256::ZERO;
    }

    let mut level: Vec<Hash256> = txids.to_vec();

    // Safety bound: a valid merkle reduction must finish in at most N rounds.
    for _ in 0..=txids.len() {
        if level.len() <= 1 {
            break;
        }

        if level.len() % 2 == 1
            && let Some(last) = level.last().copied()
        {
            level.push(last);
        }

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            let mut encoded = [0u8; 64];
            encoded[..32].copy_from_slice(&pair[0].0);
            encoded[32..].copy_from_slice(&pair[1].0);
            next.push(hash256(&encoded));
        }
        level = next;
    }

    if level.len() != 1 {
        // Defensive fallback for unexpected malformed intermediate state.
        let mut acc = Hash256::ZERO;
        for hash in level {
            let mut encoded = [0u8; 64];
            encoded[..32].copy_from_slice(&acc.0);
            encoded[32..].copy_from_slice(&hash.0);
            acc = hash256(&encoded);
        }
        return acc;
    }

    level[0]
}

#[cfg(test)]
mod tests {
    use super::merkle_root;
    use crate::hash::{Hash256, hash256};

    fn manual_pair_hash(left: Hash256, right: Hash256) -> Hash256 {
        let mut encoded = [0u8; 64];
        encoded[..32].copy_from_slice(&left.0);
        encoded[32..].copy_from_slice(&right.0);
        hash256(&encoded)
    }

    #[test]
    fn empty_list_has_zero_merkle_root() {
        assert_eq!(merkle_root(&[]).0, [0u8; 32]);
    }

    #[test]
    fn merkle_root_is_stable() {
        let txids = [hash256(b"a"), hash256(b"b"), hash256(b"c")];
        let first = merkle_root(&txids);
        let second = merkle_root(&txids);
        assert_eq!(first, second);
    }

    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let leaf = hash256(b"single");
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn two_leaf_root_matches_single_pair_hash() {
        let a = hash256(b"left");
        let b = hash256(b"right");
        let expected = manual_pair_hash(a, b);
        assert_eq!(merkle_root(&[a, b]), expected);
    }

    #[test]
    fn odd_leaf_count_duplicates_last_leaf() {
        let a = hash256(b"a");
        let b = hash256(b"b");
        let c = hash256(b"c");

        let left = manual_pair_hash(a, b);
        let right = manual_pair_hash(c, c);
        let expected = manual_pair_hash(left, right);

        assert_eq!(merkle_root(&[a, b, c]), expected);
    }

    #[test]
    fn large_even_and_odd_sets_complete_and_differ() {
        let txids = (0u16..513)
            .map(|i| hash256(&i.to_le_bytes()))
            .collect::<Vec<_>>();
        let even_root = merkle_root(&txids[..512]);
        let odd_root = merkle_root(&txids);
        assert_ne!(even_root, odd_root);
    }
}
