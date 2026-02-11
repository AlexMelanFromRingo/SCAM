use crate::hash::{Hash256, hash256};

pub fn merkle_root(txids: &[Hash256]) -> Hash256 {
    if txids.is_empty() {
        return Hash256::ZERO;
    }

    let mut level: Vec<Hash256> = txids.to_vec();

    while level.len() > 1 {
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

    level[0]
}

#[cfg(test)]
mod tests {
    use super::merkle_root;
    use crate::hash::hash256;

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
}
