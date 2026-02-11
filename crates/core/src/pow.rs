use crate::hash::Hash256;
use crate::types::{Block, BlockHeader};

pub fn header_pow_hash(header: &BlockHeader) -> Hash256 {
    header.block_hash()
}

pub fn header_meets_pow(header: &BlockHeader) -> bool {
    let pow_hash = header_pow_hash(header);
    header.target.allows_hash(&pow_hash)
}

pub fn block_meets_pow(block: &Block) -> bool {
    header_meets_pow(&block.header)
}

#[cfg(test)]
mod tests {
    use crate::{BlockHeader, Hash256, Target, header_meets_pow};

    #[test]
    fn max_target_accepts_any_hash() {
        let header = BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            timestamp: 0,
            target: Target::MAX,
            nonce: 0,
        };
        assert!(header_meets_pow(&header));
    }
}
