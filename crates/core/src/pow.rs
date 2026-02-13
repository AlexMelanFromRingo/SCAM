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
    use crate::{Block, BlockHeader, Hash256, Target, block_meets_pow, header_meets_pow};

    fn decrement_be_bytes(bytes: &mut [u8; 32]) -> bool {
        for idx in (0..bytes.len()).rev() {
            if bytes[idx] > 0 {
                bytes[idx] -= 1;
                return true;
            }
            bytes[idx] = 0xff;
        }
        false
    }

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

    #[test]
    fn header_and_block_reject_when_target_is_below_header_hash() {
        let mut header = BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            timestamp: 1,
            target: Target::MAX,
            nonce: 7,
        };
        let header_hash = header.block_hash();
        let mut below_hash = header_hash.0;
        if !decrement_be_bytes(&mut below_hash) {
            header.nonce = 8;
            let retry_hash = header.block_hash();
            below_hash = retry_hash.0;
            assert!(decrement_be_bytes(&mut below_hash));
        }
        header.target = Target(below_hash);

        let block = Block {
            header: header.clone(),
            transactions: Vec::new(),
        };
        assert!(!header_meets_pow(&header));
        assert!(!block_meets_pow(&block));
    }

    #[test]
    fn block_meets_pow_tracks_header_result() {
        let block = Block {
            header: BlockHeader {
                version: 2,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 2,
                target: Target::MAX,
                nonce: 0,
            },
            transactions: Vec::new(),
        };
        assert_eq!(block_meets_pow(&block), header_meets_pow(&block.header));
    }
}
