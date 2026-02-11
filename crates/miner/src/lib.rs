use scam_core::{Block, BlockHeader, Hash256, Target, Transaction, header_meets_pow};

#[derive(Clone, Debug)]
pub struct BlockTemplate {
    pub version: u32,
    pub prev_block: Hash256,
    pub timestamp: u64,
    pub target: Target,
    pub transactions: Vec<Transaction>,
}

impl BlockTemplate {
    pub fn build_with_nonce(&self, nonce: u64) -> Block {
        let txids: Vec<Hash256> = self.transactions.iter().map(Transaction::txid).collect();
        let merkle_root = scam_core::merkle::merkle_root(&txids);
        Block {
            header: BlockHeader {
                version: self.version,
                prev_block: self.prev_block,
                merkle_root,
                timestamp: self.timestamp,
                target: self.target,
                nonce,
            },
            transactions: self.transactions.clone(),
        }
    }
}

pub fn mine_block(template: &BlockTemplate, max_nonce: u64) -> Option<Block> {
    for nonce in 0..=max_nonce {
        let candidate = template.build_with_nonce(nonce);
        if header_meets_pow(&candidate.header) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use scam_core::{OutPoint, Target, Transaction, TxIn, TxOut};

    use crate::{BlockTemplate, mine_block};

    fn coinbase() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"coinbase".to_vec(),
                pubkey_compressed: vec![],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 50,
                key_hash20: [0u8; 20],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn max_target_finds_nonce_immediately() {
        let template = BlockTemplate {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            transactions: vec![coinbase()],
        };
        let mined = mine_block(&template, 100).expect("must mine");
        assert_eq!(mined.header.nonce, 0);
    }

    #[test]
    fn tiny_search_space_can_fail() {
        let template = BlockTemplate {
            version: 1,
            prev_block: scam_core::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::from_hex(
                "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )
            .expect("target parse"),
            transactions: vec![coinbase()],
        };
        let mined = mine_block(&template, 1);
        if let Some(block) = mined {
            assert!(scam_core::header_meets_pow(&block.header));
        }
    }
}
