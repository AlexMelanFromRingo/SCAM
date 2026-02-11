use serde::{Deserialize, Serialize};

use crate::codec::Encoder;
use crate::hash::{Hash256, hash256};
use crate::merkle::merkle_root;
use crate::target::Target;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Hash256,
    pub vout: u32,
}

impl OutPoint {
    pub const COINBASE_VOUT: u32 = u32::MAX;

    pub fn coinbase() -> Self {
        Self {
            txid: Hash256::ZERO,
            vout: Self::COINBASE_VOUT,
        }
    }

    pub fn is_coinbase(&self) -> bool {
        self.txid == Hash256::ZERO && self.vout == Self::COINBASE_VOUT
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TxIn {
    pub prev_out: OutPoint,
    pub signature: Vec<u8>,
    pub pubkey_compressed: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TxOut {
    pub value: u64,
    pub key_hash20: [u8; 20],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

impl Transaction {
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prev_out.is_coinbase()
    }

    pub fn txid(&self) -> Hash256 {
        hash256(&self.encode_for_hash())
    }

    pub fn encode_for_hash(&self) -> Vec<u8> {
        let mut enc = Encoder::with_capacity(256);
        enc.write_u32(self.version);
        enc.write_varint(self.inputs.len());
        for input in &self.inputs {
            enc.write_bytes(&input.prev_out.txid.0);
            enc.write_u32(input.prev_out.vout);
            enc.write_len_prefixed_bytes(&input.signature);
            enc.write_len_prefixed_bytes(&input.pubkey_compressed);
            enc.write_u32(input.sequence);
        }

        enc.write_varint(self.outputs.len());
        for output in &self.outputs {
            enc.write_u64(output.value);
            enc.write_bytes(&output.key_hash20);
        }

        enc.write_u32(self.lock_time);
        enc.into_bytes()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block: Hash256,
    pub merkle_root: Hash256,
    pub timestamp: u64,
    pub target: Target,
    pub nonce: u64,
}

impl BlockHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::with_capacity(128);
        enc.write_u32(self.version);
        enc.write_bytes(&self.prev_block.0);
        enc.write_bytes(&self.merkle_root.0);
        enc.write_u64(self.timestamp);
        enc.write_bytes(&self.target.0);
        enc.write_u64(self.nonce);
        enc.into_bytes()
    }

    pub fn block_hash(&self) -> Hash256 {
        hash256(&self.encode())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn computed_merkle_root(&self) -> Hash256 {
        let txids: Vec<Hash256> = self.transactions.iter().map(Transaction::txid).collect();
        merkle_root(&txids)
    }

    pub fn has_valid_merkle_root(&self) -> bool {
        self.header.merkle_root == self.computed_merkle_root()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Block, BlockHeader, OutPoint, Target, Transaction, TxIn, TxOut};

    #[test]
    fn coinbase_detection_works() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"genesis".to_vec(),
                pubkey_compressed: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 50,
                key_hash20: [0u8; 20],
            }],
            lock_time: 0,
        };
        assert!(tx.is_coinbase());
    }

    #[test]
    fn block_merkle_root_validation_works() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: b"genesis".to_vec(),
                pubkey_compressed: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 50,
                key_hash20: [1u8; 20],
            }],
            lock_time: 0,
        };

        let merkle = crate::merkle::merkle_root(&[tx.txid()]);
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: crate::Hash256::ZERO,
                merkle_root: merkle,
                timestamp: 0,
                target: Target::MAX,
                nonce: 0,
            },
            transactions: vec![tx],
        };

        assert!(block.has_valid_merkle_root());
    }
}
