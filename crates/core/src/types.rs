use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::codec::Encoder;
use crate::hash::{Hash256, hash256, tagged_hash256};
use crate::merkle::merkle_root;
use crate::target::Target;

const TX_SIGNING_TAG: &[u8] = b"SCAM-tx-signing-v1";

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
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

    pub fn signing_digest(&self, input_index: usize) -> Result<Hash256, TxSigningError> {
        self.signing_digest_with_chain_domain(input_index, &[])
    }

    pub fn signing_digest_with_chain_domain(
        &self,
        input_index: usize,
        chain_domain: &[u8],
    ) -> Result<Hash256, TxSigningError> {
        if input_index >= self.inputs.len() {
            return Err(TxSigningError::InputOutOfBounds {
                index: input_index,
                total_inputs: self.inputs.len(),
            });
        }
        let mut enc = Encoder::with_capacity(64 + self.inputs.len() * 40 + self.outputs.len() * 32);
        enc.write_len_prefixed_bytes(chain_domain);
        enc.write_bytes(&self.encode_for_signing(input_index));
        Ok(tagged_hash256(TX_SIGNING_TAG, &enc.into_bytes()))
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

    fn encode_for_signing(&self, signing_input_index: usize) -> Vec<u8> {
        let mut enc = Encoder::with_capacity(256);
        enc.write_u32(self.version);
        enc.write_varint(self.inputs.len());
        for (idx, input) in self.inputs.iter().enumerate() {
            enc.write_bytes(&input.prev_out.txid.0);
            enc.write_u32(input.prev_out.vout);
            if idx == signing_input_index {
                enc.write_len_prefixed_bytes(&input.pubkey_compressed);
            } else {
                enc.write_len_prefixed_bytes(&[]);
            }
            enc.write_u32(input.sequence);
        }

        enc.write_varint(self.outputs.len());
        for output in &self.outputs {
            enc.write_u64(output.value);
            enc.write_bytes(&output.key_hash20);
        }

        enc.write_u32(self.lock_time);
        enc.write_u32(signing_input_index as u32);
        enc.into_bytes()
    }
}

#[derive(Debug, Error)]
pub enum TxSigningError {
    #[error("input index {index} out of bounds (total inputs: {total_inputs})")]
    InputOutOfBounds { index: usize, total_inputs: usize },
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
    fn outpoint_non_coinbase_detection_works() {
        let prev = OutPoint {
            txid: crate::hash::hash256(b"prev"),
            vout: 0,
        };
        assert!(!prev.is_coinbase());
        let zero_hash_non_coinbase_vout = OutPoint {
            txid: crate::Hash256::ZERO,
            vout: 1,
        };
        assert!(!zero_hash_non_coinbase_vout.is_coinbase());
        let non_zero_hash_coinbase_vout = OutPoint {
            txid: crate::hash::hash256(b"prev2"),
            vout: OutPoint::COINBASE_VOUT,
        };
        assert!(!non_zero_hash_coinbase_vout.is_coinbase());
        assert!(OutPoint::coinbase().is_coinbase());
    }

    #[test]
    fn tx_with_regular_input_is_not_coinbase() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: crate::hash::hash256(b"prev"),
                    vout: 1,
                },
                signature: vec![1, 2, 3],
                pubkey_compressed: vec![2u8; 33],
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 50,
                key_hash20: [0u8; 20],
            }],
            lock_time: 0,
        };
        assert!(!tx.is_coinbase());
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

    #[test]
    fn block_merkle_root_validation_rejects_wrong_root() {
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
                key_hash20: [2u8; 20],
            }],
            lock_time: 0,
        };
        let mut wrong_merkle = crate::merkle::merkle_root(&[tx.txid()]).0;
        wrong_merkle[31] ^= 0x01;
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: crate::Hash256::ZERO,
                merkle_root: crate::Hash256(wrong_merkle),
                timestamp: 0,
                target: Target::MAX,
                nonce: 0,
            },
            transactions: vec![tx],
        };
        assert!(!block.has_valid_merkle_root());
    }

    #[test]
    fn encode_for_signing_only_keeps_selected_input_pubkey() {
        let signing_key = vec![3u8; 33];
        let non_signing_key = vec![4u8; 33];
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_out: OutPoint {
                        txid: crate::hash::hash256(b"prev-a"),
                        vout: 0,
                    },
                    signature: vec![9u8; 64],
                    pubkey_compressed: non_signing_key,
                    sequence: 11,
                },
                TxIn {
                    prev_out: OutPoint {
                        txid: crate::hash::hash256(b"prev-b"),
                        vout: 1,
                    },
                    signature: vec![8u8; 64],
                    pubkey_compressed: signing_key.clone(),
                    sequence: 22,
                },
            ],
            outputs: vec![TxOut {
                value: 7,
                key_hash20: [1u8; 20],
            }],
            lock_time: 5,
        };

        let encoded = tx.encode_for_signing(1);
        assert!(encoded.len() > 32);
        // Version + input count + first prevout txid + first prevout vout.
        assert_eq!(encoded[41], 0u8);
        // Second input pubkey length prefix + pubkey bytes.
        assert_eq!(encoded[82], signing_key.len() as u8);
        assert_eq!(&encoded[83..116], signing_key.as_slice());
    }

    #[test]
    fn signing_digest_is_stable() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: crate::hash::hash256(b"prev"),
                    vout: 0,
                },
                signature: vec![1, 2, 3],
                pubkey_compressed: vec![2u8; 33],
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 50,
                key_hash20: [3u8; 20],
            }],
            lock_time: 0,
        };

        let first = tx
            .signing_digest_with_chain_domain(0, b"scam-devnet")
            .expect("digest");
        let second = tx
            .signing_digest_with_chain_domain(0, b"scam-devnet")
            .expect("digest");
        assert_eq!(first, second);
    }

    #[test]
    fn signing_digest_is_domain_separated() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: crate::hash::hash256(b"prev"),
                    vout: 0,
                },
                signature: vec![],
                pubkey_compressed: vec![2u8; 33],
                sequence: 1,
            }],
            outputs: vec![TxOut {
                value: 42,
                key_hash20: [7u8; 20],
            }],
            lock_time: 0,
        };

        let tagged = tx.signing_digest(0).expect("digest");
        let untagged = crate::hash::hash256(&tx.encode_for_signing(0));
        assert_ne!(tagged, untagged);
    }

    #[test]
    fn signing_digest_changes_with_chain_domain() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: crate::hash::hash256(b"prev"),
                    vout: 0,
                },
                signature: vec![],
                pubkey_compressed: vec![3u8; 33],
                sequence: 1,
            }],
            outputs: vec![TxOut {
                value: 42,
                key_hash20: [8u8; 20],
            }],
            lock_time: 0,
        };

        let devnet = tx
            .signing_digest_with_chain_domain(0, b"scam-devnet")
            .expect("digest");
        let mainnet = tx
            .signing_digest_with_chain_domain(0, b"scam-mainnet")
            .expect("digest");
        assert_ne!(devnet, mainnet);
    }

    #[test]
    fn signing_digest_rejects_out_of_bounds_input_index() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: crate::hash::hash256(b"prev"),
                    vout: 0,
                },
                signature: vec![],
                pubkey_compressed: vec![2u8; 33],
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [1u8; 20],
            }],
            lock_time: 0,
        };

        let err = tx
            .signing_digest_with_chain_domain(1, b"scam-devnet")
            .expect_err("index 1 is out of bounds");
        assert!(matches!(
            err,
            crate::types::TxSigningError::InputOutOfBounds {
                index: 1,
                total_inputs: 1
            }
        ));
    }

    #[test]
    fn txid_changes_when_fields_change() {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: crate::hash::hash256(b"prev"),
                    vout: 0,
                },
                signature: vec![1],
                pubkey_compressed: vec![2u8; 33],
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 10,
                key_hash20: [1u8; 20],
            }],
            lock_time: 0,
        };
        let first = tx.txid();
        tx.outputs[0].value = 11;
        let second = tx.txid();
        assert_ne!(first, second);
    }

    #[test]
    fn block_hash_changes_with_nonce() {
        let mut header = BlockHeader {
            version: 1,
            prev_block: crate::Hash256::ZERO,
            merkle_root: crate::Hash256::ZERO,
            timestamp: 1_770_763_200,
            target: Target::MAX,
            nonce: 1,
        };
        let first = header.block_hash();
        header.nonce = 2;
        let second = header.block_hash();
        assert_ne!(first, second);
    }
}
