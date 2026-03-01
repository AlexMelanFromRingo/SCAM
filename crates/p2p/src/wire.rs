use bincode::Options;
use scam_core::{Block, BlockHeader, Hash256, Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum InventoryItem {
    Tx(Hash256),
    Block(Hash256),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WireMessage {
    Version {
        protocol_version: u32,
        network_id: String,
        user_agent: String,
        start_height: u64,
    },
    Verack,
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Inv {
        items: Vec<InventoryItem>,
    },
    GetData {
        items: Vec<InventoryItem>,
    },
    NotFound {
        items: Vec<InventoryItem>,
    },
    Tx {
        tx: Transaction,
    },
    Block {
        block: Block,
    },
    GetHeaders {
        locator: Vec<Hash256>,
        stop: Option<Hash256>,
    },
    GetBlocks {
        locator: Vec<Hash256>,
        stop: Option<Hash256>,
    },
    Headers {
        headers: Vec<BlockHeader>,
    },
    GetAddr,
    Addr {
        peers: Vec<PeerAddress>,
    },
    SendRecon {
        enabled: bool,
        version: u16,
        short_id_bits: u8,
        implementation: u32,
        salt: u64,
        max_sketch_items: u32,
        max_diff_items: u32,
    },
    ReqRecon {
        salt: u64,
        set_size: u32,
    },
    Sketch {
        salt: u64,
        bits: u32,
        capacity: u32,
        implementation: u32,
        bytes: Vec<u8>,
    },
    ReqSketchExt {
        salt: u64,
        capacity: u32,
    },
    ReqTx {
        salt: u64,
        short_ids: Vec<u64>,
    },
    ReconcileDiff {
        salt: u64,
        announce_txids: Vec<Hash256>,
        request_txids: Vec<Hash256>,
    },
    SendCmpct {
        high_bandwidth: bool,
        version: u64,
    },
    CmpctBlock {
        block: CompactBlock,
    },
    GetBlockTxn {
        block_hash: Hash256,
        indexes: Vec<u32>,
    },
    BlockTxn {
        block_hash: Hash256,
        transactions: Vec<Transaction>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerAddress {
    pub address: String,
    pub services: u64,
    pub last_seen_unix_sec: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrefilledTxn {
    pub index: u32,
    pub tx: Transaction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactBlock {
    pub header: BlockHeader,
    pub tx_count: u32,
    pub short_txids: Vec<u64>,
    pub prefilled: Vec<PrefilledTxn>,
}

pub fn encode_message(message: &WireMessage) -> Result<Vec<u8>, WireError> {
    bincode::options()
        .serialize(message)
        .map_err(WireError::Encode)
}

pub fn decode_message(data: &[u8], max_message_size: usize) -> Result<WireMessage, WireError> {
    if data.len() > max_message_size {
        return Err(WireError::MessageTooLarge {
            limit: max_message_size,
            got: data.len(),
        });
    }
    bincode::options()
        .with_limit(max_message_size as u64)
        .reject_trailing_bytes()
        .deserialize(data)
        .map_err(WireError::Decode)
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("wire encode failed: {0}")]
    Encode(#[source] bincode::Error),
    #[error("wire decode failed: {0}")]
    Decode(#[source] bincode::Error),
    #[error("message too large: limit={limit}, got={got}")]
    MessageTooLarge { limit: usize, got: usize },
}

#[cfg(test)]
mod tests {
    use super::{
        CompactBlock, InventoryItem, PeerAddress, PrefilledTxn, WireMessage, decode_message,
        encode_message,
    };
    use scam_core::hash::hash256;

    #[test]
    fn wire_roundtrip() {
        let msg = WireMessage::Inv {
            items: vec![
                InventoryItem::Tx(hash256(b"tx1")),
                InventoryItem::Block(hash256(b"block1")),
            ],
        };
        let encoded = encode_message(&msg).expect("encode");
        let decoded = decode_message(&encoded, 1024).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_message_enforces_size_limit_boundary() {
        let msg = WireMessage::Ping { nonce: 42 };
        let encoded = encode_message(&msg).expect("encode");

        let decoded = decode_message(&encoded, encoded.len()).expect("equal limit must decode");
        assert_eq!(decoded, msg);

        let err = decode_message(&encoded, encoded.len().saturating_sub(1))
            .expect_err("smaller limit must reject");
        assert!(matches!(err, super::WireError::MessageTooLarge { .. }));
    }

    #[test]
    fn decode_message_rejects_trailing_bytes() {
        let msg = WireMessage::Ping { nonce: 7 };
        let mut encoded = encode_message(&msg).expect("encode");
        encoded.push(0xAA);
        let err = decode_message(&encoded, 1024).expect_err("trailing bytes must reject");
        assert!(matches!(err, super::WireError::Decode(_)));
    }

    #[test]
    fn compact_and_addr_messages_roundtrip() {
        let header = scam_core::BlockHeader {
            version: 1,
            prev_block: hash256(b"prev"),
            merkle_root: hash256(b"merkle"),
            timestamp: 1_770_763_200,
            target: scam_core::Target::MAX,
            nonce: 7,
        };
        let tx = scam_core::Transaction {
            version: 1,
            inputs: vec![scam_core::TxIn {
                prev_out: scam_core::OutPoint {
                    txid: hash256(b"spend"),
                    vout: 0,
                },
                signature: vec![1u8; 64],
                pubkey_compressed: vec![0x02; 33],
                sequence: 0,
            }],
            outputs: vec![scam_core::TxOut {
                value: 42,
                key_hash20: [3u8; 20],
            }],
            lock_time: 0,
        };
        let compact = WireMessage::CmpctBlock {
            block: CompactBlock {
                header,
                tx_count: 2,
                short_txids: vec![9],
                prefilled: vec![PrefilledTxn { index: 0, tx }],
            },
        };
        let addr = WireMessage::Addr {
            peers: vec![PeerAddress {
                address: "127.0.0.1:18444".to_owned(),
                services: 1,
                last_seen_unix_sec: 1,
            }],
        };
        let recon_sketch = WireMessage::Sketch {
            salt: 42,
            bits: 32,
            capacity: 16,
            implementation: 0,
            bytes: vec![1, 2, 3],
        };
        let recon_diff = WireMessage::ReconcileDiff {
            salt: 42,
            announce_txids: vec![hash256(b"announce")],
            request_txids: vec![hash256(b"request")],
        };
        for msg in [compact, addr, recon_sketch, recon_diff] {
            let encoded = encode_message(&msg).expect("encode");
            let decoded = decode_message(&encoded, 8 * 1024).expect("decode");
            assert_eq!(decoded, msg);
        }
    }
}
