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
    Headers {
        headers: Vec<BlockHeader>,
    },
}

pub fn encode_message(message: &WireMessage) -> Result<Vec<u8>, WireError> {
    bincode::serialize(message).map_err(WireError::Encode)
}

pub fn decode_message(data: &[u8], max_message_size: usize) -> Result<WireMessage, WireError> {
    if data.len() > max_message_size {
        return Err(WireError::MessageTooLarge {
            limit: max_message_size,
            got: data.len(),
        });
    }
    bincode::deserialize(data).map_err(WireError::Decode)
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
    use super::{InventoryItem, WireMessage, decode_message, encode_message};
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
}
