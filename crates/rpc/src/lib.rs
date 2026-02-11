use scam_core::{Block, BlockHeader, Transaction};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct StatusResponse {
    pub network_id: String,
    pub tip_height: u64,
    pub tip_hash: String,
    pub utxo_count: usize,
    pub cumulative_work: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockResponse {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp: u64,
    pub target: String,
    pub tx_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct TxResponse {
    pub block_height: u64,
    pub tx_index: usize,
    pub txid: String,
    pub input_count: usize,
    pub output_count: usize,
}

pub fn to_pretty_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(value)
}

impl BlockResponse {
    pub fn from_block(height: u64, block: &Block) -> Self {
        Self {
            height,
            hash: block.header.block_hash().to_hex(),
            prev_hash: block.header.prev_block.to_hex(),
            timestamp: block.header.timestamp,
            target: block.header.target.to_hex(),
            tx_count: block.transactions.len(),
        }
    }
}

impl TxResponse {
    pub fn from_tx(block_height: u64, tx_index: usize, tx: &Transaction) -> Self {
        Self {
            block_height,
            tx_index,
            txid: tx.txid().to_hex(),
            input_count: tx.inputs.len(),
            output_count: tx.outputs.len(),
        }
    }
}

pub fn header_to_block_response(
    height: u64,
    header: &BlockHeader,
    tx_count: usize,
) -> BlockResponse {
    BlockResponse {
        height,
        hash: header.block_hash().to_hex(),
        prev_hash: header.prev_block.to_hex(),
        timestamp: header.timestamp,
        target: header.target.to_hex(),
        tx_count,
    }
}
