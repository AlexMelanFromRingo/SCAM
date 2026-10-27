#![cfg_attr(not(test), deny(clippy::unwrap_used))]
use scam_core::{Block, BlockHeader, Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Serialize)]
pub struct StatusResponse {
    pub network_id: String,
    pub tip_height: u64,
    pub tip_hash: String,
    pub utxo_count: usize,
    pub cumulative_work: String,
    pub network_hashrate_hps: f64,
    pub stratum_active_clients: Option<usize>,
    pub stratum_workers_active: Option<usize>,
    pub stratum_pool_hashrate_hps: Option<f64>,
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

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct TxSubmitRpcRequest {
    pub tx_hex: String,
    /// 0 (the default) = store the transaction's actual fee; any other value
    /// must equal it (the node never trusts a claimed fee).
    pub fee: u64,
}

pub fn decode_tx_submit_request(
    req: &TxSubmitRpcRequest,
) -> Result<(Transaction, u64), TxSubmitError> {
    if req.tx_hex.trim().is_empty() {
        return Err(TxSubmitError::EmptyTxHex);
    }
    let decoded = hex::decode(req.tx_hex.trim()).map_err(TxSubmitError::InvalidHex)?;
    let tx =
        bincode::deserialize::<Transaction>(&decoded).map_err(TxSubmitError::InvalidTxPayload)?;
    Ok((tx, req.fee))
}

pub fn parse_tx_submit_json(body: &[u8]) -> Result<(Transaction, u64), TxSubmitError> {
    let req =
        serde_json::from_slice::<TxSubmitRpcRequest>(body).map_err(TxSubmitError::InvalidJson)?;
    decode_tx_submit_request(&req)
}

#[derive(Debug, Error)]
pub enum TxSubmitError {
    #[error("invalid tx submit json: {0}")]
    InvalidJson(#[source] serde_json::Error),
    #[error("tx_hex must not be empty")]
    EmptyTxHex,
    #[error("invalid tx_hex: {0}")]
    InvalidHex(#[source] hex::FromHexError),
    #[error("invalid tx payload: {0}")]
    InvalidTxPayload(#[source] bincode::Error),
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

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use crate::{
        TxSubmitRpcRequest, decode_tx_submit_request, parse_tx_submit_json, to_pretty_json,
    };
    use scam_core::{OutPoint, Transaction, TxIn, TxOut};

    #[derive(Serialize)]
    struct Sample<'a> {
        id: u32,
        label: &'a str,
    }

    #[test]
    fn to_pretty_json_renders_expected_fields() {
        let rendered = to_pretty_json(&Sample { id: 7, label: "ok" }).expect("json");
        assert!(rendered.contains('\n'));
        assert!(rendered.contains("\"id\": 7"));
        assert!(rendered.contains("\"label\": \"ok\""));
        assert!(rendered.starts_with('{'));
        assert!(rendered.ends_with('}'));
    }

    fn sample_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: scam_core::Hash256([0x11; 32]),
                    vout: 0,
                },
                signature: vec![0x22; 64],
                pubkey_compressed: vec![0x02; 33],
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [0x33; 20],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn decode_tx_submit_request_rejects_empty_hex_payload() {
        let err = decode_tx_submit_request(&TxSubmitRpcRequest {
            tx_hex: " \n\t ".to_owned(),
            fee: 1,
        })
        .expect_err("empty tx hex must fail");
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn decode_tx_submit_request_rejects_invalid_hex_and_payload() {
        let hex_err = decode_tx_submit_request(&TxSubmitRpcRequest {
            tx_hex: "zz".to_owned(),
            fee: 1,
        })
        .expect_err("invalid hex must fail");
        assert!(hex_err.to_string().contains("invalid tx_hex"));

        let payload_err = decode_tx_submit_request(&TxSubmitRpcRequest {
            tx_hex: hex::encode([0x01, 0x02, 0x03, 0x04]),
            fee: 1,
        })
        .expect_err("invalid bincode payload must fail");
        assert!(payload_err.to_string().contains("invalid tx payload"));
    }

    #[test]
    fn parse_tx_submit_json_roundtrip() {
        let tx = sample_tx();
        let req = serde_json::json!({
            "tx_hex": hex::encode(bincode::serialize(&tx).expect("encode tx")),
            "fee": 7
        });
        let (decoded, fee) = parse_tx_submit_json(req.to_string().as_bytes()).expect("parse");
        assert_eq!(decoded.txid(), tx.txid());
        assert_eq!(fee, 7);
    }
}
