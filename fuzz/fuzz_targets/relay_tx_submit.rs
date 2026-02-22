#![no_main]

use libfuzzer_sys::fuzz_target;
use scam_rpc::{TxSubmitRpcRequest, decode_tx_submit_request, parse_tx_submit_json};

const MAX_RELAY_FRAME: usize = 4 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    // Relay wire decode path (p2p transport payload parser).
    let _ = scam_p2p::decode_message(data, MAX_RELAY_FRAME);

    // /tx/submit JSON parser path.
    let _ = parse_tx_submit_json(data);

    // /tx/submit tx_hex -> bincode decode path.
    let req = TxSubmitRpcRequest {
        tx_hex: hex::encode(data),
        fee: data.len() as u64,
    };
    let _ = decode_tx_submit_request(&req);
});
