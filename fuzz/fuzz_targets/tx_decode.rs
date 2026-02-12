#![no_main]

use libfuzzer_sys::fuzz_target;
use scam_core::Transaction;

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = bincode::deserialize::<Transaction>(data) {
        let _ = tx.txid();
        if !tx.inputs.is_empty() {
            let _ = tx.signing_digest_with_chain_domain(0, b"fuzz-domain");
        }
    }
});
