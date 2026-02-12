#![no_main]

use libfuzzer_sys::fuzz_target;
use scam_core::{Block, block_meets_pow};

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = bincode::deserialize::<Block>(data) {
        let _ = block.has_valid_merkle_root();
        let _ = block.header.block_hash();
        let _ = block_meets_pow(&block);
    }
});
