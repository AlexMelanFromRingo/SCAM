#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = scam_p2p::decode_message(data, 4 * 1024 * 1024);
});
