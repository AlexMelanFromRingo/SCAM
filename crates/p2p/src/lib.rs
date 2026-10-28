#![cfg_attr(not(test), deny(clippy::unwrap_used))]
pub mod addrman;
pub mod discovery;
pub mod gossip;
pub mod sync;
pub mod transport;
pub mod wire;

pub use addrman::{AddrEntry, AddrTable, AddrTableChanges, MANUAL_SOURCE_GROUP, address_group};
pub use discovery::{PeerCandidate, select_outbound_peers};
pub use gossip::{
    GossipEngine, GossipError, GossipTelemetry, OutboundMessage, PeerId, ReplacementRateLimit,
};
pub use sync::{
    build_block_locator, select_block_hashes_for_peer, select_block_hashes_with_lookup,
    select_headers_for_peer, select_headers_with_lookup,
};
pub use transport::{
    FrameReader, FramingConfig, LocalHandshake, RemoteHandshake, TransportError, client_handshake,
    client_handshake_async, read_message, read_message_async, request_blocks, request_blocks_async,
    request_headers, request_headers_async, send_message, send_message_async, server_handshake,
    server_handshake_async,
};
pub use wire::{
    CompactBlock, InventoryItem, PeerAddress, PrefilledTxn, WireError, WireMessage, decode_message,
    encode_message,
};
