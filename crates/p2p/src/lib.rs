pub mod gossip;
pub mod wire;

pub use gossip::{GossipEngine, GossipError, OutboundMessage, PeerId};
pub use wire::{InventoryItem, WireError, WireMessage, decode_message, encode_message};
