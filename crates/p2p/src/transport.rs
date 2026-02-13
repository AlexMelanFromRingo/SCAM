use std::io::{Read, Write};
use std::net::TcpStream;

use scam_core::{BlockHeader, Hash256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::wire::{InventoryItem, WireMessage, decode_message, encode_message};

#[derive(Clone, Debug)]
pub struct FramingConfig {
    pub magic: u32,
    pub max_message_size: usize,
}

impl Default for FramingConfig {
    fn default() -> Self {
        Self {
            magic: 0x53_43_41_4d, // "SCAM"
            max_message_size: 8 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LocalHandshake {
    pub protocol_version: u32,
    pub network_id: String,
    pub user_agent: String,
    pub start_height: u64,
}

#[derive(Clone, Debug)]
pub struct RemoteHandshake {
    pub protocol_version: u32,
    pub network_id: String,
    pub user_agent: String,
    pub start_height: u64,
}

pub fn send_message(
    stream: &mut TcpStream,
    message: &WireMessage,
    cfg: &FramingConfig,
) -> Result<(), TransportError> {
    let payload = encode_message(message).map_err(TransportError::Wire)?;
    if payload.len() > cfg.max_message_size {
        return Err(TransportError::MessageTooLarge {
            limit: cfg.max_message_size,
            got: payload.len(),
        });
    }

    let mut header = [0u8; 8];
    header[..4].copy_from_slice(&cfg.magic.to_be_bytes());
    header[4..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    stream.write_all(&header).map_err(TransportError::Io)?;
    stream.write_all(&payload).map_err(TransportError::Io)?;
    Ok(())
}

pub async fn send_message_async<S: AsyncWrite + Unpin>(
    stream: &mut S,
    message: &WireMessage,
    cfg: &FramingConfig,
) -> Result<(), TransportError> {
    let payload = encode_message(message).map_err(TransportError::Wire)?;
    if payload.len() > cfg.max_message_size {
        return Err(TransportError::MessageTooLarge {
            limit: cfg.max_message_size,
            got: payload.len(),
        });
    }

    let mut header = [0u8; 8];
    header[..4].copy_from_slice(&cfg.magic.to_be_bytes());
    header[4..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    stream
        .write_all(&header)
        .await
        .map_err(TransportError::Io)?;
    stream
        .write_all(&payload)
        .await
        .map_err(TransportError::Io)?;
    stream.flush().await.map_err(TransportError::Io)?;
    Ok(())
}

pub fn read_message(
    stream: &mut TcpStream,
    cfg: &FramingConfig,
) -> Result<WireMessage, TransportError> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).map_err(TransportError::Io)?;

    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if magic != cfg.magic {
        return Err(TransportError::InvalidMagic {
            expected: cfg.magic,
            got: magic,
        });
    }
    let payload_len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if payload_len > cfg.max_message_size {
        return Err(TransportError::MessageTooLarge {
            limit: cfg.max_message_size,
            got: payload_len,
        });
    }

    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .map_err(TransportError::Io)?;
    decode_message(&payload, cfg.max_message_size).map_err(TransportError::Wire)
}

pub async fn read_message_async<S: AsyncRead + Unpin>(
    stream: &mut S,
    cfg: &FramingConfig,
) -> Result<WireMessage, TransportError> {
    let mut header = [0u8; 8];
    stream
        .read_exact(&mut header)
        .await
        .map_err(TransportError::Io)?;

    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if magic != cfg.magic {
        return Err(TransportError::InvalidMagic {
            expected: cfg.magic,
            got: magic,
        });
    }
    let payload_len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if payload_len > cfg.max_message_size {
        return Err(TransportError::MessageTooLarge {
            limit: cfg.max_message_size,
            got: payload_len,
        });
    }

    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(TransportError::Io)?;
    decode_message(&payload, cfg.max_message_size).map_err(TransportError::Wire)
}

pub fn client_handshake(
    stream: &mut TcpStream,
    cfg: &FramingConfig,
    local: &LocalHandshake,
) -> Result<RemoteHandshake, TransportError> {
    send_message(
        stream,
        &WireMessage::Version {
            protocol_version: local.protocol_version,
            network_id: local.network_id.clone(),
            user_agent: local.user_agent.clone(),
            start_height: local.start_height,
        },
        cfg,
    )?;

    let version = read_message(stream, cfg)?;
    let remote = parse_version(version)?;
    send_message(stream, &WireMessage::Verack, cfg)?;
    let verack = read_message(stream, cfg)?;
    if !matches!(verack, WireMessage::Verack) {
        return Err(TransportError::UnexpectedMessage {
            expected: "verack",
            got: format!("{verack:?}"),
        });
    }
    Ok(remote)
}

pub async fn client_handshake_async<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &FramingConfig,
    local: &LocalHandshake,
) -> Result<RemoteHandshake, TransportError> {
    send_message_async(
        stream,
        &WireMessage::Version {
            protocol_version: local.protocol_version,
            network_id: local.network_id.clone(),
            user_agent: local.user_agent.clone(),
            start_height: local.start_height,
        },
        cfg,
    )
    .await?;

    let version = read_message_async(stream, cfg).await?;
    let remote = parse_version(version)?;
    send_message_async(stream, &WireMessage::Verack, cfg).await?;
    let verack = read_message_async(stream, cfg).await?;
    if !matches!(verack, WireMessage::Verack) {
        return Err(TransportError::UnexpectedMessage {
            expected: "verack",
            got: format!("{verack:?}"),
        });
    }
    Ok(remote)
}

pub fn server_handshake(
    stream: &mut TcpStream,
    cfg: &FramingConfig,
    local: &LocalHandshake,
) -> Result<RemoteHandshake, TransportError> {
    let version = read_message(stream, cfg)?;
    let remote = parse_version(version)?;
    send_message(
        stream,
        &WireMessage::Version {
            protocol_version: local.protocol_version,
            network_id: local.network_id.clone(),
            user_agent: local.user_agent.clone(),
            start_height: local.start_height,
        },
        cfg,
    )?;
    let verack = read_message(stream, cfg)?;
    if !matches!(verack, WireMessage::Verack) {
        return Err(TransportError::UnexpectedMessage {
            expected: "verack",
            got: format!("{verack:?}"),
        });
    }
    send_message(stream, &WireMessage::Verack, cfg)?;
    Ok(remote)
}

pub async fn server_handshake_async<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &FramingConfig,
    local: &LocalHandshake,
) -> Result<RemoteHandshake, TransportError> {
    let version = read_message_async(stream, cfg).await?;
    let remote = parse_version(version)?;
    send_message_async(
        stream,
        &WireMessage::Version {
            protocol_version: local.protocol_version,
            network_id: local.network_id.clone(),
            user_agent: local.user_agent.clone(),
            start_height: local.start_height,
        },
        cfg,
    )
    .await?;
    let verack = read_message_async(stream, cfg).await?;
    if !matches!(verack, WireMessage::Verack) {
        return Err(TransportError::UnexpectedMessage {
            expected: "verack",
            got: format!("{verack:?}"),
        });
    }
    send_message_async(stream, &WireMessage::Verack, cfg).await?;
    Ok(remote)
}

pub fn request_headers(
    stream: &mut TcpStream,
    cfg: &FramingConfig,
    locator: Vec<Hash256>,
    stop: Option<Hash256>,
) -> Result<Vec<BlockHeader>, TransportError> {
    send_message(stream, &WireMessage::GetHeaders { locator, stop }, cfg)?;
    let response = read_message(stream, cfg)?;
    match response {
        WireMessage::Headers { headers } => Ok(headers),
        other => Err(TransportError::UnexpectedMessage {
            expected: "headers",
            got: format!("{other:?}"),
        }),
    }
}

pub async fn request_headers_async<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &FramingConfig,
    locator: Vec<Hash256>,
    stop: Option<Hash256>,
) -> Result<Vec<BlockHeader>, TransportError> {
    send_message_async(stream, &WireMessage::GetHeaders { locator, stop }, cfg).await?;
    let response = read_message_async(stream, cfg).await?;
    match response {
        WireMessage::Headers { headers } => Ok(headers),
        other => Err(TransportError::UnexpectedMessage {
            expected: "headers",
            got: format!("{other:?}"),
        }),
    }
}

pub fn request_blocks(
    stream: &mut TcpStream,
    cfg: &FramingConfig,
    locator: Vec<Hash256>,
    stop: Option<Hash256>,
) -> Result<Vec<Hash256>, TransportError> {
    send_message(stream, &WireMessage::GetBlocks { locator, stop }, cfg)?;
    let response = read_message(stream, cfg)?;
    match response {
        WireMessage::Inv { items } => {
            let mut hashes = Vec::<Hash256>::new();
            for item in items {
                match item {
                    InventoryItem::Block(hash) => hashes.push(hash),
                    InventoryItem::Tx(hash) => {
                        return Err(TransportError::UnexpectedInventoryItem {
                            expected: "block hash inventory",
                            got: format!("tx:{hash}"),
                        });
                    }
                }
            }
            Ok(hashes)
        }
        other => Err(TransportError::UnexpectedMessage {
            expected: "inv",
            got: format!("{other:?}"),
        }),
    }
}

pub async fn request_blocks_async<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &FramingConfig,
    locator: Vec<Hash256>,
    stop: Option<Hash256>,
) -> Result<Vec<Hash256>, TransportError> {
    send_message_async(stream, &WireMessage::GetBlocks { locator, stop }, cfg).await?;
    let response = read_message_async(stream, cfg).await?;
    match response {
        WireMessage::Inv { items } => {
            let mut hashes = Vec::<Hash256>::new();
            for item in items {
                match item {
                    InventoryItem::Block(hash) => hashes.push(hash),
                    InventoryItem::Tx(hash) => {
                        return Err(TransportError::UnexpectedInventoryItem {
                            expected: "block hash inventory",
                            got: format!("tx:{hash}"),
                        });
                    }
                }
            }
            Ok(hashes)
        }
        other => Err(TransportError::UnexpectedMessage {
            expected: "inv",
            got: format!("{other:?}"),
        }),
    }
}

fn parse_version(message: WireMessage) -> Result<RemoteHandshake, TransportError> {
    match message {
        WireMessage::Version {
            protocol_version,
            network_id,
            user_agent,
            start_height,
        } => Ok(RemoteHandshake {
            protocol_version,
            network_id,
            user_agent,
            start_height,
        }),
        other => Err(TransportError::UnexpectedMessage {
            expected: "version",
            got: format!("{other:?}"),
        }),
    }
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io error: {0}")]
    Io(#[source] std::io::Error),
    #[error("wire error: {0}")]
    Wire(#[source] crate::wire::WireError),
    #[error("invalid magic: expected {expected:#x}, got {got:#x}")]
    InvalidMagic { expected: u32, got: u32 },
    #[error("message too large: limit={limit}, got={got}")]
    MessageTooLarge { limit: usize, got: usize },
    #[error("unexpected message: expected {expected}, got {got}")]
    UnexpectedMessage { expected: &'static str, got: String },
    #[error("unexpected inventory item: expected {expected}, got {got}")]
    UnexpectedInventoryItem { expected: &'static str, got: String },
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use scam_core::{Hash256, Target, hash::hash256};
    use tokio::io::AsyncReadExt;
    use tokio::runtime::Runtime;

    use crate::sync::{build_block_locator, select_block_hashes_for_peer, select_headers_for_peer};
    use crate::transport::{
        FramingConfig, LocalHandshake, WireMessage, client_handshake, client_handshake_async,
        read_message, read_message_async, request_blocks, request_blocks_async, request_headers,
        request_headers_async, send_message, send_message_async, server_handshake,
        server_handshake_async,
    };

    fn handshake() -> LocalHandshake {
        LocalHandshake {
            protocol_version: 1,
            network_id: "devnet".to_owned(),
            user_agent: "scam-test".to_owned(),
            start_height: 0,
        }
    }

    #[test]
    fn handshake_and_headers_roundtrip() {
        let cfg = FramingConfig::default();
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind failed: {err}"),
        };
        let addr = listener.local_addr().expect("local addr");

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("set timeout");
            let remote = server_handshake(&mut stream, &cfg, &handshake()).expect("server hs");
            assert_eq!(remote.network_id, "devnet");

            let (chain, headers_map) = chain_headers(8);
            let request = read_message(&mut stream, &cfg).expect("read req");
            let WireMessage::GetHeaders { locator, stop } = request else {
                panic!("expected getheaders");
            };
            let headers = select_headers_for_peer(&chain, &headers_map, &locator, stop, 2000);
            send_message(&mut stream, &WireMessage::Headers { headers }, &cfg)
                .expect("send headers");

            let request = read_message(&mut stream, &cfg).expect("read req");
            let WireMessage::GetBlocks { locator, stop } = request else {
                panic!("expected getblocks");
            };
            let hashes = select_block_hashes_for_peer(&chain, &locator, stop, 2000);
            let items = hashes
                .into_iter()
                .map(crate::wire::InventoryItem::Block)
                .collect();
            send_message(&mut stream, &WireMessage::Inv { items }, &cfg).expect("send inv");
        });

        let mut stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let remote = client_handshake(&mut stream, &FramingConfig::default(), &handshake())
            .expect("client hs");
        assert_eq!(remote.network_id, "devnet");

        let (local_chain, _) = chain_headers(3);
        let locator = build_block_locator(&local_chain);
        let headers = request_headers(&mut stream, &FramingConfig::default(), locator, None)
            .expect("headers");
        assert!(!headers.is_empty());

        let locator = build_block_locator(&local_chain);
        let blocks =
            request_blocks(&mut stream, &FramingConfig::default(), locator, None).expect("blocks");
        assert!(!blocks.is_empty());

        server.join().expect("server join");
    }

    #[test]
    fn async_handshake_and_headers_roundtrip() {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let cfg = FramingConfig::default();
            let (mut client_stream, mut server_stream) = tokio::io::duplex(16 * 1024);
            let server_cfg = cfg.clone();

            let server = tokio::spawn(async move {
                let remote = server_handshake_async(&mut server_stream, &server_cfg, &handshake())
                    .await
                    .expect("server hs");
                assert_eq!(remote.network_id, "devnet");

                let (chain, headers_map) = chain_headers(8);
                let request = read_message_async(&mut server_stream, &server_cfg)
                    .await
                    .expect("read req");
                let WireMessage::GetHeaders { locator, stop } = request else {
                    panic!("expected getheaders");
                };
                let headers = select_headers_for_peer(&chain, &headers_map, &locator, stop, 2000);
                send_message_async(
                    &mut server_stream,
                    &WireMessage::Headers { headers },
                    &server_cfg,
                )
                .await
                .expect("send headers");

                let request = read_message_async(&mut server_stream, &server_cfg)
                    .await
                    .expect("read req");
                let WireMessage::GetBlocks { locator, stop } = request else {
                    panic!("expected getblocks");
                };
                let hashes = select_block_hashes_for_peer(&chain, &locator, stop, 2000);
                let items = hashes
                    .into_iter()
                    .map(crate::wire::InventoryItem::Block)
                    .collect();
                send_message_async(&mut server_stream, &WireMessage::Inv { items }, &server_cfg)
                    .await
                    .expect("send inv");
            });

            let remote = client_handshake_async(&mut client_stream, &cfg, &handshake())
                .await
                .expect("client hs");
            assert_eq!(remote.network_id, "devnet");

            let (local_chain, _) = chain_headers(3);
            let locator = build_block_locator(&local_chain);
            let headers = request_headers_async(&mut client_stream, &cfg, locator, None)
                .await
                .expect("headers");
            assert!(!headers.is_empty());

            let locator = build_block_locator(&local_chain);
            let blocks = request_blocks_async(&mut client_stream, &cfg, locator, None)
                .await
                .expect("blocks");
            assert!(!blocks.is_empty());

            server.await.expect("server join");
        });
    }

    #[test]
    fn send_message_async_writes_header_and_payload_bytes() {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let cfg = FramingConfig::default();
            let (mut tx, mut rx) = tokio::io::duplex(4 * 1024);
            let message = WireMessage::Ping {
                nonce: 0xabcdef1234567890,
            };

            let writer = tokio::spawn(async move {
                send_message_async(&mut tx, &message, &cfg)
                    .await
                    .expect("send message");
            });

            let reader = tokio::spawn(async move {
                let mut header = [0u8; 8];
                tokio::time::timeout(Duration::from_millis(500), rx.read_exact(&mut header))
                    .await
                    .expect("timed out waiting for header bytes")
                    .expect("read header");
                header
            });

            writer.await.expect("writer join");
            let header = reader.await.expect("reader join");
            let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
            assert_eq!(magic, FramingConfig::default().magic);
            let payload_len =
                u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
            assert!(payload_len > 0);
        });
    }

    #[test]
    fn send_message_size_limit_boundary_is_enforced() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind failed: {err}"),
        };
        let addr = listener.local_addr().expect("local addr");
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept");
            thread::sleep(Duration::from_millis(200));
        });

        let mut stream = TcpStream::connect(addr).expect("connect");
        let message = WireMessage::Ping { nonce: 7 };
        let payload_len = crate::wire::encode_message(&message).expect("encode").len();
        let exact_cfg = FramingConfig {
            max_message_size: payload_len,
            ..FramingConfig::default()
        };
        send_message(&mut stream, &message, &exact_cfg).expect("equal limit must pass");

        let reject_cfg = FramingConfig {
            max_message_size: payload_len.saturating_sub(1),
            ..FramingConfig::default()
        };
        let err = send_message(&mut stream, &message, &reject_cfg)
            .expect_err("smaller limit must reject");
        assert!(matches!(
            err,
            crate::transport::TransportError::MessageTooLarge { .. }
        ));
        server.join().expect("server join");
    }

    #[test]
    fn send_message_async_size_limit_boundary_is_enforced() {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let message = WireMessage::Ping { nonce: 9 };
            let payload_len = crate::wire::encode_message(&message).expect("encode").len();
            let exact_cfg = FramingConfig {
                max_message_size: payload_len,
                ..FramingConfig::default()
            };
            let reject_cfg = FramingConfig {
                max_message_size: payload_len.saturating_sub(1),
                ..FramingConfig::default()
            };
            let (mut tx, _rx) = tokio::io::duplex(4096);
            send_message_async(&mut tx, &message, &exact_cfg)
                .await
                .expect("equal limit must pass");
            let err = send_message_async(&mut tx, &message, &reject_cfg)
                .await
                .expect_err("smaller limit must reject");
            assert!(matches!(
                err,
                crate::transport::TransportError::MessageTooLarge { .. }
            ));
        });
    }

    #[test]
    fn read_message_size_limit_boundary_is_enforced() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind failed: {err}"),
        };
        let addr = listener.local_addr().expect("local addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let message = WireMessage::Ping { nonce: 11 };
            let payload = crate::wire::encode_message(&message).expect("encode");
            let mut header = [0u8; 8];
            header[..4].copy_from_slice(&FramingConfig::default().magic.to_be_bytes());
            header[4..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
            stream.write_all(&header).expect("write header");
            stream.write_all(&payload).expect("write payload");
        });

        let mut stream = TcpStream::connect(addr).expect("connect");
        let max = crate::wire::encode_message(&WireMessage::Ping { nonce: 11 })
            .expect("encode")
            .len();
        let cfg = FramingConfig {
            max_message_size: max,
            ..FramingConfig::default()
        };
        let msg = read_message(&mut stream, &cfg).expect("equal max must pass");
        assert!(matches!(msg, WireMessage::Ping { nonce: 11 }));
        server.join().expect("server join");
    }

    #[test]
    fn request_headers_and_blocks_error_on_unexpected_responses() {
        let cfg = FramingConfig::default();
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind failed: {err}"),
        };
        let addr = listener.local_addr().expect("local addr");

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _ = read_message(&mut stream, &cfg).expect("first request");
            send_message(&mut stream, &WireMessage::Ping { nonce: 1 }, &cfg)
                .expect("send unexpected headers response");

            let _ = read_message(&mut stream, &cfg).expect("second request");
            let item = crate::wire::InventoryItem::Tx(hash256(b"tx"));
            send_message(&mut stream, &WireMessage::Inv { items: vec![item] }, &cfg)
                .expect("send unexpected inv response");
        });

        let mut stream = TcpStream::connect(addr).expect("connect");
        let err = request_headers(&mut stream, &FramingConfig::default(), Vec::new(), None)
            .expect_err("unexpected response must fail");
        assert!(matches!(
            err,
            crate::transport::TransportError::UnexpectedMessage { .. }
        ));

        let err = request_blocks(&mut stream, &FramingConfig::default(), Vec::new(), None)
            .expect_err("tx inventory must fail");
        assert!(matches!(
            err,
            crate::transport::TransportError::UnexpectedInventoryItem { .. }
        ));
        server.join().expect("server join");
    }

    fn chain_headers(
        count: usize,
    ) -> (
        Vec<Hash256>,
        std::collections::HashMap<Hash256, scam_core::BlockHeader>,
    ) {
        let mut chain = Vec::new();
        let mut headers = std::collections::HashMap::new();
        let mut prev = Hash256::ZERO;
        for i in 0..count {
            let header = scam_core::BlockHeader {
                version: 1,
                prev_block: prev,
                merkle_root: hash256(format!("mrkl-{i}").as_bytes()),
                timestamp: 1_770_763_200 + i as u64,
                target: Target::MAX,
                nonce: i as u64,
            };
            let hash = header.block_hash();
            prev = hash;
            chain.push(hash);
            headers.insert(hash, header);
        }
        (chain, headers)
    }
}
