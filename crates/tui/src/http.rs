//! Minimal HTTP/1.1 GET client for the local RPC.
//!
//! Avoids pulling `reqwest`/`hyper` for a TUI that only ever talks to
//! `127.0.0.1`. Supports a connect+read timeout and a response-size cap so a
//! misbehaving server cannot wedge the TUI.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use thiserror::Error;

/// Hard cap on body bytes we will read back. RPC payloads on this project are
/// small (status/mempool summaries); a malicious or buggy peer that keeps
/// streaming will be cut off rather than exhausting TUI memory.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("invalid endpoint url: {0}")]
    BadUrl(String),
    #[error("connect: {0}")]
    Connect(#[source] std::io::Error),
    #[error("io: {0}")]
    Io(#[source] std::io::Error),
    #[error("response too large (cap {MAX_RESPONSE_BYTES} bytes)")]
    ResponseTooLarge,
    #[error("malformed http response: {0}")]
    Malformed(String),
    #[error("http status {status}: {body}")]
    Status { status: u16, body: String },
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    /// Parse `http://host:port[/]` or `host:port`. Strips any path.
    pub fn parse(raw: &str) -> Result<Self, HttpError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(HttpError::BadUrl("empty".to_owned()));
        }
        let after_scheme = trimmed
            .strip_prefix("http://")
            .or_else(|| trimmed.strip_prefix("HTTP://"))
            .unwrap_or(trimmed);
        if after_scheme.starts_with("https://") {
            return Err(HttpError::BadUrl(
                "https not supported for local RPC".to_owned(),
            ));
        }
        let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
        let (host, port_str) = authority
            .rsplit_once(':')
            .ok_or_else(|| HttpError::BadUrl(format!("missing port in '{raw}'")))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| HttpError::BadUrl(format!("invalid port in '{raw}'")))?;
        if host.is_empty() {
            return Err(HttpError::BadUrl(format!("empty host in '{raw}'")));
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    pub fn display(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

/// Perform a blocking GET and return the response body as `String`.
pub fn get_text(endpoint: &Endpoint, path: &str, timeout: Duration) -> Result<String, HttpError> {
    if !path.starts_with('/') {
        return Err(HttpError::BadUrl(format!(
            "path must start with '/': '{path}'"
        )));
    }
    let addr = first_addr(&endpoint.host, endpoint.port)?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(HttpError::Connect)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(HttpError::Io)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(HttpError::Io)?;

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: scam-tui/0.3\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        host = endpoint.host,
        port = endpoint.port,
    );
    stream.write_all(req.as_bytes()).map_err(HttpError::Io)?;
    stream.flush().map_err(HttpError::Io)?;

    let mut buf = Vec::with_capacity(8 * 1024);
    let mut scratch = [0u8; 8 * 1024];
    loop {
        let n = stream.read(&mut scratch).map_err(HttpError::Io)?;
        if n == 0 {
            break;
        }
        if buf.len() + n > MAX_RESPONSE_BYTES {
            return Err(HttpError::ResponseTooLarge);
        }
        buf.extend_from_slice(&scratch[..n]);
    }

    parse_response(&buf)
}

fn first_addr(host: &str, port: u16) -> Result<SocketAddr, HttpError> {
    (host, port)
        .to_socket_addrs()
        .map_err(HttpError::Connect)?
        .next()
        .ok_or_else(|| HttpError::BadUrl(format!("dns resolved no addrs for {host}:{port}")))
}

/// Parses a minimal HTTP/1.1 response. We only need:
/// - status line (`HTTP/1.1 200 OK\r\n`)
/// - blank-line separator
/// - body (rest of the buffer; `Connection: close` means server closed it)
///
/// Chunked encoding is not honored — the RPC server uses identity encoding for
/// these endpoints, but if it ever switches we'll surface a `Malformed` error
/// rather than silently corrupting output.
fn parse_response(raw: &[u8]) -> Result<String, HttpError> {
    let sep = b"\r\n\r\n";
    let split = raw
        .windows(sep.len())
        .position(|w| w == sep)
        .ok_or_else(|| HttpError::Malformed("no header/body separator".to_owned()))?;
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|e| HttpError::Malformed(format!("non-utf8 headers: {e}")))?;
    let body_bytes = &raw[split + sep.len()..];

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| HttpError::Malformed("missing status line".to_owned()))?;
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next();
    let status_str = parts
        .next()
        .ok_or_else(|| HttpError::Malformed(format!("bad status line: {status_line}")))?;
    let status: u16 = status_str
        .parse()
        .map_err(|_| HttpError::Malformed(format!("bad status code: {status_line}")))?;

    let body = std::str::from_utf8(body_bytes)
        .map_err(|e| HttpError::Malformed(format!("non-utf8 body: {e}")))?
        .to_owned();

    let mut chunked = false;
    for header in lines {
        if header.is_empty() {
            continue;
        }
        let lower = header.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("transfer-encoding:")
            && value.trim() == "chunked"
        {
            chunked = true;
        }
    }
    if chunked {
        return Err(HttpError::Malformed(
            "chunked transfer-encoding not supported".to_owned(),
        ));
    }

    if !(200..300).contains(&status) {
        return Err(HttpError::Status { status, body });
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parses_url_and_strips_path() {
        let e = Endpoint::parse("http://127.0.0.1:18080/status").expect("parse");
        assert_eq!(e.host, "127.0.0.1");
        assert_eq!(e.port, 18080);
    }

    #[test]
    fn endpoint_parses_authority_only() {
        let e = Endpoint::parse("127.0.0.1:18080").expect("parse");
        assert_eq!(e.host, "127.0.0.1");
        assert_eq!(e.port, 18080);
    }

    #[test]
    fn endpoint_rejects_missing_port_and_empty() {
        assert!(matches!(
            Endpoint::parse("127.0.0.1"),
            Err(HttpError::BadUrl(_))
        ));
        assert!(matches!(Endpoint::parse(""), Err(HttpError::BadUrl(_))));
    }

    #[test]
    fn endpoint_rejects_https() {
        assert!(matches!(
            Endpoint::parse("https://1.2.3.4:9000"),
            Err(HttpError::BadUrl(_))
        ));
    }

    #[test]
    fn parse_response_extracts_body_for_2xx() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
        let body = parse_response(raw).expect("ok");
        assert_eq!(body, "{\"ok\":true}");
    }

    #[test]
    fn parse_response_surfaces_status_errors() {
        let raw = b"HTTP/1.1 500 Internal Server Error\r\n\r\nboom";
        match parse_response(raw) {
            Err(HttpError::Status { status, body }) => {
                assert_eq!(status, 500);
                assert_eq!(body, "boom");
            }
            other => panic!("expected status error, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_rejects_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert!(matches!(parse_response(raw), Err(HttpError::Malformed(_))));
    }

    #[test]
    fn parse_response_rejects_missing_separator() {
        let raw = b"HTTP/1.1 200 OK\r\nNo-Sep";
        assert!(matches!(parse_response(raw), Err(HttpError::Malformed(_))));
    }
}
