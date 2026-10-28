//! TUI application state: cached RPC snapshots, poll cadence, render-side
//! formatting helpers. Pure data + computation, no terminal I/O — keeps unit
//! tests trivial.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::http::{self, Endpoint};

const MIN_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MEMPOOL_PREVIEW_TXIDS: usize = 64;

/// Parsed snapshot of `/status`. We keep the fields permissive — the server
/// may add columns; `serde(default)` lets the TUI keep rendering.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct StatusSnapshot {
    pub network_id: String,
    pub tip_height: u64,
    pub tip_hash: String,
    pub utxo_count: u64,
    pub cumulative_work: String,
    pub network_hashrate_hps: f64,
    pub stratum_active_clients: Option<u64>,
    pub stratum_workers_active: Option<u64>,
    pub stratum_pool_hashrate_hps: Option<f64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct MempoolSnapshot {
    pub tx_count: Option<u64>,
    pub txids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PollSnapshot {
    pub status: Option<StatusSnapshot>,
    pub mempool: Option<MempoolSnapshot>,
    pub healthy: bool,
    pub last_error: Option<String>,
    pub fetched_at: Instant,
}

impl PollSnapshot {
    fn empty() -> Self {
        Self {
            status: None,
            mempool: None,
            healthy: false,
            last_error: None,
            fetched_at: Instant::now(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PollOutcome {
    Ok,
    PartialFailure,
    Failed,
}

pub struct AppState {
    pub endpoint: Endpoint,
    pub poll_interval: Duration,
    pub snapshot: PollSnapshot,
    pub last_outcome: PollOutcome,
    pub poll_count: u64,
    pub started_at: Instant,
    last_poll: Instant,
}

impl AppState {
    pub fn new(endpoint_raw: &str, poll_interval: Duration) -> Self {
        let endpoint = Endpoint::parse(endpoint_raw).unwrap_or(Endpoint {
            host: "127.0.0.1".to_owned(),
            port: 18080,
        });
        let poll_interval = clamp_interval(poll_interval);
        Self {
            endpoint,
            poll_interval,
            snapshot: PollSnapshot::empty(),
            last_outcome: PollOutcome::Failed,
            poll_count: 0,
            started_at: Instant::now(),
            // Trigger an immediate first poll.
            last_poll: Instant::now()
                .checked_sub(poll_interval + Duration::from_secs(1))
                .unwrap_or_else(Instant::now),
        }
    }

    pub fn due_for_poll(&self) -> bool {
        self.last_poll.elapsed() >= self.poll_interval
    }

    pub fn bump_poll_interval(&mut self, increase: bool) {
        let step = if self.poll_interval < Duration::from_secs(2) {
            Duration::from_millis(500)
        } else {
            Duration::from_secs(1)
        };
        self.poll_interval = if increase {
            clamp_interval(self.poll_interval + step)
        } else {
            clamp_interval(self.poll_interval.saturating_sub(step))
        };
    }

    pub fn poll_now(&mut self) {
        self.last_poll = Instant::now();
        self.poll_count = self.poll_count.saturating_add(1);

        let mut snapshot = PollSnapshot::empty();
        let mut first_err: Option<String> = None;
        let mut ok_any = false;

        match http::get_text(&self.endpoint, "/health", REQUEST_TIMEOUT) {
            Ok(body) => {
                snapshot.healthy = body.contains("\"ok\":true");
                ok_any = true;
            }
            Err(err) => {
                first_err.get_or_insert_with(|| format!("/health: {err}"));
            }
        }

        match http::get_text(&self.endpoint, "/status", REQUEST_TIMEOUT) {
            Ok(body) => match serde_json::from_str::<StatusSnapshot>(&body) {
                Ok(parsed) => {
                    snapshot.status = Some(parsed);
                    ok_any = true;
                }
                Err(e) => {
                    first_err.get_or_insert_with(|| format!("/status decode: {e}"));
                }
            },
            Err(err) => {
                first_err.get_or_insert_with(|| format!("/status: {err}"));
            }
        }

        match http::get_text(&self.endpoint, "/mempool", REQUEST_TIMEOUT) {
            Ok(body) => match serde_json::from_str::<MempoolSnapshot>(&body) {
                Ok(mut parsed) => {
                    if parsed.txids.len() > MEMPOOL_PREVIEW_TXIDS {
                        parsed.txids.truncate(MEMPOOL_PREVIEW_TXIDS);
                    }
                    snapshot.mempool = Some(parsed);
                    ok_any = true;
                }
                Err(e) => {
                    first_err.get_or_insert_with(|| format!("/mempool decode: {e}"));
                }
            },
            Err(err) => {
                first_err.get_or_insert_with(|| format!("/mempool: {err}"));
            }
        }

        snapshot.last_error = first_err.clone();
        snapshot.fetched_at = Instant::now();
        self.last_outcome = match (ok_any, first_err.is_some()) {
            (true, false) => PollOutcome::Ok,
            (true, true) => PollOutcome::PartialFailure,
            (false, _) => PollOutcome::Failed,
        };
        self.snapshot = snapshot;
    }

    /// Test-only injection hook: replace the snapshot without touching the
    /// network. Used to exercise the renderer deterministically.
    #[doc(hidden)]
    pub fn inject_snapshot(&mut self, snapshot: PollSnapshot, outcome: PollOutcome) {
        self.snapshot = snapshot;
        self.last_outcome = outcome;
    }
}

fn clamp_interval(d: Duration) -> Duration {
    if d < MIN_POLL_INTERVAL {
        MIN_POLL_INTERVAL
    } else if d > MAX_POLL_INTERVAL {
        MAX_POLL_INTERVAL
    } else {
        d
    }
}

/// Human-friendly hashrate formatter (matches the web console scale).
pub fn format_hashrate(hps: f64) -> String {
    if !hps.is_finite() || hps < 0.0 {
        return "-".to_owned();
    }
    const UNITS: &[(f64, &str)] = &[
        (1e18, "EH/s"),
        (1e15, "PH/s"),
        (1e12, "TH/s"),
        (1e9, "GH/s"),
        (1e6, "MH/s"),
        (1e3, "KH/s"),
    ];
    for (threshold, unit) in UNITS {
        if hps >= *threshold {
            return format!("{:.2} {}", hps / threshold, unit);
        }
    }
    format!("{hps:.2} H/s")
}

pub fn format_count(n: u64) -> String {
    let mut s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    while s.len() > 3 {
        let tail = s.split_off(s.len() - 3);
        out.insert_str(0, &format!(",{tail}"));
    }
    out.insert_str(0, &s);
    out
}

pub fn truncate_hash(hex: &str) -> String {
    if hex.len() <= 18 {
        hex.to_owned()
    } else {
        format!("{}..{}", &hex[..12], &hex[hex.len() - 6..])
    }
}

pub fn local_clock_24h() -> String {
    // Minimal local-time formatter that avoids pulling `chrono`. We accept
    // that this prints UTC seconds-of-day if the libc timezone isn't set;
    // good enough for a dev TUI footer.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let hh = (now / 3600) % 24;
    let mm = (now / 60) % 60;
    let ss = now % 60;
    format!("{hh:02}:{mm:02}:{ss:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_hashrate_scales_through_units() {
        assert_eq!(format_hashrate(0.0), "0.00 H/s");
        assert_eq!(format_hashrate(1_500.0), "1.50 KH/s");
        assert_eq!(format_hashrate(2.5e6), "2.50 MH/s");
        assert_eq!(format_hashrate(7.25e12), "7.25 TH/s");
        assert_eq!(format_hashrate(f64::NAN), "-");
        assert_eq!(format_hashrate(-1.0), "-");
    }

    #[test]
    fn format_count_inserts_thousands_separators() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(42), "42");
        assert_eq!(format_count(1234), "1,234");
        assert_eq!(format_count(1_000_000), "1,000,000");
    }

    #[test]
    fn truncate_hash_keeps_short_values_unchanged() {
        assert_eq!(truncate_hash("abc"), "abc");
        assert_eq!(truncate_hash(&"a".repeat(18)), "a".repeat(18));
        let long = "abcdefghijklmnopqrstuvwxyz0123";
        let out = truncate_hash(long);
        assert!(out.contains(".."));
        assert!(out.starts_with("abcdefghijkl"));
    }

    #[test]
    fn clamp_interval_bounds_inputs() {
        assert_eq!(clamp_interval(Duration::from_millis(10)), MIN_POLL_INTERVAL);
        assert_eq!(clamp_interval(Duration::from_secs(60)), MAX_POLL_INTERVAL);
        assert_eq!(
            clamp_interval(Duration::from_secs(2)),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn bump_poll_interval_respects_bounds() {
        let mut s = AppState::new("127.0.0.1:1", Duration::from_secs(1));
        for _ in 0..100 {
            s.bump_poll_interval(true);
        }
        assert_eq!(s.poll_interval, MAX_POLL_INTERVAL);
        for _ in 0..100 {
            s.bump_poll_interval(false);
        }
        assert_eq!(s.poll_interval, MIN_POLL_INTERVAL);
    }

    #[test]
    fn app_state_marks_initial_poll_due() {
        let s = AppState::new("127.0.0.1:1", Duration::from_secs(5));
        assert!(s.due_for_poll());
    }

    #[test]
    fn app_state_falls_back_on_bad_endpoint() {
        let s = AppState::new("not a url", Duration::from_secs(1));
        assert_eq!(s.endpoint.host, "127.0.0.1");
        assert_eq!(s.endpoint.port, 18080);
    }
}
