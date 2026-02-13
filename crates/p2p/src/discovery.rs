use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerCandidate {
    pub addr: SocketAddr,
    pub last_connected_unix_sec: u64,
    pub failure_count: u32,
}

pub fn select_outbound_peers(
    candidates: &[PeerCandidate],
    max_outbound: usize,
    rotate_after_sec: u64,
    now_unix_sec: u64,
) -> Vec<SocketAddr> {
    if max_outbound == 0 || candidates.is_empty() {
        return Vec::new();
    }

    let mut sorted = candidates.to_vec();
    sorted.sort_unstable_by(|a, b| {
        let a_stale = now_unix_sec.saturating_sub(a.last_connected_unix_sec) >= rotate_after_sec;
        let b_stale = now_unix_sec.saturating_sub(b.last_connected_unix_sec) >= rotate_after_sec;

        a.failure_count
            .cmp(&b.failure_count)
            .then_with(|| b_stale.cmp(&a_stale))
            .then_with(|| a.last_connected_unix_sec.cmp(&b.last_connected_unix_sec))
            .then_with(|| a.addr.cmp(&b.addr))
    });

    let mut selected = Vec::<SocketAddr>::new();
    let mut selected_addrs = HashSet::<SocketAddr>::new();
    let mut seen_diversity = HashSet::<String>::new();

    for candidate in &sorted {
        if selected.len() >= max_outbound {
            break;
        }
        if !selected_addrs.insert(candidate.addr) {
            continue;
        }
        let key = diversity_key(candidate.addr.ip());
        if seen_diversity.insert(key) {
            selected.push(candidate.addr);
        } else {
            selected_addrs.remove(&candidate.addr);
        }
    }

    if selected.len() < max_outbound {
        for candidate in &sorted {
            if selected.len() >= max_outbound {
                break;
            }
            if selected_addrs.insert(candidate.addr) {
                selected.push(candidate.addr);
            }
        }
    }

    selected
}

fn diversity_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("v4-{}.{}", octets[0], octets[1])
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            format!("v6-{:x}:{:x}", seg[0], seg[1])
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::discovery::{PeerCandidate, select_outbound_peers};

    fn addr(raw: &str) -> SocketAddr {
        raw.parse().expect("socket addr")
    }

    #[test]
    fn selects_diverse_subnets_first() {
        let candidates = vec![
            PeerCandidate {
                addr: addr("10.1.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("10.1.9.9:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("11.2.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
        ];

        let selected = select_outbound_peers(&candidates, 2, 60, 1_000);
        assert_eq!(selected.len(), 2);
        assert!(
            selected.contains(&addr("10.1.1.1:8333")) || selected.contains(&addr("10.1.9.9:8333"))
        );
        assert!(selected.contains(&addr("11.2.1.1:8333")));
    }

    #[test]
    fn stale_peers_are_preferred_for_rotation() {
        let candidates = vec![
            PeerCandidate {
                addr: addr("10.1.1.1:8333"),
                last_connected_unix_sec: 990,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("11.2.1.1:8333"),
                last_connected_unix_sec: 100,
                failure_count: 0,
            },
        ];

        let selected = select_outbound_peers(&candidates, 1, 120, 1_000);
        assert_eq!(selected, vec![addr("11.2.1.1:8333")]);
    }

    #[test]
    fn high_failure_candidates_are_deprioritized() {
        let candidates = vec![
            PeerCandidate {
                addr: addr("10.1.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 5,
            },
            PeerCandidate {
                addr: addr("11.2.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("12.3.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
        ];

        let selected = select_outbound_peers(&candidates, 2, 60, 1_000);
        assert_eq!(selected.len(), 2);
        assert!(selected.contains(&addr("11.2.1.1:8333")));
        assert!(selected.contains(&addr("12.3.1.1:8333")));
        assert!(!selected.contains(&addr("10.1.1.1:8333")));
    }

    #[test]
    fn select_outbound_peers_returns_empty_for_zero_limit_or_empty_input() {
        let selected = select_outbound_peers(&[], 8, 60, 1_000);
        assert!(selected.is_empty());

        let candidates = vec![PeerCandidate {
            addr: addr("10.1.1.1:8333"),
            last_connected_unix_sec: 0,
            failure_count: 0,
        }];
        let selected = select_outbound_peers(&candidates, 0, 60, 1_000);
        assert!(selected.is_empty());
    }

    #[test]
    fn fallback_path_allows_same_subnet_when_diversity_is_exhausted() {
        let candidates = vec![
            PeerCandidate {
                addr: addr("10.1.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("10.1.2.2:8333"),
                last_connected_unix_sec: 1,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("10.1.3.3:8333"),
                last_connected_unix_sec: 2,
                failure_count: 0,
            },
        ];

        let selected = select_outbound_peers(&candidates, 3, 60, 1_000);
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn staleness_boundary_prefers_older_peer_on_exact_rotate_threshold() {
        let candidates = vec![
            PeerCandidate {
                addr: addr("10.1.1.1:8333"),
                last_connected_unix_sec: 940,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("11.2.1.1:8333"),
                last_connected_unix_sec: 939,
                failure_count: 0,
            },
        ];

        let selected = select_outbound_peers(&candidates, 1, 60, 1_000);
        assert_eq!(selected, vec![addr("11.2.1.1:8333")]);
    }
}
