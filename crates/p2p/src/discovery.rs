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
    if candidates.is_empty() {
        return Vec::new();
    }
    if max_outbound == 0 {
        return Vec::new();
    }

    let mut dedup = candidates.to_vec();
    dedup.sort_unstable_by(|a, b| a.addr.cmp(&b.addr));
    dedup.dedup_by_key(|candidate| candidate.addr);

    let mut tried = Vec::<PeerCandidate>::new();
    let mut new = Vec::<PeerCandidate>::new();
    for candidate in dedup {
        if candidate.last_connected_unix_sec == 0 {
            new.push(candidate);
        } else {
            tried.push(candidate);
        }
    }

    sort_candidates(&mut tried, rotate_after_sec, now_unix_sec);
    sort_candidates(&mut new, rotate_after_sec, now_unix_sec);

    // Addrman-inspired quota: bias toward previously successful peers while always
    // keeping room for "new" addresses to avoid eclipse lock-in.
    let (tried_quota, new_quota) = addrman_quotas(max_outbound, !tried.is_empty());

    let mut selected = Vec::<SocketAddr>::new();
    let mut selected_addrs = HashSet::<SocketAddr>::new();
    let mut seen_groups = HashSet::<String>::new();

    select_diverse(
        &tried,
        tried_quota,
        &mut selected,
        &mut selected_addrs,
        &mut seen_groups,
    );
    select_diverse(
        &new,
        new_quota,
        &mut selected,
        &mut selected_addrs,
        &mut seen_groups,
    );

    // Backfill in addrman-like priority order when one partition is exhausted.
    backfill_candidates(&tried, max_outbound, &mut selected, &mut selected_addrs);
    backfill_candidates(&new, max_outbound, &mut selected, &mut selected_addrs);
    selected.truncate(max_outbound);
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

fn sort_candidates(candidates: &mut [PeerCandidate], rotate_after_sec: u64, now_unix_sec: u64) {
    let stale_cutoff = now_unix_sec.saturating_sub(rotate_after_sec.max(1));
    candidates.sort_unstable_by(|a, b| {
        let a_stale = is_stale(a.last_connected_unix_sec, stale_cutoff);
        let b_stale = is_stale(b.last_connected_unix_sec, stale_cutoff);
        a.failure_count
            .cmp(&b.failure_count)
            // Rotate away from recently-used peers.
            .then_with(|| b_stale.cmp(&a_stale))
            // Prefer peers that have not been selected recently.
            .then_with(|| a.last_connected_unix_sec.cmp(&b.last_connected_unix_sec))
            .then_with(|| a.addr.cmp(&b.addr))
    });
}

fn is_stale(last_connected_unix_sec: u64, stale_cutoff: u64) -> bool {
    last_connected_unix_sec <= stale_cutoff
}

fn addrman_quotas(max_outbound: usize, has_tried_peers: bool) -> (usize, usize) {
    let tried_quota = if has_tried_peers {
        // 2/3 bias toward tried addresses.
        ((max_outbound.saturating_mul(2)) / 3).max(1)
    } else {
        0
    };
    let tried_quota = tried_quota.min(max_outbound);
    let new_quota = max_outbound.saturating_sub(tried_quota);
    (tried_quota, new_quota)
}

fn select_diverse(
    candidates: &[PeerCandidate],
    quota: usize,
    selected: &mut Vec<SocketAddr>,
    selected_addrs: &mut HashSet<SocketAddr>,
    seen_groups: &mut HashSet<String>,
) {
    if quota == 0 {
        return;
    }
    let start_len = selected.len();
    for candidate in candidates {
        if selected.len().saturating_sub(start_len) >= quota {
            break;
        }
        if !selected_addrs.insert(candidate.addr) {
            continue;
        }
        let group = diversity_key(candidate.addr.ip());
        if seen_groups.insert(group) {
            selected.push(candidate.addr);
        } else {
            selected_addrs.remove(&candidate.addr);
        }
    }
}

fn backfill_candidates(
    candidates: &[PeerCandidate],
    max_outbound: usize,
    selected: &mut Vec<SocketAddr>,
    selected_addrs: &mut HashSet<SocketAddr>,
) {
    for candidate in candidates {
        if selected.len() >= max_outbound {
            break;
        }
        if selected_addrs.insert(candidate.addr) {
            selected.push(candidate.addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use crate::discovery::{PeerCandidate, addrman_quotas, is_stale, select_outbound_peers};

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
                last_connected_unix_sec: 941,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("11.2.1.1:8333"),
                last_connected_unix_sec: 940,
                failure_count: 0,
            },
        ];

        let selected = select_outbound_peers(&candidates, 1, 60, 1_000);
        assert_eq!(selected, vec![addr("11.2.1.1:8333")]);
    }

    #[test]
    fn addrman_bias_keeps_room_for_new_addresses() {
        let candidates = vec![
            PeerCandidate {
                addr: addr("10.1.1.1:8333"),
                last_connected_unix_sec: 100,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("11.1.1.1:8333"),
                last_connected_unix_sec: 120,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("12.1.1.1:8333"),
                last_connected_unix_sec: 140,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("13.2.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("14.3.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
        ];

        let selected = select_outbound_peers(&candidates, 3, 60, 1_000);
        assert_eq!(selected.len(), 3);
        assert!(selected.iter().any(|addr| matches!(addr.ip(), IpAddr::V4(v4) if v4.octets()[0] == 13 || v4.octets()[0] == 14)));
    }

    #[test]
    fn select_outbound_peers_deduplicates_duplicates_from_candidate_list() {
        let duplicate = addr("10.1.1.1:8333");
        let candidates = vec![
            PeerCandidate {
                addr: duplicate,
                last_connected_unix_sec: 100,
                failure_count: 0,
            },
            PeerCandidate {
                addr: duplicate,
                last_connected_unix_sec: 0,
                failure_count: 5,
            },
            PeerCandidate {
                addr: addr("11.1.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
        ];

        let selected = select_outbound_peers(&candidates, 2, 60, 1_000);
        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected.iter().filter(|addr| **addr == duplicate).count(),
            1
        );
    }

    #[test]
    fn addrman_quota_math_prefers_tried_two_thirds_and_keeps_new_remainder() {
        let candidates = vec![
            // tried
            PeerCandidate {
                addr: addr("10.1.1.1:8333"),
                last_connected_unix_sec: 100,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("11.1.1.1:8333"),
                last_connected_unix_sec: 110,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("12.1.1.1:8333"),
                last_connected_unix_sec: 120,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("13.1.1.1:8333"),
                last_connected_unix_sec: 130,
                failure_count: 0,
            },
            // new
            PeerCandidate {
                addr: addr("20.1.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("21.1.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("22.1.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("23.1.1.1:8333"),
                last_connected_unix_sec: 0,
                failure_count: 0,
            },
        ];

        let selected = select_outbound_peers(&candidates, 6, 60, 1_000);
        assert_eq!(selected.len(), 6);
        let tried_count = selected
            .iter()
            .filter(
                |addr| matches!(addr.ip(), IpAddr::V4(v4) if (10..=13).contains(&v4.octets()[0])),
            )
            .count();
        let new_count = selected
            .iter()
            .filter(
                |addr| matches!(addr.ip(), IpAddr::V4(v4) if (20..=23).contains(&v4.octets()[0])),
            )
            .count();
        assert_eq!(
            tried_count, 4,
            "expected 2/3 tried quota for max_outbound=6"
        );
        assert_eq!(new_count, 2, "expected remainder quota for new peers");
    }

    #[test]
    fn rotate_boundary_does_not_mark_recent_peer_as_stale() {
        let candidates = vec![
            PeerCandidate {
                addr: addr("10.1.1.1:8333"),
                last_connected_unix_sec: 940, // exactly threshold stale at rotate=60, now=1000
                failure_count: 0,
            },
            PeerCandidate {
                addr: addr("11.1.1.1:8333"),
                last_connected_unix_sec: 999, // very recent, must not be stale
                failure_count: 0,
            },
        ];

        let selected = select_outbound_peers(&candidates, 1, 60, 1_000);
        assert_eq!(selected, vec![addr("10.1.1.1:8333")]);
    }

    #[test]
    fn stale_cutoff_is_inclusive_and_changes_at_boundary() {
        assert!(is_stale(940, 940));
        assert!(is_stale(939, 940));
        assert!(!is_stale(941, 940));
    }

    #[test]
    fn addrman_quota_helper_uses_two_thirds_bias() {
        assert_eq!(addrman_quotas(0, false), (0, 0));
        assert_eq!(addrman_quotas(1, true), (1, 0));
        assert_eq!(addrman_quotas(2, true), (1, 1));
        assert_eq!(addrman_quotas(3, true), (2, 1));
        assert_eq!(addrman_quotas(6, true), (4, 2));
        assert_eq!(addrman_quotas(7, true), (4, 3));
        assert_eq!(addrman_quotas(6, false), (0, 6));
    }

    #[test]
    fn addrman_quota_helper_never_exceeds_max_outbound() {
        for max_outbound in 0..32 {
            let (tried, new) = addrman_quotas(max_outbound, true);
            assert!(tried <= max_outbound);
            assert_eq!(tried + new, max_outbound);
        }
    }
}
