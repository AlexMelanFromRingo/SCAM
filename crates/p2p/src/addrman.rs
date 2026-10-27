//! Addrman-style table of known peer addresses.
//!
//! Every address lives in one slot of a fixed bucket grid. The bucket of a
//! gossiped ("new") address is chosen by a keyed hash of the address's
//! network group *and* of the group of the peer that announced it, and each
//! source group can reach only `NEW_BUCKETS_PER_SOURCE_GROUP` of the
//! `NEW_BUCKETS` buckets: one peer, or many peers in one /16, can fill at
//! most that share of the table however many addresses it sends. Addresses
//! we connected to successfully move to the "tried" grid, bucketed by their
//! own group. The secret key makes placements unpredictable to peers and is
//! persisted so the layout survives restarts. The table is bounded
//! (`capacity()`), and changes are tracked so callers persist only them.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

pub const NEW_BUCKETS: usize = 64;
pub const TRIED_BUCKETS: usize = 16;
pub const BUCKET_SIZE: usize = 32;
pub const NEW_BUCKETS_PER_SOURCE_GROUP: u64 = 8;
pub const TRIED_BUCKETS_PER_GROUP: u64 = 4;
/// Operator-configured addresses kept outside the bucket grid.
pub const MAX_MANUAL_ADDRESSES: usize = 1_024;
/// Source group of operator-configured addresses.
pub const MANUAL_SOURCE_GROUP: &str = "manual";
/// Addresses not seen for this long are evicted first.
pub const ADDR_HORIZON_SEC: u64 = 30 * 24 * 60 * 60;
const MAX_FAILURES_WITHOUT_SUCCESS: u32 = 3;
const MAX_FAILURES: u32 = 10;
const RECENT_SUCCESS_SEC: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddrEntry {
    pub address: String,
    /// Network group of the peer that announced it (or `manual`).
    pub source_group: String,
    pub services: u64,
    pub last_seen_unix_sec: u64,
    pub last_success_unix_sec: u64,
    pub failures: u32,
    pub tried: bool,
}

impl AddrEntry {
    pub fn new(address: &str, source_group: &str) -> Self {
        Self {
            address: address.to_owned(),
            source_group: source_group.to_owned(),
            services: 0,
            last_seen_unix_sec: 0,
            last_success_unix_sec: 0,
            failures: 0,
            tried: false,
        }
    }

    pub fn is_manual(&self) -> bool {
        self.source_group == MANUAL_SOURCE_GROUP
    }

    /// Not worth keeping when its slot is wanted (Bitcoin's `IsTerrible`).
    pub fn is_terrible(&self, now_unix_sec: u64) -> bool {
        if now_unix_sec.saturating_sub(self.last_seen_unix_sec) > ADDR_HORIZON_SEC {
            return true;
        }
        if self.last_success_unix_sec == 0 && self.failures >= MAX_FAILURES_WITHOUT_SUCCESS {
            return true;
        }
        self.failures >= MAX_FAILURES
            && now_unix_sec.saturating_sub(self.last_success_unix_sec) > RECENT_SUCCESS_SEC
    }
}

/// Network group used for bucketing: IPv4 /16, IPv6 /32. Host names share
/// one group: a peer can invent any number of names, so names must not buy
/// it more buckets.
pub fn address_group(address: &str) -> String {
    let host = address
        .rsplit_once(':')
        .map_or(address, |(host, _port)| host)
        .trim_start_matches('[')
        .trim_end_matches(']');
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let [a, b, ..] = ip.octets();
            format!("v4:{a}.{b}")
        }
        Ok(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
            Some(v4) => {
                let [a, b, ..] = v4.octets();
                format!("v4:{a}.{b}")
            }
            None => {
                let seg = ip.segments();
                format!("v6:{:x}:{:x}", seg[0], seg[1])
            }
        },
        Err(_) => "host".to_owned(),
    }
}

/// What changed since the last [`AddrTable::take_changes`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AddrTableChanges {
    pub upserted: Vec<AddrEntry>,
    pub removed: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Slot {
    New(usize, usize),
    Tried(usize, usize),
    Manual,
}

#[derive(Clone, Debug)]
pub struct AddrTable {
    secret: [u8; 32],
    new_grid: Vec<Option<String>>,
    tried_grid: Vec<Option<String>>,
    entries: HashMap<String, (AddrEntry, Slot)>,
    manual_count: usize,
    dirty: HashSet<String>,
}

impl AddrTable {
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            new_grid: vec![None; NEW_BUCKETS * BUCKET_SIZE],
            tried_grid: vec![None; TRIED_BUCKETS * BUCKET_SIZE],
            entries: HashMap::new(),
            manual_count: 0,
            dirty: HashSet::new(),
        }
    }

    /// Rebuild from persisted entries. Entries that no longer fit (their
    /// slot is taken) are reported as removed by the next `take_changes`.
    pub fn from_entries(secret: [u8; 32], entries: Vec<AddrEntry>, now_unix_sec: u64) -> Self {
        let mut table = Self::new(secret);
        let mut ordered = entries;
        // Tried first (they own their tried slots), then most recent.
        ordered.sort_by(|a, b| {
            b.tried
                .cmp(&a.tried)
                .then_with(|| b.last_seen_unix_sec.cmp(&a.last_seen_unix_sec))
                .then_with(|| a.address.cmp(&b.address))
        });
        let loaded = ordered
            .iter()
            .map(|entry| entry.address.clone())
            .collect::<Vec<_>>();
        for entry in ordered {
            table.insert_loaded(entry, now_unix_sec);
        }
        // Loading is not a change; only entries that did not fit (or were
        // displaced while loading) must be deleted from the store.
        table.dirty = loaded
            .into_iter()
            .filter(|address| !table.entries.contains_key(address))
            .collect();
        table
    }

    pub fn capacity() -> usize {
        NEW_BUCKETS * BUCKET_SIZE + TRIED_BUCKETS * BUCKET_SIZE + MAX_MANUAL_ADDRESSES
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, address: &str) -> Option<&AddrEntry> {
        self.entries.get(address).map(|(entry, _)| entry)
    }

    pub fn entries(&self) -> impl Iterator<Item = &AddrEntry> {
        self.entries.values().map(|(entry, _)| entry)
    }

    /// Learn `address` from a peer in `source_group` (or `manual`). Returns
    /// whether the table changed. A new address never displaces a live one:
    /// it only takes an empty slot or one holding a terrible entry.
    pub fn add(
        &mut self,
        address: &str,
        source_group: &str,
        services: u64,
        last_seen_unix_sec: u64,
        now_unix_sec: u64,
    ) -> bool {
        if let Some((entry, slot)) = self.entries.get_mut(address) {
            let before = entry.clone();
            entry.last_seen_unix_sec = entry.last_seen_unix_sec.max(last_seen_unix_sec);
            entry.services |= services;
            if source_group == MANUAL_SOURCE_GROUP && *slot != Slot::Manual {
                // Operator pins an address we already knew from gossip.
                let mut pinned = entry.clone();
                pinned.source_group = MANUAL_SOURCE_GROUP.to_owned();
                self.remove(address);
                return self.insert_manual(pinned);
            }
            let changed = *entry != before;
            if changed {
                self.dirty.insert(address.to_owned());
            }
            return changed;
        }
        let mut entry = AddrEntry::new(address, source_group);
        entry.services = services;
        entry.last_seen_unix_sec = last_seen_unix_sec;
        if entry.is_manual() {
            return self.insert_manual(entry);
        }
        let (bucket, slot) = self.new_slot(&entry);
        self.place_new(entry, bucket, slot, now_unix_sec)
    }

    /// A connection to `address` succeeded: it moves to the tried grid,
    /// sending whatever held its tried slot back to the new grid.
    pub fn mark_good(&mut self, address: &str, now_unix_sec: u64) {
        let Some((mut entry, slot)) = self.entries.get(address).cloned() else {
            return;
        };
        entry.last_success_unix_sec = now_unix_sec;
        entry.last_seen_unix_sec = entry.last_seen_unix_sec.max(now_unix_sec);
        entry.failures = 0;
        self.dirty.insert(address.to_owned());
        match slot {
            Slot::Manual | Slot::Tried(..) => {
                if let Some((stored, _)) = self.entries.get_mut(address) {
                    stored.last_success_unix_sec = entry.last_success_unix_sec;
                    stored.last_seen_unix_sec = entry.last_seen_unix_sec;
                    stored.failures = 0;
                    stored.tried = matches!(slot, Slot::Tried(..)) || stored.tried;
                }
            }
            Slot::New(..) => {
                self.remove(address);
                self.dirty.insert(address.to_owned());
                let (bucket, tslot) = self.tried_slot(&entry);
                let index = bucket * BUCKET_SIZE + tslot;
                if let Some(evicted) = self.tried_grid[index].take() {
                    // Demote the previous occupant to the new grid.
                    if let Some((mut old, _)) = self.entries.remove(&evicted) {
                        old.tried = false;
                        let (nb, ns) = self.new_slot(&old);
                        if !self.place_new(old, nb, ns, now_unix_sec) {
                            self.dirty.insert(evicted);
                        }
                    }
                }
                entry.tried = true;
                self.tried_grid[index] = Some(address.to_owned());
                self.entries
                    .insert(address.to_owned(), (entry, Slot::Tried(bucket, tslot)));
            }
        }
    }

    pub fn mark_failed(&mut self, address: &str) {
        if let Some((entry, _)) = self.entries.get_mut(address) {
            entry.failures = entry.failures.saturating_add(1);
            self.dirty.insert(address.to_owned());
        }
    }

    pub fn remove(&mut self, address: &str) -> bool {
        let Some((_, slot)) = self.entries.remove(address) else {
            return false;
        };
        match slot {
            Slot::New(b, s) => self.new_grid[b * BUCKET_SIZE + s] = None,
            Slot::Tried(b, s) => self.tried_grid[b * BUCKET_SIZE + s] = None,
            Slot::Manual => self.manual_count = self.manual_count.saturating_sub(1),
        }
        self.dirty.insert(address.to_owned());
        true
    }

    /// Up to `max_items` usable entries in an order peers cannot predict
    /// (keyed by the secret and `nonce`), e.g. for `addr` replies.
    pub fn sample(&self, max_items: usize, nonce: u64, now_unix_sec: u64) -> Vec<AddrEntry> {
        let mut usable = self
            .entries()
            .filter(|entry| !entry.is_terrible(now_unix_sec))
            .map(|entry| {
                (
                    self.keyed(&[b"sample", &nonce.to_le_bytes(), entry.address.as_bytes()]),
                    entry,
                )
            })
            .collect::<Vec<_>>();
        usable.sort_unstable_by_key(|(key, _)| *key);
        usable
            .into_iter()
            .take(max_items)
            .map(|(_, entry)| entry.clone())
            .collect()
    }

    /// Entries changed or removed since the last call.
    pub fn take_changes(&mut self) -> AddrTableChanges {
        let mut changes = AddrTableChanges::default();
        for address in std::mem::take(&mut self.dirty) {
            match self.entries.get(&address) {
                Some((entry, _)) => changes.upserted.push(entry.clone()),
                None => changes.removed.push(address),
            }
        }
        changes.upserted.sort_by(|a, b| a.address.cmp(&b.address));
        changes.removed.sort();
        changes
    }

    /// Put changes back after a failed write so the next flush retries.
    pub fn requeue(&mut self, changes: AddrTableChanges) {
        self.dirty
            .extend(changes.upserted.into_iter().map(|entry| entry.address));
        self.dirty.extend(changes.removed);
    }

    fn insert_loaded(&mut self, entry: AddrEntry, now_unix_sec: u64) -> bool {
        if entry.is_manual() {
            return self.insert_manual(entry);
        }
        if entry.tried {
            let (bucket, slot) = self.tried_slot(&entry);
            let index = bucket * BUCKET_SIZE + slot;
            if self.tried_grid[index].is_none() {
                self.tried_grid[index] = Some(entry.address.clone());
                self.entries
                    .insert(entry.address.clone(), (entry, Slot::Tried(bucket, slot)));
                return true;
            }
        }
        let mut entry = entry;
        entry.tried = false;
        let (bucket, slot) = self.new_slot(&entry);
        self.place_new(entry, bucket, slot, now_unix_sec)
    }

    fn insert_manual(&mut self, entry: AddrEntry) -> bool {
        if self.manual_count >= MAX_MANUAL_ADDRESSES {
            return false;
        }
        self.manual_count += 1;
        self.dirty.insert(entry.address.clone());
        self.entries
            .insert(entry.address.clone(), (entry, Slot::Manual));
        true
    }

    fn place_new(
        &mut self,
        entry: AddrEntry,
        bucket: usize,
        slot: usize,
        now_unix_sec: u64,
    ) -> bool {
        let index = bucket * BUCKET_SIZE + slot;
        if let Some(occupant) = self.new_grid[index].clone() {
            let replaceable = self
                .entries
                .get(&occupant)
                .is_none_or(|(existing, _)| existing.is_terrible(now_unix_sec));
            if !replaceable {
                return false;
            }
            self.remove(&occupant);
        }
        self.dirty.insert(entry.address.clone());
        self.new_grid[index] = Some(entry.address.clone());
        self.entries
            .insert(entry.address.clone(), (entry, Slot::New(bucket, slot)));
        true
    }

    fn new_slot(&self, entry: &AddrEntry) -> (usize, usize) {
        let group = address_group(&entry.address);
        let source = entry.source_group.as_bytes();
        let pick = self.keyed(&[b"new-1", group.as_bytes(), source]) % NEW_BUCKETS_PER_SOURCE_GROUP;
        let bucket =
            (self.keyed(&[b"new-2", source, &pick.to_le_bytes()]) % NEW_BUCKETS as u64) as usize;
        let slot = (self.keyed(&[b"new-slot", &bucket.to_le_bytes(), entry.address.as_bytes()])
            % BUCKET_SIZE as u64) as usize;
        (bucket, slot)
    }

    fn tried_slot(&self, entry: &AddrEntry) -> (usize, usize) {
        let group = address_group(&entry.address);
        let pick = self.keyed(&[b"tried-1", entry.address.as_bytes()]) % TRIED_BUCKETS_PER_GROUP;
        let bucket = (self.keyed(&[b"tried-2", group.as_bytes(), &pick.to_le_bytes()])
            % TRIED_BUCKETS as u64) as usize;
        let slot = (self.keyed(&[
            b"tried-slot",
            &bucket.to_le_bytes(),
            entry.address.as_bytes(),
        ]) % BUCKET_SIZE as u64) as usize;
        (bucket, slot)
    }

    fn keyed(&self, parts: &[&[u8]]) -> u64 {
        let mut buf = Vec::with_capacity(32 + parts.iter().map(|p| p.len() + 8).sum::<usize>());
        buf.extend_from_slice(&self.secret);
        for part in parts {
            buf.extend_from_slice(&(part.len() as u64).to_le_bytes());
            buf.extend_from_slice(part);
        }
        let digest = scam_core::hash256(&buf);
        u64::from_le_bytes(digest.0[..8].try_into().expect("invariant: 32-byte digest"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn groups_ipv4_by_16_ipv6_by_32_and_names_together() {
        assert_eq!(address_group("10.1.2.3:8333"), "v4:10.1");
        assert_eq!(address_group("10.1.200.3:1"), "v4:10.1");
        assert_eq!(address_group("[2001:db8:1::1]:8333"), "v6:2001:db8");
        assert_eq!(address_group("[::ffff:10.1.2.3]:8333"), "v4:10.1");
        assert_eq!(address_group("seed.example.org:8333"), "host");
        assert_eq!(address_group("other.example.net:1"), "host");
    }

    /// One source group can fill at most its share of the new grid, no
    /// matter how many addresses (in how many groups) it announces.
    #[test]
    fn one_source_cannot_fill_more_than_its_bucket_share() {
        let mut table = AddrTable::new([7u8; 32]);
        for i in 0..20_000u32 {
            let address = format!(
                "{}.{}.{}.{}:8333",
                1 + (i % 200),
                (i / 200) % 250,
                i % 250,
                1
            );
            table.add(&address, "v4:66.66", 1, NOW, NOW);
        }
        let share = NEW_BUCKETS_PER_SOURCE_GROUP as usize * BUCKET_SIZE;
        assert!(table.len() <= share, "{} > {share}", table.len());
        // An honest source gets in about as well as into an empty table:
        // the flood took only the flooder's own buckets.
        let honest = |table: &mut AddrTable| {
            (0..200u32)
                .filter(|i| table.add(&format!("20.{i}.0.1:8333"), "v4:20.20", 1, NOW, NOW))
                .count()
        };
        let baseline = honest(&mut AddrTable::new([7u8; 32]));
        let admitted = honest(&mut table);
        assert!(
            admitted * 10 >= baseline * 7,
            "honest admitted {admitted} vs {baseline} into an empty table"
        );
    }

    #[test]
    fn live_entries_are_not_displaced_but_terrible_ones_are() {
        let mut table = AddrTable::new([1u8; 32]);
        // Fill one source's buckets completely with live entries.
        for i in 0..50_000u32 {
            table.add(
                &format!("30.{}.{}.1:1", i / 250, i % 250),
                "v4:5.5",
                1,
                NOW,
                NOW,
            );
        }
        let before = table.len();
        let existing = table
            .entries()
            .map(|e| e.address.clone())
            .collect::<HashSet<_>>();
        for i in 0..1_000u32 {
            table.add(
                &format!("40.{}.{}.1:1", i / 250, i % 250),
                "v4:5.5",
                1,
                NOW,
                NOW,
            );
        }
        assert!(existing.iter().all(|a| table.get(a).is_some()), "live kept");
        assert_eq!(table.len(), before);
        // Once stale, they make room.
        let later = NOW + ADDR_HORIZON_SEC + 1;
        let mut admitted = 0;
        for i in 0..1_000u32 {
            if table.add(
                &format!("50.{}.{}.1:1", i / 250, i % 250),
                "v4:5.5",
                1,
                later,
                later,
            ) {
                admitted += 1;
            }
        }
        assert!(admitted > 0);
    }

    #[test]
    fn mark_good_moves_to_tried_and_survives_reload() {
        let secret = [9u8; 32];
        let mut table = AddrTable::new(secret);
        assert!(table.add("10.0.0.1:8333", "v4:1.1", 1, NOW, NOW));
        table.mark_failed("10.0.0.1:8333");
        table.mark_good("10.0.0.1:8333", NOW + 5);
        let entry = table.get("10.0.0.1:8333").expect("entry").clone();
        assert!(entry.tried);
        assert_eq!(entry.failures, 0);
        assert_eq!(entry.last_success_unix_sec, NOW + 5);
        assert!(table.add("seed.example.org:8333", MANUAL_SOURCE_GROUP, 1, 0, NOW));

        let changes = table.take_changes();
        assert!(changes.removed.is_empty());
        assert_eq!(changes.upserted.len(), 2);
        assert!(table.take_changes().upserted.is_empty(), "drained");

        let mut reloaded = AddrTable::from_entries(secret, changes.upserted, NOW);
        assert_eq!(reloaded.len(), 2);
        assert_eq!(
            reloaded.take_changes(),
            AddrTableChanges::default(),
            "loading is not a change"
        );
        assert!(reloaded.get("10.0.0.1:8333").expect("tried").tried);
        assert!(
            reloaded
                .get("seed.example.org:8333")
                .expect("manual")
                .is_manual()
        );
    }

    #[test]
    fn timestamps_and_services_merge_and_removal_is_tracked() {
        let mut table = AddrTable::new([3u8; 32]);
        table.add("10.0.0.1:1", "v4:1.1", 1, 100, NOW);
        table.take_changes();
        assert!(
            !table.add("10.0.0.1:1", "v4:2.2", 1, 50, NOW),
            "older seen: no change"
        );
        assert!(table.add("10.0.0.1:1", "v4:2.2", 2, 200, NOW));
        let entry = table.get("10.0.0.1:1").expect("entry");
        assert_eq!((entry.services, entry.last_seen_unix_sec), (3, 200));
        assert_eq!(entry.source_group, "v4:1.1", "first source sticks");
        assert!(table.remove("10.0.0.1:1"));
        assert_eq!(table.take_changes().removed, vec!["10.0.0.1:1".to_owned()]);
    }

    #[test]
    fn sample_skips_terrible_entries_and_is_bounded() {
        let mut table = AddrTable::new([4u8; 32]);
        for i in 0..100u32 {
            table.add(&format!("60.{i}.0.1:1"), &format!("v4:{i}.0"), 1, NOW, NOW);
        }
        table.add("70.0.0.1:1", "v4:9.9", 1, 0, NOW);
        let sample = table.sample(10, 1, NOW);
        assert_eq!(sample.len(), 10);
        let all = table.sample(1_000, 2, NOW);
        assert!(
            all.iter().all(|e| e.address != "70.0.0.1:1"),
            "stale excluded"
        );
        assert_ne!(
            table.sample(10, 1, NOW),
            table.sample(10, 3, NOW),
            "order depends on the nonce"
        );
    }
}
