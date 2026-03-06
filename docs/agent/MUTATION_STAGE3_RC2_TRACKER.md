# Mutation Stage3 RC2 Tracker

Source: `target/mutants-stage-rc2/stage3/mutants.out/{missed,timeout}.txt`

- Missed: **0**
- Timeout: **0**
- Total open: **0**

Status key: `[x] closed` (revalidated on 2026-03-06 with targeted mutation sweeps)

## Missed

### `crates/chain/src/lib.rs` (1)
- [x] `crates/chain/src/lib.rs:245:48` — replace - with / in ChainRuntime::expected_target_for_next_block

### `crates/node/src/main.rs` (47)
- [x] `crates/node/src/main.rs:1216:5` — replace wallet_seed_mode_from_env -> Result<WalletSeedMode, NodeError> with Ok(Default::default())
- [x] `crates/node/src/main.rs:1546:5` — replace is_peer_book_db_lock_conflict -> bool with false
- [x] `crates/node/src/main.rs:1546:5` — replace is_peer_book_db_lock_conflict -> bool with true
- [x] `crates/node/src/main.rs:1548:9` — replace || with && in is_peer_book_db_lock_conflict
- [x] `crates/node/src/main.rs:1549:9` — replace || with && in is_peer_book_db_lock_conflict
- [x] `crates/node/src/main.rs:3784:5` — replace mempool_spent_outpoints -> HashSet<OutPoint> with HashSet::new()
- [x] `crates/node/src/main.rs:3788:20` — delete ! in mempool_spent_outpoints
- [x] `crates/node/src/main.rs:3801:5` — replace load_wallet_reserved_outpoints -> Result<HashSet<OutPoint>, NodeError> with Ok(HashSet::new())
- [x] `crates/node/src/main.rs:3801:8` — delete ! in load_wallet_reserved_outpoints
- [x] `crates/node/src/main.rs:4203:5` — replace consensus_fingerprint -> String with "xyzzy".into()
- [x] `crates/node/src/main.rs:4203:5` — replace consensus_fingerprint -> String with String::new()
- [x] `crates/node/src/main.rs:4236:5` — replace ensure_consensus_fingerprint_match -> Result<(), NodeError> with Ok(())
- [x] `crates/node/src/main.rs:5787:20` — replace < with <= in tx_fee_from_known_prevouts
- [x] `crates/node/src/main.rs:5787:20` — replace < with == in tx_fee_from_known_prevouts
- [x] `crates/node/src/main.rs:8586:34` — replace > with < in run_relay_serve
- [x] `crates/node/src/main.rs:8586:34` — replace > with == in run_relay_serve
- [x] `crates/node/src/main.rs:8586:34` — replace > with >= in run_relay_serve
- [x] `crates/node/src/main.rs:9734:31` — replace && with || in sanitize_template_mempool_fees
- [x] `crates/node/src/main.rs:9734:48` — replace > with >= in sanitize_template_mempool_fees
- [x] `crates/node/src/main.rs:9751:20` — replace < with <= in sanitize_template_mempool_fees
- [x] `crates/node/src/main.rs:9751:20` — replace < with == in sanitize_template_mempool_fees
- [x] `crates/node/src/main.rs:9759:12` — delete ! in sanitize_template_mempool_fees
- [x] `crates/node/src/main.rs:9956:17` — replace < with <= in rewrite_coinbase_to_expected_value
- [x] `crates/node/src/main.rs:9956:17` — replace < with == in rewrite_coinbase_to_expected_value
- [x] `crates/node/src/main.rs:9961:28` — replace - with + in rewrite_coinbase_to_expected_value
- [x] `crates/node/src/main.rs:10530:49` — replace || with && in run_stratum_client_async
- [x] `crates/node/src/main.rs:11523:25` — replace match guard is_runtime_db_lock_conflict(&err) || is_mempool_db_lock_conflict(&err) with false in submit_tx_via_mempool_db_with_retry
- [x] `crates/node/src/main.rs:11523:25` — replace match guard is_runtime_db_lock_conflict(&err) || is_mempool_db_lock_conflict(&err) with true in submit_tx_via_mempool_db_with_retry
- [x] `crates/node/src/main.rs:11523:59` — replace || with && in submit_tx_via_mempool_db_with_retry
- [x] `crates/node/src/main.rs:11525:24` — replace + with * in submit_tx_via_mempool_db_with_retry
- [x] `crates/node/src/main.rs:11525:24` — replace + with - in submit_tx_via_mempool_db_with_retry
- [x] `crates/node/src/main.rs:11525:28` — replace < with <= in submit_tx_via_mempool_db_with_retry
- [x] `crates/node/src/main.rs:11525:28` — replace < with == in submit_tx_via_mempool_db_with_retry
- [x] `crates/node/src/main.rs:11525:28` — replace < with > in submit_tx_via_mempool_db_with_retry
- [x] `crates/node/src/main.rs:14916:21` — replace match guard is_runtime_db_lock_conflict(&err) with false in axum_runtime_for_query
- [x] `crates/node/src/main.rs:14916:21` — replace match guard is_runtime_db_lock_conflict(&err) with true in axum_runtime_for_query
- [x] `crates/node/src/main.rs:14976:5` — replace axum_block_response -> AxumResponse with Default::default()
- [x] `crates/node/src/main.rs:15293:38` — replace > with < in axum_mempool_handler
- [x] `crates/node/src/main.rs:15293:38` — replace > with == in axum_mempool_handler
- [x] `crates/node/src/main.rs:15293:38` — replace > with >= in axum_mempool_handler
- [x] `crates/node/src/main.rs:15375:5` — replace axum_tx_handler -> AxumResponse with Default::default()
- [x] `crates/node/src/main.rs:15468:5` — replace axum_wallet_new_handler -> AxumResponse with Default::default()
- [x] `crates/node/src/main.rs:15766:5` — replace axum_tx_submit_handler -> AxumResponse with Default::default()
- [x] `crates/node/src/main.rs:15802:5` — replace axum_wallet_qr_handler -> AxumResponse with Default::default()
- [x] `crates/node/src/main.rs:16294:46` — replace > with < in run_rpc_serve_inner_legacy
- [x] `crates/node/src/main.rs:16294:46` — replace > with == in run_rpc_serve_inner_legacy
- [x] `crates/node/src/main.rs:16294:46` — replace > with >= in run_rpc_serve_inner_legacy

### `crates/wallet/src/mnemonic.rs` (4)
- [x] `crates/wallet/src/mnemonic.rs:17:9` — replace WalletSeedMode::as_str -> &'static str with ""
- [x] `crates/wallet/src/mnemonic.rs:17:9` — replace WalletSeedMode::as_str -> &'static str with "xyzzy"
- [x] `crates/wallet/src/mnemonic.rs:78:9` — replace WalletMnemonic::to_seed_scam_blake -> [u8; 64] with [0; 64]
- [x] `crates/wallet/src/mnemonic.rs:78:9` — replace WalletMnemonic::to_seed_scam_blake -> [u8; 64] with [1; 64]

## Timeout

### `crates/node/src/main.rs` (69)
- [x] `crates/node/src/main.rs:1169:9` — replace <impl From<WalletSeedModeArg> for WalletSeedMode>::from -> Self with Default::default()
- [x] `crates/node/src/main.rs:1178:9` — replace Network::as_str -> &'static str with ""
- [x] `crates/node/src/main.rs:1178:9` — replace Network::as_str -> &'static str with "xyzzy"
- [x] `crates/node/src/main.rs:1391:5` — replace persist_mempool_db -> Result<(), NodeError> with Ok(())
- [x] `crates/node/src/main.rs:1405:28` — replace != with == in load_mempool_from_db_or_empty
- [x] `crates/node/src/main.rs:1610:5` — replace persist_with_retry -> Result<(), NodeError> with Ok(())
- [x] `crates/node/src/main.rs:1676:5` — replace persist_mempool_db_with_retry -> Result<(), NodeError> with Ok(())
- [x] `crates/node/src/main.rs:2753:30` — replace != with == in load_or_init_peer_book
- [x] `crates/node/src/main.rs:2850:5` — replace parse_relay_target_endpoint -> Option<RelayTargetEndpoint> with None
- [x] `crates/node/src/main.rs:2875:5` — replace is_cjdns_ip -> bool with true
- [x] `crates/node/src/main.rs:2904:5` — replace relay_target_allowed_by_policy -> bool with false
- [x] `crates/node/src/main.rs:2995:5` — replace apply_bucket_cap_with_secret -> Vec<SocketAddr> with vec![]
- [x] `crates/node/src/main.rs:2995:23` — replace == with != in apply_bucket_cap_with_secret
- [x] `crates/node/src/main.rs:3003:19` — replace >= with < in apply_bucket_cap_with_secret
- [x] `crates/node/src/main.rs:3013:5` — replace run_add_peer -> Result<(), NodeError> with Ok(())
- [x] `crates/node/src/main.rs:3021:8` — delete ! in run_add_peer
- [x] `crates/node/src/main.rs:5767:5` — replace tx_fee_from_known_prevouts -> Option<u64> with None
- [x] `crates/node/src/main.rs:5767:5` — replace tx_fee_from_known_prevouts -> Option<u64> with Some(0)
- [x] `crates/node/src/main.rs:5767:5` — replace tx_fee_from_known_prevouts -> Option<u64> with Some(1)
- [x] `crates/node/src/main.rs:5787:20` — replace < with > in tx_fee_from_known_prevouts
- [x] `crates/node/src/main.rs:5790:31` — replace - with / in tx_fee_from_known_prevouts
- [x] `crates/node/src/main.rs:6277:5` — replace relay_messages_for_peer -> Vec<WireMessage> with vec![]
- [x] `crates/node/src/main.rs:6294:5` — replace relay_gossip_outbound_for_peer -> Vec<WireMessage> with vec![]
- [x] `crates/node/src/main.rs:6295:62` — replace == with != in relay_gossip_outbound_for_peer
- [x] `crates/node/src/main.rs:6307:5` — replace relay_timeout_streak_reached_limit -> bool with true
- [x] `crates/node/src/main.rs:6307:20` — replace >= with < in relay_timeout_streak_reached_limit
- [x] `crates/node/src/main.rs:6311:5` — delete ! in relay_startup_send_failed
- [x] `crates/node/src/main.rs:6311:5` — replace relay_startup_send_failed -> bool with true
- [x] `crates/node/src/main.rs:6329:5` — replace merge_outbound_targets -> Vec<String> with vec!["xyzzy".into()]
- [x] `crates/node/src/main.rs:6329:5` — replace merge_outbound_targets -> Vec<String> with vec![String::new()]
- [x] `crates/node/src/main.rs:6329:5` — replace merge_outbound_targets -> Vec<String> with vec![]
- [x] `crates/node/src/main.rs:6513:5` — replace process_relay_wire_message_with_archive -> Result<Vec<WireMessage>, NodeError> with Ok(vec![])
- [x] `crates/node/src/main.rs:6663:5` — replace process_relay_wire_message_inner -> Result<Vec<WireMessage>, NodeError> with Ok(vec![])
- [x] `crates/node/src/main.rs:6682:28` — replace > with < in process_relay_wire_message_inner
- [x] `crates/node/src/main.rs:6734:30` — replace > with < in process_relay_wire_message_inner
- [x] `crates/node/src/main.rs:7142:5` — replace load_relay_outbound_targets_selected -> Result<Vec<String>, NodeError> with Ok(vec!["xyzzy".into()])
- [x] `crates/node/src/main.rs:7142:5` — replace load_relay_outbound_targets_selected -> Result<Vec<String>, NodeError> with Ok(vec![String::new()])
- [x] `crates/node/src/main.rs:7142:5` — replace load_relay_outbound_targets_selected -> Result<Vec<String>, NodeError> with Ok(vec![])
- [x] `crates/node/src/main.rs:7164:12` — delete ! in load_relay_outbound_targets_selected
- [x] `crates/node/src/main.rs:7179:30` — replace && with || in load_relay_outbound_targets_selected
- [x] `crates/node/src/main.rs:7225:5` — replace relay_target_matches_bind -> bool with true
- [x] `crates/node/src/main.rs:7225:18` — replace == with != in relay_target_matches_bind
- [x] `crates/node/src/main.rs:7236:20` — replace != with == in relay_target_matches_bind
- [x] `crates/node/src/main.rs:7304:5` — replace run_relay_outbound_worker with ()
- [x] `crates/node/src/main.rs:7491:5` — replace run_relay_outbound_worker_async with ()
- [x] `crates/node/src/main.rs:7620:5` — replace relay_target_is_anonymous_network -> bool with true
- [x] `crates/node/src/main.rs:7833:5` — replace run_relay_outbound_supervisor_async with ()
- [x] `crates/node/src/main.rs:7982:5` — replace relay_runtime_or_mempool_changed -> (bool, bool) with (false, false)
- [x] `crates/node/src/main.rs:7982:5` — replace relay_runtime_or_mempool_changed -> (bool, bool) with (true, false)
- [x] `crates/node/src/main.rs:7982:45` — replace != with == in relay_runtime_or_mempool_changed
- [x] `crates/node/src/main.rs:7986:5` — replace relay_max_active_sessions -> usize with 0
- [x] `crates/node/src/main.rs:7986:5` — replace relay_max_active_sessions -> usize with 1
- [x] `crates/node/src/main.rs:8386:24` — delete ! in run_relay_peer_session_async
- [x] `crates/node/src/main.rs:8460:16` — delete ! in run_relay_peer_session_async
- [x] `crates/node/src/main.rs:9055:5` — replace admit_peer_tx_into_relay -> Result<(), NodeError> with Ok(())
- [x] `crates/node/src/main.rs:9062:12` — delete ! in admit_peer_tx_into_relay
- [x] `crates/node/src/main.rs:10611:5` — replace max_requests_limit_hit -> bool with false
- [x] `crates/node/src/main.rs:10611:59` — replace >= with < in max_requests_limit_hit
- [x] `crates/node/src/main.rs:10615:5` — replace max_requests_limit_configured -> bool with false
- [x] `crates/node/src/main.rs:10615:18` — replace != with == in max_requests_limit_configured
- [x] `crates/node/src/main.rs:10851:5` — replace relay_send_message_or_closed_async -> Result<bool, NodeError> with Ok(false)
- [x] `crates/node/src/main.rs:10851:5` — replace relay_send_message_or_closed_async -> Result<bool, NodeError> with Ok(true)
- [x] `crates/node/src/main.rs:10876:5` — replace relay_send_messages_until_closed_async -> Result<bool, NodeError> with Ok(false)
- [x] `crates/node/src/main.rs:10876:5` — replace relay_send_messages_until_closed_async -> Result<bool, NodeError> with Ok(true)
- [x] `crates/node/src/main.rs:10877:12` — delete ! in relay_send_messages_until_closed_async
- [x] `crates/node/src/main.rs:14637:5` — replace rpc_exact_route_matches -> bool with true
- [x] `crates/node/src/main.rs:14637:12` — replace == with != in rpc_exact_route_matches
- [x] `crates/node/src/main.rs:14637:31` — replace && with || in rpc_exact_route_matches
- [x] `crates/node/src/main.rs:14637:39` — replace == with != in rpc_exact_route_matches

