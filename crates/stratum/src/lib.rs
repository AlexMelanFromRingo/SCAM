use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use scam_core::{BlockHeader, Hash256, Target};
use secp256k1::ecdh::SharedSecret;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use snow::Builder as NoiseBuilder;
use snow::params::NoiseParams;
use snow::{HandshakeState as NoiseHandshakeState, TransportState as NoiseTransportState};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const SUPPORTED_SV2_VERSION: u16 = 2;
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;
pub const SV2_HEADER_LEN: usize = 6;
pub const SV2_EXTENSION_MINING: u16 = 0;
const U24_MAX: usize = 0x00ff_ffff;
const SECURE_HANDSHAKE_MAGIC: &[u8; 8] = b"SCAMSV2N";
const SECURE_HANDSHAKE_SIZE: usize = 8 + 33;
const SECURE_AEAD_TAG_LEN: usize = 16;
const SECURE_MAX_FRAME_SIZE: usize = MAX_FRAME_SIZE + SV2_HEADER_LEN + SECURE_AEAD_TAG_LEN;
const SECURE_KEY_CONTEXT_CLIENT_TO_SERVER: &str = "SCAM-SV2-NoiseLike-c2s-v1";
const SECURE_KEY_CONTEXT_SERVER_TO_CLIENT: &str = "SCAM-SV2-NoiseLike-s2c-v1";
const SECURE_KEY_CONTEXT_REKEY: &str = "SCAM-SV2-NoiseLike-rekey-v1";
const DEFAULT_SECURE_REKEY_INTERVAL_MESSAGES: u64 = 10_000;
const NOISE_PROTOCOL_XX: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const NOISE_HANDSHAKE_MAX_PACKET_SIZE: usize = 65_535;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureTransportMode {
    Legacy,
    NoiseXx,
}

impl SecureTransportMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::NoiseXx => "noise_xx",
        }
    }
}

impl std::str::FromStr for SecureTransportMode {
    type Err = StratumError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "legacy" => Ok(Self::Legacy),
            "noise_xx" => Ok(Self::NoiseXx),
            other => Err(StratumError::InvalidConfig(format!(
                "unsupported secure transport mode: {other}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoiseStaticKeypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

const MSG_SETUP_CONNECTION: u8 = 0x00;
const MSG_SETUP_CONNECTION_SUCCESS: u8 = 0x01;
const MSG_SETUP_CONNECTION_ERROR: u8 = 0x02;
const MSG_OPEN_STANDARD_MINING_CHANNEL: u8 = 0x10;
const MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS: u8 = 0x11;
const MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR: u8 = 0x12;
const MSG_NEW_MINING_JOB: u8 = 0x20;
const MSG_SET_NEW_PREV_HASH: u8 = 0x21;
const MSG_SET_TARGET: u8 = 0x22;
const MSG_SUBMIT_SHARES_STANDARD: u8 = 0x30;
const MSG_SUBMIT_SHARES_SUCCESS: u8 = 0x31;
const MSG_SUBMIT_SHARES_ERROR: u8 = 0x32;
const MSG_KEEP_ALIVE: u8 = 0x40;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Sv2Message {
    SetupConnection {
        protocol: u16,
        min_version: u16,
        max_version: u16,
        flags: u32,
        user_agent: String,
    },
    SetupConnectionSuccess {
        used_version: u16,
        flags: u32,
    },
    SetupConnectionError {
        code: String,
        reason: String,
    },
    OpenStandardMiningChannel {
        request_id: u32,
        user: String,
    },
    OpenStandardMiningChannelSuccess {
        request_id: u32,
        channel_id: u32,
        target_hex: String,
        extranonce_prefix_hex: String,
    },
    OpenStandardMiningChannelError {
        request_id: u32,
        code: String,
        reason: String,
    },
    NewMiningJob {
        channel_id: u32,
        job_id: u32,
        version: u32,
        prev_hash_hex: String,
        merkle_root_hex: String,
        ntime: u64,
        network_target_hex: String,
    },
    SetNewPrevHash {
        channel_id: u32,
        job_id: u32,
        prev_hash_hex: String,
        ntime: u64,
        network_target_hex: String,
    },
    SetTarget {
        channel_id: u32,
        maximum_target_hex: String,
    },
    SubmitSharesStandard {
        channel_id: u32,
        job_id: u32,
        nonce: u64,
        ntime: u64,
    },
    SubmitSharesSuccess {
        channel_id: u32,
        accepted: u32,
        is_block: bool,
    },
    SubmitSharesError {
        channel_id: u32,
        code: String,
        reason: String,
    },
    KeepAlive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningJob {
    pub channel_id: u32,
    pub job_id: u32,
    pub version: u32,
    pub prev_hash: Hash256,
    pub merkle_root: Hash256,
    pub ntime: u64,
    pub network_target: Target,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningTemplate {
    pub version: u32,
    pub prev_hash: Hash256,
    pub merkle_root: Hash256,
    pub ntime: u64,
    pub network_target: Target,
}

pub trait JobDeclarator {
    fn next_job_id(&mut self) -> u32;

    fn declare_standard_job(&mut self, channel_id: u32, template: MiningTemplate) -> MiningJob {
        MiningJob {
            channel_id,
            job_id: self.next_job_id(),
            version: template.version,
            prev_hash: template.prev_hash,
            merkle_root: template.merkle_root,
            ntime: template.ntime,
            network_target: template.network_target,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequentialJobDeclarator {
    next_job_id: u32,
}

impl SequentialJobDeclarator {
    pub fn new(start_job_id: u32) -> Self {
        Self {
            next_job_id: start_job_id,
        }
    }
}

impl Default for SequentialJobDeclarator {
    fn default() -> Self {
        Self::new(0)
    }
}

impl JobDeclarator for SequentialJobDeclarator {
    fn next_job_id(&mut self) -> u32 {
        self.next_job_id = self.next_job_id.wrapping_add(1);
        self.next_job_id
    }
}

pub trait Translator {
    fn parse_remote_job_message(
        &self,
        message: Sv2Message,
    ) -> Result<Option<MiningJob>, StratumError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityTranslator;

impl Translator for IdentityTranslator {
    fn parse_remote_job_message(
        &self,
        message: Sv2Message,
    ) -> Result<Option<MiningJob>, StratumError> {
        match message {
            Sv2Message::NewMiningJob {
                channel_id,
                job_id,
                version,
                prev_hash_hex,
                merkle_root_hex,
                ntime,
                network_target_hex,
            } => {
                let prev_hash = Hash256::from_hex(&prev_hash_hex).map_err(|e| {
                    StratumError::InvalidMessage(format!("invalid prev_hash_hex in job: {e}"))
                })?;
                let merkle_root = Hash256::from_hex(&merkle_root_hex).map_err(|e| {
                    StratumError::InvalidMessage(format!("invalid merkle_root_hex in job: {e}"))
                })?;
                let network_target = Target::from_hex(&network_target_hex).map_err(|e| {
                    StratumError::InvalidMessage(format!("invalid network_target_hex in job: {e}"))
                })?;
                Ok(Some(MiningJob {
                    channel_id,
                    job_id,
                    version,
                    prev_hash,
                    merkle_root,
                    ntime,
                    network_target,
                }))
            }
            _ => Ok(None),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareSubmission {
    pub channel_id: u32,
    pub job_id: u32,
    pub nonce: u64,
    pub ntime: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShareValidation {
    AcceptedShare {
        header_hash: Hash256,
        is_block: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SessionConfig {
    pub channel_id: u32,
    pub share_target: Target,
    pub min_share_target: Target,
    pub max_share_target: Target,
    pub max_jobs: usize,
    pub supported_version: u16,
    pub vardiff_target_shares_per_minute: u32,
    pub vardiff_retarget_interval_shares: usize,
    pub vardiff_clamp_up: f64,
    pub vardiff_clamp_down: f64,
    pub max_rejected_shares: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionState {
    AwaitSetup,
    AwaitOpenChannel,
    Active,
    Closed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionStats {
    pub accepted_shares: u64,
    pub rejected_shares: u64,
    pub target_updates: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionEvent {
    SetupAccepted,
    ChannelOpened {
        channel_id: u32,
        user: String,
    },
    ShareAccepted {
        channel_id: u32,
        job_id: u32,
        nonce: u64,
        ntime: u64,
        header_hash: Hash256,
        is_block: bool,
    },
    ShareRejected {
        channel_id: u32,
        job_id: Option<u32>,
        reason: String,
    },
    ShareTargetChanged {
        channel_id: u32,
        target: Target,
    },
    ChannelClosed {
        channel_id: u32,
        reason: String,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionResponse {
    pub outbound: Vec<Sv2Message>,
    pub events: Vec<SessionEvent>,
}

pub struct Sv2Session {
    cfg: SessionConfig,
    state: SessionState,
    user: Option<String>,
    jobs: HashMap<u32, MiningJob>,
    job_order: VecDeque<u32>,
    stats: SessionStats,
    current_share_target: Target,
    recent_share_timestamps: VecDeque<u64>,
}

impl Sv2Session {
    pub fn new(cfg: SessionConfig) -> Result<Self, StratumError> {
        if cfg.max_jobs == 0 {
            return Err(StratumError::InvalidConfig(
                "max_jobs must be greater than zero".to_owned(),
            ));
        }
        if cfg.max_rejected_shares == 0 {
            return Err(StratumError::InvalidConfig(
                "max_rejected_shares must be greater than zero".to_owned(),
            ));
        }
        if cfg.vardiff_clamp_up < 1.0 {
            return Err(StratumError::InvalidConfig(
                "vardiff_clamp_up must be >= 1.0".to_owned(),
            ));
        }
        if !(0.0..=1.0).contains(&cfg.vardiff_clamp_down) || cfg.vardiff_clamp_down == 0.0 {
            return Err(StratumError::InvalidConfig(
                "vardiff_clamp_down must be in (0.0, 1.0]".to_owned(),
            ));
        }
        if cfg.vardiff_retarget_interval_shares < 2 {
            return Err(StratumError::InvalidConfig(
                "vardiff_retarget_interval_shares must be >= 2".to_owned(),
            ));
        }
        if cfg.vardiff_target_shares_per_minute == 0 {
            return Err(StratumError::InvalidConfig(
                "vardiff_target_shares_per_minute must be > 0".to_owned(),
            ));
        }
        if cfg.min_share_target > cfg.max_share_target {
            return Err(StratumError::InvalidConfig(
                "min_share_target must be <= max_share_target".to_owned(),
            ));
        }
        if cfg.share_target < cfg.min_share_target || cfg.share_target > cfg.max_share_target {
            return Err(StratumError::InvalidConfig(
                "share_target must be within [min_share_target, max_share_target]".to_owned(),
            ));
        }

        Ok(Self {
            cfg,
            state: SessionState::AwaitSetup,
            user: None,
            jobs: HashMap::new(),
            job_order: VecDeque::new(),
            stats: SessionStats::default(),
            current_share_target: cfg.share_target,
            recent_share_timestamps: VecDeque::new(),
        })
    }

    pub fn channel_id(&self) -> u32 {
        self.cfg.channel_id
    }

    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }

    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }

    pub fn share_target(&self) -> Target {
        self.current_share_target
    }

    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }

    pub fn handle_message(&mut self, message: Sv2Message) -> Result<SessionResponse, StratumError> {
        self.handle_message_at(message, current_unix_time_sec())
    }

    pub fn handle_message_at(
        &mut self,
        message: Sv2Message,
        now_unix_sec: u64,
    ) -> Result<SessionResponse, StratumError> {
        if self.state == SessionState::Closed {
            return Err(StratumError::ProtocolState(
                "message received for closed session".to_owned(),
            ));
        }

        match message {
            Sv2Message::SetupConnection {
                protocol,
                min_version,
                max_version,
                flags,
                user_agent: _,
            } => self.handle_setup(protocol, min_version, max_version, flags),
            Sv2Message::OpenStandardMiningChannel { request_id, user } => {
                self.handle_open_channel(request_id, user)
            }
            Sv2Message::SubmitSharesStandard {
                channel_id,
                job_id,
                nonce,
                ntime,
            } => self.handle_submit_share(
                ShareSubmission {
                    channel_id,
                    job_id,
                    nonce,
                    ntime,
                },
                now_unix_sec,
            ),
            Sv2Message::KeepAlive => Ok(SessionResponse {
                outbound: vec![Sv2Message::KeepAlive],
                events: Vec::new(),
            }),
            other => Err(StratumError::ProtocolState(format!(
                "unexpected message in current state: {other:?}"
            ))),
        }
    }

    pub fn install_job(&mut self, job: MiningJob) -> Result<Sv2Message, StratumError> {
        if self.state != SessionState::Active {
            return Err(StratumError::ProtocolState(
                "channel is not active yet".to_owned(),
            ));
        }
        if job.channel_id != self.cfg.channel_id {
            return Err(StratumError::ChannelMismatch {
                expected: self.cfg.channel_id,
                got: job.channel_id,
            });
        }

        if self.jobs.contains_key(&job.job_id) {
            self.job_order.retain(|job_id| *job_id != job.job_id);
        }
        self.jobs.insert(job.job_id, job.clone());
        self.job_order.push_back(job.job_id);
        while self.job_order.len() > self.cfg.max_jobs {
            if let Some(evicted) = self.job_order.pop_front() {
                self.jobs.remove(&evicted);
            }
        }

        Ok(Sv2Message::NewMiningJob {
            channel_id: job.channel_id,
            job_id: job.job_id,
            version: job.version,
            prev_hash_hex: job.prev_hash.to_hex(),
            merkle_root_hex: job.merkle_root.to_hex(),
            ntime: job.ntime,
            network_target_hex: job.network_target.to_hex(),
        })
    }

    pub fn set_new_prev_hash(&self, job: &MiningJob) -> Result<Sv2Message, StratumError> {
        if job.channel_id != self.cfg.channel_id {
            return Err(StratumError::ChannelMismatch {
                expected: self.cfg.channel_id,
                got: job.channel_id,
            });
        }
        Ok(Sv2Message::SetNewPrevHash {
            channel_id: job.channel_id,
            job_id: job.job_id,
            prev_hash_hex: job.prev_hash.to_hex(),
            ntime: job.ntime,
            network_target_hex: job.network_target.to_hex(),
        })
    }

    pub fn set_target_message(&self) -> Sv2Message {
        Sv2Message::SetTarget {
            channel_id: self.cfg.channel_id,
            maximum_target_hex: self.current_share_target.to_hex(),
        }
    }

    pub fn job(&self, job_id: u32) -> Option<&MiningJob> {
        self.jobs.get(&job_id)
    }

    fn handle_setup(
        &mut self,
        protocol: u16,
        min_version: u16,
        max_version: u16,
        flags: u32,
    ) -> Result<SessionResponse, StratumError> {
        if self.state != SessionState::AwaitSetup {
            return Err(StratumError::ProtocolState(
                "setup_connection received out of order".to_owned(),
            ));
        }

        if protocol != 2
            || self.cfg.supported_version < min_version
            || self.cfg.supported_version > max_version
        {
            return Ok(SessionResponse {
                outbound: vec![Sv2Message::SetupConnectionError {
                    code: "unsupported_version".to_owned(),
                    reason: format!(
                        "supported={}, requested_range=[{}, {}], protocol={}",
                        self.cfg.supported_version, min_version, max_version, protocol
                    ),
                }],
                events: Vec::new(),
            });
        }

        self.state = SessionState::AwaitOpenChannel;
        Ok(SessionResponse {
            outbound: vec![Sv2Message::SetupConnectionSuccess {
                used_version: self.cfg.supported_version,
                flags,
            }],
            events: vec![SessionEvent::SetupAccepted],
        })
    }

    fn handle_open_channel(
        &mut self,
        request_id: u32,
        user: String,
    ) -> Result<SessionResponse, StratumError> {
        if self.state != SessionState::AwaitOpenChannel {
            return Err(StratumError::ProtocolState(
                "open_standard_mining_channel received out of order".to_owned(),
            ));
        }
        if user.trim().is_empty() {
            return Ok(SessionResponse {
                outbound: vec![Sv2Message::OpenStandardMiningChannelError {
                    request_id,
                    code: "invalid_user".to_owned(),
                    reason: "user must be non-empty".to_owned(),
                }],
                events: Vec::new(),
            });
        }

        self.user = Some(user.clone());
        self.state = SessionState::Active;
        Ok(SessionResponse {
            outbound: vec![
                Sv2Message::OpenStandardMiningChannelSuccess {
                    request_id,
                    channel_id: self.cfg.channel_id,
                    target_hex: self.current_share_target.to_hex(),
                    extranonce_prefix_hex: format!("{:08x}", self.cfg.channel_id),
                },
                self.set_target_message(),
            ],
            events: vec![SessionEvent::ChannelOpened {
                channel_id: self.cfg.channel_id,
                user,
            }],
        })
    }

    fn handle_submit_share(
        &mut self,
        submission: ShareSubmission,
        now_unix_sec: u64,
    ) -> Result<SessionResponse, StratumError> {
        if self.state != SessionState::Active {
            return Err(StratumError::ProtocolState(
                "submit_share received before active channel".to_owned(),
            ));
        }
        if submission.channel_id != self.cfg.channel_id {
            return Err(StratumError::ChannelMismatch {
                expected: self.cfg.channel_id,
                got: submission.channel_id,
            });
        }

        let Some(job) = self.jobs.get(&submission.job_id) else {
            let reason = format!("unknown job {}", submission.job_id);
            return Ok(self.reject_share(Some(submission.job_id), "unknown_job", reason));
        };

        match validate_share(job, submission, self.current_share_target) {
            Ok(ShareValidation::AcceptedShare {
                header_hash,
                is_block,
            }) => {
                self.stats.accepted_shares = self.stats.accepted_shares.saturating_add(1);
                let mut outbound = vec![Sv2Message::SubmitSharesSuccess {
                    channel_id: self.cfg.channel_id,
                    accepted: 1,
                    is_block,
                }];
                let mut events = vec![SessionEvent::ShareAccepted {
                    channel_id: self.cfg.channel_id,
                    job_id: submission.job_id,
                    nonce: submission.nonce,
                    ntime: submission.ntime,
                    header_hash,
                    is_block,
                }];

                if let Some(new_target) = self.record_share_timestamp(now_unix_sec)? {
                    outbound.push(Sv2Message::SetTarget {
                        channel_id: self.cfg.channel_id,
                        maximum_target_hex: new_target.to_hex(),
                    });
                    events.push(SessionEvent::ShareTargetChanged {
                        channel_id: self.cfg.channel_id,
                        target: new_target,
                    });
                }

                Ok(SessionResponse { outbound, events })
            }
            Err(err) => {
                let reason = err.to_string();
                Ok(self.reject_share(Some(submission.job_id), "low_difficulty", reason))
            }
        }
    }

    fn reject_share(&mut self, job_id: Option<u32>, code: &str, reason: String) -> SessionResponse {
        self.stats.rejected_shares = self.stats.rejected_shares.saturating_add(1);

        let mut outbound = vec![Sv2Message::SubmitSharesError {
            channel_id: self.cfg.channel_id,
            code: code.to_owned(),
            reason: reason.clone(),
        }];
        let mut events = vec![SessionEvent::ShareRejected {
            channel_id: self.cfg.channel_id,
            job_id,
            reason,
        }];

        if self.stats.rejected_shares >= self.cfg.max_rejected_shares as u64 {
            self.state = SessionState::Closed;
            let close_reason = format!(
                "maximum rejected shares reached ({})",
                self.cfg.max_rejected_shares
            );
            outbound.push(Sv2Message::SubmitSharesError {
                channel_id: self.cfg.channel_id,
                code: "channel_closed".to_owned(),
                reason: close_reason.clone(),
            });
            events.push(SessionEvent::ChannelClosed {
                channel_id: self.cfg.channel_id,
                reason: close_reason,
            });
        }

        SessionResponse { outbound, events }
    }

    fn record_share_timestamp(
        &mut self,
        now_unix_sec: u64,
    ) -> Result<Option<Target>, StratumError> {
        self.recent_share_timestamps.push_back(now_unix_sec);
        let max_points = self.cfg.vardiff_retarget_interval_shares + 1;
        while self.recent_share_timestamps.len() > max_points {
            self.recent_share_timestamps.pop_front();
        }

        if self.recent_share_timestamps.len() < max_points {
            return Ok(None);
        }

        let Some(first) = self.recent_share_timestamps.front().copied() else {
            return Ok(None);
        };
        let Some(last) = self.recent_share_timestamps.back().copied() else {
            return Ok(None);
        };
        let actual_span = last.saturating_sub(first).max(1);

        let share_count = self.cfg.vardiff_retarget_interval_shares as u128;
        let target_rate = self.cfg.vardiff_target_shares_per_minute as u128;
        let expected_span = (share_count * 60).div_ceil(target_rate);
        let expected_span = expected_span.max(1) as u64;

        let mut ratio = (actual_span as f64) / (expected_span as f64);
        ratio = ratio.clamp(self.cfg.vardiff_clamp_down, self.cfg.vardiff_clamp_up);

        if (ratio - 1.0).abs() < 0.05 {
            return Ok(None);
        }

        let scaled = scale_target(self.current_share_target, ratio)?;
        let clamped = scaled.clamp(self.cfg.min_share_target, self.cfg.max_share_target);
        if clamped == self.current_share_target {
            return Ok(None);
        }

        self.current_share_target = clamped;
        self.stats.target_updates = self.stats.target_updates.saturating_add(1);
        Ok(Some(clamped))
    }
}

fn current_unix_time_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug)]
pub struct SecureSv2Transport {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_nonce: u64,
    recv_nonce: u64,
    rekey_interval_messages: u64,
    send_epoch: u64,
    recv_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecureRole {
    Client,
    Server,
}

impl SecureSv2Transport {
    pub fn handshake_client<IO: Read + Write>(io: &mut IO) -> Result<Self, StratumError> {
        let secp = Secp256k1::new();
        let (local_sk, local_pk) = secp.generate_keypair(&mut OsRng);
        let handshake = encode_secure_handshake_packet(&local_pk);
        io.write_all(&handshake).map_err(StratumError::Io)?;
        io.flush().map_err(StratumError::Io)?;

        let mut remote_handshake = [0u8; SECURE_HANDSHAKE_SIZE];
        io.read_exact(&mut remote_handshake)
            .map_err(StratumError::Io)?;
        let remote_pk = decode_secure_handshake_packet(&remote_handshake)?;

        Ok(Self::from_handshake(
            local_sk,
            local_pk,
            remote_pk,
            SecureRole::Client,
        ))
    }

    pub async fn handshake_client_async<IO: AsyncRead + AsyncWrite + Unpin>(
        io: &mut IO,
    ) -> Result<Self, StratumError> {
        let secp = Secp256k1::new();
        let (local_sk, local_pk) = secp.generate_keypair(&mut OsRng);
        let handshake = encode_secure_handshake_packet(&local_pk);
        io.write_all(&handshake).await.map_err(StratumError::Io)?;
        io.flush().await.map_err(StratumError::Io)?;

        let mut remote_handshake = [0u8; SECURE_HANDSHAKE_SIZE];
        io.read_exact(&mut remote_handshake)
            .await
            .map_err(StratumError::Io)?;
        let remote_pk = decode_secure_handshake_packet(&remote_handshake)?;

        Ok(Self::from_handshake(
            local_sk,
            local_pk,
            remote_pk,
            SecureRole::Client,
        ))
    }

    pub fn handshake_server<IO: Read + Write>(io: &mut IO) -> Result<Self, StratumError> {
        let secp = Secp256k1::new();
        let (local_sk, local_pk) = secp.generate_keypair(&mut OsRng);

        let mut remote_handshake = [0u8; SECURE_HANDSHAKE_SIZE];
        io.read_exact(&mut remote_handshake)
            .map_err(StratumError::Io)?;
        let remote_pk = decode_secure_handshake_packet(&remote_handshake)?;

        let handshake = encode_secure_handshake_packet(&local_pk);
        io.write_all(&handshake).map_err(StratumError::Io)?;
        io.flush().map_err(StratumError::Io)?;

        Ok(Self::from_handshake(
            local_sk,
            local_pk,
            remote_pk,
            SecureRole::Server,
        ))
    }

    pub async fn handshake_server_async<IO: AsyncRead + AsyncWrite + Unpin>(
        io: &mut IO,
    ) -> Result<Self, StratumError> {
        let secp = Secp256k1::new();
        let (local_sk, local_pk) = secp.generate_keypair(&mut OsRng);

        let mut remote_handshake = [0u8; SECURE_HANDSHAKE_SIZE];
        io.read_exact(&mut remote_handshake)
            .await
            .map_err(StratumError::Io)?;
        let remote_pk = decode_secure_handshake_packet(&remote_handshake)?;

        let handshake = encode_secure_handshake_packet(&local_pk);
        io.write_all(&handshake).await.map_err(StratumError::Io)?;
        io.flush().await.map_err(StratumError::Io)?;

        Ok(Self::from_handshake(
            local_sk,
            local_pk,
            remote_pk,
            SecureRole::Server,
        ))
    }

    pub fn set_rekey_interval_messages(&mut self, interval: u64) -> Result<(), StratumError> {
        if interval == 0 {
            return Err(StratumError::InvalidConfig(
                "secure rekey interval must be > 0".to_owned(),
            ));
        }
        self.rekey_interval_messages = interval;
        Ok(())
    }

    pub fn write_message<W: Write>(
        &mut self,
        writer: &mut W,
        message: &Sv2Message,
    ) -> Result<(), StratumError> {
        let mut plaintext = Vec::new();
        write_frame(&mut plaintext, message)?;

        let ciphertext = self.encrypt_payload(&plaintext)?;
        if ciphertext.len() > SECURE_MAX_FRAME_SIZE {
            return Err(StratumError::FrameTooLarge {
                got: ciphertext.len(),
                max: SECURE_MAX_FRAME_SIZE,
            });
        }

        let len = u32::try_from(ciphertext.len()).map_err(|_| StratumError::FrameTooLarge {
            got: ciphertext.len(),
            max: SECURE_MAX_FRAME_SIZE,
        })?;
        writer
            .write_all(&len.to_le_bytes())
            .map_err(StratumError::Io)?;
        writer.write_all(&ciphertext).map_err(StratumError::Io)?;
        writer.flush().map_err(StratumError::Io)
    }

    pub async fn write_message_async<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        message: &Sv2Message,
    ) -> Result<(), StratumError> {
        let mut plaintext = Vec::new();
        write_frame(&mut plaintext, message)?;

        let ciphertext = self.encrypt_payload(&plaintext)?;
        if ciphertext.len() > SECURE_MAX_FRAME_SIZE {
            return Err(StratumError::FrameTooLarge {
                got: ciphertext.len(),
                max: SECURE_MAX_FRAME_SIZE,
            });
        }

        let len = u32::try_from(ciphertext.len()).map_err(|_| StratumError::FrameTooLarge {
            got: ciphertext.len(),
            max: SECURE_MAX_FRAME_SIZE,
        })?;
        writer
            .write_all(&len.to_le_bytes())
            .await
            .map_err(StratumError::Io)?;
        writer
            .write_all(&ciphertext)
            .await
            .map_err(StratumError::Io)?;
        writer.flush().await.map_err(StratumError::Io)
    }

    pub fn read_message<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Sv2Message>, StratumError> {
        let mut first = [0u8; 1];
        match reader.read(&mut first) {
            Ok(0) => return Ok(None),
            Ok(1) => {}
            Ok(_) => unreachable!(),
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(StratumError::Io(err)),
        }

        let mut rest = [0u8; 3];
        reader.read_exact(&mut rest).map_err(StratumError::Io)?;
        let len = u32::from_le_bytes([first[0], rest[0], rest[1], rest[2]]) as usize;
        if len == 0 {
            return Err(StratumError::InvalidFrameLength(0));
        }
        if len > SECURE_MAX_FRAME_SIZE {
            return Err(StratumError::FrameTooLarge {
                got: len,
                max: SECURE_MAX_FRAME_SIZE,
            });
        }

        let mut ciphertext = vec![0u8; len];
        reader
            .read_exact(&mut ciphertext)
            .map_err(StratumError::Io)?;
        let plaintext = self.decrypt_payload(&ciphertext)?;
        decode_single_frame_bytes(&plaintext).map(Some)
    }

    pub async fn read_message_async<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Sv2Message>, StratumError> {
        let len = match read_secure_frame_length_async(reader).await? {
            Some(len) => len,
            None => return Ok(None),
        };

        let mut ciphertext = vec![0u8; len];
        reader
            .read_exact(&mut ciphertext)
            .await
            .map_err(StratumError::Io)?;
        let plaintext = self.decrypt_payload(&ciphertext)?;
        decode_single_frame_bytes(&plaintext).map(Some)
    }

    fn from_handshake(
        local_sk: SecretKey,
        local_pk: PublicKey,
        remote_pk: PublicKey,
        role: SecureRole,
    ) -> Self {
        let shared = SharedSecret::new(&remote_pk, &local_sk).secret_bytes();
        let local_ser = local_pk.serialize();
        let remote_ser = remote_pk.serialize();
        let (client_pub, server_pub) = match role {
            SecureRole::Client => (local_ser, remote_ser),
            SecureRole::Server => (remote_ser, local_ser),
        };

        let mut material = [0u8; 32 + 33 + 33];
        material[..32].copy_from_slice(&shared);
        material[32..65].copy_from_slice(&client_pub);
        material[65..98].copy_from_slice(&server_pub);

        let c2s = blake3::derive_key(SECURE_KEY_CONTEXT_CLIENT_TO_SERVER, &material);
        let s2c = blake3::derive_key(SECURE_KEY_CONTEXT_SERVER_TO_CLIENT, &material);
        let (send_key, recv_key) = match role {
            SecureRole::Client => (c2s, s2c),
            SecureRole::Server => (s2c, c2s),
        };

        Self {
            send_key,
            recv_key,
            send_nonce: 0,
            recv_nonce: 0,
            rekey_interval_messages: DEFAULT_SECURE_REKEY_INTERVAL_MESSAGES,
            send_epoch: 0,
            recv_epoch: 0,
        }
    }

    fn encrypt_payload(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, StratumError> {
        let nonce = next_nonce(&mut self.send_nonce)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.send_key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| StratumError::SecureTransport("encryption failed".to_owned()))?;
        self.maybe_rekey_send()?;
        Ok(ciphertext)
    }

    fn decrypt_payload(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, StratumError> {
        let nonce = next_nonce(&mut self.recv_nonce)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.recv_key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| StratumError::SecureTransport("decryption failed".to_owned()))?;
        self.maybe_rekey_recv()?;
        Ok(plaintext)
    }

    fn maybe_rekey_send(&mut self) -> Result<(), StratumError> {
        if self.send_nonce < self.rekey_interval_messages {
            return Ok(());
        }
        self.send_epoch = self.send_epoch.checked_add(1).ok_or_else(|| {
            StratumError::SecureTransport("secure send epoch overflow".to_owned())
        })?;
        self.send_key = derive_rekey_key(self.send_key, self.send_epoch);
        self.send_nonce = 0;
        Ok(())
    }

    fn maybe_rekey_recv(&mut self) -> Result<(), StratumError> {
        if self.recv_nonce < self.rekey_interval_messages {
            return Ok(());
        }
        self.recv_epoch = self.recv_epoch.checked_add(1).ok_or_else(|| {
            StratumError::SecureTransport("secure recv epoch overflow".to_owned())
        })?;
        self.recv_key = derive_rekey_key(self.recv_key, self.recv_epoch);
        self.recv_nonce = 0;
        Ok(())
    }
}

#[derive(Debug)]
pub struct NoiseSv2Transport {
    transport: NoiseTransportState,
    rekey_interval_messages: u64,
    sent_messages: u64,
    received_messages: u64,
}

pub fn generate_noise_static_keypair() -> Result<NoiseStaticKeypair, StratumError> {
    let params = parse_noise_params()?;
    let builder = NoiseBuilder::new(params);
    let keypair = builder.generate_keypair().map_err(|e| {
        StratumError::SecureTransport(format!("noise keypair generation failed: {e}"))
    })?;
    let private = decode_noise_key_bytes(&keypair.private, "private")?;
    let public = decode_noise_key_bytes(&keypair.public, "public")?;
    Ok(NoiseStaticKeypair { private, public })
}

impl NoiseSv2Transport {
    pub fn handshake_client<IO: Read + Write>(
        io: &mut IO,
        local_static_private_key: Option<[u8; 32]>,
        expected_remote_static_public_key: Option<[u8; 32]>,
    ) -> Result<Self, StratumError> {
        let local_static = resolve_noise_private_key(local_static_private_key)?;
        let mut state = build_noise_handshake_state(true, local_static)?;
        let mut out_buf = vec![0u8; NOISE_HANDSHAKE_MAX_PACKET_SIZE];
        let mut in_buf = vec![0u8; NOISE_HANDSHAKE_MAX_PACKET_SIZE];

        let first_len = state.write_message(&[], &mut out_buf).map_err(|e| {
            StratumError::SecureHandshake(format!("noise initiator write m1 failed: {e}"))
        })?;
        write_noise_handshake_packet(io, &out_buf[..first_len])?;

        let second = read_noise_handshake_packet(io)?;
        state.read_message(&second, &mut in_buf).map_err(|e| {
            StratumError::SecureHandshake(format!("noise initiator read m2 failed: {e}"))
        })?;

        let third_len = state.write_message(&[], &mut out_buf).map_err(|e| {
            StratumError::SecureHandshake(format!("noise initiator write m3 failed: {e}"))
        })?;
        write_noise_handshake_packet(io, &out_buf[..third_len])?;

        if let Some(expected) = expected_remote_static_public_key {
            match state.get_remote_static() {
                Some(remote) if remote == expected => {}
                Some(_) => {
                    return Err(StratumError::SecureHandshake(
                        "noise remote static key mismatch".to_owned(),
                    ));
                }
                None => {
                    return Err(StratumError::SecureHandshake(
                        "noise remote static key missing".to_owned(),
                    ));
                }
            }
        }

        let transport = state.into_transport_mode().map_err(|e| {
            StratumError::SecureHandshake(format!("noise initiator transport upgrade failed: {e}"))
        })?;
        Ok(Self {
            transport,
            rekey_interval_messages: DEFAULT_SECURE_REKEY_INTERVAL_MESSAGES,
            sent_messages: 0,
            received_messages: 0,
        })
    }

    pub async fn handshake_client_async<IO: AsyncRead + AsyncWrite + Unpin>(
        io: &mut IO,
        local_static_private_key: Option<[u8; 32]>,
        expected_remote_static_public_key: Option<[u8; 32]>,
    ) -> Result<Self, StratumError> {
        let local_static = resolve_noise_private_key(local_static_private_key)?;
        let mut state = build_noise_handshake_state(true, local_static)?;
        let mut out_buf = vec![0u8; NOISE_HANDSHAKE_MAX_PACKET_SIZE];
        let mut in_buf = vec![0u8; NOISE_HANDSHAKE_MAX_PACKET_SIZE];

        let first_len = state.write_message(&[], &mut out_buf).map_err(|e| {
            StratumError::SecureHandshake(format!("noise initiator write m1 failed: {e}"))
        })?;
        write_noise_handshake_packet_async(io, &out_buf[..first_len]).await?;

        let second = read_noise_handshake_packet_async(io).await?;
        state.read_message(&second, &mut in_buf).map_err(|e| {
            StratumError::SecureHandshake(format!("noise initiator read m2 failed: {e}"))
        })?;

        let third_len = state.write_message(&[], &mut out_buf).map_err(|e| {
            StratumError::SecureHandshake(format!("noise initiator write m3 failed: {e}"))
        })?;
        write_noise_handshake_packet_async(io, &out_buf[..third_len]).await?;

        if let Some(expected) = expected_remote_static_public_key {
            match state.get_remote_static() {
                Some(remote) if remote == expected => {}
                Some(_) => {
                    return Err(StratumError::SecureHandshake(
                        "noise remote static key mismatch".to_owned(),
                    ));
                }
                None => {
                    return Err(StratumError::SecureHandshake(
                        "noise remote static key missing".to_owned(),
                    ));
                }
            }
        }

        let transport = state.into_transport_mode().map_err(|e| {
            StratumError::SecureHandshake(format!("noise initiator transport upgrade failed: {e}"))
        })?;
        Ok(Self {
            transport,
            rekey_interval_messages: DEFAULT_SECURE_REKEY_INTERVAL_MESSAGES,
            sent_messages: 0,
            received_messages: 0,
        })
    }

    pub fn handshake_server<IO: Read + Write>(
        io: &mut IO,
        local_static_private_key: Option<[u8; 32]>,
        expected_remote_static_public_key: Option<[u8; 32]>,
    ) -> Result<Self, StratumError> {
        let local_static = resolve_noise_private_key(local_static_private_key)?;
        let mut state = build_noise_handshake_state(false, local_static)?;
        let mut out_buf = vec![0u8; NOISE_HANDSHAKE_MAX_PACKET_SIZE];
        let mut in_buf = vec![0u8; NOISE_HANDSHAKE_MAX_PACKET_SIZE];

        let first = read_noise_handshake_packet(io)?;
        state.read_message(&first, &mut in_buf).map_err(|e| {
            StratumError::SecureHandshake(format!("noise responder read m1 failed: {e}"))
        })?;

        let second_len = state.write_message(&[], &mut out_buf).map_err(|e| {
            StratumError::SecureHandshake(format!("noise responder write m2 failed: {e}"))
        })?;
        write_noise_handshake_packet(io, &out_buf[..second_len])?;

        let third = read_noise_handshake_packet(io)?;
        state.read_message(&third, &mut in_buf).map_err(|e| {
            StratumError::SecureHandshake(format!("noise responder read m3 failed: {e}"))
        })?;

        if let Some(expected) = expected_remote_static_public_key {
            match state.get_remote_static() {
                Some(remote) if remote == expected => {}
                Some(_) => {
                    return Err(StratumError::SecureHandshake(
                        "noise remote static key mismatch".to_owned(),
                    ));
                }
                None => {
                    return Err(StratumError::SecureHandshake(
                        "noise remote static key missing".to_owned(),
                    ));
                }
            }
        }

        let transport = state.into_transport_mode().map_err(|e| {
            StratumError::SecureHandshake(format!("noise responder transport upgrade failed: {e}"))
        })?;
        Ok(Self {
            transport,
            rekey_interval_messages: DEFAULT_SECURE_REKEY_INTERVAL_MESSAGES,
            sent_messages: 0,
            received_messages: 0,
        })
    }

    pub async fn handshake_server_async<IO: AsyncRead + AsyncWrite + Unpin>(
        io: &mut IO,
        local_static_private_key: Option<[u8; 32]>,
        expected_remote_static_public_key: Option<[u8; 32]>,
    ) -> Result<Self, StratumError> {
        let local_static = resolve_noise_private_key(local_static_private_key)?;
        let mut state = build_noise_handshake_state(false, local_static)?;
        let mut out_buf = vec![0u8; NOISE_HANDSHAKE_MAX_PACKET_SIZE];
        let mut in_buf = vec![0u8; NOISE_HANDSHAKE_MAX_PACKET_SIZE];

        let first = read_noise_handshake_packet_async(io).await?;
        state.read_message(&first, &mut in_buf).map_err(|e| {
            StratumError::SecureHandshake(format!("noise responder read m1 failed: {e}"))
        })?;

        let second_len = state.write_message(&[], &mut out_buf).map_err(|e| {
            StratumError::SecureHandshake(format!("noise responder write m2 failed: {e}"))
        })?;
        write_noise_handshake_packet_async(io, &out_buf[..second_len]).await?;

        let third = read_noise_handshake_packet_async(io).await?;
        state.read_message(&third, &mut in_buf).map_err(|e| {
            StratumError::SecureHandshake(format!("noise responder read m3 failed: {e}"))
        })?;

        if let Some(expected) = expected_remote_static_public_key {
            match state.get_remote_static() {
                Some(remote) if remote == expected => {}
                Some(_) => {
                    return Err(StratumError::SecureHandshake(
                        "noise remote static key mismatch".to_owned(),
                    ));
                }
                None => {
                    return Err(StratumError::SecureHandshake(
                        "noise remote static key missing".to_owned(),
                    ));
                }
            }
        }

        let transport = state.into_transport_mode().map_err(|e| {
            StratumError::SecureHandshake(format!("noise responder transport upgrade failed: {e}"))
        })?;
        Ok(Self {
            transport,
            rekey_interval_messages: DEFAULT_SECURE_REKEY_INTERVAL_MESSAGES,
            sent_messages: 0,
            received_messages: 0,
        })
    }

    pub fn set_rekey_interval_messages(&mut self, interval: u64) -> Result<(), StratumError> {
        if interval == 0 {
            return Err(StratumError::InvalidConfig(
                "secure rekey interval must be > 0".to_owned(),
            ));
        }
        self.rekey_interval_messages = interval;
        Ok(())
    }

    pub fn write_message<W: Write>(
        &mut self,
        writer: &mut W,
        message: &Sv2Message,
    ) -> Result<(), StratumError> {
        let mut plaintext = Vec::new();
        write_frame(&mut plaintext, message)?;

        let mut ciphertext = vec![0u8; plaintext.len() + 64];
        let encrypted_len = self
            .transport
            .write_message(&plaintext, &mut ciphertext)
            .map_err(|e| StratumError::SecureTransport(format!("noise encrypt failed: {e}")))?;
        ciphertext.truncate(encrypted_len);
        if ciphertext.len() > SECURE_MAX_FRAME_SIZE {
            return Err(StratumError::FrameTooLarge {
                got: ciphertext.len(),
                max: SECURE_MAX_FRAME_SIZE,
            });
        }

        let len = u32::try_from(ciphertext.len()).map_err(|_| StratumError::FrameTooLarge {
            got: ciphertext.len(),
            max: SECURE_MAX_FRAME_SIZE,
        })?;
        writer
            .write_all(&len.to_le_bytes())
            .map_err(StratumError::Io)?;
        writer.write_all(&ciphertext).map_err(StratumError::Io)?;
        writer.flush().map_err(StratumError::Io)?;
        self.sent_messages = self.sent_messages.saturating_add(1);
        self.maybe_rekey_outgoing()
    }

    pub async fn write_message_async<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        message: &Sv2Message,
    ) -> Result<(), StratumError> {
        let mut plaintext = Vec::new();
        write_frame(&mut plaintext, message)?;

        let mut ciphertext = vec![0u8; plaintext.len() + 64];
        let encrypted_len = self
            .transport
            .write_message(&plaintext, &mut ciphertext)
            .map_err(|e| StratumError::SecureTransport(format!("noise encrypt failed: {e}")))?;
        ciphertext.truncate(encrypted_len);
        if ciphertext.len() > SECURE_MAX_FRAME_SIZE {
            return Err(StratumError::FrameTooLarge {
                got: ciphertext.len(),
                max: SECURE_MAX_FRAME_SIZE,
            });
        }

        let len = u32::try_from(ciphertext.len()).map_err(|_| StratumError::FrameTooLarge {
            got: ciphertext.len(),
            max: SECURE_MAX_FRAME_SIZE,
        })?;
        writer
            .write_all(&len.to_le_bytes())
            .await
            .map_err(StratumError::Io)?;
        writer
            .write_all(&ciphertext)
            .await
            .map_err(StratumError::Io)?;
        writer.flush().await.map_err(StratumError::Io)?;
        self.sent_messages = self.sent_messages.saturating_add(1);
        self.maybe_rekey_outgoing()
    }

    pub fn read_message<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Sv2Message>, StratumError> {
        let mut first = [0u8; 1];
        match reader.read(&mut first) {
            Ok(0) => return Ok(None),
            Ok(1) => {}
            Ok(_) => unreachable!(),
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(StratumError::Io(err)),
        }

        let mut rest = [0u8; 3];
        reader.read_exact(&mut rest).map_err(StratumError::Io)?;
        let len = u32::from_le_bytes([first[0], rest[0], rest[1], rest[2]]) as usize;
        if len == 0 {
            return Err(StratumError::InvalidFrameLength(0));
        }
        if len > SECURE_MAX_FRAME_SIZE {
            return Err(StratumError::FrameTooLarge {
                got: len,
                max: SECURE_MAX_FRAME_SIZE,
            });
        }

        let mut ciphertext = vec![0u8; len];
        reader
            .read_exact(&mut ciphertext)
            .map_err(StratumError::Io)?;

        let mut plaintext = vec![0u8; len];
        let decrypted_len = self
            .transport
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|e| StratumError::SecureTransport(format!("noise decrypt failed: {e}")))?;
        plaintext.truncate(decrypted_len);
        self.received_messages = self.received_messages.saturating_add(1);
        self.maybe_rekey_incoming()?;
        decode_single_frame_bytes(&plaintext).map(Some)
    }

    pub async fn read_message_async<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Sv2Message>, StratumError> {
        let len = match read_secure_frame_length_async(reader).await? {
            Some(len) => len,
            None => return Ok(None),
        };

        let mut ciphertext = vec![0u8; len];
        reader
            .read_exact(&mut ciphertext)
            .await
            .map_err(StratumError::Io)?;

        let mut plaintext = vec![0u8; len];
        let decrypted_len = self
            .transport
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|e| StratumError::SecureTransport(format!("noise decrypt failed: {e}")))?;
        plaintext.truncate(decrypted_len);
        self.received_messages = self.received_messages.saturating_add(1);
        self.maybe_rekey_incoming()?;
        decode_single_frame_bytes(&plaintext).map(Some)
    }

    fn maybe_rekey_outgoing(&mut self) -> Result<(), StratumError> {
        if self.sent_messages < self.rekey_interval_messages {
            return Ok(());
        }
        self.transport.rekey_outgoing();
        self.sent_messages = 0;
        Ok(())
    }

    fn maybe_rekey_incoming(&mut self) -> Result<(), StratumError> {
        if self.received_messages < self.rekey_interval_messages {
            return Ok(());
        }
        self.transport.rekey_incoming();
        self.received_messages = 0;
        Ok(())
    }
}

fn parse_noise_params() -> Result<NoiseParams, StratumError> {
    NOISE_PROTOCOL_XX
        .parse()
        .map_err(|e| StratumError::SecureTransport(format!("noise params parse failed: {e}")))
}

fn decode_noise_key_bytes(input: &[u8], label: &str) -> Result<[u8; 32], StratumError> {
    let bytes: [u8; 32] = input.try_into().map_err(|_| {
        StratumError::SecureTransport(format!("noise {label} key must be 32 bytes"))
    })?;
    Ok(bytes)
}

fn resolve_noise_private_key(
    local_static_private_key: Option<[u8; 32]>,
) -> Result<[u8; 32], StratumError> {
    if let Some(private_key) = local_static_private_key {
        return Ok(private_key);
    }
    Err(StratumError::InvalidConfig(
        "noise_xx transport requires local static private key".to_owned(),
    ))
}

fn build_noise_handshake_state(
    initiator: bool,
    local_private_key: [u8; 32],
) -> Result<NoiseHandshakeState, StratumError> {
    let params = parse_noise_params()?;
    let builder = NoiseBuilder::new(params).local_private_key(&local_private_key);
    if initiator {
        builder.build_initiator().map_err(|e| {
            StratumError::SecureHandshake(format!("noise build initiator failed: {e}"))
        })
    } else {
        builder.build_responder().map_err(|e| {
            StratumError::SecureHandshake(format!("noise build responder failed: {e}"))
        })
    }
}

fn write_noise_handshake_packet<IO: Write>(
    io: &mut IO,
    payload: &[u8],
) -> Result<(), StratumError> {
    if payload.is_empty() {
        return Err(StratumError::SecureHandshake(
            "noise handshake payload cannot be empty".to_owned(),
        ));
    }
    if payload.len() > NOISE_HANDSHAKE_MAX_PACKET_SIZE {
        return Err(StratumError::FrameTooLarge {
            got: payload.len(),
            max: NOISE_HANDSHAKE_MAX_PACKET_SIZE,
        });
    }
    let len = u16::try_from(payload.len()).map_err(|_| StratumError::FrameTooLarge {
        got: payload.len(),
        max: NOISE_HANDSHAKE_MAX_PACKET_SIZE,
    })?;
    io.write_all(&len.to_le_bytes()).map_err(StratumError::Io)?;
    io.write_all(payload).map_err(StratumError::Io)?;
    io.flush().map_err(StratumError::Io)?;
    Ok(())
}

async fn write_noise_handshake_packet_async<IO: AsyncWrite + Unpin>(
    io: &mut IO,
    payload: &[u8],
) -> Result<(), StratumError> {
    if payload.is_empty() {
        return Err(StratumError::SecureHandshake(
            "noise handshake payload cannot be empty".to_owned(),
        ));
    }
    if payload.len() > NOISE_HANDSHAKE_MAX_PACKET_SIZE {
        return Err(StratumError::FrameTooLarge {
            got: payload.len(),
            max: NOISE_HANDSHAKE_MAX_PACKET_SIZE,
        });
    }
    let len = u16::try_from(payload.len()).map_err(|_| StratumError::FrameTooLarge {
        got: payload.len(),
        max: NOISE_HANDSHAKE_MAX_PACKET_SIZE,
    })?;
    io.write_all(&len.to_le_bytes())
        .await
        .map_err(StratumError::Io)?;
    io.write_all(payload).await.map_err(StratumError::Io)?;
    io.flush().await.map_err(StratumError::Io)?;
    Ok(())
}

fn read_noise_handshake_packet<IO: Read>(io: &mut IO) -> Result<Vec<u8>, StratumError> {
    let mut len_buf = [0u8; 2];
    io.read_exact(&mut len_buf).map_err(StratumError::Io)?;
    let len = u16::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Err(StratumError::SecureHandshake(
            "noise handshake payload cannot be empty".to_owned(),
        ));
    }
    if len > NOISE_HANDSHAKE_MAX_PACKET_SIZE {
        return Err(StratumError::FrameTooLarge {
            got: len,
            max: NOISE_HANDSHAKE_MAX_PACKET_SIZE,
        });
    }
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).map_err(StratumError::Io)?;
    Ok(payload)
}

async fn read_noise_handshake_packet_async<IO: AsyncRead + Unpin>(
    io: &mut IO,
) -> Result<Vec<u8>, StratumError> {
    let mut len_buf = [0u8; 2];
    io.read_exact(&mut len_buf)
        .await
        .map_err(StratumError::Io)?;
    let len = u16::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Err(StratumError::SecureHandshake(
            "noise handshake payload cannot be empty".to_owned(),
        ));
    }
    if len > NOISE_HANDSHAKE_MAX_PACKET_SIZE {
        return Err(StratumError::FrameTooLarge {
            got: len,
            max: NOISE_HANDSHAKE_MAX_PACKET_SIZE,
        });
    }
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload)
        .await
        .map_err(StratumError::Io)?;
    Ok(payload)
}

async fn read_secure_frame_length_async<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<usize>, StratumError> {
    let mut first = [0u8; 1];
    match reader.read_exact(&mut first).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(StratumError::Io(err)),
    }

    let mut rest = [0u8; 3];
    reader
        .read_exact(&mut rest)
        .await
        .map_err(StratumError::Io)?;
    let len = u32::from_le_bytes([first[0], rest[0], rest[1], rest[2]]) as usize;
    if len == 0 {
        return Err(StratumError::InvalidFrameLength(0));
    }
    if len > SECURE_MAX_FRAME_SIZE {
        return Err(StratumError::FrameTooLarge {
            got: len,
            max: SECURE_MAX_FRAME_SIZE,
        });
    }
    Ok(Some(len))
}

fn encode_secure_handshake_packet(pubkey: &PublicKey) -> [u8; SECURE_HANDSHAKE_SIZE] {
    let mut packet = [0u8; SECURE_HANDSHAKE_SIZE];
    packet[..8].copy_from_slice(SECURE_HANDSHAKE_MAGIC);
    packet[8..].copy_from_slice(&pubkey.serialize());
    packet
}

fn decode_secure_handshake_packet(
    packet: &[u8; SECURE_HANDSHAKE_SIZE],
) -> Result<PublicKey, StratumError> {
    if &packet[..8] != SECURE_HANDSHAKE_MAGIC {
        return Err(StratumError::SecureHandshake(
            "invalid secure transport magic".to_owned(),
        ));
    }
    PublicKey::from_slice(&packet[8..])
        .map_err(|e| StratumError::SecureHandshake(format!("invalid handshake pubkey: {e}")))
}

fn next_nonce(counter: &mut u64) -> Result<[u8; 12], StratumError> {
    let current = *counter;
    *counter = counter
        .checked_add(1)
        .ok_or_else(|| StratumError::SecureTransport("secure nonce overflow".to_owned()))?;
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&current.to_le_bytes());
    Ok(nonce)
}

fn derive_rekey_key(current_key: [u8; 32], epoch: u64) -> [u8; 32] {
    let mut material = [0u8; 32 + 8];
    material[..32].copy_from_slice(&current_key);
    material[32..40].copy_from_slice(&epoch.to_le_bytes());
    blake3::derive_key(SECURE_KEY_CONTEXT_REKEY, &material)
}

fn decode_single_frame_bytes(buf: &[u8]) -> Result<Sv2Message, StratumError> {
    let mut cursor = std::io::Cursor::new(buf);
    let message = read_frame(&mut cursor)?
        .ok_or_else(|| StratumError::SecureTransport("empty decrypted frame".to_owned()))?;
    if cursor.position() as usize != buf.len() {
        return Err(StratumError::SecureTransport(
            "trailing data in decrypted frame".to_owned(),
        ));
    }
    Ok(message)
}

pub fn write_frame<W: Write>(writer: &mut W, message: &Sv2Message) -> Result<(), StratumError> {
    let payload = bincode::serialize(message).map_err(StratumError::Codec)?;
    if payload.is_empty() {
        return Err(StratumError::InvalidFrameLength(0));
    }
    if payload.len() > MAX_FRAME_SIZE {
        return Err(StratumError::FrameTooLarge {
            got: payload.len(),
            max: MAX_FRAME_SIZE,
        });
    }
    if payload.len() > U24_MAX {
        return Err(StratumError::FrameTooLarge {
            got: payload.len(),
            max: U24_MAX,
        });
    }

    writer
        .write_all(&SV2_EXTENSION_MINING.to_le_bytes())
        .map_err(StratumError::Io)?;
    writer
        .write_all(&[message_type(message)])
        .map_err(StratumError::Io)?;

    let len = payload.len() as u32;
    let len_buf = [
        (len & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        ((len >> 16) & 0xff) as u8,
    ];
    writer.write_all(&len_buf).map_err(StratumError::Io)?;
    writer.write_all(&payload).map_err(StratumError::Io)?;
    writer.flush().map_err(StratumError::Io)
}

pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Sv2Message>, StratumError> {
    let mut first = [0u8; 1];
    match reader.read(&mut first) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!(),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(StratumError::Io(err)),
    }

    let mut rest = [0u8; SV2_HEADER_LEN - 1];
    reader.read_exact(&mut rest).map_err(StratumError::Io)?;

    let extension = u16::from_le_bytes([first[0], rest[0]]);
    if extension != SV2_EXTENSION_MINING {
        return Err(StratumError::UnsupportedExtension(extension));
    }

    let msg_type = rest[1];
    if !is_known_message_type(msg_type) {
        return Err(StratumError::UnsupportedMessageType(msg_type));
    }

    let len = (rest[2] as usize) | ((rest[3] as usize) << 8) | ((rest[4] as usize) << 16);
    if len == 0 {
        return Err(StratumError::InvalidFrameLength(0));
    }
    if len > MAX_FRAME_SIZE {
        return Err(StratumError::FrameTooLarge {
            got: len,
            max: MAX_FRAME_SIZE,
        });
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).map_err(StratumError::Io)?;
    let message: Sv2Message = bincode::deserialize(&payload).map_err(StratumError::Codec)?;

    let payload_type = message_type(&message);
    if payload_type != msg_type {
        return Err(StratumError::MessageTypeMismatch {
            header_type: msg_type,
            payload_type,
        });
    }

    Ok(Some(message))
}

pub async fn write_frame_async<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &Sv2Message,
) -> Result<(), StratumError> {
    let payload = bincode::serialize(message).map_err(StratumError::Codec)?;
    if payload.is_empty() {
        return Err(StratumError::InvalidFrameLength(0));
    }
    if payload.len() > MAX_FRAME_SIZE {
        return Err(StratumError::FrameTooLarge {
            got: payload.len(),
            max: MAX_FRAME_SIZE,
        });
    }
    if payload.len() > U24_MAX {
        return Err(StratumError::FrameTooLarge {
            got: payload.len(),
            max: U24_MAX,
        });
    }

    writer
        .write_all(&SV2_EXTENSION_MINING.to_le_bytes())
        .await
        .map_err(StratumError::Io)?;
    writer
        .write_all(&[message_type(message)])
        .await
        .map_err(StratumError::Io)?;

    let len = payload.len() as u32;
    let len_buf = [
        (len & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        ((len >> 16) & 0xff) as u8,
    ];
    writer.write_all(&len_buf).await.map_err(StratumError::Io)?;
    writer.write_all(&payload).await.map_err(StratumError::Io)?;
    writer.flush().await.map_err(StratumError::Io)
}

pub async fn read_frame_async<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Sv2Message>, StratumError> {
    let mut first = [0u8; 1];
    match reader.read_exact(&mut first).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(StratumError::Io(err)),
    }

    let mut rest = [0u8; SV2_HEADER_LEN - 1];
    reader
        .read_exact(&mut rest)
        .await
        .map_err(StratumError::Io)?;

    let extension = u16::from_le_bytes([first[0], rest[0]]);
    if extension != SV2_EXTENSION_MINING {
        return Err(StratumError::UnsupportedExtension(extension));
    }

    let msg_type = rest[1];
    if !is_known_message_type(msg_type) {
        return Err(StratumError::UnsupportedMessageType(msg_type));
    }

    let len = (rest[2] as usize) | ((rest[3] as usize) << 8) | ((rest[4] as usize) << 16);
    if len == 0 {
        return Err(StratumError::InvalidFrameLength(0));
    }
    if len > MAX_FRAME_SIZE {
        return Err(StratumError::FrameTooLarge {
            got: len,
            max: MAX_FRAME_SIZE,
        });
    }

    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(StratumError::Io)?;
    let message: Sv2Message = bincode::deserialize(&payload).map_err(StratumError::Codec)?;

    let payload_type = message_type(&message);
    if payload_type != msg_type {
        return Err(StratumError::MessageTypeMismatch {
            header_type: msg_type,
            payload_type,
        });
    }

    Ok(Some(message))
}

pub fn validate_share(
    job: &MiningJob,
    submission: ShareSubmission,
    share_target: Target,
) -> Result<ShareValidation, StratumError> {
    if submission.channel_id != job.channel_id || submission.job_id != job.job_id {
        return Err(StratumError::UnknownJob {
            channel_id: submission.channel_id,
            job_id: submission.job_id,
        });
    }

    let header = BlockHeader {
        version: job.version,
        prev_block: job.prev_hash,
        merkle_root: job.merkle_root,
        timestamp: submission.ntime,
        target: job.network_target,
        nonce: submission.nonce,
    };
    let hash = header.block_hash();
    if !share_target.allows_hash(&hash) {
        return Err(StratumError::LowDifficultyShare { hash, share_target });
    }

    Ok(ShareValidation::AcceptedShare {
        header_hash: hash,
        is_block: job.network_target.allows_hash(&hash),
    })
}

fn message_type(message: &Sv2Message) -> u8 {
    match message {
        Sv2Message::SetupConnection { .. } => MSG_SETUP_CONNECTION,
        Sv2Message::SetupConnectionSuccess { .. } => MSG_SETUP_CONNECTION_SUCCESS,
        Sv2Message::SetupConnectionError { .. } => MSG_SETUP_CONNECTION_ERROR,
        Sv2Message::OpenStandardMiningChannel { .. } => MSG_OPEN_STANDARD_MINING_CHANNEL,
        Sv2Message::OpenStandardMiningChannelSuccess { .. } => {
            MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS
        }
        Sv2Message::OpenStandardMiningChannelError { .. } => MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR,
        Sv2Message::NewMiningJob { .. } => MSG_NEW_MINING_JOB,
        Sv2Message::SetNewPrevHash { .. } => MSG_SET_NEW_PREV_HASH,
        Sv2Message::SetTarget { .. } => MSG_SET_TARGET,
        Sv2Message::SubmitSharesStandard { .. } => MSG_SUBMIT_SHARES_STANDARD,
        Sv2Message::SubmitSharesSuccess { .. } => MSG_SUBMIT_SHARES_SUCCESS,
        Sv2Message::SubmitSharesError { .. } => MSG_SUBMIT_SHARES_ERROR,
        Sv2Message::KeepAlive => MSG_KEEP_ALIVE,
    }
}

fn is_known_message_type(msg_type: u8) -> bool {
    matches!(
        msg_type,
        MSG_SETUP_CONNECTION
            | MSG_SETUP_CONNECTION_SUCCESS
            | MSG_SETUP_CONNECTION_ERROR
            | MSG_OPEN_STANDARD_MINING_CHANNEL
            | MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS
            | MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR
            | MSG_NEW_MINING_JOB
            | MSG_SET_NEW_PREV_HASH
            | MSG_SET_TARGET
            | MSG_SUBMIT_SHARES_STANDARD
            | MSG_SUBMIT_SHARES_SUCCESS
            | MSG_SUBMIT_SHARES_ERROR
            | MSG_KEEP_ALIVE
    )
}

fn scale_target(target: Target, factor: f64) -> Result<Target, StratumError> {
    if !factor.is_finite() || factor <= 0.0 {
        return Err(StratumError::InvalidVarDiff(format!(
            "invalid vardiff factor: {factor}"
        )));
    }

    let scale = 1_000_000u64;
    let scaled_factor = (factor * (scale as f64)).round().max(1.0) as u64;

    let base = BigUint::from_bytes_be(&target.0);
    let mut next = (base * BigUint::from(scaled_factor)) / BigUint::from(scale);
    if next.is_zero() {
        next = BigUint::one();
    }

    biguint_to_target_clamped(next)
}

fn biguint_to_target_clamped(value: BigUint) -> Result<Target, StratumError> {
    let mut bytes = value.to_bytes_be();
    if bytes.is_empty() {
        bytes.push(0u8);
    }

    if bytes.len() > 32 {
        return Ok(Target::MAX);
    }

    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    if out == [0u8; 32] {
        return Err(StratumError::TargetOverflow);
    }
    Ok(Target(out))
}

#[derive(Debug, Error)]
pub enum StratumError {
    #[error("stratum io error: {0}")]
    Io(#[source] std::io::Error),
    #[error("binary codec error: {0}")]
    Codec(#[source] Box<bincode::ErrorKind>),
    #[error("invalid stratum config: {0}")]
    InvalidConfig(String),
    #[error("invalid vardiff state: {0}")]
    InvalidVarDiff(String),
    #[error("invalid frame length {0}")]
    InvalidFrameLength(usize),
    #[error("frame too large: got={got}, max={max}")]
    FrameTooLarge { got: usize, max: usize },
    #[error("unsupported extension type {0}")]
    UnsupportedExtension(u16),
    #[error("unsupported message type {0}")]
    UnsupportedMessageType(u8),
    #[error("frame type mismatch: header={header_type}, payload={payload_type}")]
    MessageTypeMismatch { header_type: u8, payload_type: u8 },
    #[error("channel mismatch: expected={expected}, got={got}")]
    ChannelMismatch { expected: u32, got: u32 },
    #[error("unknown share job channel={channel_id} job={job_id}")]
    UnknownJob { channel_id: u32, job_id: u32 },
    #[error("share hash {hash} does not meet share target {share_target}")]
    LowDifficultyShare { hash: Hash256, share_target: Target },
    #[error("target overflows valid 256-bit range")]
    TargetOverflow,
    #[error("invalid message field: {0}")]
    InvalidMessage(String),
    #[error("protocol state violation: {0}")]
    ProtocolState(String),
    #[error("secure handshake failed: {0}")]
    SecureHandshake(String),
    #[error("secure transport failure: {0}")]
    SecureTransport(String),
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::Cursor;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;
    #[cfg(unix)]
    use std::thread;
    use std::time::Duration;

    use num_bigint::BigUint;
    use scam_core::{Hash256, Target};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::runtime::Runtime;

    use crate::{
        IdentityTranslator, JobDeclarator, MiningJob, MiningTemplate, NoiseSv2Transport,
        SUPPORTED_SV2_VERSION, SecureRole, SecureSv2Transport, SecureTransportMode,
        SequentialJobDeclarator, SessionConfig, SessionEvent, ShareSubmission, ShareValidation,
        StratumError, Sv2Message, Sv2Session, Translator, decode_secure_handshake_packet,
        decode_single_frame_bytes, read_frame, read_frame_async, validate_share, write_frame,
        write_frame_async,
    };

    fn test_session_config() -> SessionConfig {
        SessionConfig {
            channel_id: 7,
            share_target: Target::MAX,
            min_share_target: Target::from_hex(
                "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )
            .expect("min target"),
            max_share_target: Target::MAX,
            max_jobs: 8,
            supported_version: SUPPORTED_SV2_VERSION,
            vardiff_target_shares_per_minute: 6,
            vardiff_retarget_interval_shares: 3,
            vardiff_clamp_up: 4.0,
            vardiff_clamp_down: 0.25,
            max_rejected_shares: 3,
        }
    }

    fn activate_session(mut cfg: SessionConfig) -> Sv2Session {
        cfg.max_jobs = cfg.max_jobs.max(1);
        let mut session = Sv2Session::new(cfg).expect("session");
        session
            .handle_message(Sv2Message::SetupConnection {
                protocol: 2,
                min_version: 2,
                max_version: 2,
                flags: 0,
                user_agent: "test-miner".to_owned(),
            })
            .expect("setup");
        session
            .handle_message(Sv2Message::OpenStandardMiningChannel {
                request_id: 1,
                user: "alice".to_owned(),
            })
            .expect("open");
        session
    }

    fn keepalive_frame_bytes() -> Vec<u8> {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Sv2Message::KeepAlive).expect("encode keepalive");
        buf
    }

    #[cfg(unix)]
    fn apply_test_socket_timeouts(stream: &UnixStream) -> bool {
        let timeout = Some(Duration::from_millis(250));
        if let Err(err) = stream.set_read_timeout(timeout) {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                return false;
            }
            panic!("set_read_timeout failed: {err}");
        }
        if let Err(err) = stream.set_write_timeout(timeout) {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                return false;
            }
            panic!("set_write_timeout failed: {err}");
        }
        true
    }

    #[test]
    fn frame_roundtrip() {
        let message = Sv2Message::SetupConnection {
            protocol: 2,
            min_version: 2,
            max_version: 2,
            flags: 0,
            user_agent: "scam-miner/0.1".to_owned(),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &message).expect("encode frame");

        let mut cursor = Cursor::new(buf);
        let decoded = read_frame(&mut cursor)
            .expect("decode")
            .expect("some frame");
        assert_eq!(decoded, message);
    }

    #[test]
    fn secure_transport_mode_string_roundtrip() {
        assert_eq!(SecureTransportMode::Legacy.as_str(), "legacy");
        assert_eq!(SecureTransportMode::NoiseXx.as_str(), "noise_xx");
        assert_eq!(
            "legacy"
                .parse::<SecureTransportMode>()
                .expect("legacy mode"),
            SecureTransportMode::Legacy
        );
        assert_eq!(
            "noise_xx"
                .parse::<SecureTransportMode>()
                .expect("noise mode"),
            SecureTransportMode::NoiseXx
        );
        assert!("unknown".parse::<SecureTransportMode>().is_err());
    }

    #[test]
    fn session_accessors_and_close_path_work() {
        let mut session = Sv2Session::new(test_session_config()).expect("session");
        assert_eq!(session.channel_id(), 7);
        assert!(!session.is_active());
        assert_eq!(session.stats().accepted_shares, 0);

        session = activate_session(test_session_config());
        assert!(session.is_active());
        session.close();
        assert!(!session.is_active());
        let err = session
            .handle_message(Sv2Message::KeepAlive)
            .expect_err("closed session must reject messages");
        assert!(matches!(err, StratumError::ProtocolState(_)));
    }

    #[test]
    fn read_frame_rejects_invalid_extension() {
        let mut frame = keepalive_frame_bytes();
        frame[0] = 1;
        frame[1] = 0;
        let err = read_frame(&mut Cursor::new(frame)).expect_err("must reject extension");
        assert!(matches!(err, crate::StratumError::UnsupportedExtension(_)));
    }

    #[test]
    fn read_frame_rejects_unknown_message_type() {
        let mut frame = keepalive_frame_bytes();
        frame[2] = 0xff;
        let err = read_frame(&mut Cursor::new(frame)).expect_err("must reject unknown type");
        assert!(matches!(
            err,
            crate::StratumError::UnsupportedMessageType(0xff)
        ));
    }

    #[test]
    fn read_frame_rejects_zero_and_oversized_lengths() {
        let mut zero_len = keepalive_frame_bytes();
        zero_len.truncate(crate::SV2_HEADER_LEN);
        zero_len[3] = 0;
        zero_len[4] = 0;
        zero_len[5] = 0;
        let err = read_frame(&mut Cursor::new(zero_len)).expect_err("must reject zero len");
        assert!(matches!(err, crate::StratumError::InvalidFrameLength(0)));

        let mut oversized = keepalive_frame_bytes();
        oversized.truncate(crate::SV2_HEADER_LEN);
        let len = (crate::MAX_FRAME_SIZE + 1) as u32;
        oversized[3] = (len & 0xff) as u8;
        oversized[4] = ((len >> 8) & 0xff) as u8;
        oversized[5] = ((len >> 16) & 0xff) as u8;
        let err = read_frame(&mut Cursor::new(oversized)).expect_err("must reject oversized");
        assert!(matches!(err, crate::StratumError::FrameTooLarge { .. }));
    }

    #[test]
    fn read_frame_rejects_type_mismatch_and_trailing_payload() {
        let mut mismatch = keepalive_frame_bytes();
        let header_type = crate::message_type(&Sv2Message::SetupConnection {
            protocol: 2,
            min_version: 2,
            max_version: 2,
            flags: 0,
            user_agent: "x".to_owned(),
        });
        mismatch[2] = header_type;
        let err = read_frame(&mut Cursor::new(mismatch)).expect_err("must reject type mismatch");
        assert!(matches!(
            err,
            crate::StratumError::MessageTypeMismatch {
                header_type: _,
                payload_type: _
            }
        ));

        let mut framed = keepalive_frame_bytes();
        framed.push(0xff);
        let err = decode_single_frame_bytes(&framed).expect_err("must reject trailing payload");
        assert!(matches!(err, crate::StratumError::SecureTransport(_)));
    }

    #[test]
    fn frame_roundtrip_with_large_payload_exercises_u24_len_encoding() {
        let message = Sv2Message::SetupConnection {
            protocol: 2,
            min_version: 2,
            max_version: 2,
            flags: 0,
            user_agent: "x".repeat(70_000),
        };
        let payload_len = bincode::serialize(&message).expect("serialize").len();
        assert!(payload_len > 0xffff);

        let mut buf = Vec::new();
        write_frame(&mut buf, &message).expect("encode frame");
        let len = u32::from_le_bytes([buf[3], buf[4], buf[5], 0]) as usize;
        assert_eq!(len, payload_len);

        let decoded = read_frame(&mut Cursor::new(buf))
            .expect("decode")
            .expect("frame");
        assert_eq!(decoded, message);
    }

    #[test]
    fn session_state_machine_happy_path() {
        let mut session = Sv2Session::new(test_session_config()).expect("session");

        let setup = session
            .handle_message(Sv2Message::SetupConnection {
                protocol: 2,
                min_version: 2,
                max_version: 2,
                flags: 0,
                user_agent: "miner/1".to_owned(),
            })
            .expect("setup handled");
        assert!(matches!(
            setup.outbound.as_slice(),
            [Sv2Message::SetupConnectionSuccess { .. }]
        ));

        let open = session
            .handle_message(Sv2Message::OpenStandardMiningChannel {
                request_id: 11,
                user: "alice".to_owned(),
            })
            .expect("open handled");
        assert!(matches!(
            open.events.as_slice(),
            [SessionEvent::ChannelOpened { channel_id: 7, .. }]
        ));

        let job = MiningJob {
            channel_id: 7,
            job_id: 1,
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            ntime: 1_770_763_200,
            network_target: Target::MAX,
        };
        session.install_job(job).expect("install job");

        let submit = session
            .handle_message_at(
                Sv2Message::SubmitSharesStandard {
                    channel_id: 7,
                    job_id: 1,
                    nonce: 0,
                    ntime: 1_770_763_200,
                },
                1_770_763_200,
            )
            .expect("submit handled");
        assert!(matches!(
            submit.events.as_slice(),
            [SessionEvent::ShareAccepted { is_block: true, .. }]
        ));
    }

    #[test]
    fn install_job_evicts_oldest_entry_and_preserves_cache_invariants() {
        let mut cfg = test_session_config();
        cfg.max_jobs = 2;
        let mut session = activate_session(cfg);

        let mk_job = |job_id: u32| MiningJob {
            channel_id: 7,
            job_id,
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            ntime: 1_770_763_200 + job_id as u64,
            network_target: Target::MAX,
        };

        session.install_job(mk_job(1)).expect("job 1");
        session.install_job(mk_job(2)).expect("job 2");
        session.install_job(mk_job(3)).expect("job 3");

        assert!(session.job(1).is_none());
        assert!(session.job(2).is_some());
        assert!(session.job(3).is_some());
        assert_eq!(session.jobs.len(), 2);
        assert_eq!(session.job_order, VecDeque::from(vec![2, 3]));
    }

    #[test]
    fn install_job_replacing_same_id_keeps_single_queue_entry() {
        let mut cfg = test_session_config();
        cfg.max_jobs = 4;
        let mut session = activate_session(cfg);

        let first = MiningJob {
            channel_id: 7,
            job_id: 42,
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            ntime: 1_770_763_200,
            network_target: Target::MAX,
        };
        let mut second = first.clone();
        second.version = 2;
        second.ntime = first.ntime + 1;

        session.install_job(first).expect("install first");
        session.install_job(second.clone()).expect("replace");

        assert_eq!(session.jobs.len(), 1);
        assert_eq!(session.job_order, VecDeque::from(vec![42]));
        assert_eq!(session.job(42).expect("job"), &second);
    }

    #[test]
    fn set_new_prev_hash_rejects_channel_mismatch() {
        let session = activate_session(test_session_config());
        let job = MiningJob {
            channel_id: 99,
            job_id: 1,
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            ntime: 1_770_763_200,
            network_target: Target::MAX,
        };
        let err = session
            .set_new_prev_hash(&job)
            .expect_err("must reject channel mismatch");
        assert!(matches!(
            err,
            StratumError::ChannelMismatch {
                expected: 7,
                got: 99
            }
        ));
    }

    #[test]
    fn session_rejects_unknown_job() {
        let mut session = Sv2Session::new(test_session_config()).expect("session");
        session
            .handle_message(Sv2Message::SetupConnection {
                protocol: 2,
                min_version: 2,
                max_version: 2,
                flags: 0,
                user_agent: "miner/1".to_owned(),
            })
            .expect("setup");
        session
            .handle_message(Sv2Message::OpenStandardMiningChannel {
                request_id: 1,
                user: "user".to_owned(),
            })
            .expect("open");

        let submit = session
            .handle_message(Sv2Message::SubmitSharesStandard {
                channel_id: 7,
                job_id: 999,
                nonce: 0,
                ntime: 1_770_763_200,
            })
            .expect("submit handled");
        assert!(matches!(
            submit.outbound.as_slice(),
            [Sv2Message::SubmitSharesError { code, .. }] if code == "unknown_job"
        ));
    }

    #[test]
    fn session_closes_after_reject_budget_is_exhausted() {
        let mut cfg = test_session_config();
        cfg.max_rejected_shares = 2;
        let mut session = Sv2Session::new(cfg).expect("session");
        session
            .handle_message(Sv2Message::SetupConnection {
                protocol: 2,
                min_version: 2,
                max_version: 2,
                flags: 0,
                user_agent: "miner/1".to_owned(),
            })
            .expect("setup");
        session
            .handle_message(Sv2Message::OpenStandardMiningChannel {
                request_id: 1,
                user: "user".to_owned(),
            })
            .expect("open");

        session
            .handle_message(Sv2Message::SubmitSharesStandard {
                channel_id: 7,
                job_id: 101,
                nonce: 0,
                ntime: 1,
            })
            .expect("first reject");

        let second = session
            .handle_message(Sv2Message::SubmitSharesStandard {
                channel_id: 7,
                job_id: 102,
                nonce: 0,
                ntime: 2,
            })
            .expect("second reject");
        assert!(
            second
                .events
                .iter()
                .any(|event| matches!(event, SessionEvent::ChannelClosed { .. }))
        );
        assert!(!session.is_active());
    }

    #[test]
    fn vardiff_reduces_target_when_shares_are_too_fast() {
        let mut session = Sv2Session::new(test_session_config()).expect("session");
        let initial = session.share_target();

        let _ = session.record_share_timestamp(1_000).expect("record 1");
        let _ = session.record_share_timestamp(1_001).expect("record 2");
        let _ = session.record_share_timestamp(1_002).expect("record 3");
        let updated = session.record_share_timestamp(1_003).expect("record 4");

        assert!(updated.is_some());
        assert!(session.share_target() < initial);
    }

    #[test]
    fn vardiff_respects_clamp_up_boundary() {
        let mut cfg = test_session_config();
        cfg.share_target =
            Target::from_hex("20ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target");
        cfg.max_share_target =
            Target::from_hex("40ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target");
        let mut session = Sv2Session::new(cfg).expect("session");

        let _ = session.record_share_timestamp(1_000).expect("record 1");
        let _ = session.record_share_timestamp(2_000).expect("record 2");
        let _ = session.record_share_timestamp(3_000).expect("record 3");
        let updated = session.record_share_timestamp(4_000).expect("record 4");

        let expected = super::scale_target(cfg.share_target, cfg.vardiff_clamp_up)
            .expect("scaled")
            .clamp(cfg.min_share_target, cfg.max_share_target);
        assert_eq!(updated, Some(expected));
        assert_eq!(session.share_target(), expected);
    }

    #[test]
    fn vardiff_respects_clamp_down_boundary() {
        let mut cfg = test_session_config();
        cfg.share_target =
            Target::from_hex("40ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target");
        cfg.min_share_target =
            Target::from_hex("10ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("target");
        let mut session = Sv2Session::new(cfg).expect("session");

        let _ = session.record_share_timestamp(1_000).expect("record 1");
        let _ = session.record_share_timestamp(1_001).expect("record 2");
        let _ = session.record_share_timestamp(1_002).expect("record 3");
        let updated = session.record_share_timestamp(1_003).expect("record 4");

        let expected = super::scale_target(cfg.share_target, cfg.vardiff_clamp_down)
            .expect("scaled")
            .clamp(cfg.min_share_target, cfg.max_share_target);
        assert_eq!(updated, Some(expected));
        assert_eq!(session.share_target(), expected);
    }

    #[test]
    fn share_validation_accepts_max_target_job() {
        let job = MiningJob {
            channel_id: 1,
            job_id: 42,
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            ntime: 1_770_763_200,
            network_target: Target::MAX,
        };
        let result = validate_share(
            &job,
            ShareSubmission {
                channel_id: 1,
                job_id: 42,
                nonce: 0,
                ntime: 1_770_763_200,
            },
            Target::MAX,
        )
        .expect("share accepted");
        assert!(matches!(
            result,
            ShareValidation::AcceptedShare { is_block: true, .. }
        ));
    }

    #[test]
    fn validate_share_rejects_channel_or_job_mismatch() {
        let job = MiningJob {
            channel_id: 1,
            job_id: 42,
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            ntime: 1_770_763_200,
            network_target: Target::MAX,
        };
        let wrong_channel = validate_share(
            &job,
            ShareSubmission {
                channel_id: 2,
                job_id: 42,
                nonce: 0,
                ntime: 1_770_763_200,
            },
            Target::MAX,
        )
        .expect_err("wrong channel");
        assert!(matches!(
            wrong_channel,
            StratumError::UnknownJob {
                channel_id: 2,
                job_id: 42
            }
        ));

        let wrong_job = validate_share(
            &job,
            ShareSubmission {
                channel_id: 1,
                job_id: 43,
                nonce: 0,
                ntime: 1_770_763_200,
            },
            Target::MAX,
        )
        .expect_err("wrong job id");
        assert!(matches!(
            wrong_job,
            StratumError::UnknownJob {
                channel_id: 1,
                job_id: 43
            }
        ));
    }

    #[test]
    fn secure_transport_handshake_and_encrypted_roundtrip() {
        let secp = Secp256k1::new();
        let client_sk = SecretKey::from_slice(&[1u8; 32]).expect("client sk");
        let server_sk = SecretKey::from_slice(&[2u8; 32]).expect("server sk");
        let client_pk = PublicKey::from_secret_key(&secp, &client_sk);
        let server_pk = PublicKey::from_secret_key(&secp, &server_sk);

        let mut client =
            SecureSv2Transport::from_handshake(client_sk, client_pk, server_pk, SecureRole::Client);
        let mut server =
            SecureSv2Transport::from_handshake(server_sk, server_pk, client_pk, SecureRole::Server);

        let setup = Sv2Message::SetupConnection {
            protocol: 2,
            min_version: SUPPORTED_SV2_VERSION,
            max_version: SUPPORTED_SV2_VERSION,
            flags: 0,
            user_agent: "test".to_owned(),
        };
        let mut c2s = Vec::new();
        client.write_message(&mut c2s, &setup).expect("encrypt c2s");
        let decoded_setup = server
            .read_message(&mut Cursor::new(c2s))
            .expect("decrypt c2s")
            .expect("message");
        assert_eq!(decoded_setup, setup);

        let mut s2c = Vec::new();
        server
            .write_message(&mut s2c, &Sv2Message::KeepAlive)
            .expect("encrypt s2c");
        let decoded_keepalive = client
            .read_message(&mut Cursor::new(s2c))
            .expect("decrypt s2c")
            .expect("message");
        assert_eq!(decoded_keepalive, Sv2Message::KeepAlive);
    }

    #[test]
    fn secure_transport_rejects_zero_rekey_interval() {
        let secp = Secp256k1::new();
        let client_sk = SecretKey::from_slice(&[13u8; 32]).expect("client sk");
        let server_sk = SecretKey::from_slice(&[14u8; 32]).expect("server sk");
        let client_pk = PublicKey::from_secret_key(&secp, &client_sk);
        let server_pk = PublicKey::from_secret_key(&secp, &server_sk);

        let mut client =
            SecureSv2Transport::from_handshake(client_sk, client_pk, server_pk, SecureRole::Client);
        let _server =
            SecureSv2Transport::from_handshake(server_sk, server_pk, client_pk, SecureRole::Server);
        let err = client
            .set_rekey_interval_messages(0)
            .expect_err("interval=0 must be rejected");
        assert!(matches!(err, StratumError::InvalidConfig(_)));
    }

    #[test]
    fn secure_transport_read_message_returns_none_on_clean_eof() {
        let secp = Secp256k1::new();
        let client_sk = SecretKey::from_slice(&[15u8; 32]).expect("client sk");
        let server_sk = SecretKey::from_slice(&[16u8; 32]).expect("server sk");
        let client_pk = PublicKey::from_secret_key(&secp, &client_sk);
        let server_pk = PublicKey::from_secret_key(&secp, &server_sk);
        let mut client =
            SecureSv2Transport::from_handshake(client_sk, client_pk, server_pk, SecureRole::Client);
        let _server =
            SecureSv2Transport::from_handshake(server_sk, server_pk, client_pk, SecureRole::Server);

        let result = client
            .read_message(&mut Cursor::new(Vec::<u8>::new()))
            .expect("eof should map to None");
        assert!(result.is_none());
    }

    #[test]
    fn secure_transport_rejects_invalid_handshake_magic() {
        let mut invalid = [0u8; crate::SECURE_HANDSHAKE_SIZE];
        invalid[..8].copy_from_slice(b"BADMAGIC");
        let err = decode_secure_handshake_packet(&invalid).expect_err("must fail");
        assert!(err.to_string().contains("secure handshake failed"));
    }

    #[test]
    fn secure_transport_rekeys_after_interval() {
        let secp = Secp256k1::new();
        let client_sk = SecretKey::from_slice(&[3u8; 32]).expect("client sk");
        let server_sk = SecretKey::from_slice(&[4u8; 32]).expect("server sk");
        let client_pk = PublicKey::from_secret_key(&secp, &client_sk);
        let server_pk = PublicKey::from_secret_key(&secp, &server_sk);

        let mut client =
            SecureSv2Transport::from_handshake(client_sk, client_pk, server_pk, SecureRole::Client);
        let mut server =
            SecureSv2Transport::from_handshake(server_sk, server_pk, client_pk, SecureRole::Server);
        client.set_rekey_interval_messages(2).expect("client cfg");
        server.set_rekey_interval_messages(2).expect("server cfg");

        for _ in 0..6 {
            let mut wire = Vec::new();
            client
                .write_message(&mut wire, &Sv2Message::KeepAlive)
                .expect("encrypt");
            let decoded = server
                .read_message(&mut Cursor::new(wire))
                .expect("decrypt")
                .expect("msg");
            assert_eq!(decoded, Sv2Message::KeepAlive);
        }
    }

    #[cfg(unix)]
    #[test]
    fn noise_transport_handshake_and_encrypted_roundtrip() {
        let client_private = [1u8; 32];
        let server_private = [2u8; 32];
        let (mut client_io, mut server_io) = UnixStream::pair().expect("unix pair");
        if !apply_test_socket_timeouts(&client_io) || !apply_test_socket_timeouts(&server_io) {
            return;
        }

        let server = thread::spawn(move || -> Result<(), crate::StratumError> {
            let mut server =
                NoiseSv2Transport::handshake_server(&mut server_io, Some(server_private), None)?;
            let setup = server
                .read_message(&mut server_io)?
                .expect("server should receive setup");
            match setup {
                Sv2Message::SetupConnection { .. } => {}
                other => panic!("unexpected setup message: {other:?}"),
            }
            server.write_message(&mut server_io, &Sv2Message::KeepAlive)?;
            Ok(())
        });

        let mut client =
            match NoiseSv2Transport::handshake_client(&mut client_io, Some(client_private), None) {
                Ok(client) => client,
                Err(crate::StratumError::Io(err))
                    if err.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    let _ = server.join();
                    return;
                }
                Err(other) => panic!("client handshake: {other}"),
            };
        client
            .write_message(
                &mut client_io,
                &Sv2Message::SetupConnection {
                    protocol: 2,
                    min_version: SUPPORTED_SV2_VERSION,
                    max_version: SUPPORTED_SV2_VERSION,
                    flags: 0,
                    user_agent: "noise-test".to_owned(),
                },
            )
            .expect("client write");
        let keepalive = client
            .read_message(&mut client_io)
            .expect("client read")
            .expect("keepalive");
        assert_eq!(keepalive, Sv2Message::KeepAlive);
        server.join().expect("server thread").expect("server ok");
    }

    #[cfg(unix)]
    #[test]
    fn noise_transport_expected_remote_key_mismatch_is_rejected() {
        let client_private = [11u8; 32];
        let server_private = [12u8; 32];
        let expected_wrong_remote = [9u8; 32];
        let (mut client_io, mut server_io) = UnixStream::pair().expect("unix pair");
        if !apply_test_socket_timeouts(&client_io) || !apply_test_socket_timeouts(&server_io) {
            return;
        }

        let server = thread::spawn(move || -> Result<(), crate::StratumError> {
            let _ =
                NoiseSv2Transport::handshake_server(&mut server_io, Some(server_private), None)?;
            Ok(())
        });

        let err = NoiseSv2Transport::handshake_client(
            &mut client_io,
            Some(client_private),
            Some(expected_wrong_remote),
        )
        .expect_err("mismatched expected remote key must fail");
        assert!(matches!(err, StratumError::SecureHandshake(_)));
        let _ = server.join();
    }

    #[cfg(unix)]
    #[test]
    fn noise_transport_rekeys_after_interval() {
        let client_private = [3u8; 32];
        let server_private = [4u8; 32];
        let (mut client_io, mut server_io) = UnixStream::pair().expect("unix pair");
        if !apply_test_socket_timeouts(&client_io) || !apply_test_socket_timeouts(&server_io) {
            return;
        }

        let server = thread::spawn(move || -> Result<(), crate::StratumError> {
            let mut server =
                NoiseSv2Transport::handshake_server(&mut server_io, Some(server_private), None)?;
            server.set_rekey_interval_messages(2)?;
            for _ in 0..6 {
                let msg = server.read_message(&mut server_io)?.expect("message");
                assert_eq!(msg, Sv2Message::KeepAlive);
            }
            Ok(())
        });

        let mut client =
            match NoiseSv2Transport::handshake_client(&mut client_io, Some(client_private), None) {
                Ok(client) => client,
                Err(crate::StratumError::Io(err))
                    if err.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    let _ = server.join();
                    return;
                }
                Err(other) => panic!("client handshake: {other}"),
            };
        client
            .set_rekey_interval_messages(2)
            .expect("client rekey cfg");
        for _ in 0..6 {
            client
                .write_message(&mut client_io, &Sv2Message::KeepAlive)
                .expect("write keepalive");
        }
        server.join().expect("server thread").expect("server ok");
    }

    #[cfg(unix)]
    #[test]
    fn noise_transport_rejects_zero_rekey_interval() {
        let client_private = [23u8; 32];
        let server_private = [24u8; 32];
        let (mut client_io, mut server_io) = UnixStream::pair().expect("unix pair");
        if !apply_test_socket_timeouts(&client_io) || !apply_test_socket_timeouts(&server_io) {
            return;
        }

        let server = thread::spawn(move || -> Result<(), crate::StratumError> {
            let _ =
                NoiseSv2Transport::handshake_server(&mut server_io, Some(server_private), None)?;
            Ok(())
        });

        let mut client =
            match NoiseSv2Transport::handshake_client(&mut client_io, Some(client_private), None) {
                Ok(client) => client,
                Err(crate::StratumError::Io(err))
                    if err.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    let _ = server.join();
                    return;
                }
                Err(other) => panic!("client handshake: {other}"),
            };
        let err = client
            .set_rekey_interval_messages(0)
            .expect_err("interval=0 must fail");
        assert!(matches!(err, StratumError::InvalidConfig(_)));
        let _ = server.join();
    }

    #[test]
    fn async_frame_roundtrip_matches_sync_codec() {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let (mut tx, mut rx) = tokio::io::duplex(4 * 1024);
            let message = Sv2Message::KeepAlive;

            let writer = tokio::spawn(async move {
                write_frame_async(&mut tx, &message)
                    .await
                    .expect("write frame");
            });
            let reader = tokio::spawn(async move {
                read_frame_async(&mut rx)
                    .await
                    .expect("read frame")
                    .expect("frame payload")
            });

            writer.await.expect("writer join");
            let decoded = reader.await.expect("reader join");
            assert_eq!(decoded, Sv2Message::KeepAlive);
        });
    }

    #[test]
    fn async_frame_roundtrip_with_large_payload_exercises_u24_len_encoding() {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let message = Sv2Message::SetupConnection {
                protocol: 2,
                min_version: 2,
                max_version: 2,
                flags: 0,
                user_agent: "y".repeat(70_000),
            };
            let mut encoded = Vec::new();
            write_frame(&mut encoded, &message).expect("sync frame encode");
            let len = u32::from_le_bytes([encoded[3], encoded[4], encoded[5], 0]) as usize;
            assert!(len > 0xffff);

            let (mut tx, mut rx) = tokio::io::duplex(encoded.len() + 16);
            tx.write_all(&encoded).await.expect("write encoded frame");
            tx.flush().await.expect("flush encoded frame");
            drop(tx);

            let decoded = read_frame_async(&mut rx)
                .await
                .expect("read frame")
                .expect("some frame");
            assert_eq!(decoded, message);
        });
    }

    #[test]
    fn async_read_frame_rejects_malformed_headers() {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let mut frame = keepalive_frame_bytes();
            frame[2] = crate::message_type(&Sv2Message::SetupConnection {
                protocol: 2,
                min_version: 2,
                max_version: 2,
                flags: 0,
                user_agent: "x".to_owned(),
            });

            let (mut tx, mut rx) = tokio::io::duplex(4 * 1024);
            tx.write_all(&frame).await.expect("write malformed frame");
            tx.flush().await.expect("flush malformed frame");
            drop(tx);

            let err = read_frame_async(&mut rx)
                .await
                .expect_err("must reject malformed frame");
            assert!(matches!(
                err,
                crate::StratumError::MessageTypeMismatch { .. }
            ));
        });
    }

    #[test]
    fn async_read_frame_returns_none_on_eof() {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let (tx, mut rx) = tokio::io::duplex(64);
            drop(tx);
            let decoded = read_frame_async(&mut rx).await.expect("decode");
            assert!(decoded.is_none());
        });
    }

    #[test]
    fn async_secure_transport_roundtrip() {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let (mut client_io, mut server_io) = tokio::io::duplex(8 * 1024);

            let client = tokio::spawn(async move {
                let mut transport = SecureSv2Transport::handshake_client_async(&mut client_io)
                    .await
                    .expect("client handshake");
                transport
                    .write_message_async(&mut client_io, &Sv2Message::KeepAlive)
                    .await
                    .expect("client write");
                transport
                    .read_message_async(&mut client_io)
                    .await
                    .expect("client read")
                    .expect("client message")
            });

            let server = tokio::spawn(async move {
                let mut transport = SecureSv2Transport::handshake_server_async(&mut server_io)
                    .await
                    .expect("server handshake");
                let inbound = transport
                    .read_message_async(&mut server_io)
                    .await
                    .expect("server read")
                    .expect("server message");
                assert_eq!(inbound, Sv2Message::KeepAlive);
                transport
                    .write_message_async(&mut server_io, &Sv2Message::KeepAlive)
                    .await
                    .expect("server write");
            });

            let echoed = client.await.expect("client join");
            server.await.expect("server join");
            assert_eq!(echoed, Sv2Message::KeepAlive);
        });
    }

    #[test]
    fn async_noise_transport_expected_remote_key_mismatch_is_rejected() {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let (mut client_io, mut server_io) = tokio::io::duplex(8 * 1024);
            let server = tokio::spawn(async move {
                let _ = NoiseSv2Transport::handshake_server_async(
                    &mut server_io,
                    Some([19u8; 32]),
                    None,
                )
                .await;
            });
            let err = NoiseSv2Transport::handshake_client_async(
                &mut client_io,
                Some([18u8; 32]),
                Some([1u8; 32]),
            )
            .await
            .expect_err("mismatched expected remote key must fail");
            assert!(matches!(err, StratumError::SecureHandshake(_)));
            server.await.expect("server join");
        });
    }

    #[test]
    fn async_secure_transport_write_message_emits_bytes() {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let (mut client_io, mut server_io) = tokio::io::duplex(8 * 1024);

            let client = tokio::spawn(async move {
                let mut transport = SecureSv2Transport::handshake_client_async(&mut client_io)
                    .await
                    .expect("client handshake");
                transport
                    .write_message_async(&mut client_io, &Sv2Message::KeepAlive)
                    .await
                    .expect("client write");
            });

            let server = tokio::spawn(async move {
                let _transport = SecureSv2Transport::handshake_server_async(&mut server_io)
                    .await
                    .expect("server handshake");
                let mut len_prefix = [0u8; 4];
                tokio::time::timeout(
                    Duration::from_millis(500),
                    server_io.read_exact(&mut len_prefix),
                )
                .await
                .expect("timed out waiting for secure frame")
                .expect("read secure frame len");
            });

            client.await.expect("client join");
            server.await.expect("server join");
        });
    }

    #[test]
    fn noise_helpers_validate_key_input_nonce_and_scaling() {
        assert!(super::decode_noise_key_bytes(&[0u8; 31], "public").is_err());
        assert!(super::resolve_noise_private_key(None).is_err());

        let mut nonce_ctr = 0u64;
        let first = super::next_nonce(&mut nonce_ctr).expect("nonce");
        assert_eq!(first, [0u8; 12]);
        assert_eq!(nonce_ctr, 1);
        let mut overflow = u64::MAX;
        assert!(super::next_nonce(&mut overflow).is_err());

        let key = [7u8; 32];
        let a = super::derive_rekey_key(key, 1);
        let b = super::derive_rekey_key(key, 2);
        assert_ne!(a, b);
        assert_ne!(a, key);
    }

    #[test]
    fn noise_handshake_packet_sync_roundtrip_and_bounds() {
        let payload = vec![0x5au8; super::NOISE_HANDSHAKE_MAX_PACKET_SIZE];
        let mut wire = Vec::new();
        super::write_noise_handshake_packet(&mut wire, &payload).expect("write max packet");
        let decoded =
            super::read_noise_handshake_packet(&mut Cursor::new(wire)).expect("read max packet");
        assert_eq!(decoded, payload);

        let empty_err = super::write_noise_handshake_packet(&mut Vec::<u8>::new(), &[])
            .expect_err("empty payload must fail");
        assert!(matches!(empty_err, StratumError::SecureHandshake(_)));

        let oversize = vec![0u8; super::NOISE_HANDSHAKE_MAX_PACKET_SIZE + 1];
        let big_err = super::write_noise_handshake_packet(&mut Vec::<u8>::new(), &oversize)
            .expect_err("oversized payload must fail");
        assert!(matches!(big_err, StratumError::FrameTooLarge { .. }));

        let zero_err = super::read_noise_handshake_packet(&mut Cursor::new(vec![0u8, 0u8]))
            .expect_err("zero-len packet must fail");
        assert!(matches!(zero_err, StratumError::SecureHandshake(_)));
    }

    #[test]
    fn noise_handshake_packet_async_roundtrip_and_bounds() {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let payload = vec![0x33u8; super::NOISE_HANDSHAKE_MAX_PACKET_SIZE];
            let (mut tx, mut rx) = tokio::io::duplex(payload.len() + 16);
            super::write_noise_handshake_packet_async(&mut tx, &payload)
                .await
                .expect("write");
            drop(tx);
            let decoded = super::read_noise_handshake_packet_async(&mut rx)
                .await
                .expect("read");
            assert_eq!(decoded, payload);
        });
    }

    #[test]
    fn read_secure_frame_length_async_handles_eof_and_limits() {
        let runtime = Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let (tx, mut rx) = tokio::io::duplex(16);
            drop(tx);
            let none = super::read_secure_frame_length_async(&mut rx)
                .await
                .expect("eof");
            assert!(none.is_none());

            let (mut tx_zero, mut rx_zero) = tokio::io::duplex(16);
            tx_zero
                .write_all(&[0u8, 0u8, 0u8, 0u8])
                .await
                .expect("write");
            drop(tx_zero);
            let zero_err = super::read_secure_frame_length_async(&mut rx_zero)
                .await
                .expect_err("zero length must fail");
            assert!(matches!(zero_err, StratumError::InvalidFrameLength(0)));

            let too_large = (super::SECURE_MAX_FRAME_SIZE + 1) as u32;
            let prefix = too_large.to_le_bytes();
            let (mut tx_big, mut rx_big) = tokio::io::duplex(16);
            tx_big.write_all(&prefix).await.expect("write");
            drop(tx_big);
            let big_err = super::read_secure_frame_length_async(&mut rx_big)
                .await
                .expect_err("oversize must fail");
            assert!(matches!(big_err, StratumError::FrameTooLarge { .. }));
        });
    }

    #[test]
    fn scale_target_validates_factors_and_clamps_large_values() {
        let base =
            Target::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("base target");
        assert!(super::scale_target(base, 0.0).is_err());
        assert!(super::scale_target(base, f64::NAN).is_err());

        let larger = super::scale_target(base, 2.0).expect("scale up");
        assert!(larger > base);

        let huge = BigUint::from(1u8) << 300usize;
        let clamped = super::biguint_to_target_clamped(huge).expect("clamped");
        assert_eq!(clamped, Target::MAX);
    }

    #[test]
    fn sequential_job_declarator_assigns_monotonic_ids() {
        let mut declarator = SequentialJobDeclarator::new(40);
        let template = MiningTemplate {
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            ntime: 1_770_763_200,
            network_target: Target::MAX,
        };
        let first = declarator.declare_standard_job(7, template.clone());
        let second = declarator.declare_standard_job(7, template);
        assert_eq!(first.job_id, 41);
        assert_eq!(second.job_id, 42);
    }

    #[test]
    fn identity_translator_parses_remote_job_message() {
        let translator = IdentityTranslator;
        let parsed = translator
            .parse_remote_job_message(Sv2Message::NewMiningJob {
                channel_id: 1,
                job_id: 2,
                version: 3,
                prev_hash_hex: Hash256::ZERO.to_hex(),
                merkle_root_hex: Hash256::ZERO.to_hex(),
                ntime: 1_770_763_200,
                network_target_hex: Target::MAX.to_hex(),
            })
            .expect("parse")
            .expect("some");
        assert_eq!(parsed.channel_id, 1);
        assert_eq!(parsed.job_id, 2);
    }
}
