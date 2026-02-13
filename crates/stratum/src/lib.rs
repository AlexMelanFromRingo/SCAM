use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use num_bigint::BigUint;
use num_traits::{One, Zero};
use scam_core::{BlockHeader, Hash256, Target};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SUPPORTED_SV2_VERSION: u16 = 2;
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;
pub const SV2_HEADER_LEN: usize = 6;
pub const SV2_EXTENSION_MINING: u16 = 0;
const U24_MAX: usize = 0x00ff_ffff;

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
    #[error("protocol state violation: {0}")]
    ProtocolState(String),
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use scam_core::{Hash256, Target};

    use crate::{
        MiningJob, SUPPORTED_SV2_VERSION, SessionConfig, SessionEvent, ShareSubmission,
        ShareValidation, Sv2Message, Sv2Session, read_frame, validate_share, write_frame,
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
}
