use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};

use scam_core::{BlockHeader, Hash256, Target};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SUPPORTED_SV2_VERSION: u16 = 2;
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionConfig {
    pub channel_id: u32,
    pub share_target: Target,
    pub max_jobs: usize,
    pub supported_version: u16,
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
}

impl Sv2Session {
    pub fn new(cfg: SessionConfig) -> Result<Self, StratumError> {
        if cfg.max_jobs == 0 {
            return Err(StratumError::InvalidConfig(
                "max_jobs must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            cfg,
            state: SessionState::AwaitSetup,
            user: None,
            jobs: HashMap::new(),
            job_order: VecDeque::new(),
            stats: SessionStats::default(),
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

    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }

    pub fn handle_message(&mut self, message: Sv2Message) -> Result<SessionResponse, StratumError> {
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
            } => self.handle_submit_share(ShareSubmission {
                channel_id,
                job_id,
                nonce,
                ntime,
            }),
            Sv2Message::KeepAlive => Ok(SessionResponse::default()),
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
            outbound: vec![Sv2Message::OpenStandardMiningChannelSuccess {
                request_id,
                channel_id: self.cfg.channel_id,
                target_hex: self.cfg.share_target.to_hex(),
                extranonce_prefix_hex: format!("{:08x}", self.cfg.channel_id),
            }],
            events: vec![SessionEvent::ChannelOpened {
                channel_id: self.cfg.channel_id,
                user,
            }],
        })
    }

    fn handle_submit_share(
        &mut self,
        submission: ShareSubmission,
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
            self.stats.rejected_shares = self.stats.rejected_shares.saturating_add(1);
            let reason = format!("unknown job {}", submission.job_id);
            return Ok(SessionResponse {
                outbound: vec![Sv2Message::SubmitSharesError {
                    channel_id: self.cfg.channel_id,
                    code: "unknown_job".to_owned(),
                    reason: reason.clone(),
                }],
                events: vec![SessionEvent::ShareRejected {
                    channel_id: self.cfg.channel_id,
                    job_id: Some(submission.job_id),
                    reason,
                }],
            });
        };

        match validate_share(job, submission, self.cfg.share_target) {
            Ok(ShareValidation::AcceptedShare {
                header_hash,
                is_block,
            }) => {
                self.stats.accepted_shares = self.stats.accepted_shares.saturating_add(1);
                Ok(SessionResponse {
                    outbound: vec![Sv2Message::SubmitSharesSuccess {
                        channel_id: self.cfg.channel_id,
                        accepted: 1,
                        is_block,
                    }],
                    events: vec![SessionEvent::ShareAccepted {
                        channel_id: self.cfg.channel_id,
                        job_id: submission.job_id,
                        nonce: submission.nonce,
                        ntime: submission.ntime,
                        header_hash,
                        is_block,
                    }],
                })
            }
            Err(err) => {
                self.stats.rejected_shares = self.stats.rejected_shares.saturating_add(1);
                let reason = err.to_string();
                Ok(SessionResponse {
                    outbound: vec![Sv2Message::SubmitSharesError {
                        channel_id: self.cfg.channel_id,
                        code: "low_difficulty".to_owned(),
                        reason: reason.clone(),
                    }],
                    events: vec![SessionEvent::ShareRejected {
                        channel_id: self.cfg.channel_id,
                        job_id: Some(submission.job_id),
                        reason,
                    }],
                })
            }
        }
    }
}

pub fn write_frame<W: Write>(writer: &mut W, message: &Sv2Message) -> Result<(), StratumError> {
    let payload = serde_json::to_vec(message).map_err(StratumError::Serde)?;
    if payload.is_empty() {
        return Err(StratumError::InvalidFrameLength(0));
    }
    if payload.len() > MAX_FRAME_SIZE {
        return Err(StratumError::FrameTooLarge {
            got: payload.len(),
            max: MAX_FRAME_SIZE,
        });
    }

    let len = u32::try_from(payload.len())
        .map_err(|_| StratumError::FrameTooLarge {
            got: payload.len(),
            max: MAX_FRAME_SIZE,
        })?
        .to_be_bytes();
    writer.write_all(&len).map_err(StratumError::Io)?;
    writer.write_all(&payload).map_err(StratumError::Io)?;
    writer.flush().map_err(StratumError::Io)
}

pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Sv2Message>, StratumError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(StratumError::Io(err)),
    }

    let len = u32::from_be_bytes(len_buf) as usize;
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
    let message: Sv2Message = serde_json::from_slice(&payload).map_err(StratumError::Serde)?;
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

#[derive(Debug, Error)]
pub enum StratumError {
    #[error("stratum io error: {0}")]
    Io(#[source] std::io::Error),
    #[error("json codec error: {0}")]
    Serde(#[source] serde_json::Error),
    #[error("invalid stratum config: {0}")]
    InvalidConfig(String),
    #[error("invalid frame length {0}")]
    InvalidFrameLength(usize),
    #[error("frame too large: got={got}, max={max}")]
    FrameTooLarge { got: usize, max: usize },
    #[error("channel mismatch: expected={expected}, got={got}")]
    ChannelMismatch { expected: u32, got: u32 },
    #[error("unknown share job channel={channel_id} job={job_id}")]
    UnknownJob { channel_id: u32, job_id: u32 },
    #[error("share hash {hash} does not meet share target {share_target}")]
    LowDifficultyShare { hash: Hash256, share_target: Target },
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
        let mut session = Sv2Session::new(SessionConfig {
            channel_id: 7,
            share_target: Target::MAX,
            max_jobs: 8,
            supported_version: SUPPORTED_SV2_VERSION,
        })
        .expect("session");

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
            .handle_message(Sv2Message::SubmitSharesStandard {
                channel_id: 7,
                job_id: 1,
                nonce: 0,
                ntime: 1_770_763_200,
            })
            .expect("submit handled");
        assert!(matches!(
            submit.events.as_slice(),
            [SessionEvent::ShareAccepted { is_block: true, .. }]
        ));
    }

    #[test]
    fn session_rejects_unknown_job() {
        let mut session = Sv2Session::new(SessionConfig {
            channel_id: 1,
            share_target: Target::MAX,
            max_jobs: 8,
            supported_version: SUPPORTED_SV2_VERSION,
        })
        .expect("session");
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
                channel_id: 1,
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
