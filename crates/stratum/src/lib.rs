use scam_core::{BlockHeader, Hash256, Target};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Sv2Message {
    SetupConnection {
        protocol: u16,
        min_version: u16,
        max_version: u16,
        flags: u32,
    },
    SetupConnectionSuccess {
        used_version: u16,
        flags: u32,
    },
    OpenStandardMiningChannel {
        request_id: u32,
        user: String,
    },
    OpenStandardMiningChannelSuccess {
        request_id: u32,
        channel_id: u32,
        target_hex: String,
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
    SubmitSharesStandard {
        channel_id: u32,
        job_id: u32,
        nonce: u64,
        ntime: u64,
    },
    SubmitSharesSuccess {
        channel_id: u32,
        accepted: u32,
    },
    SubmitSharesError {
        channel_id: u32,
        code: String,
        reason: String,
    },
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

pub fn encode_line(message: &Sv2Message) -> Result<String, StratumError> {
    let mut out = serde_json::to_string(message).map_err(StratumError::Serde)?;
    out.push('\n');
    Ok(out)
}

pub fn decode_line(raw: &str) -> Result<Sv2Message, StratumError> {
    serde_json::from_str(raw.trim()).map_err(StratumError::Serde)
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
    #[error("json codec error: {0}")]
    Serde(#[source] serde_json::Error),
    #[error("unknown share job channel={channel_id} job={job_id}")]
    UnknownJob { channel_id: u32, job_id: u32 },
    #[error("share hash {hash} does not meet share target {share_target}")]
    LowDifficultyShare { hash: Hash256, share_target: Target },
}

#[cfg(test)]
mod tests {
    use scam_core::{Hash256, Target};

    use crate::{
        MiningJob, ShareSubmission, ShareValidation, Sv2Message, decode_line, encode_line,
        validate_share,
    };

    #[test]
    fn sv2_message_roundtrip_json_line() {
        let msg = Sv2Message::SetupConnection {
            protocol: 2,
            min_version: 2,
            max_version: 2,
            flags: 0,
        };
        let encoded = encode_line(&msg).expect("encode");
        let decoded = decode_line(&encoded).expect("decode");
        assert_eq!(decoded, msg);
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
