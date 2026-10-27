//! Partial Multisig Transaction (PMT) — SCAM's lightweight "PSBT-lite"
//! coordination format for k-of-n multisig spends.
//!
//! ## Problem
//!
//! `scam_consensus::multisig` accepts a multisig spend at consensus
//! time when the input carries:
//! - the full `MultisigDescriptor` blob in `pubkey_compressed`, and
//! - a `k * 64`-byte concatenation of Schnorr signatures in
//!   `signature`.
//!
//! Producing the signature blob requires `k` parties, holding `k` of
//! the `n` pubkeys' secret keys, to each sign the *exact same*
//! per-input signing digest. The digest is deterministic from the
//! tx contents + input index + chain domain, so any signer can
//! recompute it locally — but the parties still need a way to
//! exchange the tx and partial signatures.
//!
//! Bitcoin solved this with PSBT (BIP174), a complex multi-role
//! binary format. SCAM doesn't have on-chain scripts so we don't
//! need PSBT's full surface area. This module ships a minimal JSON
//! envelope that handles the same workflow:
//!
//! 1. **Initiator** builds the unsigned `Transaction` (full inputs +
//!    outputs + lock_time), wraps it as a `PartialMultisigTx` with
//!    the per-input `MultisigDescriptor` and an empty signature map.
//! 2. **Each signer** receives the JSON, computes the signing digest
//!    for their input(s), signs with their secret key, appends
//!    `(pubkey, signature)` to the input's `partial_signatures` map.
//!    Forwards the updated JSON to the next signer.
//! 3. **Finalizer** validates that ≥k unique signatures are present
//!    per multisig input, concatenates them in `pubkey-order`, and
//!    produces a fully-signed `Transaction` ready for `tx/submit`.
//!
//! ## Why JSON
//!
//! - Human-readable for debugging.
//! - Trivially serializable via `serde_json` (already a workspace
//!   dep).
//! - Easy to pipe through any transport (email, signal, paste-bin)
//!   that strips binary.
//!
//! The format is versioned (`version` field) so a future MuSig2
//! upgrade can ship as `version: 2` without breaking v1 wallets.

use std::collections::BTreeMap;

use scam_consensus::{
    MULTISIG_TAG, MultisigDescriptor, MultisigError, PUBKEY_LEN, SIG_LEN, looks_like_multisig_blob,
};
use scam_core::{Hash256, Transaction};
use secp256k1::schnorr::Signature;
use secp256k1::{Message, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::signer::WalletKey;

/// v2 adds `prev_txs` so signers can verify input amounts and the fee.
pub const PARTIAL_MULTISIG_TX_VERSION: u32 = 2;

/// JSON envelope for an unsigned-or-partially-signed multisig
/// transaction.
///
/// Non-multisig inputs (legacy P2PKH) MAY be present and are signed
/// by the initiator before the envelope is shared — we don't try to
/// coordinate P2PKH signers because there's no value (the initiator
/// must already hold the only secret key).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PartialMultisigTx {
    pub version: u32,
    pub chain_domain_hex: String,
    pub tx: Transaction,
    /// Per-input partial-signature state. Indexed by input index. Only
    /// the multisig inputs appear here; non-multisig inputs are
    /// expected to be already-signed in `tx.inputs[i].signature`.
    pub inputs: BTreeMap<u32, PartialMultisigInput>,
    /// The transactions that created every output `tx` spends. Each is
    /// re-hashed and matched against the input's `prev_out.txid`, so the
    /// amounts cannot be forged: signers see exactly what they spend and
    /// what fee they pay.
    pub prev_txs: Vec<Transaction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PartialMultisigInput {
    /// Multisig descriptor bytes; must round-trip through
    /// `MultisigDescriptor::parse`.
    pub descriptor_hex: String,
    /// `pubkey_hex → signature_hex`. The order parties contribute in
    /// is irrelevant; `finalize` re-orders to descriptor order before
    /// concatenating.
    pub partial_signatures: BTreeMap<String, String>,
}

impl PartialMultisigTx {
    /// Build a fresh envelope from an unsigned tx and a list of
    /// `(input_index, descriptor_blob)` pairs identifying which
    /// inputs are multisig.
    pub fn new(
        chain_domain: &[u8],
        tx: Transaction,
        multisig_inputs: &[(u32, Vec<u8>)],
        prev_txs: &[Transaction],
    ) -> Result<Self, PartialMultisigError> {
        for (idx, blob) in multisig_inputs {
            if !looks_like_multisig_blob(blob) {
                return Err(PartialMultisigError::NotMultisigBlob { input_index: *idx });
            }
            MultisigDescriptor::parse(blob).map_err(|source| PartialMultisigError::Descriptor {
                input_index: *idx,
                source,
            })?;
        }
        // The sighash commits to the spending input's `pubkey_compressed`,
        // which for multisig is the descriptor blob. Fill it in *before*
        // anyone signs; otherwise the signatures cover a different digest
        // than the finalized transaction and consensus rejects it.
        let mut tx = tx;
        for (idx, blob) in multisig_inputs {
            let input = tx
                .inputs
                .get_mut(*idx as usize)
                .ok_or(PartialMultisigError::UnknownInput { input_index: *idx })?;
            input.pubkey_compressed = blob.clone();
            input.signature.clear();
        }
        let mut inputs = BTreeMap::new();
        for (idx, blob) in multisig_inputs {
            inputs.insert(
                *idx,
                PartialMultisigInput {
                    descriptor_hex: hex::encode(blob),
                    partial_signatures: BTreeMap::new(),
                },
            );
        }
        let mut seen = std::collections::HashSet::new();
        let prev_txs = prev_txs
            .iter()
            .filter(|prev| seen.insert(prev.txid()))
            .cloned()
            .collect::<Vec<_>>();
        let envelope = Self {
            version: PARTIAL_MULTISIG_TX_VERSION,
            chain_domain_hex: hex::encode(chain_domain),
            tx,
            inputs,
            prev_txs,
        };
        envelope.input_values()?;
        Ok(envelope)
    }

    /// Value of every input, resolved through `prev_txs` and verified: the
    /// previous tx must hash to the input's `prev_out.txid`, the output must
    /// exist, and a multisig input must spend an output locked to its
    /// descriptor.
    pub fn input_values(&self) -> Result<Vec<u64>, PartialMultisigError> {
        let by_txid = self
            .prev_txs
            .iter()
            .map(|prev| (prev.txid(), prev))
            .collect::<std::collections::HashMap<_, _>>();
        let mut values = Vec::with_capacity(self.tx.inputs.len());
        for (index, input) in self.tx.inputs.iter().enumerate() {
            let input_index = index as u32;
            let prev = by_txid
                .get(&input.prev_out.txid)
                .ok_or(PartialMultisigError::MissingPrevTx { input_index })?;
            let output = prev
                .outputs
                .get(input.prev_out.vout as usize)
                .ok_or(PartialMultisigError::MissingPrevTx { input_index })?;
            if let Some(entry) = self.inputs.get(&input_index) {
                let blob = hex::decode(&entry.descriptor_hex).map_err(|_| {
                    PartialMultisigError::BadEnvelope("descriptor_hex bad".to_owned())
                })?;
                if MultisigDescriptor::script_hash20(&blob) != output.key_hash20 {
                    return Err(PartialMultisigError::PrevOutputNotMultisig { input_index });
                }
            }
            values.push(output.value);
        }
        Ok(values)
    }

    /// Fee the finalized transaction pays (inputs − outputs), from verified
    /// input amounts.
    pub fn fee(&self) -> Result<u64, PartialMultisigError> {
        let inputs = self
            .input_values()?
            .into_iter()
            .try_fold(0u64, u64::checked_add)
            .ok_or_else(|| PartialMultisigError::BadEnvelope("input sum overflow".to_owned()))?;
        let outputs = self
            .tx
            .outputs
            .iter()
            .map(|out| out.value)
            .try_fold(0u64, u64::checked_add)
            .ok_or_else(|| PartialMultisigError::BadEnvelope("output sum overflow".to_owned()))?;
        inputs.checked_sub(outputs).ok_or_else(|| {
            PartialMultisigError::BadEnvelope(format!(
                "outputs ({outputs}) exceed inputs ({inputs})"
            ))
        })
    }

    /// Chain domain (network id bytes) the envelope's signatures commit to.
    /// Signers should compare it with the network they intend to sign for.
    pub fn chain_domain(&self) -> Result<Vec<u8>, PartialMultisigError> {
        hex::decode(&self.chain_domain_hex).map_err(|_| {
            PartialMultisigError::BadEnvelope("chain_domain_hex is not valid hex".to_owned())
        })
    }

    /// Descriptor blob of a multisig input, checked against the input's
    /// `pubkey_compressed` (an envelope edited after creation must not make
    /// signers sign a digest the final transaction will not have).
    fn checked_descriptor_blob(&self, input_index: u32) -> Result<Vec<u8>, PartialMultisigError> {
        let entry = self
            .inputs
            .get(&input_index)
            .ok_or(PartialMultisigError::UnknownInput { input_index })?;
        let blob = hex::decode(&entry.descriptor_hex)
            .map_err(|_| PartialMultisigError::BadEnvelope("descriptor_hex bad".to_owned()))?;
        let input = self
            .tx
            .inputs
            .get(input_index as usize)
            .ok_or(PartialMultisigError::UnknownInput { input_index })?;
        if input.pubkey_compressed != blob {
            return Err(PartialMultisigError::BadEnvelope(format!(
                "input #{input_index} pubkey field does not match its multisig descriptor"
            )));
        }
        Ok(blob)
    }

    /// Compute the signing digest for one input, exactly as the
    /// consensus validator does. Signers call this locally to know
    /// what to feed into their secret key.
    pub fn signing_digest(&self, input_index: u32) -> Result<Hash256, PartialMultisigError> {
        self.checked_descriptor_blob(input_index)?;
        let domain = hex::decode(&self.chain_domain_hex).map_err(|_| {
            PartialMultisigError::BadEnvelope("chain_domain_hex is not valid hex".to_owned())
        })?;
        self.tx
            .signing_digest_with_chain_domain(input_index as usize, &domain)
            .map_err(|e| PartialMultisigError::BadEnvelope(format!("digest: {e}")))
    }

    /// Sign one input with a single key. The key's pubkey must appear
    /// in the input's multisig descriptor; otherwise the signature
    /// would be useless at finalize-time and we reject early.
    ///
    /// Idempotent: signing twice with the same key replaces (no-op if
    /// signature equal). Detects pubkey collisions across calls.
    pub fn sign_input(
        &mut self,
        input_index: u32,
        wallet_key: &WalletKey,
    ) -> Result<(), PartialMultisigError> {
        let blob = self.checked_descriptor_blob(input_index)?;
        let descriptor = MultisigDescriptor::parse(&blob).map_err(|source| {
            PartialMultisigError::Descriptor {
                input_index,
                source,
            }
        })?;
        // Never sign without verified amounts: the fee is part of what the
        // signer agrees to.
        self.fee()?;

        let our_pubkey = wallet_key.pubkey_compressed();
        if !descriptor.pubkeys.iter().any(|pk| pk == &our_pubkey) {
            return Err(PartialMultisigError::PubkeyNotInDescriptor {
                input_index,
                pubkey_hex: hex::encode(our_pubkey),
            });
        }
        // Compute digest locally — never trust an external "to_sign"
        // because that would let an attacker substitute a different
        // tx and harvest our signature for it.
        let domain = hex::decode(&self.chain_domain_hex).map_err(|_| {
            PartialMultisigError::BadEnvelope("chain_domain_hex is not valid hex".to_owned())
        })?;
        let digest = self
            .tx
            .signing_digest_with_chain_domain(input_index as usize, &domain)
            .map_err(|e| PartialMultisigError::BadEnvelope(format!("digest: {e}")))?;
        let signature = crate::signer::sign_digest(wallet_key, digest.0)
            .map_err(|e| PartialMultisigError::SigningFailed(format!("{e}")))?;
        let entry = self
            .inputs
            .get_mut(&input_index)
            .ok_or(PartialMultisigError::UnknownInput { input_index })?;
        entry
            .partial_signatures
            .insert(hex::encode(our_pubkey), hex::encode(signature));
        Ok(())
    }

    /// Validate that every multisig input has ≥k valid partial
    /// signatures. Returns the per-input status as a Vec for display.
    /// Does NOT mutate the envelope.
    pub fn inspect(&self) -> Result<Vec<InspectStatus>, PartialMultisigError> {
        let mut out = Vec::with_capacity(self.inputs.len());
        for (idx, entry) in &self.inputs {
            let blob = self.checked_descriptor_blob(*idx)?;
            let descriptor = MultisigDescriptor::parse(&blob).map_err(|source| {
                PartialMultisigError::Descriptor {
                    input_index: *idx,
                    source,
                }
            })?;
            let digest = self.signing_digest(*idx)?;
            let mut valid_sigs = 0u8;
            let mut invalid_sigs = 0u8;
            let mut unknown_pubkeys = 0u8;
            let secp = Secp256k1::verification_only();
            for (pk_hex, sig_hex) in &entry.partial_signatures {
                let Ok(pk_bytes) = hex::decode(pk_hex) else {
                    invalid_sigs += 1;
                    continue;
                };
                if pk_bytes.len() != PUBKEY_LEN {
                    invalid_sigs += 1;
                    continue;
                }
                let mut pk_arr = [0u8; PUBKEY_LEN];
                pk_arr.copy_from_slice(&pk_bytes);
                if !descriptor.pubkeys.iter().any(|p| p == &pk_arr) {
                    unknown_pubkeys += 1;
                    continue;
                }
                let Ok(sig_bytes) = hex::decode(sig_hex) else {
                    invalid_sigs += 1;
                    continue;
                };
                if sig_bytes.len() != SIG_LEN {
                    invalid_sigs += 1;
                    continue;
                }
                let Ok(parsed_pk) = PublicKey::from_slice(&pk_arr) else {
                    invalid_sigs += 1;
                    continue;
                };
                let (xonly, _) = parsed_pk.x_only_public_key();
                let Ok(message) = Message::from_digest_slice(&digest.0) else {
                    invalid_sigs += 1;
                    continue;
                };
                let Ok(parsed_sig) = Signature::from_slice(&sig_bytes) else {
                    invalid_sigs += 1;
                    continue;
                };
                if secp.verify_schnorr(&parsed_sig, &message, &xonly).is_ok() {
                    valid_sigs += 1;
                } else {
                    invalid_sigs += 1;
                }
            }
            out.push(InspectStatus {
                input_index: *idx,
                k: descriptor.k,
                n: descriptor.n,
                valid_sigs,
                invalid_sigs,
                unknown_pubkeys,
                threshold_reached: valid_sigs >= descriptor.k,
            });
        }
        Ok(out)
    }

    /// Combine the envelope into a fully-signed transaction.
    ///
    /// For each multisig input:
    /// - Select up to k valid signatures (in descriptor-pubkey order
    ///   for determinism).
    /// - Concatenate into the `TxIn::signature` blob.
    /// - Set `TxIn::pubkey_compressed` to the descriptor blob.
    ///
    /// Returns the finalized tx ready for submission, or a typed
    /// error if any input is under-signed.
    pub fn finalize(&self) -> Result<Transaction, PartialMultisigError> {
        self.fee()?;
        let mut tx = self.tx.clone();
        for (idx, entry) in &self.inputs {
            let input_index = *idx as usize;
            if input_index >= tx.inputs.len() {
                return Err(PartialMultisigError::UnknownInput { input_index: *idx });
            }
            let blob = hex::decode(&entry.descriptor_hex)
                .map_err(|_| PartialMultisigError::BadEnvelope("descriptor_hex bad".to_owned()))?;
            let descriptor = MultisigDescriptor::parse(&blob).map_err(|source| {
                PartialMultisigError::Descriptor {
                    input_index: *idx,
                    source,
                }
            })?;
            let digest = self.signing_digest(*idx)?;
            let secp = Secp256k1::verification_only();
            let message = Message::from_digest_slice(&digest.0).map_err(|_| {
                PartialMultisigError::BadEnvelope("digest message build".to_owned())
            })?;

            // For determinism on chain, emit signatures in descriptor
            // pubkey order (skipping pubkeys without a contribution).
            let mut emitted: Vec<u8> = Vec::with_capacity((descriptor.k as usize) * SIG_LEN);
            let mut emitted_count: u8 = 0;
            for pk in &descriptor.pubkeys {
                if emitted_count == descriptor.k {
                    break;
                }
                let pk_hex = hex::encode(pk);
                let Some(sig_hex) = entry.partial_signatures.get(&pk_hex) else {
                    continue;
                };
                let Ok(sig_bytes) = hex::decode(sig_hex) else {
                    continue;
                };
                if sig_bytes.len() != SIG_LEN {
                    continue;
                }
                let Ok(parsed_pk) = PublicKey::from_slice(pk) else {
                    continue;
                };
                let (xonly, _) = parsed_pk.x_only_public_key();
                let Ok(parsed_sig) = Signature::from_slice(&sig_bytes) else {
                    continue;
                };
                if secp.verify_schnorr(&parsed_sig, &message, &xonly).is_err() {
                    continue;
                }
                emitted.extend_from_slice(&sig_bytes);
                emitted_count += 1;
            }
            if emitted_count < descriptor.k {
                return Err(PartialMultisigError::Underthreshold {
                    input_index: *idx,
                    required: descriptor.k,
                    have_valid: emitted_count,
                });
            }
            tx.inputs[input_index].signature = emitted;
            tx.inputs[input_index].pubkey_compressed = blob;
        }
        Ok(tx)
    }

    pub fn to_json(&self) -> Result<String, PartialMultisigError> {
        serde_json::to_string_pretty(self).map_err(|e| PartialMultisigError::Serde(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self, PartialMultisigError> {
        let parsed: PartialMultisigTx =
            serde_json::from_str(s).map_err(|e| PartialMultisigError::Serde(e.to_string()))?;
        if parsed.version != PARTIAL_MULTISIG_TX_VERSION {
            return Err(PartialMultisigError::BadEnvelope(format!(
                "unsupported PMT version {} (this build expects {})",
                parsed.version, PARTIAL_MULTISIG_TX_VERSION
            )));
        }
        // Sanity-check chain_domain hex parses now, so any malformed
        // envelope is caught at load time rather than at sign time.
        if hex::decode(&parsed.chain_domain_hex).is_err() {
            return Err(PartialMultisigError::BadEnvelope(
                "chain_domain_hex is not valid hex".to_owned(),
            ));
        }
        Ok(parsed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InspectStatus {
    pub input_index: u32,
    pub k: u8,
    pub n: u8,
    pub valid_sigs: u8,
    pub invalid_sigs: u8,
    pub unknown_pubkeys: u8,
    pub threshold_reached: bool,
}

#[derive(Debug, Error)]
pub enum PartialMultisigError {
    #[error("envelope JSON malformed: {0}")]
    BadEnvelope(String),
    #[error("input #{input_index} is not in the envelope")]
    UnknownInput { input_index: u32 },
    #[error("input #{input_index} blob is not a multisig descriptor")]
    NotMultisigBlob { input_index: u32 },
    #[error("input #{input_index} descriptor parse failed: {source}")]
    Descriptor {
        input_index: u32,
        source: MultisigError,
    },
    #[error(
        "input #{input_index} signing pubkey {pubkey_hex} is not a participant of this multisig"
    )]
    PubkeyNotInDescriptor {
        input_index: u32,
        pubkey_hex: String,
    },
    #[error("input #{input_index} has {have_valid} valid sigs, need {required}")]
    Underthreshold {
        input_index: u32,
        required: u8,
        have_valid: u8,
    },
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("serde: {0}")]
    Serde(String),
    #[error(
        "input #{input_index}: previous transaction missing from the envelope (or vout out of range)"
    )]
    MissingPrevTx { input_index: u32 },
    #[error("input #{input_index} spends an output that is not locked to its multisig descriptor")]
    PrevOutputNotMultisig { input_index: u32 },
}

// The MULTISIG_TAG re-export keeps API ergonomics: callers don't have
// to also import scam_consensus for the tag length constant in tests.
pub const TAG_LEN: usize = MULTISIG_TAG.len();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::derive_wallet_key;
    use scam_core::{OutPoint, TxIn, TxOut};
    use secp256k1::SecretKey;

    fn key(seed: u8) -> WalletKey {
        derive_wallet_key(&[seed; 64], 0, 0).expect("derive")
    }

    /// The previous tx paying 1_000 to the descriptor, and an unsigned tx
    /// spending it with a 999 fee.
    fn unsigned_tx_with_one_multisig_input(blob: &[u8]) -> (Transaction, Transaction) {
        let prev = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: Hash256([0xAA; 32]),
                    vout: 0,
                },
                signature: vec![1; 64],
                pubkey_compressed: vec![2; 33],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 1_000,
                key_hash20: MultisigDescriptor::script_hash20(blob),
            }],
            lock_time: 0,
        };
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: prev.txid(),
                    vout: 0,
                },
                signature: Vec::new(),
                pubkey_compressed: blob.to_vec(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [0xBB; 20],
            }],
            lock_time: 0,
        };
        (tx, prev)
    }

    fn three_party_descriptor() -> (Vec<u8>, [WalletKey; 3]) {
        let a = key(1);
        let b = key(2);
        let c = key(3);
        let blob = MultisigDescriptor::encode(
            2,
            &[
                a.pubkey_compressed(),
                b.pubkey_compressed(),
                c.pubkey_compressed(),
            ],
        )
        .expect("encode 2-of-3");
        (blob, [a, b, c])
    }

    #[test]
    fn new_rejects_non_multisig_blob_in_multisig_slot() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::coinbase(),
                signature: Vec::new(),
                pubkey_compressed: vec![0x02; 33],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 1,
                key_hash20: [0u8; 20],
            }],
            lock_time: 0,
        };
        let err = PartialMultisigTx::new(b"devnet", tx, &[(0, vec![0x02; 33])], &[])
            .expect_err("33-byte blob is not multisig");
        assert!(matches!(err, PartialMultisigError::NotMultisigBlob { .. }));
    }

    /// R8: signers see verified input amounts and the fee; forged or
    /// missing previous transactions are refused before anyone signs.
    #[test]
    fn envelope_verifies_input_amounts_and_reports_fee() {
        let (blob, keys) = three_party_descriptor();
        let (tx, prev) = unsigned_tx_with_one_multisig_input(&blob);
        let pmt = PartialMultisigTx::new(
            b"devnet",
            tx.clone(),
            &[(0, blob.clone())],
            std::slice::from_ref(&prev),
        )
        .expect("new");
        assert_eq!(pmt.input_values().expect("values"), vec![1_000]);
        assert_eq!(pmt.fee().expect("fee"), 999);

        assert!(matches!(
            PartialMultisigTx::new(b"devnet", tx.clone(), &[(0, blob.clone())], &[]),
            Err(PartialMultisigError::MissingPrevTx { input_index: 0 })
        ));

        // Inflating the amount changes the prev tx hash: no longer matches.
        let mut forged = prev.clone();
        forged.outputs[0].value = 1_000_000;
        assert!(matches!(
            PartialMultisigTx::new(
                b"devnet",
                tx.clone(),
                &[(0, blob.clone())],
                &[forged.clone()]
            ),
            Err(PartialMultisigError::MissingPrevTx { .. })
        ));

        // A tampered envelope cannot be signed.
        let mut tampered = pmt.clone();
        tampered.prev_txs = vec![forged];
        assert!(tampered.sign_input(0, &keys[0]).is_err());

        // The spent output must be locked to the descriptor.
        let mut not_ours = prev;
        not_ours.outputs[0].key_hash20 = [0x55; 20];
        let mut spend = tx;
        spend.inputs[0].prev_out.txid = not_ours.txid();
        assert!(matches!(
            PartialMultisigTx::new(b"devnet", spend, &[(0, blob)], &[not_ours]),
            Err(PartialMultisigError::PrevOutputNotMultisig { input_index: 0 })
        ));
    }

    #[test]
    fn json_roundtrip_preserves_signatures() {
        let (blob, keys) = three_party_descriptor();
        let (tx, prev) = unsigned_tx_with_one_multisig_input(&blob);
        let mut pmt = PartialMultisigTx::new(
            b"devnet",
            tx,
            &[(0, blob.clone())],
            std::slice::from_ref(&prev),
        )
        .expect("new");
        pmt.sign_input(0, &keys[0]).expect("sign 0");
        let json = pmt.to_json().expect("encode");
        let parsed = PartialMultisigTx::from_json(&json).expect("decode");
        assert_eq!(parsed, pmt);
    }

    #[test]
    fn from_json_rejects_version_mismatch() {
        let bad = r#"{"version":99,"chain_domain_hex":"","tx":{"version":1,"inputs":[],"outputs":[],"lock_time":0},"inputs":{},"prev_txs":[]}"#;
        let err = PartialMultisigTx::from_json(bad).expect_err("must reject");
        assert!(matches!(err, PartialMultisigError::BadEnvelope(_)));
        // A v1 envelope (no verifiable amounts) is refused too.
        let v1 = r#"{"version":1,"chain_domain_hex":"","tx":{"version":1,"inputs":[],"outputs":[],"lock_time":0},"inputs":{}}"#;
        assert!(PartialMultisigTx::from_json(v1).is_err());
    }

    #[test]
    fn sign_input_rejects_non_participant_key() {
        let (blob, _keys) = three_party_descriptor();
        let stranger = key(99); // not in descriptor
        let (tx, prev) = unsigned_tx_with_one_multisig_input(&blob);
        let mut pmt =
            PartialMultisigTx::new(b"devnet", tx, &[(0, blob)], std::slice::from_ref(&prev))
                .expect("new");
        let err = pmt
            .sign_input(0, &stranger)
            .expect_err("stranger key must be rejected");
        assert!(matches!(
            err,
            PartialMultisigError::PubkeyNotInDescriptor { .. }
        ));
    }

    #[test]
    fn inspect_reports_threshold_status() {
        let (blob, keys) = three_party_descriptor();
        let (tx, prev) = unsigned_tx_with_one_multisig_input(&blob);
        let mut pmt = PartialMultisigTx::new(
            b"devnet",
            tx,
            &[(0, blob.clone())],
            std::slice::from_ref(&prev),
        )
        .expect("new");
        // 0/2 sigs.
        let status = pmt.inspect().expect("inspect");
        assert_eq!(status[0].valid_sigs, 0);
        assert!(!status[0].threshold_reached);
        // 1/2 sigs.
        pmt.sign_input(0, &keys[0]).expect("sign 0");
        let status = pmt.inspect().expect("inspect");
        assert_eq!(status[0].valid_sigs, 1);
        assert!(!status[0].threshold_reached);
        // 2/2 sigs.
        pmt.sign_input(0, &keys[1]).expect("sign 1");
        let status = pmt.inspect().expect("inspect");
        assert_eq!(status[0].valid_sigs, 2);
        assert!(status[0].threshold_reached);
    }

    /// R8: the initiator does not have to pre-fill the descriptor; the
    /// finalized tx must still verify under consensus.
    #[test]
    fn finalize_verifies_when_initiator_left_pubkey_field_empty() {
        let (blob, keys) = three_party_descriptor();
        let (mut tx, prev) = unsigned_tx_with_one_multisig_input(&blob);
        tx.inputs[0].pubkey_compressed = Vec::new();
        let mut pmt = PartialMultisigTx::new(
            b"devnet",
            tx,
            &[(0, blob.clone())],
            std::slice::from_ref(&prev),
        )
        .expect("new");
        pmt.sign_input(0, &keys[0]).expect("sign 0");
        pmt.sign_input(0, &keys[1]).expect("sign 1");
        let finalized = pmt.finalize().expect("finalize");
        let digest = finalized
            .signing_digest_with_chain_domain(0, b"devnet")
            .expect("digest");
        let descriptor = MultisigDescriptor::parse(&blob).expect("parse");
        scam_consensus::verify_multisig_spend(&descriptor, digest, &finalized.inputs[0].signature)
            .expect("consensus verifies finalized multisig spend");

        // Tampering with the pubkey field after creation is detected.
        let mut tampered = pmt.clone();
        tampered.tx.inputs[0].pubkey_compressed = vec![0x02; 33];
        assert!(tampered.sign_input(0, &keys[2]).is_err());
    }

    #[test]
    fn finalize_under_threshold_rejects() {
        let (blob, keys) = three_party_descriptor();
        let (tx, prev) = unsigned_tx_with_one_multisig_input(&blob);
        let mut pmt = PartialMultisigTx::new(
            b"devnet",
            tx,
            &[(0, blob.clone())],
            std::slice::from_ref(&prev),
        )
        .expect("new");
        pmt.sign_input(0, &keys[0]).expect("sign 0");
        let err = pmt.finalize().expect_err("1/2 must fail");
        assert!(matches!(
            err,
            PartialMultisigError::Underthreshold {
                required: 2,
                have_valid: 1,
                ..
            }
        ));
    }

    #[test]
    fn finalize_produces_consensus_verifiable_tx() {
        let (blob, keys) = three_party_descriptor();
        let (tx, prev) = unsigned_tx_with_one_multisig_input(&blob);
        let mut pmt = PartialMultisigTx::new(
            b"devnet",
            tx,
            &[(0, blob.clone())],
            std::slice::from_ref(&prev),
        )
        .expect("new");
        pmt.sign_input(0, &keys[0]).expect("sign 0");
        pmt.sign_input(0, &keys[2]).expect("sign 2");

        let finalized = pmt.finalize().expect("finalize");
        assert_eq!(finalized.inputs[0].pubkey_compressed, blob);
        assert_eq!(
            finalized.inputs[0].signature.len(),
            2 * SIG_LEN,
            "k=2 multisig spend must carry exactly 2*64 bytes of sig"
        );

        // Run the consensus-side verifier directly: parse the
        // descriptor, recompute the digest, and verify_multisig_spend
        // — same logic the chain validator uses.
        let descriptor = MultisigDescriptor::parse(&blob).expect("parse");
        let digest = finalized
            .signing_digest_with_chain_domain(0, b"devnet")
            .expect("digest");
        scam_consensus::verify_multisig_spend(&descriptor, digest, &finalized.inputs[0].signature)
            .expect("consensus verifier accepts finalized PMT");
    }

    /// A second call with the same key replaces (not appends), so a
    /// duplicate sign is idempotent rather than corrupting.
    #[test]
    fn sign_input_is_idempotent() {
        let (blob, keys) = three_party_descriptor();
        let (tx, prev) = unsigned_tx_with_one_multisig_input(&blob);
        let mut pmt =
            PartialMultisigTx::new(b"devnet", tx, &[(0, blob)], std::slice::from_ref(&prev))
                .expect("new");
        pmt.sign_input(0, &keys[0]).expect("sign 0");
        let snapshot = pmt.clone();
        pmt.sign_input(0, &keys[0]).expect("idempotent second sign");
        assert_eq!(
            pmt.inputs[&0].partial_signatures.len(),
            snapshot.inputs[&0].partial_signatures.len()
        );
    }

    // Touch SecretKey to keep its import in the test build — used in
    // future PSBT tests for raw secret-key signers, kept here as the
    // anchor so the workspace dep is exercised.
    #[allow(dead_code)]
    fn _dummy(sk: SecretKey) -> SecretKey {
        sk
    }
}
