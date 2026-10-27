//! k-of-n multisig spend authorization.
//!
//! ## Wire format (input side only)
//!
//! Standard P2PKH spends put a 33-byte compressed pubkey in
//! `TxIn::pubkey_compressed` and a 64-byte Schnorr signature in
//! `TxIn::signature`. Multisig reuses both fields but with a
//! domain-separated, structured layout:
//!
//! ```text
//! pubkey_compressed = MULTISIG_TAG (16 bytes)
//!                  || k             (1 byte, 1..=MAX_PARTICIPANTS)
//!                  || n             (1 byte, k..=MAX_PARTICIPANTS)
//!                  || pubkey_1      (33 bytes, compressed sec1)
//!                  || ...
//!                  || pubkey_n      (33 bytes, compressed sec1)
//!
//! signature       = sig_1 || ... || sig_k             (k * 64 bytes)
//! ```
//!
//! ## Validation contract
//!
//! - The UTXO's `key_hash20` MUST equal
//!   `RIPEMD160(BLAKE3(pubkey_compressed))`. Domain separation comes for
//!   free because the tag prefix is the first 16 bytes of every multisig
//!   blob, and no 33-byte legacy pubkey ever starts with the tag (legal
//!   compressed pubkeys begin `0x02` or `0x03`).
//! - All `n` pubkeys MUST decode under `secp256k1::PublicKey::from_slice`
//!   and be distinct as x-only keys (`02||X` and `03||X` alias the same
//!   BIP340 signer).
//! - Exactly `k` signatures provided, ordered like the descriptor's
//!   pubkeys; each Schnorr-verifies against a strictly later pubkey than
//!   the previous one.
//!
//! ## Output side
//!
//! `TxOut` stays `{value, key_hash20}` for both P2PKH and multisig. The
//! validator dispatches purely on the *spending* input's blob shape:
//!
//! - `pubkey_compressed.len() == 33` → P2PKH path (legacy).
//! - `pubkey_compressed.len() >= MULTISIG_MIN_BLOB` AND blob starts
//!   with `MULTISIG_TAG` → multisig path.
//! - Anything else → invalid.
//!
//! Off-chain, the recipient encodes a multisig address as bech32m of
//! the same 20-byte hash, just with a distinguishing HRP suffix so
//! wallet UIs can render them differently. The consensus rules don't
//! care about the address-level encoding.

use scam_core::{Hash256, hash160_blake3};
use secp256k1::schnorr::Signature;
use secp256k1::{Message, PublicKey, Secp256k1};
use thiserror::Error;

/// 16-byte tag prefix. First three bytes (`b"SCA"`) overlap visually
/// with legacy pubkeys that start with `0x02`/`0x03`, so the *length*
/// check (legacy = exactly 33 bytes) is what guarantees no collision.
pub const MULTISIG_TAG: &[u8; 16] = b"SCAM-multisig-v1";

pub const MAX_PARTICIPANTS: usize = 15;
pub const PUBKEY_LEN: usize = 33;
pub const SIG_LEN: usize = 64;

/// Smallest legal multisig blob = tag + k + n + 1*pubkey for the 1-of-1
/// degenerate case.
pub const MULTISIG_MIN_BLOB: usize = MULTISIG_TAG.len() + 1 + 1 + PUBKEY_LEN;
/// Largest legal multisig blob.
pub const MULTISIG_MAX_BLOB: usize = MULTISIG_TAG.len() + 1 + 1 + MAX_PARTICIPANTS * PUBKEY_LEN;

/// Parsed multisig descriptor extracted from a `TxIn::pubkey_compressed`
/// blob. All invariants enforced in `parse`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultisigDescriptor {
    pub k: u8,
    pub n: u8,
    pub pubkeys: Vec<[u8; PUBKEY_LEN]>,
}

impl MultisigDescriptor {
    /// Build a descriptor from raw parts and return the canonical wire
    /// blob. Used by the wallet to construct outputs.
    pub fn encode(k: u8, pubkeys: &[[u8; PUBKEY_LEN]]) -> Result<Vec<u8>, MultisigError> {
        let n = pubkeys.len();
        if n == 0 || n > MAX_PARTICIPANTS {
            return Err(MultisigError::InvalidN { n });
        }
        if k == 0 || (k as usize) > n {
            return Err(MultisigError::InvalidK { k, n: n as u8 });
        }
        // Distinct-key rule, compared on the x-only key (bytes 1..33):
        // BIP340 verification ignores the parity byte, so `02||X` and
        // `03||X` are the same signer.
        for i in 0..n {
            for j in (i + 1)..n {
                if xonly_bytes(&pubkeys[i]) == xonly_bytes(&pubkeys[j]) {
                    return Err(MultisigError::DuplicatePubkey { index: j });
                }
            }
        }
        // Real ECC validity: each pubkey must lift to a curve point.
        for (i, pk) in pubkeys.iter().enumerate() {
            if PublicKey::from_slice(pk).is_err() {
                return Err(MultisigError::InvalidPubkey { index: i });
            }
        }
        let mut blob = Vec::with_capacity(MULTISIG_TAG.len() + 2 + (n * PUBKEY_LEN));
        blob.extend_from_slice(MULTISIG_TAG);
        blob.push(k);
        blob.push(n as u8);
        for pk in pubkeys {
            blob.extend_from_slice(pk);
        }
        Ok(blob)
    }

    /// `script_hash20` to use as `TxOut::key_hash20` when sending to
    /// this multisig descriptor.
    pub fn script_hash20(blob: &[u8]) -> [u8; 20] {
        hash160_blake3(blob)
    }

    /// Parse and validate a multisig blob. Returns the structured
    /// descriptor or a typed error. Does *not* touch signatures.
    pub fn parse(blob: &[u8]) -> Result<Self, MultisigError> {
        if blob.len() < MULTISIG_MIN_BLOB || blob.len() > MULTISIG_MAX_BLOB {
            return Err(MultisigError::BadLength { got: blob.len() });
        }
        if &blob[..MULTISIG_TAG.len()] != MULTISIG_TAG {
            return Err(MultisigError::BadTag);
        }
        let k = blob[MULTISIG_TAG.len()];
        let n = blob[MULTISIG_TAG.len() + 1];
        let n_usize = n as usize;
        if n == 0 || n_usize > MAX_PARTICIPANTS {
            return Err(MultisigError::InvalidN { n: n_usize });
        }
        if k == 0 || k > n {
            return Err(MultisigError::InvalidK { k, n });
        }
        let expected_len = MULTISIG_TAG.len() + 2 + (n_usize * PUBKEY_LEN);
        if blob.len() != expected_len {
            return Err(MultisigError::BadLength { got: blob.len() });
        }
        let mut pubkeys = Vec::with_capacity(n_usize);
        let mut cursor = MULTISIG_TAG.len() + 2;
        for i in 0..n_usize {
            let mut pk = [0u8; PUBKEY_LEN];
            pk.copy_from_slice(&blob[cursor..cursor + PUBKEY_LEN]);
            // Real curve check: rejects all-zero, low-order, etc.
            if PublicKey::from_slice(&pk).is_err() {
                return Err(MultisigError::InvalidPubkey { index: i });
            }
            if pubkeys
                .iter()
                .any(|existing: &[u8; PUBKEY_LEN]| xonly_bytes(existing) == xonly_bytes(&pk))
            {
                return Err(MultisigError::DuplicatePubkey { index: i });
            }
            pubkeys.push(pk);
            cursor += PUBKEY_LEN;
        }
        Ok(Self { k, n, pubkeys })
    }
}

fn xonly_bytes(pubkey: &[u8; PUBKEY_LEN]) -> &[u8] {
    &pubkey[1..]
}

/// Heuristic dispatch: is `pubkey_compressed` shaped like a multisig
/// blob? Used by the consensus validator before parsing.
///
/// Returns true iff length is in the multisig blob range AND the blob
/// begins with `MULTISIG_TAG`. False for any 33-byte input (legacy
/// P2PKH) and for any malformed length.
pub fn looks_like_multisig_blob(pubkey_compressed: &[u8]) -> bool {
    if pubkey_compressed.len() < MULTISIG_MIN_BLOB || pubkey_compressed.len() > MULTISIG_MAX_BLOB {
        return false;
    }
    &pubkey_compressed[..MULTISIG_TAG.len()] == MULTISIG_TAG
}

/// Validate a k-of-n multisig spend.
///
/// `signing_digest` is the SCAM-domain-separated sighash that
/// individual signers signed. `signature_blob` is the concatenation
/// of `k` 64-byte Schnorr signatures.
///
/// Returns `Ok(())` iff:
/// - `signature_blob.len() == k * 64`.
/// - Each of the `k` signatures Schnorr-verifies against a pubkey from the
///   descriptor, in strictly increasing descriptor order (so no pubkey is
///   used twice and at most `n` verifications are performed).
pub fn verify_multisig_spend(
    descriptor: &MultisigDescriptor,
    signing_digest: Hash256,
    signature_blob: &[u8],
) -> Result<(), MultisigError> {
    let expected = (descriptor.k as usize) * SIG_LEN;
    if signature_blob.len() != expected {
        return Err(MultisigError::BadSignatureLength {
            expected,
            got: signature_blob.len(),
        });
    }
    let secp = Secp256k1::verification_only();
    let message =
        Message::from_digest_slice(&signing_digest.0).map_err(|_| MultisigError::BadDigest)?;

    // Signatures must follow descriptor order: each signature is matched
    // against the remaining pubkeys after the previous match. That makes
    // the witness canonical and caps the work at `n` verifications.
    let mut next_pubkey = 0usize;
    let mut matched_keys = Vec::with_capacity(descriptor.k as usize);
    for sig_idx in 0..(descriptor.k as usize) {
        let raw = &signature_blob[sig_idx * SIG_LEN..(sig_idx + 1) * SIG_LEN];
        let signature = Signature::from_slice(raw)
            .map_err(|_| MultisigError::InvalidSignatureEncoding { sig_index: sig_idx })?;
        // Leave room for the signatures still to come.
        let remaining_sigs = descriptor.k as usize - sig_idx - 1;
        let last_candidate = descriptor.pubkeys.len().saturating_sub(remaining_sigs);
        let mut matched = None;
        while next_pubkey < last_candidate {
            let pk_idx = next_pubkey;
            next_pubkey += 1;
            let Ok(parsed) = PublicKey::from_slice(&descriptor.pubkeys[pk_idx]) else {
                // Already-validated in parse(); double-check for safety.
                continue;
            };
            let (xonly, _) = parsed.x_only_public_key();
            // Defense in depth for descriptors not produced by `parse`:
            // one x-only signer never fills two slots.
            if matched_keys.contains(&xonly) {
                continue;
            }
            if secp.verify_schnorr(&signature, &message, &xonly).is_ok() {
                matched = Some(xonly);
                break;
            }
        }
        match matched {
            Some(xonly) => matched_keys.push(xonly),
            None => return Err(MultisigError::SignatureUnmatched { sig_index: sig_idx }),
        }
    }
    Ok(())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MultisigError {
    #[error("multisig blob length {got} out of range")]
    BadLength { got: usize },
    #[error("multisig blob is missing the SCAM-multisig-v1 tag prefix")]
    BadTag,
    #[error("multisig n must be in 1..={MAX_PARTICIPANTS}, got {n}")]
    InvalidN { n: usize },
    #[error("multisig k must be in 1..=n (got k={k}, n={n})")]
    InvalidK { k: u8, n: u8 },
    #[error("pubkey #{index} is not a valid secp256k1 point")]
    InvalidPubkey { index: usize },
    #[error("pubkey #{index} duplicates an earlier pubkey")]
    DuplicatePubkey { index: usize },
    #[error("signature blob length: expected {expected}, got {got}")]
    BadSignatureLength { expected: usize, got: usize },
    #[error("signing digest could not be turned into a 32-byte message")]
    BadDigest,
    #[error("signature #{sig_index} is not a valid 64-byte Schnorr signature")]
    InvalidSignatureEncoding { sig_index: usize },
    #[error("signature #{sig_index} did not verify against any unused pubkey")]
    SignatureUnmatched { sig_index: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SecretKey};

    fn keypair_from_seed(seed: u8) -> (Keypair, [u8; PUBKEY_LEN]) {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).expect("valid seed");
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let pubkey = PublicKey::from_secret_key(&secp, &secret).serialize();
        (keypair, pubkey)
    }

    fn sign(keypair: &Keypair, digest: Hash256) -> [u8; SIG_LEN] {
        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(&digest.0).expect("message");
        let sig = secp.sign_schnorr_no_aux_rand(&message, keypair);
        let mut out = [0u8; SIG_LEN];
        out.copy_from_slice(sig.as_ref());
        out
    }

    #[test]
    fn looks_like_multisig_blob_distinguishes_p2pkh() {
        // A 33-byte legacy pubkey is not multisig regardless of bytes.
        assert!(!looks_like_multisig_blob(&[0x02; 33]));
        assert!(!looks_like_multisig_blob(&[0x03; 33]));
        // A multisig blob is recognized.
        let (_, pk) = keypair_from_seed(1);
        let blob = MultisigDescriptor::encode(1, &[pk]).expect("encode 1-of-1");
        assert!(looks_like_multisig_blob(&blob));
        // Random fat blob without the tag is not multisig.
        assert!(!looks_like_multisig_blob(&[0xaa; 100]));
    }

    #[test]
    fn encode_then_parse_roundtrip_preserves_descriptor() {
        let (_, pk_a) = keypair_from_seed(2);
        let (_, pk_b) = keypair_from_seed(3);
        let (_, pk_c) = keypair_from_seed(4);
        let blob = MultisigDescriptor::encode(2, &[pk_a, pk_b, pk_c]).expect("encode 2-of-3");
        let d = MultisigDescriptor::parse(&blob).expect("parse");
        assert_eq!(d.k, 2);
        assert_eq!(d.n, 3);
        assert_eq!(d.pubkeys, vec![pk_a, pk_b, pk_c]);
    }

    #[test]
    fn encode_rejects_k_zero_or_above_n() {
        let (_, pk_a) = keypair_from_seed(5);
        assert!(matches!(
            MultisigDescriptor::encode(0, &[pk_a]),
            Err(MultisigError::InvalidK { .. })
        ));
        assert!(matches!(
            MultisigDescriptor::encode(2, &[pk_a]),
            Err(MultisigError::InvalidK { .. })
        ));
    }

    #[test]
    fn encode_rejects_duplicate_pubkeys() {
        let (_, pk_a) = keypair_from_seed(6);
        assert!(matches!(
            MultisigDescriptor::encode(2, &[pk_a, pk_a]),
            Err(MultisigError::DuplicatePubkey { .. })
        ));
    }

    #[test]
    fn parse_rejects_blob_too_small_or_missing_tag() {
        assert!(matches!(
            MultisigDescriptor::parse(&[0u8; 10]),
            Err(MultisigError::BadLength { .. })
        ));
        let mut blob = MultisigDescriptor::encode(1, &[keypair_from_seed(7).1]).expect("encode");
        blob[0] = blob[0].wrapping_add(1); // tamper tag
        assert!(matches!(
            MultisigDescriptor::parse(&blob),
            Err(MultisigError::BadTag)
        ));
    }

    #[test]
    fn parse_rejects_blob_with_wrong_tail_length() {
        let (_, pk_a) = keypair_from_seed(8);
        let mut blob = MultisigDescriptor::encode(1, &[pk_a]).expect("encode");
        blob.push(0xFF); // extra byte
        assert!(matches!(
            MultisigDescriptor::parse(&blob),
            Err(MultisigError::BadLength { .. })
        ));
    }

    #[test]
    fn parse_rejects_invalid_curve_point_in_pubkey_slot() {
        // Build a blob with one valid + one all-zero (invalid) pubkey.
        let (_, valid) = keypair_from_seed(9);
        let mut blob = Vec::new();
        blob.extend_from_slice(MULTISIG_TAG);
        blob.push(1); // k
        blob.push(2); // n
        blob.extend_from_slice(&valid);
        blob.extend_from_slice(&[0u8; PUBKEY_LEN]); // invalid
        assert!(matches!(
            MultisigDescriptor::parse(&blob),
            Err(MultisigError::InvalidPubkey { .. })
        ));
    }

    #[test]
    fn verify_multisig_spend_2_of_3_happy_path() {
        let (kp_a, pk_a) = keypair_from_seed(10);
        let (_, pk_b) = keypair_from_seed(11);
        let (kp_c, pk_c) = keypair_from_seed(12);
        let blob = MultisigDescriptor::encode(2, &[pk_a, pk_b, pk_c]).expect("encode");
        let d = MultisigDescriptor::parse(&blob).expect("parse");
        let digest = Hash256([0x33; 32]);
        let sig_a = sign(&kp_a, digest);
        let sig_c = sign(&kp_c, digest);
        let mut sigs = Vec::with_capacity(128);
        sigs.extend_from_slice(&sig_a);
        sigs.extend_from_slice(&sig_c);
        verify_multisig_spend(&d, digest, &sigs).expect("2-of-3 must verify");
    }

    #[test]
    fn verify_multisig_spend_rejects_wrong_digest() {
        let (kp_a, pk_a) = keypair_from_seed(13);
        let (_, pk_b) = keypair_from_seed(14);
        let blob = MultisigDescriptor::encode(1, &[pk_a, pk_b]).expect("encode 1-of-2");
        let d = MultisigDescriptor::parse(&blob).expect("parse");
        let digest = Hash256([0x44; 32]);
        let other_digest = Hash256([0x55; 32]);
        let sig = sign(&kp_a, digest);
        assert!(matches!(
            verify_multisig_spend(&d, other_digest, &sig),
            Err(MultisigError::SignatureUnmatched { .. })
        ));
    }

    #[test]
    fn verify_multisig_spend_rejects_signature_reuse_against_same_pubkey() {
        // 2-of-2 with both sigs from key A — should fail because pubkey
        // can only count once.
        let (kp_a, pk_a) = keypair_from_seed(15);
        let (_, pk_b) = keypair_from_seed(16);
        let blob = MultisigDescriptor::encode(2, &[pk_a, pk_b]).expect("encode 2-of-2");
        let d = MultisigDescriptor::parse(&blob).expect("parse");
        let digest = Hash256([0x66; 32]);
        let sig_a = sign(&kp_a, digest);
        let mut sigs = Vec::with_capacity(128);
        sigs.extend_from_slice(&sig_a);
        sigs.extend_from_slice(&sig_a); // duplicate
        assert!(matches!(
            verify_multisig_spend(&d, digest, &sigs),
            Err(MultisigError::SignatureUnmatched { .. })
        ));
    }

    /// `02||X` and `03||X` are distinct 33-byte encodings of keys that
    /// share the x-only key `X`, and BIP340 verification only looks at `X`.
    /// Before the fix the holder of `X` could fill two slots of a k-of-n
    /// with one signature, e.g. satisfy a "2-of-3 escrow" alone.
    #[test]
    fn xonly_aliased_pubkeys_are_rejected_as_duplicates() {
        let (kp_a, pk_a) = keypair_from_seed(40);
        let (_, pk_b) = keypair_from_seed(41);
        let mut alias = pk_a;
        alias[0] = if pk_a[0] == 0x02 { 0x03 } else { 0x02 };
        assert!(
            PublicKey::from_slice(&alias).is_ok(),
            "alias is a valid point"
        );

        assert!(matches!(
            MultisigDescriptor::encode(2, &[pk_a, alias, pk_b]),
            Err(MultisigError::DuplicatePubkey { index: 1 })
        ));

        let mut blob = Vec::new();
        blob.extend_from_slice(MULTISIG_TAG);
        blob.push(2);
        blob.push(3);
        blob.extend_from_slice(&pk_a);
        blob.extend_from_slice(&alias);
        blob.extend_from_slice(&pk_b);
        assert!(matches!(
            MultisigDescriptor::parse(&blob),
            Err(MultisigError::DuplicatePubkey { index: 1 })
        ));

        // And the one-key-two-slots spend itself must not verify even if a
        // descriptor were constructed by hand.
        let d = MultisigDescriptor {
            k: 2,
            n: 3,
            pubkeys: vec![pk_a, alias, pk_b],
        };
        let digest = Hash256([0x21; 32]);
        let sig = sign(&kp_a, digest);
        let mut sigs = Vec::new();
        sigs.extend_from_slice(&sig);
        sigs.extend_from_slice(&sig);
        assert!(verify_multisig_spend(&d, digest, &sigs).is_err());
    }

    /// Signatures must appear in descriptor order. This bounds verification
    /// to at most `n` Schnorr checks per input (instead of `k * n`) and makes
    /// the witness canonical.
    #[test]
    fn verify_multisig_spend_rejects_out_of_order_signatures() {
        let (kp_a, pk_a) = keypair_from_seed(42);
        let (_, pk_b) = keypair_from_seed(43);
        let (kp_c, pk_c) = keypair_from_seed(44);
        let blob = MultisigDescriptor::encode(2, &[pk_a, pk_b, pk_c]).expect("encode");
        let d = MultisigDescriptor::parse(&blob).expect("parse");
        let digest = Hash256([0x22; 32]);
        let sig_a = sign(&kp_a, digest);
        let sig_c = sign(&kp_c, digest);
        let mut reversed = Vec::new();
        reversed.extend_from_slice(&sig_c);
        reversed.extend_from_slice(&sig_a);
        assert!(matches!(
            verify_multisig_spend(&d, digest, &reversed),
            Err(MultisigError::SignatureUnmatched { .. })
        ));
    }

    #[test]
    fn verify_multisig_spend_rejects_wrong_signature_blob_length() {
        let (_, pk_a) = keypair_from_seed(17);
        let (_, pk_b) = keypair_from_seed(18);
        let blob = MultisigDescriptor::encode(2, &[pk_a, pk_b]).expect("encode");
        let d = MultisigDescriptor::parse(&blob).expect("parse");
        let digest = Hash256([0x77; 32]);
        // Only 1 sig provided for a 2-of-2 → length mismatch.
        let one_sig = [0u8; SIG_LEN];
        assert!(matches!(
            verify_multisig_spend(&d, digest, &one_sig),
            Err(MultisigError::BadSignatureLength { .. })
        ));
    }

    #[test]
    fn script_hash20_is_deterministic_per_blob() {
        let (_, pk_a) = keypair_from_seed(19);
        let (_, pk_b) = keypair_from_seed(20);
        let blob_1 = MultisigDescriptor::encode(2, &[pk_a, pk_b]).expect("encode");
        let blob_2 = MultisigDescriptor::encode(2, &[pk_a, pk_b]).expect("encode again");
        assert_eq!(blob_1, blob_2);
        assert_eq!(
            MultisigDescriptor::script_hash20(&blob_1),
            MultisigDescriptor::script_hash20(&blob_2)
        );
    }

    /// Critical: changing the participant order changes the blob and
    /// thus the script_hash20. Mitigates the "same group, different
    /// canonical order" address ambiguity that bit Bitcoin's
    /// legacy multisig.
    #[test]
    fn script_hash20_changes_with_pubkey_order() {
        let (_, pk_a) = keypair_from_seed(21);
        let (_, pk_b) = keypair_from_seed(22);
        let blob_ab = MultisigDescriptor::encode(2, &[pk_a, pk_b]).expect("encode ab");
        let blob_ba = MultisigDescriptor::encode(2, &[pk_b, pk_a]).expect("encode ba");
        assert_ne!(blob_ab, blob_ba);
        assert_ne!(
            MultisigDescriptor::script_hash20(&blob_ab),
            MultisigDescriptor::script_hash20(&blob_ba),
            "different participant order must yield different addresses; \
             wallet code should sort canonically before encode"
        );
    }
}
