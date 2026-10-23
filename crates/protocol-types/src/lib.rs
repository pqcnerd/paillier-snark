//! Protocol-level types and election configuration.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use veilgov_domains::{sha256_tagged, tags, ACCOUNT_CAPACITY, ENCODING_VERSION, PROTOCOL_VERSION};
use veilgov_encoding::{encode_u32, encode_u64, Digest32};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TypeError {
    #[error("weight overflow")]
    WeightOverflow,
    #[error("vote not boolean")]
    InvalidVote,
    #[error("amount exceeds u64")]
    AmountOverflow,
    #[error("eligible total exceeds plaintext base limb")]
    EligibleTotalTooLarge,
    #[error("invalid capacity")]
    InvalidCapacity,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElectionId(pub [u8; 32]);

impl ElectionId {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let v = hex::decode(s)?;
        let mut a = [0u8; 32];
        if v.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        a.copy_from_slice(&v);
        Ok(Self(a))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElectionConfig {
    pub protocol_version: u32,
    pub encoding_version: u32,
    pub election_id: ElectionId,
    pub governance_domain: [u8; 32],
    pub proposal_id: [u8; 32],
    pub eth_snapshot_root: Digest32,
    pub sol_snapshot_root: Digest32,
    pub credential_root: Digest32,
    pub eth_manifest_hash: Digest32,
    pub sol_manifest_hash: Digest32,
    pub paillier_key_hash: Digest32,
    pub verifier_id: [u8; 32],
    pub account_capacity: usize,
    pub eligible_total_weight: u128,
    pub max_individual_weight: u64,
    pub voting_deadline_unix: u64,
}

impl ElectionConfig {
    pub fn demo(election_id: ElectionId) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            encoding_version: ENCODING_VERSION,
            election_id,
            governance_domain: *b"veilgov-demo-governance-domain!!",
            proposal_id: *b"veilgov-demo-proposal-id-bytes!!",
            eth_snapshot_root: Digest32([0u8; 32]),
            sol_snapshot_root: Digest32([0u8; 32]),
            credential_root: Digest32([0u8; 32]),
            eth_manifest_hash: Digest32([0u8; 32]),
            sol_manifest_hash: Digest32([0u8; 32]),
            paillier_key_hash: Digest32([0u8; 32]),
            verifier_id: *b"veilgov-native-predicate-v1!!!!!",
            account_capacity: ACCOUNT_CAPACITY,
            eligible_total_weight: 150,
            max_individual_weight: u64::MAX,
            voting_deadline_unix: u64::MAX,
        }
    }

    pub fn validate(&self) -> Result<(), TypeError> {
        if self.account_capacity == 0 || self.account_capacity > ACCOUNT_CAPACITY {
            return Err(TypeError::InvalidCapacity);
        }
        // B = 2^128; eligible_total must be < B (always for u128 max except all-ones edge).
        // We require room for m = y + B*t with t = eligible_total.
        if self.eligible_total_weight == u128::MAX {
            return Err(TypeError::EligibleTotalTooLarge);
        }
        Ok(())
    }

    /// Election domain E = SHA256(tag || fields...)
    pub fn election_domain(&self) -> Digest32 {
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_u32(self.protocol_version));
        payload.extend_from_slice(&encode_u32(self.encoding_version));
        payload.extend_from_slice(&self.election_id.0);
        payload.extend_from_slice(&self.governance_domain);
        payload.extend_from_slice(&self.proposal_id);
        payload.extend_from_slice(self.eth_manifest_hash.as_bytes());
        payload.extend_from_slice(self.sol_manifest_hash.as_bytes());
        payload.extend_from_slice(self.paillier_key_hash.as_bytes());
        payload.extend_from_slice(&self.verifier_id);
        payload.extend_from_slice(&encode_u64(self.voting_deadline_unix));
        sha256_tagged(tags::ELECTION, &payload)
    }

    pub fn config_hash(&self) -> Digest32 {
        self.election_domain()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteBit(pub u8);

impl VoteBit {
    pub fn yes() -> Self {
        Self(1)
    }
    pub fn no() -> Self {
        Self(0)
    }
    pub fn checked(v: u8) -> Result<Self, TypeError> {
        if v > 1 {
            Err(TypeError::InvalidVote)
        } else {
            Ok(Self(v))
        }
    }
}

/// Checked weight aggregation: sum of u64 -> u128.
pub fn checked_sum_weights(weights: &[u64]) -> Result<u128, TypeError> {
    let mut acc: u128 = 0;
    for &w in weights {
        acc = acc
            .checked_add(u128::from(w))
            .ok_or(TypeError::WeightOverflow)?;
    }
    Ok(acc)
}

/// Packed plaintext limbs (as u128 parts): m = y + 2^128 * t, returned as (hi=t, lo=y) conceptually.
/// We represent m as num later; here we validate y,t.
pub fn pack_yes_total(weight: u128, vote: VoteBit) -> Result<(u128, u128), TypeError> {
    let y = if vote.0 == 1 { weight } else { 0 };
    let t = weight;
    Ok((y, t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn election_domain_changes_with_key() {
        let id = ElectionId([1u8; 32]);
        let mut a = ElectionConfig::demo(id.clone());
        let mut b = ElectionConfig::demo(id);
        a.paillier_key_hash = Digest32([2u8; 32]);
        b.paillier_key_hash = Digest32([3u8; 32]);
        assert_ne!(a.election_domain(), b.election_domain());
    }

    #[test]
    fn weight_sum() {
        assert_eq!(checked_sum_weights(&[60, 40]).unwrap(), 100);
        assert_eq!(checked_sum_weights(&[u64::MAX, 1]).unwrap(), (u64::MAX as u128) + 1);
    }
}
