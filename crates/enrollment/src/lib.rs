//! Enrollment registrar: one-account-one-credential (quorum-enforced).

use ark_bn254::Fr;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
use veilgov_domains::fr_to_bytes;
use veilgov_encoding::Digest32;
use veilgov_identity::registration_uniqueness_key;
use veilgov_merkle::{default_depth, PoseidonTree};
use veilgov_snapshot_core::credential_leaf;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnrollmentError {
    #[error("account already enrolled in this scope")]
    DuplicateAccount,
    #[error("nonce replay")]
    NonceReplay,
    #[error("expired")]
    Expired,
    #[error("request commitment encoding mismatch")]
    CommitmentMismatch,
    #[error("request snapshot leaf encoding mismatch")]
    SnapshotLeafMismatch,
    #[error("{0}")]
    Msg(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub scope: Digest32,
    pub chain_tag: u64,
    pub owner: Vec<u8>,
    pub amount: u64,
    pub account_commitment: [u8; 32],
    pub snapshot_leaf: [u8; 32],
    pub nonce: u64,
    pub expiry_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuedCredential {
    pub request: EnrollmentRequest,
    pub credential_leaf: [u8; 32],
}

#[derive(Default)]
pub struct RegistrarState {
    uniqueness: HashSet<[u8; 32]>,
    used_nonces: HashSet<(Vec<u8>, u64)>,
    pending: Vec<IssuedCredential>,
}

impl RegistrarState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enroll(
        &mut self,
        req: EnrollmentRequest,
        account_commitment_fr: Fr,
        snapshot_leaf_fr: Fr,
        now_unix: u64,
    ) -> Result<IssuedCredential, EnrollmentError> {
        if now_unix > req.expiry_unix {
            return Err(EnrollmentError::Expired);
        }
        if req.account_commitment != fr_to_bytes(&account_commitment_fr) {
            return Err(EnrollmentError::CommitmentMismatch);
        }
        if req.snapshot_leaf != fr_to_bytes(&snapshot_leaf_fr) {
            return Err(EnrollmentError::SnapshotLeafMismatch);
        }
        let u = registration_uniqueness_key(&req.scope, &req.owner);
        if !self.uniqueness.insert(*u.as_bytes()) {
            return Err(EnrollmentError::DuplicateAccount);
        }
        let nonce_key = (req.owner.clone(), req.nonce);
        if !self.used_nonces.insert(nonce_key) {
            return Err(EnrollmentError::NonceReplay);
        }
        let leaf = credential_leaf(
            req.scope.as_bytes(),
            req.chain_tag,
            &req.owner,
            req.amount,
            account_commitment_fr,
            snapshot_leaf_fr,
        );
        let issued = IssuedCredential {
            request: req,
            credential_leaf: fr_to_bytes(&leaf),
        };
        self.pending.push(issued.clone());
        Ok(issued)
    }

    /// Shuffle pending credentials and build a Poseidon credential root.
    pub fn seal_batch(&mut self, rng: &mut impl Rng) -> Result<(PoseidonTree, Vec<IssuedCredential>), EnrollmentError> {
        if self.pending.is_empty() {
            return Err(EnrollmentError::Msg("empty batch".into()));
        }
        let mut batch = std::mem::take(&mut self.pending);
        batch.shuffle(rng);
        let leaves: Vec<Fr> = batch
            .iter()
            .map(|c| veilgov_domains::bytes_to_fr(&c.credential_leaf))
            .collect();
        let tree = PoseidonTree::with_leaves(default_depth(), &leaves)
            .map_err(|e| EnrollmentError::Msg(e.to_string()))?;
        Ok((tree, batch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn rejects_duplicate_account() {
        let mut reg = RegistrarState::new();
        let scope = Digest32([1u8; 32]);
        let commitment = Fr::from(2u64);
        let snapshot_leaf = Fr::from(3u64);
        let req = EnrollmentRequest {
            scope: scope.clone(),
            chain_tag: 1,
            owner: vec![0xAA; 20],
            amount: 60,
            account_commitment: fr_to_bytes(&commitment),
            snapshot_leaf: fr_to_bytes(&snapshot_leaf),
            nonce: 1,
            expiry_unix: 100,
        };
        reg.enroll(req.clone(), commitment, snapshot_leaf, 50)
            .unwrap();
        let mut req2 = req;
        req2.nonce = 2;
        let replacement_commitment = Fr::from(9u64);
        req2.account_commitment = fr_to_bytes(&replacement_commitment);
        assert_eq!(
            reg.enroll(req2, replacement_commitment, snapshot_leaf, 50)
                .unwrap_err(),
            EnrollmentError::DuplicateAccount
        );
    }

    #[test]
    fn seal_batch_shuffles() {
        let mut reg = RegistrarState::new();
        for i in 0..4u8 {
            let commitment = Fr::from(i as u64);
            let snapshot_leaf = Fr::from(i as u64);
            let req = EnrollmentRequest {
                scope: Digest32([i; 32]),
                chain_tag: 1,
                owner: vec![i; 20],
                amount: 10,
                account_commitment: fr_to_bytes(&commitment),
                snapshot_leaf: fr_to_bytes(&snapshot_leaf),
                nonce: 1,
                expiry_unix: 100,
            };
            reg.enroll(req, commitment, snapshot_leaf, 1)
                .unwrap();
        }
        let mut rng = StdRng::seed_from_u64(0);
        let (tree, batch) = reg.seal_batch(&mut rng).unwrap();
        assert_eq!(batch.len(), 4);
        assert_ne!(tree.root_bytes(), [0u8; 32]);
    }
}
