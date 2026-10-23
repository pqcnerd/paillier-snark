//! Solana SPL token snapshot builder.
//!
//! IMPORTANT: Standard Solana RPC does not provide portable Ethereum-style
//! account inclusion proofs. MVP snapshots are **quorum-attested** over
//! retained finalized-bank fixtures, not trustlessly state-proven.

use ark_bn254::Fr;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use veilgov_domains::{sha256_tagged, tags};
use veilgov_encoding::Digest32;
use veilgov_snapshot_core::{
    build_snapshot, sol_snapshot_leaf, BuiltSnapshot, ChainKind, SnapshotError,
};

pub const SOLANA_TRUST_NOTE: &str =
    "Solana snapshot roots are quorum-attested over retained finalized-bank data; \
     not trustlessly state-proven via a global inclusion proof.";

#[derive(Debug, Error)]
pub enum SolError {
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("{0}")]
    Msg(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolFinalizedBank {
    pub genesis_hash: [u8; 32],
    pub slot: u64,
    pub blockhash: [u8; 32],
    pub rpc_identity: [u8; 32],
    pub retained_artifact_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SplHolder {
    /// Token authority pubkey (32 bytes).
    pub authority: [u8; 32],
    /// Aggregated raw amount across all token accounts for this mint+authority.
    pub amount: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SplTokenAdapter {
    pub mint: [u8; 32],
    pub token_program: [u8; 32],
    pub weight_policy: String,
}

impl SplTokenAdapter {
    pub fn mock_gov() -> Self {
        let mut mint = [0u8; 32];
        mint[31] = 0x50;
        let mut prog = [0u8; 32];
        prog[31] = 0x06; // placeholder Tokenkeg-like suffix
        Self {
            mint,
            token_program: prog,
            weight_policy: "raw_spl_amount_aggregated".into(),
        }
    }
}

pub fn weight_policy_hash(adapter: &SplTokenAdapter) -> [u8; 32] {
    *sha256_tagged(tags::SCOPE, adapter.weight_policy.as_bytes()).as_bytes()
}

pub fn build_sol_snapshot(
    election_id: [u8; 32],
    bank: &SolFinalizedBank,
    adapter: &SplTokenAdapter,
    holders: &[SplHolder],
) -> Result<BuiltSnapshot, SolError> {
    let policy = weight_policy_hash(adapter);
    let mut rows = Vec::new();
    for h in holders {
        let leaf = sol_snapshot_leaf(
            &election_id,
            &bank.genesis_hash,
            bank.slot,
            &adapter.mint,
            &h.authority,
            h.amount,
        );
        rows.push((h.authority.to_vec(), h.amount, leaf));
    }
    Ok(build_snapshot(
        ChainKind::Solana,
        election_id,
        bank.genesis_hash,
        None,
        bank.slot,
        bank.blockhash,
        adapter.mint.to_vec(),
        policy,
        rows,
    )?)
}

pub fn enrollment_message(
    cluster_genesis: &[u8; 32],
    program_id: &[u8; 32],
    scope: &Digest32,
    account_commitment: &[u8; 32],
    nonce: u64,
    expiry: u64,
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(tags::ENROLL_SOL.as_bytes());
    msg.extend_from_slice(cluster_genesis);
    msg.extend_from_slice(program_id);
    msg.extend_from_slice(scope.as_bytes());
    msg.extend_from_slice(account_commitment);
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg.extend_from_slice(&expiry.to_be_bytes());
    // Domain-separated hash for fixed-size signing convenience.
    let digest = Sha256::digest(&msg);
    digest.to_vec()
}

pub fn sign_enrollment(sk: &SigningKey, message: &[u8]) -> Signature {
    sk.sign(message)
}

pub fn verify_enrollment(
    vk: &VerifyingKey,
    message: &[u8],
    sig: &Signature,
) -> Result<(), SolError> {
    vk.verify(message, sig)
        .map_err(|_| SolError::InvalidSignature)
}

pub fn leaf_for_holder(
    election_id: &[u8; 32],
    bank: &SolFinalizedBank,
    adapter: &SplTokenAdapter,
    holder: &SplHolder,
) -> Fr {
    sol_snapshot_leaf(
        election_id,
        &bank.genesis_hash,
        bank.slot,
        &adapter.mint,
        &holder.authority,
        holder.amount,
    )
}

pub fn demo_bank() -> SolFinalizedBank {
    SolFinalizedBank {
        genesis_hash: [0x44; 32],
        slot: 50_000,
        blockhash: [0x55; 32],
        rpc_identity: [0x66; 32],
        retained_artifact_hash: [0x77; 32],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn snapshot_alice_bob() {
        let bank = demo_bank();
        let adapter = SplTokenAdapter::mock_gov();
        let holders = vec![
            SplHolder {
                authority: [0xA2; 32],
                amount: 40,
            },
            SplHolder {
                authority: [0xB2; 32],
                amount: 30,
            },
        ];
        let snap = build_sol_snapshot([9u8; 32], &bank, &adapter, &holders).unwrap();
        assert_eq!(snap.manifest.total_weight, 70);
        assert!(SOLANA_TRUST_NOTE.contains("quorum-attested"));
    }

    #[test]
    fn enrollment_sign_verify() {
        let sk = SigningKey::generate(&mut OsRng);
        let scope = Digest32([1u8; 32]);
        let msg = enrollment_message(&[2u8; 32], &[3u8; 32], &scope, &[4u8; 32], 1, 9);
        let sig = sign_enrollment(&sk, &msg);
        verify_enrollment(&sk.verifying_key(), &msg, &sig).unwrap();
    }
}
