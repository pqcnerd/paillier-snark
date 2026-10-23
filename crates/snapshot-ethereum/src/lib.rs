//! Ethereum snapshot builder for mock ERC-20 GOV balances.
//!
//! MVP does not require a live RPC: fixtures supply address→balance maps at a
//! finalized block header. EIP-712 enrollment challenge binding is provided.

use ark_bn254::Fr;
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;
use veilgov_domains::{sha256_tagged, tags};
use veilgov_encoding::Digest32;
use veilgov_snapshot_core::{
    build_snapshot, eth_snapshot_leaf, BuiltSnapshot, ChainKind, SnapshotError,
};

#[derive(Debug, Error)]
pub enum EthError {
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("address mismatch")]
    AddressMismatch,
    #[error("{0}")]
    Msg(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthFinalizedHeader {
    pub chain_id: u64,
    pub genesis_hash: [u8; 32],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthHolder {
    pub address: [u8; 20],
    pub balance: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthTokenAdapter {
    pub token_address: [u8; 20],
    pub decimals: u8,
    pub balance_mapping_slot: u64,
    /// Raw balance (not delegated votes).
    pub weight_policy: String,
}

impl EthTokenAdapter {
    pub fn mock_gov() -> Self {
        let mut token = [0u8; 20];
        token[19] = 0x60; // mock GOV token address suffix
        Self {
            token_address: token,
            decimals: 18,
            balance_mapping_slot: 0,
            weight_policy: "raw_balance".into(),
        }
    }
}

pub fn weight_policy_hash(adapter: &EthTokenAdapter) -> [u8; 32] {
    *sha256_tagged(tags::SCOPE, adapter.weight_policy.as_bytes()).as_bytes()
}

pub fn build_eth_snapshot(
    election_id: [u8; 32],
    header: &EthFinalizedHeader,
    adapter: &EthTokenAdapter,
    holders: &[EthHolder],
) -> Result<BuiltSnapshot, EthError> {
    let policy = weight_policy_hash(adapter);
    let mut rows = Vec::new();
    for h in holders {
        let leaf = eth_snapshot_leaf(
            &election_id,
            header.chain_id,
            &header.block_hash,
            &adapter.token_address,
            &h.address,
            h.balance,
        );
        rows.push((h.address.to_vec(), h.balance, leaf));
    }
    Ok(build_snapshot(
        ChainKind::Ethereum,
        election_id,
        header.genesis_hash,
        Some(header.chain_id),
        header.block_number,
        header.block_hash,
        adapter.token_address.to_vec(),
        policy,
        rows,
    )?)
}

/// EIP-712-like enrollment digest (simplified typed data for MVP).
pub fn enrollment_digest(
    chain_id: u64,
    verifying_contract: &[u8; 20],
    scope: &Digest32,
    account_commitment: &[u8; 32],
    nonce: u64,
    expiry: u64,
) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(tags::ENROLL_ETH.as_bytes());
    payload.extend_from_slice(&chain_id.to_be_bytes());
    payload.extend_from_slice(verifying_contract);
    payload.extend_from_slice(scope.as_bytes());
    payload.extend_from_slice(account_commitment);
    payload.extend_from_slice(&nonce.to_be_bytes());
    payload.extend_from_slice(&expiry.to_be_bytes());
    let mut h = Keccak256::new();
    h.update(&payload);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

pub fn sign_enrollment(sk: &SigningKey, digest: &[u8; 32]) -> Signature {
    sk.sign_prehash(digest).expect("sign")
}

pub fn address_from_verifying_key(vk: &VerifyingKey) -> [u8; 20] {
    let point = vk.as_affine();
    use k256::elliptic_curve::sec1::ToEncodedPoint as _;
    let enc = point.to_encoded_point(false);
    let bytes = enc.as_bytes(); // 0x04 || X || Y
    let mut h = Keccak256::new();
    h.update(&bytes[1..]);
    let hash = h.finalize();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

pub fn verify_enrollment(
    address: &[u8; 20],
    digest: &[u8; 32],
    sig: &Signature,
) -> Result<(), EthError> {
    use k256::ecdsa::RecoveryId;
    use k256::ecdsa::VerifyingKey as Vk;
    // Try both recovery ids.
    for rid in [0u8, 1u8] {
        if let Some(rec_id) = RecoveryId::from_byte(rid) {
            if let Ok(vk) = Vk::recover_from_prehash(digest, sig, rec_id) {
                let got = address_from_verifying_key(&vk);
                if &got == address {
                    return Ok(());
                }
            }
        }
    }
    Err(EthError::InvalidSignature)
}

pub fn leaf_for_holder(
    election_id: &[u8; 32],
    header: &EthFinalizedHeader,
    adapter: &EthTokenAdapter,
    holder: &EthHolder,
) -> Fr {
    eth_snapshot_leaf(
        election_id,
        header.chain_id,
        &header.block_hash,
        &adapter.token_address,
        &holder.address,
        holder.balance,
    )
}

pub fn demo_header() -> EthFinalizedHeader {
    EthFinalizedHeader {
        chain_id: 31337,
        genesis_hash: [0x11; 32],
        block_number: 100,
        block_hash: [0x22; 32],
        state_root: [0x33; 32],
        timestamp: 1_700_000_000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_alice_bob() {
        let header = demo_header();
        let adapter = EthTokenAdapter::mock_gov();
        let holders = vec![
            EthHolder {
                address: [0xA1; 20],
                balance: 60,
            },
            EthHolder {
                address: [0xB1; 20],
                balance: 20,
            },
        ];
        let snap = build_eth_snapshot([9u8; 32], &header, &adapter, &holders).unwrap();
        assert_eq!(snap.manifest.leaf_count, 2);
        assert_eq!(snap.manifest.total_weight, 80);
    }

    #[test]
    fn enrollment_sign_verify() {
        let sk = SigningKey::random(&mut rand::rngs::OsRng);
        let addr = address_from_verifying_key(&sk.verifying_key());
        let scope = Digest32([5u8; 32]);
        let commit = [6u8; 32];
        let digest = enrollment_digest(31337, &[7u8; 20], &scope, &commit, 1, 999);
        let sig = sign_enrollment(&sk, &digest);
        verify_enrollment(&addr, &digest, &sig).unwrap();
    }
}
