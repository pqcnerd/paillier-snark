//! Deterministic snapshot manifests and Poseidon trees.

use ark_bn254::Fr;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use veilgov_domains::{
    bytes_to_fr, fr_to_bytes, hash_tagged, sha256_raw, tags,
};
use veilgov_encoding::Digest32;
use veilgov_merkle::{default_depth, PoseidonTree};

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("duplicate owner")]
    DuplicateOwner,
    #[error("quorum not met")]
    QuorumNotMet,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("empty snapshot")]
    Empty,
    #[error("{0}")]
    Msg(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChainKind {
    Ethereum,
    Solana,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub owner: Vec<u8>,
    pub amount: u64,
    pub leaf: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub chain: ChainKind,
    pub election_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub chain_id: Option<u64>,
    pub height_or_slot: u64,
    pub block_hash: [u8; 32],
    pub asset_id: Vec<u8>,
    pub weight_policy_hash: [u8; 32],
    pub leaf_count: u64,
    pub total_weight: u128,
    pub root: [u8; 32],
    pub artifact_digest: [u8; 32],
    pub builder_version: u32,
}

impl SnapshotManifest {
    pub fn digest(&self) -> Digest32 {
        let bytes = serde_json::to_vec(self).expect("manifest serialize");
        // Manifest digest uses SHA256 over canonical JSON for MVP operator signatures.
        // Leaf trees remain Poseidon.
        sha256_raw(&bytes)
    }
}

pub fn eth_snapshot_leaf(
    election_id: &[u8; 32],
    chain_id: u64,
    block_hash: &[u8; 32],
    asset_id: &[u8],
    address: &[u8; 20],
    amount: u64,
) -> Fr {
    hash_tagged(
        tags::ETH_SNAPSHOT,
        &[
            bytes_to_fr(election_id),
            Fr::from(chain_id),
            bytes_to_fr(block_hash),
            bytes_to_fr(asset_id),
            bytes_to_fr(address),
            Fr::from(amount),
        ],
    )
}

pub fn sol_snapshot_leaf(
    election_id: &[u8; 32],
    genesis_hash: &[u8; 32],
    slot: u64,
    asset_id: &[u8],
    pubkey: &[u8; 32],
    amount: u64,
) -> Fr {
    let pk0 = bytes_to_fr(&pubkey[..16]);
    let pk1 = bytes_to_fr(&pubkey[16..]);
    hash_tagged(
        tags::SOL_SNAPSHOT,
        &[
            bytes_to_fr(election_id),
            bytes_to_fr(genesis_hash),
            Fr::from(slot),
            bytes_to_fr(asset_id),
            pk0,
            pk1,
            Fr::from(amount),
        ],
    )
}

pub fn credential_leaf(
    scope: &[u8; 32],
    chain_tag: u64,
    owner: &[u8],
    amount: u64,
    account_commitment: Fr,
    snapshot_leaf: Fr,
) -> Fr {
    hash_tagged(
        tags::CREDENTIAL,
        &[
            bytes_to_fr(scope),
            Fr::from(chain_tag),
            bytes_to_fr(owner),
            Fr::from(amount),
            account_commitment,
            snapshot_leaf,
        ],
    )
}

pub struct BuiltSnapshot {
    pub records: Vec<SnapshotRecord>,
    pub tree: PoseidonTree,
    pub manifest: SnapshotManifest,
}

pub fn build_snapshot(
    chain: ChainKind,
    election_id: [u8; 32],
    genesis_hash: [u8; 32],
    chain_id: Option<u64>,
    height_or_slot: u64,
    block_hash: [u8; 32],
    asset_id: Vec<u8>,
    weight_policy_hash: [u8; 32],
    mut owners_amounts: Vec<(Vec<u8>, u64, Fr)>,
) -> Result<BuiltSnapshot, SnapshotError> {
    if owners_amounts.is_empty() {
        return Err(SnapshotError::Empty);
    }
    owners_amounts.sort_by(|a, b| a.0.cmp(&b.0));
    for w in owners_amounts.windows(2) {
        if w[0].0 == w[1].0 {
            return Err(SnapshotError::DuplicateOwner);
        }
    }
    let mut total: u128 = 0;
    let mut leaves = Vec::new();
    let mut records = Vec::new();
    for (owner, amount, leaf) in owners_amounts {
        total = total
            .checked_add(u128::from(amount))
            .ok_or_else(|| SnapshotError::Msg("weight overflow".into()))?;
        let leaf_bytes = fr_to_bytes(&leaf);
        leaves.push(leaf);
        records.push(SnapshotRecord {
            owner,
            amount,
            leaf: leaf_bytes,
        });
    }
    let tree = PoseidonTree::with_leaves(default_depth(), &leaves)
        .map_err(|e| SnapshotError::Msg(e.to_string()))?;
    let root = tree.root_bytes();
    let mut manifest = SnapshotManifest {
        chain,
        election_id,
        genesis_hash,
        chain_id,
        height_or_slot,
        block_hash,
        asset_id,
        weight_policy_hash,
        leaf_count: records.len() as u64,
        total_weight: total,
        root,
        artifact_digest: [0u8; 32],
        builder_version: 1,
    };
    let art = sha256_raw(&serde_json::to_vec(&records).unwrap());
    manifest.artifact_digest = *art.as_bytes();
    Ok(BuiltSnapshot {
        records,
        tree,
        manifest,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedManifest {
    pub manifest: SnapshotManifest,
    pub signatures: Vec<Vec<u8>>,
}

pub fn sign_manifest(sk: &SigningKey, manifest: &SnapshotManifest) -> Signature {
    let d = manifest.digest();
    sk.sign(d.as_bytes())
}

pub fn verify_quorum(
    operators: &[VerifyingKey],
    signed: &SignedManifest,
    threshold: usize,
) -> Result<(), SnapshotError> {
    if signed.signatures.len() < threshold {
        return Err(SnapshotError::QuorumNotMet);
    }
    let d = signed.manifest.digest();
    let mut ok = 0usize;
    for sig_bytes in &signed.signatures {
        let sig = Signature::from_slice(sig_bytes).map_err(|_| SnapshotError::InvalidSignature)?;
        for vk in operators {
            if vk.verify(d.as_bytes(), &sig).is_ok() {
                ok += 1;
                break;
            }
        }
    }
    if ok < threshold {
        return Err(SnapshotError::QuorumNotMet);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn build_rejects_duplicates() {
        let leaf = Fr::from(1u64);
        let res = build_snapshot(
            ChainKind::Ethereum,
            [1u8; 32],
            [2u8; 32],
            Some(1),
            10,
            [3u8; 32],
            b"gov".to_vec(),
            [4u8; 32],
            vec![(vec![1], 1, leaf), (vec![1], 2, leaf)],
        );
        assert!(matches!(res, Err(SnapshotError::DuplicateOwner)));
    }

    #[test]
    fn quorum_3_of_4() {
        let mut rng = OsRng;
        let keys: Vec<SigningKey> = (0..4).map(|_| SigningKey::generate(&mut rng)).collect();
        let vks: Vec<_> = keys.iter().map(|k| k.verifying_key()).collect();
        let built = build_snapshot(
            ChainKind::Solana,
            [9u8; 32],
            [8u8; 32],
            None,
            100,
            [7u8; 32],
            b"mint".to_vec(),
            [6u8; 32],
            vec![(vec![1, 2, 3], 40, Fr::from(40u64))],
        )
        .unwrap();
        let sigs: Vec<Vec<u8>> = keys[..3]
            .iter()
            .map(|k| sign_manifest(k, &built.manifest).to_bytes().to_vec())
            .collect();
        let signed = SignedManifest {
            manifest: built.manifest,
            signatures: sigs,
        };
        verify_quorum(&vks, &signed, 3).unwrap();
    }
}
