//! Indexed binary Merkle trees (Poseidon for ZK trees, Keccak for EVM ballot root).

use ark_bn254::Fr;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use veilgov_domains::{
    bytes_to_fr, fr_to_bytes, hash_tagged, keccak256_tagged, tags, MERKLE_DEPTH,
};
use veilgov_encoding::Digest32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MerkleError {
    #[error("index out of range")]
    IndexOutOfRange,
    #[error("invalid proof")]
    InvalidProof,
    #[error("tree capacity exceeded")]
    CapacityExceeded,
    #[error("empty tree")]
    EmptyTree,
}

#[derive(Clone, Debug)]
pub struct PoseidonTree {
    pub depth: usize,
    #[allow(dead_code)]
    leaves: Vec<Fr>,
    /// levels[0] = leaves padded to 2^depth
    levels: Vec<Vec<Fr>>,
}

fn empty_leaf(_depth_index: u32) -> Fr {
    use std::sync::OnceLock;
    static EMPTY: OnceLock<Fr> = OnceLock::new();
    *EMPTY.get_or_init(|| hash_tagged(tags::EMPTY_LEAF, &[Fr::from(0u64)]))
}

fn parent_poseidon(left: Fr, right: Fr) -> Fr {
    hash_tagged(tags::MERKLE_NODE, &[left, right])
}

impl PoseidonTree {
    pub fn new(depth: usize) -> Self {
        assert!(depth <= 32);
        let n = 1usize << depth;
        let leaves = vec![empty_leaf(0); n];
        let mut tree = Self {
            depth,
            leaves: Vec::new(),
            levels: vec![leaves],
        };
        tree.recompute();
        tree
    }

    pub fn with_leaves(depth: usize, leaves: &[Fr]) -> Result<Self, MerkleError> {
        let n = 1usize << depth;
        if leaves.len() > n {
            return Err(MerkleError::CapacityExceeded);
        }
        let mut padded = leaves.to_vec();
        padded.resize(n, empty_leaf(0));
        let mut tree = Self {
            depth,
            leaves: leaves.to_vec(),
            levels: vec![padded],
        };
        tree.recompute();
        Ok(tree)
    }

    fn recompute(&mut self) {
        let n = 1usize << self.depth;
        let mut level = self.levels[0].clone();
        if level.len() != n {
            level.resize(n, empty_leaf(0));
            self.levels[0] = level.clone();
        }
        self.levels = vec![level.clone()];
        for _d in 0..self.depth {
            let mut next = Vec::with_capacity(level.len() / 2);
            for chunk in level.chunks(2) {
                next.push(parent_poseidon(chunk[0], chunk[1]));
            }
            self.levels.push(next.clone());
            level = next;
        }
    }

    pub fn root(&self) -> Fr {
        *self.levels.last().unwrap().first().unwrap()
    }

    pub fn root_bytes(&self) -> [u8; 32] {
        fr_to_bytes(&self.root())
    }

    pub fn prove(&self, index: usize) -> Result<MerkleProof, MerkleError> {
        let n = 1usize << self.depth;
        if index >= n {
            return Err(MerkleError::IndexOutOfRange);
        }
        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = index;
        for d in 0..self.depth {
            let sib = idx ^ 1;
            siblings.push(self.levels[d][sib]);
            idx >>= 1;
        }
        Ok(MerkleProof {
            index: index as u64,
            siblings: siblings.iter().map(fr_to_bytes).collect(),
        })
    }

    pub fn verify(root: Fr, leaf: Fr, proof: &MerkleProof, depth: usize) -> bool {
        if proof.siblings.len() != depth {
            return false;
        }
        let mut acc = leaf;
        let mut idx = proof.index as usize;
        for sib_bytes in &proof.siblings {
            let sib = bytes_to_fr(sib_bytes);
            if idx & 1 == 0 {
                acc = parent_poseidon(acc, sib);
            } else {
                acc = parent_poseidon(sib, acc);
            }
            idx >>= 1;
        }
        acc == root
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProof {
    pub index: u64,
    pub siblings: Vec<[u8; 32]>,
}

/// Append-only Keccak ballot tree (dense leaves, fixed empty = 0x00..00).
#[derive(Clone, Debug, Default)]
pub struct KeccakBallotTree {
    leaves: Vec<[u8; 32]>,
}

fn keccak_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(left);
    payload[32..].copy_from_slice(right);
    *keccak256_tagged(tags::BALLOT_LEAF, &payload).as_bytes()
}

impl KeccakBallotTree {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn append(&mut self, leaf: [u8; 32]) -> usize {
        self.leaves.push(leaf);
        self.leaves.len() - 1
    }

    pub fn count(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn root(&self) -> Digest32 {
        if self.leaves.is_empty() {
            return Digest32([0u8; 32]);
        }
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push([0u8; 32]);
            }
            let mut next = Vec::with_capacity(level.len() / 2);
            for chunk in level.chunks(2) {
                next.push(keccak_parent(&chunk[0], &chunk[1]));
            }
            level = next;
        }
        Digest32(level[0])
    }

    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }
}

pub fn ballot_leaf_hash(
    index: u64,
    statement_digest: &[u8; 32],
    receipt_hash: &[u8; 32],
    ciphertext: &[u8],
    n_id: &[u8; 32],
    n_accounts: &[[u8; 32]],
) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&index.to_be_bytes());
    payload.extend_from_slice(statement_digest);
    payload.extend_from_slice(receipt_hash);
    payload.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    payload.extend_from_slice(ciphertext);
    payload.extend_from_slice(n_id);
    payload.extend_from_slice(&(n_accounts.len() as u32).to_be_bytes());
    for n in n_accounts {
        payload.extend_from_slice(n);
    }
    *keccak256_tagged(tags::BALLOT_LEAF, &payload).as_bytes()
}

/// Convenience: default depth tree.
pub fn default_depth() -> usize {
    MERKLE_DEPTH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon_membership_roundtrip() {
        let leaves = vec![Fr::from(10u64), Fr::from(20u64), Fr::from(30u64)];
        let tree = PoseidonTree::with_leaves(4, &leaves).unwrap();
        let root = tree.root();
        let proof = tree.prove(1).unwrap();
        assert!(PoseidonTree::verify(root, leaves[1], &proof, 4));
        assert!(!PoseidonTree::verify(root, leaves[0], &proof, 4));
    }

    #[test]
    fn keccak_append_changes_root() {
        let mut t = KeccakBallotTree::new();
        let r0 = t.root();
        t.append([1u8; 32]);
        let r1 = t.root();
        assert_ne!(r0, r1);
        t.append([2u8; 32]);
        assert_ne!(r1, t.root());
    }

    #[test]
    fn hash2_used_in_empty() {
        let a = empty_leaf(0);
        let b = hash_tagged(tags::EMPTY_LEAF, &[Fr::from(1u64)]);
        assert_ne!(a, b);
        let _ = veilgov_domains::hash2(a, b);
    }
}
