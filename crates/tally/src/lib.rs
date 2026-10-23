//! Exact-set tally: product of ciphertexts under frozen ballot root/count.

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use veilgov_ballot::{make_ballot_leaf, BallotReceipt};
use veilgov_encoding::Digest32;
use veilgov_merkle::KeccakBallotTree;
use veilgov_paillier::{aggregate, decrypt, unpack_plaintext, PublicKey, SecretKey, DEV_WARNING};

#[derive(Debug, Error)]
pub enum TallyError {
    #[error("root mismatch")]
    RootMismatch,
    #[error("count mismatch")]
    CountMismatch,
    #[error("index gap or duplicate")]
    IndexError,
    #[error("leaf mismatch at {0}")]
    LeafMismatch(u64),
    #[error("paillier: {0}")]
    Paillier(String),
    #[error("{0}")]
    Msg(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptedBallot {
    pub index: u64,
    pub receipt: BallotReceipt,
    pub leaf: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub struct BallotRegistry {
    tree: KeccakBallotTree,
    ballots: Vec<AcceptedBallot>,
    nullifiers: std::collections::HashSet<[u8; 32]>,
    frozen: bool,
}

impl BallotRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept(&mut self, receipt: BallotReceipt) -> Result<AcceptedBallot, TallyError> {
        if self.frozen {
            return Err(TallyError::Msg("registry frozen".into()));
        }
        // Consume identity + account nullifiers atomically.
        let mut pending = Vec::new();
        pending.push(receipt.nullifiers.identity);
        for n in &receipt.nullifiers.accounts {
            pending.push(*n);
        }
        for n in &pending {
            if self.nullifiers.contains(n) {
                return Err(TallyError::Msg("duplicate nullifier".into()));
            }
        }
        for n in &pending {
            self.nullifiers.insert(*n);
        }
        let index = self.tree.count();
        let leaf = make_ballot_leaf(index, &receipt);
        self.tree.append(leaf);
        let accepted = AcceptedBallot {
            index,
            receipt,
            leaf,
        };
        self.ballots.push(accepted.clone());
        Ok(accepted)
    }

    pub fn freeze(&mut self) -> (Digest32, u64) {
        self.frozen = true;
        (self.tree.root(), self.tree.count())
    }

    pub fn root(&self) -> Digest32 {
        self.tree.root()
    }

    pub fn count(&self) -> u64 {
        self.tree.count()
    }

    pub fn ballots(&self) -> &[AcceptedBallot] {
        &self.ballots
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TallyResult {
    pub yes: u128,
    pub no: u128,
    pub total: u128,
    pub ballot_root: [u8; 32],
    pub ballot_count: u64,
    pub aggregate_ciphertext: Vec<u8>,
    pub development_only: bool,
    pub warning: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TallyProofNative {
    pub ballot_root: [u8; 32],
    pub ballot_count: u64,
    pub aggregate_ciphertext: Vec<u8>,
    pub scanned: u64,
    pub ok: bool,
}

/// Scan exactly records 0..count-1, recompute leaves/root, aggregate ciphertexts.
pub fn prove_tally_exact_set(
    pk: &PublicKey,
    expected_root: &Digest32,
    expected_count: u64,
    ballots: &[AcceptedBallot],
) -> Result<(TallyProofNative, BigUint), TallyError> {
    if ballots.len() as u64 != expected_count {
        return Err(TallyError::CountMismatch);
    }
    let mut tree = KeccakBallotTree::new();
    let mut cts = Vec::new();
    for (i, b) in ballots.iter().enumerate() {
        if b.index != i as u64 {
            return Err(TallyError::IndexError);
        }
        let leaf = make_ballot_leaf(b.index, &b.receipt);
        if leaf != b.leaf {
            return Err(TallyError::LeafMismatch(b.index));
        }
        tree.append(leaf);
        let c = pk
            .decode_ciphertext(&b.receipt.statement.ciphertext)
            .map_err(|e| TallyError::Paillier(e.to_string()))?;
        cts.push(c);
    }
    let root = tree.root();
    if &root != expected_root {
        return Err(TallyError::RootMismatch);
    }
    let agg = if cts.is_empty() {
        BigUint::from(1u32)
    } else {
        aggregate(pk, &cts).map_err(|e| TallyError::Paillier(e.to_string()))?
    };
    let agg_bytes = pk
        .encode_ciphertext(&agg)
        .or_else(|_| {
            // Identity ciphertext 1 may fail gcd check when empty — use one for empty elections only.
            if cts.is_empty() {
                Ok([0u8; veilgov_encoding::PAILLIER_CT_LEN])
            } else {
                Err(veilgov_paillier::PaillierError::InvalidCiphertext)
            }
        })
        .map_err(|e| TallyError::Paillier(e.to_string()))?;

    let proof = TallyProofNative {
        ballot_root: *root.as_bytes(),
        ballot_count: expected_count,
        aggregate_ciphertext: agg_bytes.to_vec(),
        scanned: expected_count,
        ok: true,
    };
    Ok((proof, agg))
}

pub fn decrypt_result(
    sk: &SecretKey,
    pk: &PublicKey,
    proof: &TallyProofNative,
    agg: &BigUint,
) -> Result<TallyResult, TallyError> {
    let m = decrypt(sk, agg).map_err(|e| TallyError::Paillier(e.to_string()))?;
    let (yes, total) = unpack_plaintext(&m).map_err(|e| TallyError::Paillier(e.to_string()))?;
    let no = total - yes;
    let _ = pk;
    Ok(TallyResult {
        yes,
        no,
        total,
        ballot_root: proof.ballot_root,
        ballot_count: proof.ballot_count,
        aggregate_ciphertext: proof.aggregate_ciphertext.clone(),
        development_only: true,
        warning: DEV_WARNING.to_string(),
    })
}

pub fn tally_transcript_hash(proof: &TallyProofNative) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"VEILGOV_TALLY_TRANSCRIPT_V1");
    h.update(&proof.ballot_root);
    h.update(&proof.ballot_count.to_be_bytes());
    h.update(&proof.aggregate_ciphertext);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}
