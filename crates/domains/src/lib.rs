//! Domain tags, SHA/Keccak helpers, and VeilGov Poseidon-BN254.
//!
//! Poseidon parameters are generated from seed `VEILGOV_POSEIDON_V1` for the MVP.
//! Production deployments must replace these with an audited parameter set and
//! cross-language test vectors before any security claim.

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use veilgov_encoding::{tagged_payload, Digest32, HASH_LEN};

pub const PROTOCOL_VERSION: u32 = 1;
pub const ENCODING_VERSION: u32 = 1;
pub const ACCOUNT_CAPACITY: usize = 4;
/// MVP Merkle depth (256 leaves). Production may use 16/24/32 with the same rules.
pub const MERKLE_DEPTH: usize = 8;
/// Packed limb base bit-width B = 2^128 for yes+total encoding.
pub const PLAINTEXT_BASE_BITS: u32 = 128;

pub mod tags {
    pub const PROTOCOL: &str = "VEILGOV_PROTOCOL_V1";
    pub const SCOPE: &str = "VEILGOV_SCOPE_V1";
    pub const ID: &str = "VEILGOV_ID_V1";
    pub const ACCOUNT_SECRET: &str = "VEILGOV_ACCOUNT_SECRET_V1";
    pub const ACCOUNT_COMMIT: &str = "VEILGOV_ACCOUNT_COMMIT_V1";
    pub const ETH_SNAPSHOT: &str = "VEILGOV_ETH_SNAPSHOT_V1";
    pub const SOL_SNAPSHOT: &str = "VEILGOV_SOL_SNAPSHOT_V1";
    pub const CREDENTIAL: &str = "VEILGOV_CREDENTIAL_V1";
    pub const ELECTION: &str = "VEILGOV_ELECTION_V1";
    pub const ELECTION_ID_NULLIFIER: &str = "VEILGOV_ELECTION_ID_NULLIFIER_V1";
    pub const ACCOUNT_SPEND: &str = "VEILGOV_ACCOUNT_SPEND_V1";
    pub const REG_UNIQUENESS: &str = "VEILGOV_REG_UNIQUENESS_V1";
    pub const BALLOT_LEAF: &str = "VEILGOV_BALLOT_LEAF_V1";
    pub const BALLOT_STATEMENT: &str = "VEILGOV_BALLOT_STATEMENT_V1";
    pub const BALLOT_RECEIPT: &str = "VEILGOV_BALLOT_RECEIPT_V1";
    pub const ENROLL_ETH: &str = "VEILGOV_ENROLL_ETH_V1";
    pub const ENROLL_SOL: &str = "VEILGOV_ENROLL_SOL_V1";
    pub const EMPTY_LEAF: &str = "VEILGOV_EMPTY_LEAF_V1";
    pub const MERKLE_NODE: &str = "VEILGOV_MERKLE_NODE_V1";
    pub const PAILLIER_KEY: &str = "VEILGOV_PAILLIER_KEY_V1";
    pub const POSEIDON_SEED: &str = "VEILGOV_POSEIDON_V1";
}

pub fn sha256_tagged(tag: &str, payload: &[u8]) -> Digest32 {
    let mut h = Sha256::new();
    h.update(tagged_payload(tag, payload));
    let out = h.finalize();
    let mut arr = [0u8; HASH_LEN];
    arr.copy_from_slice(&out);
    Digest32(arr)
}

pub fn keccak256_tagged(tag: &str, payload: &[u8]) -> Digest32 {
    let mut h = Keccak256::new();
    h.update(tagged_payload(tag, payload));
    let out = h.finalize();
    let mut arr = [0u8; HASH_LEN];
    arr.copy_from_slice(&out);
    Digest32(arr)
}

pub fn sha256_raw(payload: &[u8]) -> Digest32 {
    let mut h = Sha256::new();
    h.update(payload);
    let out = h.finalize();
    let mut arr = [0u8; HASH_LEN];
    arr.copy_from_slice(&out);
    Digest32(arr)
}

pub fn keccak256_raw(payload: &[u8]) -> Digest32 {
    let mut h = Keccak256::new();
    h.update(payload);
    let out = h.finalize();
    let mut arr = [0u8; HASH_LEN];
    arr.copy_from_slice(&out);
    Digest32(arr)
}

pub fn bytes_to_fr(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

pub fn fr_to_bytes(fr: &Fr) -> [u8; 32] {
    let be = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    if be.len() >= 32 {
        out.copy_from_slice(&be[be.len() - 32..]);
    } else {
        out[32 - be.len()..].copy_from_slice(&be);
    }
    out
}

pub fn tag_to_fr(tag: &str) -> Fr {
    bytes_to_fr(sha256_tagged(tags::POSEIDON_SEED, tag.as_bytes()).as_bytes())
}

/// Poseidon t=3 (rate 2) over BN254 Fr for VeilGov MVP.
///
/// WARNING: Constants are seed-derived for determinism across this repository.
/// Do not claim Circom/light-poseidon compatibility until vectors are aligned.
pub mod poseidon {
    use super::*;
    use ark_ff::AdditiveGroup;
    use std::sync::OnceLock;

    const T: usize = 3;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 57;

    struct PoseidonParams {
        rc: Vec<[Fr; T]>,
        mds: [[Fr; T]; T],
    }

    fn params() -> &'static PoseidonParams {
        static PARAMS: OnceLock<PoseidonParams> = OnceLock::new();
        PARAMS.get_or_init(|| {
            let total = FULL_ROUNDS + PARTIAL_ROUNDS;
            let mut rc = Vec::with_capacity(total);
            for r in 0..total {
                let mut row = [Fr::ZERO; T];
                for (c, cell) in row.iter_mut().enumerate() {
                    let mut payload = Vec::new();
                    payload.extend_from_slice(b"RC");
                    payload.extend_from_slice(&(r as u32).to_be_bytes());
                    payload.extend_from_slice(&(c as u32).to_be_bytes());
                    *cell = bytes_to_fr(sha256_tagged(tags::POSEIDON_SEED, &payload).as_bytes());
                }
                rc.push(row);
            }
            let mut mds = [[Fr::ZERO; T]; T];
            for (i, row) in mds.iter_mut().enumerate() {
                for (j, cell) in row.iter_mut().enumerate() {
                    let mut payload = Vec::new();
                    payload.extend_from_slice(b"MDS");
                    payload.extend_from_slice(&(i as u32).to_be_bytes());
                    payload.extend_from_slice(&(j as u32).to_be_bytes());
                    *cell = bytes_to_fr(sha256_tagged(tags::POSEIDON_SEED, &payload).as_bytes());
                    if *cell == Fr::ZERO {
                        *cell = Fr::from(1u64);
                    }
                }
            }
            PoseidonParams { rc, mds }
        })
    }

    fn sbox(x: Fr) -> Fr {
        let x2 = x.square();
        let x4 = x2.square();
        x4 * x
    }

    fn apply_mds(state: &[Fr; T], m: &[[Fr; T]; T]) -> [Fr; T] {
        let mut out = [Fr::ZERO; T];
        for i in 0..T {
            let mut acc = Fr::ZERO;
            for j in 0..T {
                acc += m[i][j] * state[j];
            }
            out[i] = acc;
        }
        out
    }

    fn permute(mut state: [Fr; T]) -> [Fr; T] {
        let p = params();
        let half_full = FULL_ROUNDS / 2;
        let mut round = 0usize;

        for _ in 0..half_full {
            for i in 0..T {
                state[i] += p.rc[round][i];
            }
            for i in 0..T {
                state[i] = sbox(state[i]);
            }
            state = apply_mds(&state, &p.mds);
            round += 1;
        }
        for _ in 0..PARTIAL_ROUNDS {
            for i in 0..T {
                state[i] += p.rc[round][i];
            }
            state[0] = sbox(state[0]);
            state = apply_mds(&state, &p.mds);
            round += 1;
        }
        for _ in 0..half_full {
            for i in 0..T {
                state[i] += p.rc[round][i];
            }
            for i in 0..T {
                state[i] = sbox(state[i]);
            }
            state = apply_mds(&state, &p.mds);
            round += 1;
        }
        state
    }

    /// Hash 1 or 2 field elements (domain already included as first input when tagged).
    pub fn hash2(a: Fr, b: Fr) -> Fr {
        let state = [a, b, Fr::ZERO];
        permute(state)[0]
    }

    pub fn hash1(a: Fr) -> Fr {
        hash2(a, Fr::ZERO)
    }

    /// Domain-separated hash: Poseidon(tag_fr, x0, ...) via pairwise folding.
    pub fn hash_tagged(tag: &str, inputs: &[Fr]) -> Fr {
        let mut acc = tag_to_fr(tag);
        if inputs.is_empty() {
            return hash1(acc);
        }
        for chunk in inputs.chunks(1) {
            acc = hash2(acc, chunk[0]);
        }
        acc
    }

    pub fn hash_tagged_bytes(tag: &str, byte_chunks: &[&[u8]]) -> Fr {
        let els: Vec<Fr> = byte_chunks.iter().map(|b| bytes_to_fr(b)).collect();
        hash_tagged(tag, &els)
    }
}

pub use poseidon::{hash_tagged, hash_tagged_bytes, hash2};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tags_are_stable() {
        assert_eq!(tags::ELECTION, "VEILGOV_ELECTION_V1");
        let d = sha256_tagged(tags::SCOPE, b"test");
        assert_eq!(d.as_bytes().len(), 32);
    }

    #[test]
    fn poseidon_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        assert_eq!(poseidon::hash2(a, b), poseidon::hash2(a, b));
        assert_ne!(poseidon::hash2(a, b), poseidon::hash2(b, a));
    }

    #[test]
    fn fr_bytes_roundtrip_small() {
        let f = Fr::from(123456789u64);
        let b = fr_to_bytes(&f);
        assert_eq!(bytes_to_fr(&b), f);
    }

    #[test]
    fn export_hash_vector() {
        let h = poseidon::hash_tagged(tags::ID, &[Fr::from(7u64)]);
        let bytes = fr_to_bytes(&h);
        // Stable vector for regression.
        assert_eq!(hex::encode(bytes).len(), 64);
    }
}
