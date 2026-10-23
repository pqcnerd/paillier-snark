//! Anonymous identity secrets, account commitments, and nullifiers.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use veilgov_domains::{
    bytes_to_fr, fr_to_bytes, hash_tagged, sha256_tagged, tags,
};
use veilgov_encoding::Digest32;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret {
    pub fr: Fr,
}

impl MasterSecret {
    pub fn random(rng: &mut impl RngCore) -> Self {
        Self {
            fr: Fr::rand(rng),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            fr: bytes_to_fr(bytes),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        fr_to_bytes(&self.fr)
    }

    pub fn identity_commitment(&self) -> Fr {
        hash_tagged(tags::ID, &[self.fr])
    }
}

impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSecret([redacted])")
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AccountRandomness {
    pub fr: Fr,
}

impl std::fmt::Debug for AccountRandomness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountRandomness([redacted])")
    }
}

impl AccountRandomness {
    pub fn random(rng: &mut impl RngCore) -> Self {
        Self {
            fr: Fr::rand(rng),
        }
    }
}

/// scope_i = SHA256(SCOPE || chainGenesis || chainId? || snapshotId || assetId || weightPolicyHash)
pub fn compute_scope(
    chain_genesis: &[u8],
    chain_id: Option<u64>,
    snapshot_id: &[u8],
    asset_id: &[u8],
    weight_policy_hash: &[u8; 32],
) -> Digest32 {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(chain_genesis.len() as u32).to_be_bytes());
    payload.extend_from_slice(chain_genesis);
    match chain_id {
        Some(id) => {
            payload.push(1);
            payload.extend_from_slice(&id.to_be_bytes());
        }
        None => payload.push(0),
    }
    payload.extend_from_slice(&(snapshot_id.len() as u32).to_be_bytes());
    payload.extend_from_slice(snapshot_id);
    payload.extend_from_slice(&(asset_id.len() as u32).to_be_bytes());
    payload.extend_from_slice(asset_id);
    payload.extend_from_slice(weight_policy_hash);
    sha256_tagged(tags::SCOPE, &payload)
}

/// x = Poseidon(ACCOUNT_SECRET, s, rho, scope_field)
pub fn account_secret(s: &MasterSecret, rho: &AccountRandomness, scope: &Digest32) -> Fr {
    let scope_fr = bytes_to_fr(scope.as_bytes());
    hash_tagged(tags::ACCOUNT_SECRET, &[s.fr, rho.fr, scope_fr])
}

/// A = Poseidon(ACCOUNT_COMMIT, x)
pub fn account_commitment(x: Fr) -> Fr {
    hash_tagged(tags::ACCOUNT_COMMIT, &[x])
}

pub fn account_commitment_bytes(x: Fr) -> [u8; 32] {
    fr_to_bytes(&account_commitment(x))
}

/// N_id = Poseidon(ELECTION_ID_NULLIFIER, s, E_field)
pub fn election_identity_nullifier(s: &MasterSecret, election_domain: &Digest32) -> Fr {
    let e = bytes_to_fr(election_domain.as_bytes());
    hash_tagged(tags::ELECTION_ID_NULLIFIER, &[s.fr, e])
}

/// N_i = Poseidon(ACCOUNT_SPEND, x, E_field)
pub fn account_spend_nullifier(x: Fr, election_domain: &Digest32) -> Fr {
    let e = bytes_to_fr(election_domain.as_bytes());
    hash_tagged(tags::ACCOUNT_SPEND, &[x, e])
}

/// Private registrar uniqueness key — never publish.
pub fn registration_uniqueness_key(scope: &Digest32, canonical_owner: &[u8]) -> Digest32 {
    let mut payload = Vec::new();
    payload.extend_from_slice(scope.as_bytes());
    payload.extend_from_slice(&(canonical_owner.len() as u32).to_be_bytes());
    payload.extend_from_slice(canonical_owner);
    sha256_tagged(tags::REG_UNIQUENESS, &payload)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicNullifiers {
    pub identity: [u8; 32],
    pub accounts: Vec<[u8; 32]>,
}

impl PublicNullifiers {
    pub fn from_frs(n_id: Fr, n_accounts: &[Fr]) -> Self {
        Self {
            identity: fr_to_bytes(&n_id),
            accounts: n_accounts.iter().map(fr_to_bytes).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn nullifiers_domain_separated() {
        let mut rng = StdRng::seed_from_u64(1);
        let s = MasterSecret::random(&mut rng);
        let rho = AccountRandomness::random(&mut rng);
        let scope = compute_scope(b"genesis", Some(1), b"snap", b"asset", &[9u8; 32]);
        let x = account_secret(&s, &rho, &scope);
        let e1 = Digest32([1u8; 32]);
        let e2 = Digest32([2u8; 32]);
        assert_ne!(
            election_identity_nullifier(&s, &e1),
            election_identity_nullifier(&s, &e2)
        );
        assert_ne!(
            account_spend_nullifier(x, &e1),
            account_spend_nullifier(x, &e2)
        );
    }

    #[test]
    fn uniqueness_key_private_stable() {
        let scope = Digest32([3u8; 32]);
        let a = registration_uniqueness_key(&scope, &[0xab; 20]);
        let b = registration_uniqueness_key(&scope, &[0xab; 20]);
        assert_eq!(a, b);
        let c = registration_uniqueness_key(&scope, &[0xac; 20]);
        assert_ne!(a, c);
    }
}
