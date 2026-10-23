//! Deterministic confidential-ballot predicate shared by native tests and the zkVM guest.

use ark_bn254::Fr;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
use veilgov_domains::{
    bytes_to_fr, fr_to_bytes, sha256_tagged, tags, ACCOUNT_CAPACITY, MERKLE_DEPTH,
};
use veilgov_encoding::{take_bytes, Digest32, EncodingError, PAILLIER_CT_LEN, PAILLIER_N_LEN};
use veilgov_identity::{
    account_commitment, account_secret, account_spend_nullifier, compute_scope,
    election_identity_nullifier, AccountRandomness, MasterSecret, PublicNullifiers,
};
use veilgov_merkle::{ballot_leaf_hash, MerkleProof, PoseidonTree};
use veilgov_paillier::{encrypt_packed_with_randomness, PublicKey};
use veilgov_protocol_types::{checked_sum_weights, ElectionConfig, TypeError, VoteBit};
use veilgov_snapshot_core::{credential_leaf, eth_snapshot_leaf, sol_snapshot_leaf};

// Re-export constant used in statement size.
pub use veilgov_encoding::PAILLIER_CT_LEN as CT_LEN;

#[derive(Debug, Error)]
pub enum BallotError {
    #[error(transparent)]
    Type(#[from] TypeError),
    #[error("membership failed")]
    Membership,
    #[error("capacity exceeded")]
    Capacity,
    #[error("inactive slot has nonzero weight")]
    InactiveWeight,
    #[error("commitment mismatch")]
    CommitmentMismatch,
    #[error("snapshot leaf mismatch")]
    SnapshotLeafMismatch,
    #[error("credential leaf mismatch")]
    CredentialLeafMismatch,
    #[error("public configuration mismatch: {0}")]
    PublicConfigMismatch(&'static str),
    #[error("invalid owner length")]
    InvalidOwner,
    #[error("duplicate active credential")]
    DuplicateCredential,
    #[error("weight exceeds configured bound")]
    WeightBound,
    #[error("invalid witness shape")]
    InvalidWitnessShape,
    #[error("canonical statement encoding: {0}")]
    Encoding(String),
    #[error("paillier: {0}")]
    Paillier(String),
    #[error("{0}")]
    Msg(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EthereumSnapshotContext {
    pub genesis_hash: [u8; 32],
    pub chain_id: u64,
    pub block_hash: [u8; 32],
    pub asset_id: Vec<u8>,
    pub weight_policy_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolanaSnapshotContext {
    pub genesis_hash: [u8; 32],
    pub slot: u64,
    pub asset_id: Vec<u8>,
    pub weight_policy_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountWitness {
    pub active: bool,
    pub rho: [u8; 32],
    pub scope: Digest32,
    pub chain_tag: u64,
    pub owner: Vec<u8>,
    pub amount: u64,
    pub snapshot_leaf: [u8; 32],
    pub snapshot_proof: MerkleProof,
    pub credential_leaf: [u8; 32],
    pub credential_proof: MerkleProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BallotWitness {
    pub master_secret: [u8; 32],
    pub vote: u8,
    pub accounts: Vec<AccountWitness>,
    /// Private Paillier randomness, canonical unsigned big-endian.
    pub paillier_randomness: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BallotStatementV1 {
    pub protocol_version: u32,
    pub election_domain: [u8; 32],
    pub eth_snapshot_root: [u8; 32],
    pub sol_snapshot_root: [u8; 32],
    pub credential_root: [u8; 32],
    pub paillier_key_hash: [u8; 32],
    pub n_id: [u8; 32],
    pub n_accounts: Vec<[u8; 32]>,
    pub ciphertext: Vec<u8>,
}

impl BallotStatementV1 {
    pub fn digest(&self) -> [u8; 32] {
        *sha256_tagged(tags::BALLOT_STATEMENT, &self.canonical_bytes()).as_bytes()
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.election_domain);
        out.extend_from_slice(&self.eth_snapshot_root);
        out.extend_from_slice(&self.sol_snapshot_root);
        out.extend_from_slice(&self.credential_root);
        out.extend_from_slice(&self.paillier_key_hash);
        out.extend_from_slice(&self.n_id);
        out.extend_from_slice(&(self.n_accounts.len() as u32).to_be_bytes());
        for n in &self.n_accounts {
            out.extend_from_slice(n);
        }
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BallotError> {
        let (version_bytes, mut rest) =
            take_bytes(bytes, 4).map_err(|e| BallotError::Encoding(e.to_string()))?;
        let protocol_version = u32::from_be_bytes(version_bytes.try_into().unwrap());
        let take32 = |input: &mut &[u8]| -> Result<[u8; 32], BallotError> {
            let (value, remaining) =
                take_bytes(input, 32).map_err(|e| BallotError::Encoding(e.to_string()))?;
            *input = remaining;
            Ok(value.try_into().unwrap())
        };
        let election_domain = take32(&mut rest)?;
        let eth_snapshot_root = take32(&mut rest)?;
        let sol_snapshot_root = take32(&mut rest)?;
        let credential_root = take32(&mut rest)?;
        let paillier_key_hash = take32(&mut rest)?;
        let n_id = take32(&mut rest)?;
        let (count_bytes, remaining) =
            take_bytes(rest, 4).map_err(|e| BallotError::Encoding(e.to_string()))?;
        rest = remaining;
        let count = u32::from_be_bytes(count_bytes.try_into().unwrap()) as usize;
        if count != ACCOUNT_CAPACITY {
            return Err(BallotError::InvalidWitnessShape);
        }
        let mut n_accounts = Vec::with_capacity(count);
        for _ in 0..count {
            n_accounts.push(take32(&mut rest)?);
        }
        let (len_bytes, remaining) =
            take_bytes(rest, 4).map_err(|e| BallotError::Encoding(e.to_string()))?;
        rest = remaining;
        let ciphertext_len = u32::from_be_bytes(len_bytes.try_into().unwrap()) as usize;
        if ciphertext_len != PAILLIER_CT_LEN {
            return Err(BallotError::Encoding("wrong ciphertext length".into()));
        }
        let (ciphertext, trailing) =
            take_bytes(rest, ciphertext_len).map_err(|e| BallotError::Encoding(e.to_string()))?;
        if !trailing.is_empty() {
            return Err(BallotError::Encoding(
                EncodingError::TrailingBytes(trailing.len()).to_string(),
            ));
        }
        Ok(Self {
            protocol_version,
            election_domain,
            eth_snapshot_root,
            sol_snapshot_root,
            credential_root,
            paillier_key_hash,
            n_id,
            n_accounts,
            ciphertext: ciphertext.to_vec(),
        })
    }

    pub fn validate_public_context(
        &self,
        config: &ElectionConfig,
    ) -> Result<(), BallotError> {
        if self.protocol_version != config.protocol_version {
            return Err(BallotError::PublicConfigMismatch("protocol version"));
        }
        if self.election_domain != *config.election_domain().as_bytes() {
            return Err(BallotError::PublicConfigMismatch("election domain"));
        }
        if self.eth_snapshot_root != config.eth_snapshot_root.0 {
            return Err(BallotError::PublicConfigMismatch("Ethereum root"));
        }
        if self.sol_snapshot_root != config.sol_snapshot_root.0 {
            return Err(BallotError::PublicConfigMismatch("Solana root"));
        }
        if self.credential_root != config.credential_root.0 {
            return Err(BallotError::PublicConfigMismatch("credential root"));
        }
        if self.paillier_key_hash != config.paillier_key_hash.0 {
            return Err(BallotError::PublicConfigMismatch("Paillier key"));
        }
        if self.n_accounts.len() != ACCOUNT_CAPACITY || self.ciphertext.len() != PAILLIER_CT_LEN {
            return Err(BallotError::InvalidWitnessShape);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BallotReceipt {
    pub statement: BallotStatementV1,
    pub nullifiers: PublicNullifiers,
    pub receipt_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct VerifiedBallot {
    pub statement: BallotStatementV1,
    pub nullifiers: PublicNullifiers,
    /// Kept in private host/guest execution only; never committed to the journal.
    pub private_weight: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BallotPublicInputs {
    pub config: ElectionConfig,
    pub ethereum: EthereumSnapshotContext,
    pub solana: SolanaSnapshotContext,
    /// Canonical fixed-width 256-byte Paillier modulus.
    pub paillier_modulus: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BallotProofInput {
    pub public: BallotPublicInputs,
    pub witness: BallotWitness,
}

impl BallotPublicInputs {
    pub fn paillier_public_key(&self) -> Result<PublicKey, BallotError> {
        PublicKey::decode_modulus(&self.paillier_modulus)
            .map_err(|e| BallotError::Paillier(e.to_string()))
    }
}

fn dummy_account(index: usize) -> AccountWitness {
    AccountWitness {
        active: false,
        rho: fr_to_bytes(&Fr::from((index as u64) + 0xDEC0)),
        scope: Digest32([0u8; 32]),
        chain_tag: 0,
        owner: Vec::new(),
        amount: 0,
        snapshot_leaf: [0u8; 32],
        snapshot_proof: MerkleProof {
            index: 0,
            siblings: vec![[0u8; 32]; MERKLE_DEPTH],
        },
        credential_leaf: [0u8; 32],
        credential_proof: MerkleProof {
            index: 0,
            siblings: vec![[0u8; 32]; MERKLE_DEPTH],
        },
    }
}

pub fn pad_witness_accounts(witness: &mut BallotWitness) -> Result<(), BallotError> {
    if witness.accounts.len() > ACCOUNT_CAPACITY {
        return Err(BallotError::Capacity);
    }
    while witness.accounts.len() < ACCOUNT_CAPACITY {
        witness.accounts.push(dummy_account(witness.accounts.len()));
    }
    Ok(())
}

/// The single deterministic statement attested by native differential tests and
/// by the RISC Zero guest. No randomness, I/O, time, or environment access.
pub fn verify_ballot_statement(
    inputs: &BallotPublicInputs,
    witness: &BallotWitness,
) -> Result<VerifiedBallot, BallotError> {
    inputs.config.validate()?;
    if inputs.config.account_capacity != ACCOUNT_CAPACITY
        || witness.accounts.len() != ACCOUNT_CAPACITY
        || inputs.paillier_modulus.len() != PAILLIER_N_LEN
    {
        return Err(BallotError::InvalidWitnessShape);
    }

    let paillier_pk = inputs.paillier_public_key()?;
    if inputs.config.eth_snapshot_root.0 == [0u8; 32]
        || inputs.config.sol_snapshot_root.0 == [0u8; 32]
        || inputs.config.credential_root.0 == [0u8; 32]
    {
        return Err(BallotError::PublicConfigMismatch("zero root"));
    }
    if paillier_pk.fingerprint() != inputs.config.paillier_key_hash {
        return Err(BallotError::PublicConfigMismatch("Paillier modulus"));
    }
    let vote = VoteBit::checked(witness.vote)?;
    let e = inputs.config.election_domain();
    let master = MasterSecret::from_bytes(&witness.master_secret);
    let mut weights = Vec::new();
    let mut spend_nullifiers = Vec::new();
    let mut active_credentials = HashSet::new();

    for acc in &witness.accounts {
        let rho = AccountRandomness {
            fr: bytes_to_fr(&acc.rho),
        };
        let x = account_secret(&master, &rho, &acc.scope);
        let n_i = account_spend_nullifier(x, &e);
        spend_nullifiers.push(n_i);

        if !acc.active {
            if acc.amount != 0 || acc.chain_tag != 0 || !acc.owner.is_empty() {
                return Err(BallotError::InactiveWeight);
            }
            weights.push(0);
            continue;
        }

        if acc.amount > inputs.config.max_individual_weight {
            return Err(BallotError::WeightBound);
        }
        let a = account_commitment(x);
        let (expected_scope, expected_snapshot_leaf, snapshot_root) = match acc.chain_tag {
            1 => {
                let address: [u8; 20] = acc
                    .owner
                    .as_slice()
                    .try_into()
                    .map_err(|_| BallotError::InvalidOwner)?;
                let scope = compute_scope(
                    &inputs.ethereum.genesis_hash,
                    Some(inputs.ethereum.chain_id),
                    &inputs.config.election_id.0,
                    &inputs.ethereum.asset_id,
                    &inputs.ethereum.weight_policy_hash,
                );
                let leaf = eth_snapshot_leaf(
                    &inputs.config.election_id.0,
                    inputs.ethereum.chain_id,
                    &inputs.ethereum.block_hash,
                    &inputs.ethereum.asset_id,
                    &address,
                    acc.amount,
                );
                (scope, leaf, bytes_to_fr(inputs.config.eth_snapshot_root.as_bytes()))
            }
            2 => {
                let pubkey: [u8; 32] = acc
                    .owner
                    .as_slice()
                    .try_into()
                    .map_err(|_| BallotError::InvalidOwner)?;
                let scope = compute_scope(
                    &inputs.solana.genesis_hash,
                    None,
                    &inputs.config.election_id.0,
                    &inputs.solana.asset_id,
                    &inputs.solana.weight_policy_hash,
                );
                let leaf = sol_snapshot_leaf(
                    &inputs.config.election_id.0,
                    &inputs.solana.genesis_hash,
                    inputs.solana.slot,
                    &inputs.solana.asset_id,
                    &pubkey,
                    acc.amount,
                );
                (scope, leaf, bytes_to_fr(inputs.config.sol_snapshot_root.as_bytes()))
            }
            _ => return Err(BallotError::Msg("unknown chain_tag".into())),
        };
        if acc.scope != expected_scope {
            return Err(BallotError::PublicConfigMismatch("account scope"));
        }
        if fr_to_bytes(&expected_snapshot_leaf) != acc.snapshot_leaf {
            return Err(BallotError::SnapshotLeafMismatch);
        }
        if !PoseidonTree::verify(
            snapshot_root,
            expected_snapshot_leaf,
            &acc.snapshot_proof,
            MERKLE_DEPTH,
        ) {
            return Err(BallotError::Membership);
        }

        let expected_credential_leaf = credential_leaf(
            acc.scope.as_bytes(),
            acc.chain_tag,
            &acc.owner,
            acc.amount,
            a,
            expected_snapshot_leaf,
        );
        if fr_to_bytes(&expected_credential_leaf) != acc.credential_leaf {
            return Err(BallotError::CredentialLeafMismatch);
        }
        if !active_credentials.insert(acc.credential_leaf) {
            return Err(BallotError::DuplicateCredential);
        }
        if !PoseidonTree::verify(
            bytes_to_fr(inputs.config.credential_root.as_bytes()),
            expected_credential_leaf,
            &acc.credential_proof,
            MERKLE_DEPTH,
        ) {
            return Err(BallotError::Membership);
        }
        weights.push(acc.amount);
    }

    let w = checked_sum_weights(&weights)?;
    if w > inputs.config.eligible_total_weight {
        return Err(BallotError::WeightBound);
    }
    let n_id = election_identity_nullifier(&master, &e);
    let randomness = BigUint::from_bytes_be(&witness.paillier_randomness);
    let ct = encrypt_packed_with_randomness(&paillier_pk, w, vote.0, &randomness)
        .map_err(|e| BallotError::Paillier(e.to_string()))?;
    let ct_bytes = paillier_pk
        .encode_ciphertext(&ct)
        .map_err(|e| BallotError::Paillier(e.to_string()))?;

    let statement = BallotStatementV1 {
        protocol_version: inputs.config.protocol_version,
        election_domain: *e.as_bytes(),
        eth_snapshot_root: inputs.config.eth_snapshot_root.0,
        sol_snapshot_root: inputs.config.sol_snapshot_root.0,
        credential_root: inputs.config.credential_root.0,
        paillier_key_hash: *paillier_pk.fingerprint().as_bytes(),
        n_id: fr_to_bytes(&n_id),
        n_accounts: spend_nullifiers.iter().map(fr_to_bytes).collect(),
        ciphertext: ct_bytes.to_vec(),
    };
    statement.validate_public_context(&inputs.config)?;
    Ok(VerifiedBallot {
        private_weight: w,
        nullifiers: PublicNullifiers::from_frs(n_id, &spend_nullifiers),
        statement,
    })
}

/// Native differential oracle. The proof-backed path uses the same predicate in
/// the guest and constructs a receipt only after cryptographic verification.
pub fn prove_ballot_native(
    inputs: &BallotPublicInputs,
    witness: &BallotWitness,
) -> Result<VerifiedBallot, BallotError> {
    verify_ballot_statement(inputs, witness)
}

pub fn receipt_from_verified_statement(
    statement: BallotStatementV1,
    proof_commitment: [u8; 32],
) -> BallotReceipt {
    let nullifiers = PublicNullifiers {
        identity: statement.n_id,
        accounts: statement.n_accounts.clone(),
    };
    BallotReceipt {
        statement,
        nullifiers,
        receipt_hash: proof_commitment,
    }
}

pub fn make_ballot_leaf(index: u64, receipt: &BallotReceipt) -> [u8; 32] {
    let stmt = receipt.statement.digest();
    ballot_leaf_hash(
        index,
        &stmt,
        &receipt.receipt_hash,
        &receipt.statement.ciphertext,
        &receipt.nullifiers.identity,
        &receipt.nullifiers.accounts,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use veilgov_identity::{account_commitment, account_secret};
    use veilgov_merkle::default_depth;
    use veilgov_paillier::{keygen_for_tests, sample_randomness};
    use crate::CT_LEN;
    use veilgov_protocol_types::ElectionId;

    fn valid_fixture() -> (BallotPublicInputs, BallotWitness) {
        let mut rng = StdRng::seed_from_u64(0x5A4B);
        let (pk, _) = keygen_for_tests(&mut rng);
        let election_id = ElectionId([0xE1; 32]);
        let ethereum = EthereumSnapshotContext {
            genesis_hash: [0x11; 32],
            chain_id: 1,
            block_hash: [0x12; 32],
            asset_id: vec![0x13; 20],
            weight_policy_hash: [0x14; 32],
        };
        let solana = SolanaSnapshotContext {
            genesis_hash: [0x21; 32],
            slot: 42,
            asset_id: vec![0x22; 32],
            weight_policy_hash: [0x23; 32],
        };
        let eth_owner = vec![0xA1; 20];
        let sol_owner = vec![0xA2; 32];
        let eth_amount = 10;
        let sol_amount = 20;
        let eth_scope = compute_scope(
            &ethereum.genesis_hash,
            Some(ethereum.chain_id),
            &election_id.0,
            &ethereum.asset_id,
            &ethereum.weight_policy_hash,
        );
        let sol_scope = compute_scope(
            &solana.genesis_hash,
            None,
            &election_id.0,
            &solana.asset_id,
            &solana.weight_policy_hash,
        );
        let eth_leaf = eth_snapshot_leaf(
            &election_id.0,
            ethereum.chain_id,
            &ethereum.block_hash,
            &ethereum.asset_id,
            eth_owner.as_slice().try_into().unwrap(),
            eth_amount,
        );
        let sol_leaf = sol_snapshot_leaf(
            &election_id.0,
            &solana.genesis_hash,
            solana.slot,
            &solana.asset_id,
            sol_owner.as_slice().try_into().unwrap(),
            sol_amount,
        );
        let eth_tree = PoseidonTree::with_leaves(default_depth(), &[eth_leaf]).unwrap();
        let sol_tree = PoseidonTree::with_leaves(default_depth(), &[sol_leaf]).unwrap();

        let master = MasterSecret::from_bytes(&[0x31; 32]);
        let eth_rho = AccountRandomness { fr: Fr::from(7u64) };
        let sol_rho = AccountRandomness { fr: Fr::from(8u64) };
        let eth_commitment =
            account_commitment(account_secret(&master, &eth_rho, &eth_scope));
        let sol_commitment =
            account_commitment(account_secret(&master, &sol_rho, &sol_scope));
        let eth_credential = credential_leaf(
            eth_scope.as_bytes(),
            1,
            &eth_owner,
            eth_amount,
            eth_commitment,
            eth_leaf,
        );
        let sol_credential = credential_leaf(
            sol_scope.as_bytes(),
            2,
            &sol_owner,
            sol_amount,
            sol_commitment,
            sol_leaf,
        );
        let credential_tree = PoseidonTree::with_leaves(
            default_depth(),
            &[eth_credential, sol_credential],
        )
        .unwrap();

        let mut config = ElectionConfig::demo(election_id);
        config.eth_snapshot_root = Digest32(eth_tree.root_bytes());
        config.sol_snapshot_root = Digest32(sol_tree.root_bytes());
        config.credential_root = Digest32(credential_tree.root_bytes());
        config.paillier_key_hash = pk.fingerprint();
        config.eligible_total_weight = 30;
        config.max_individual_weight = 20;

        let mut witness = BallotWitness {
            master_secret: master.to_bytes(),
            vote: 1,
            accounts: vec![
                AccountWitness {
                    active: true,
                    rho: fr_to_bytes(&eth_rho.fr),
                    scope: eth_scope,
                    chain_tag: 1,
                    owner: eth_owner,
                    amount: eth_amount,
                    snapshot_leaf: fr_to_bytes(&eth_leaf),
                    snapshot_proof: eth_tree.prove(0).unwrap(),
                    credential_leaf: fr_to_bytes(&eth_credential),
                    credential_proof: credential_tree.prove(0).unwrap(),
                },
                AccountWitness {
                    active: true,
                    rho: fr_to_bytes(&sol_rho.fr),
                    scope: sol_scope,
                    chain_tag: 2,
                    owner: sol_owner,
                    amount: sol_amount,
                    snapshot_leaf: fr_to_bytes(&sol_leaf),
                    snapshot_proof: sol_tree.prove(0).unwrap(),
                    credential_leaf: fr_to_bytes(&sol_credential),
                    credential_proof: credential_tree.prove(1).unwrap(),
                },
            ],
            paillier_randomness: sample_randomness(&pk, &mut rng).to_bytes_be(),
        };
        pad_witness_accounts(&mut witness).unwrap();
        (
            BallotPublicInputs {
                config,
                ethereum,
                solana,
                paillier_modulus: pk.encode_modulus().unwrap().to_vec(),
            },
            witness,
        )
    }

    #[test]
    fn statement_canonical_stable() {
        let cfg = ElectionConfig::demo(ElectionId([1u8; 32]));
        let s = BallotStatementV1 {
            protocol_version: 1,
            election_domain: *cfg.election_domain().as_bytes(),
            eth_snapshot_root: [2u8; 32],
            sol_snapshot_root: [3u8; 32],
            credential_root: [4u8; 32],
            paillier_key_hash: [5u8; 32],
            n_id: [6u8; 32],
            n_accounts: vec![[7u8; 32]; 4],
            ciphertext: vec![0u8; CT_LEN],
        };
        let bytes = s.canonical_bytes();
        assert_eq!(BallotStatementV1::from_canonical_bytes(&bytes).unwrap().canonical_bytes(), bytes);
    }

    #[test]
    fn full_cross_chain_statement_is_deterministic() {
        let (inputs, witness) = valid_fixture();
        let a = verify_ballot_statement(&inputs, &witness).unwrap();
        let b = verify_ballot_statement(&inputs, &witness).unwrap();
        assert_eq!(a.private_weight, 30);
        assert_eq!(a.statement.canonical_bytes(), b.statement.canonical_bytes());
        assert_eq!(a.statement.canonical_bytes().len(), 844);
    }

    #[test]
    fn public_journal_excludes_private_witness_fields() {
        let (inputs, witness) = valid_fixture();
        let statement = verify_ballot_statement(&inputs, &witness).unwrap().statement;
        let journal = statement.canonical_bytes();
        assert!(!journal.windows(20).any(|window| window == [0xA1; 20]));
        assert!(!journal.windows(32).any(|window| window == [0xA2; 32]));
        assert!(!journal
            .windows(32)
            .any(|window| window == witness.master_secret));
        assert!(!journal
            .windows(witness.paillier_randomness.len())
            .any(|window| window == witness.paillier_randomness));
        // Vote, individual balances, and aggregate weight have no journal fields;
        // parsing succeeds only for the explicitly documented public layout.
        assert_eq!(
            BallotStatementV1::from_canonical_bytes(&journal)
                .unwrap()
                .canonical_bytes(),
            journal
        );
    }

    #[test]
    fn rejects_wrong_snapshot_path_and_balance() {
        let (inputs, mut witness) = valid_fixture();
        witness.accounts[0].snapshot_proof.siblings[0][0] ^= 1;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::Membership)
        ));

        let (inputs, mut witness) = valid_fixture();
        witness.accounts[0].amount += 1;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::SnapshotLeafMismatch)
        ));

        let (inputs, mut witness) = valid_fixture();
        witness.accounts[1].snapshot_proof.siblings[0][0] ^= 1;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::Membership)
        ));

        let (inputs, mut witness) = valid_fixture();
        witness.accounts[1].credential_proof.siblings[0][0] ^= 1;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::Membership)
        ));
    }

    #[test]
    fn rejects_wrong_identity_vote_and_key_context() {
        let (inputs, mut witness) = valid_fixture();
        witness.master_secret[0] ^= 1;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::CredentialLeafMismatch)
        ));

        let (inputs, mut witness) = valid_fixture();
        witness.vote = 2;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::Type(TypeError::InvalidVote))
        ));

        let (mut inputs, witness) = valid_fixture();
        inputs.config.paillier_key_hash.0[0] ^= 1;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::PublicConfigMismatch("Paillier modulus"))
        ));

        let (mut inputs, witness) = valid_fixture();
        inputs.config.election_id.0[0] ^= 1;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::PublicConfigMismatch("account scope"))
                | Err(BallotError::SnapshotLeafMismatch)
        ));

        let (inputs, mut witness) = valid_fixture();
        witness.paillier_randomness = vec![0];
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::Paillier(_))
        ));
    }

    #[test]
    fn rejects_duplicate_credential_and_weight_bound() {
        let (inputs, mut witness) = valid_fixture();
        witness.accounts[1] = witness.accounts[0].clone();
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::DuplicateCredential)
        ));

        let (mut inputs, witness) = valid_fixture();
        inputs.config.eligible_total_weight = 29;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::WeightBound)
        ));

        let (mut inputs, witness) = valid_fixture();
        inputs.config.max_individual_weight = 19;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::WeightBound)
        ));
    }

    #[test]
    fn rejects_root_and_owner_mutations() {
        let (mut inputs, witness) = valid_fixture();
        inputs.config.eth_snapshot_root.0[0] ^= 1;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::Membership)
        ));

        let (mut inputs, witness) = valid_fixture();
        inputs.config.sol_snapshot_root.0[0] ^= 1;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::Membership)
        ));

        let (mut inputs, witness) = valid_fixture();
        inputs.config.credential_root.0[0] ^= 1;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::Membership)
        ));

        let (inputs, mut witness) = valid_fixture();
        witness.accounts[0].owner.push(0);
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::InvalidOwner)
        ));

        let (inputs, mut witness) = valid_fixture();
        witness.accounts[0].chain_tag = 99;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::Msg(_))
        ));
    }

    #[test]
    fn rejects_inactive_slot_leak_and_zero_roots() {
        let (inputs, mut witness) = valid_fixture();
        // Pad slots after the two active accounts must stay inert.
        let pad = &mut witness.accounts[2];
        pad.active = false;
        pad.amount = 1;
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::InactiveWeight)
        ));

        let (mut inputs, witness) = valid_fixture();
        inputs.config.eth_snapshot_root = Digest32([0u8; 32]);
        assert!(matches!(
            verify_ballot_statement(&inputs, &witness),
            Err(BallotError::PublicConfigMismatch("zero root"))
        ));
    }

    #[test]
    fn different_valid_r_yields_different_ciphertext() {
        let (inputs, mut witness) = valid_fixture();
        let a = verify_ballot_statement(&inputs, &witness).unwrap();
        // Valid alternate r for educational modulus (must stay in Z_n*).
        witness.paillier_randomness = vec![3];
        let b = verify_ballot_statement(&inputs, &witness).unwrap();
        assert_ne!(a.statement.ciphertext, b.statement.ciphertext);
        assert_eq!(a.statement.n_id, b.statement.n_id);
    }

    #[test]
    fn statement_digest_stable_and_receipt_helper() {
        let (inputs, witness) = valid_fixture();
        let verified = verify_ballot_statement(&inputs, &witness).unwrap();
        let d1 = verified.statement.digest();
        let d2 = BallotStatementV1::from_canonical_bytes(&verified.statement.canonical_bytes())
            .unwrap()
            .digest();
        assert_eq!(d1, d2);
        let receipt = receipt_from_verified_statement(verified.statement.clone(), [0xAB; 32]);
        assert_eq!(receipt.receipt_hash, [0xAB; 32]);
        assert_eq!(receipt.nullifiers.identity, verified.statement.n_id);
        assert_eq!(receipt.statement.canonical_bytes(), verified.statement.canonical_bytes());
    }
}
