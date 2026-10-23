//! Adversarial integration tests for VeilGov MVP.
#![cfg(test)]

use ark_bn254::Fr;
use rand::rngs::StdRng;
use rand::SeedableRng;
use veilgov_ballot::{BallotReceipt, BallotStatementV1};
use veilgov_encoding::Digest32;
use veilgov_enrollment::{EnrollmentError, EnrollmentRequest, RegistrarState};
use veilgov_identity::{
    account_commitment, account_secret, AccountRandomness, MasterSecret, PublicNullifiers,
};
use veilgov_paillier::{encrypt_packed, keygen_for_tests, pack_plaintext, unpack_plaintext};
use veilgov_tally::BallotRegistry;

#[test]
fn duplicate_enrollment_rejected() {
    let mut reg = RegistrarState::new();
    let scope = Digest32([1u8; 32]);
    let commitment = Fr::from(2u64);
    let snapshot_leaf = Fr::from(3u64);
    let req = EnrollmentRequest {
        scope,
        chain_tag: 1,
        owner: vec![1; 20],
        amount: 10,
        account_commitment: veilgov_domains::fr_to_bytes(&commitment),
        snapshot_leaf: veilgov_domains::fr_to_bytes(&snapshot_leaf),
        nonce: 1,
        expiry_unix: 100,
    };
    reg.enroll(req.clone(), commitment, snapshot_leaf, 1)
        .unwrap();
    let mut req2 = req;
    req2.nonce = 2;
    assert_eq!(
        reg.enroll(req2, commitment, snapshot_leaf, 1)
            .unwrap_err(),
        EnrollmentError::DuplicateAccount
    );
}

#[test]
fn packed_plaintext_bounds() {
    let m = pack_plaintext(100, 1).unwrap();
    let (y, t) = unpack_plaintext(&m).unwrap();
    assert_eq!((y, t), (100, 100));
    let m2 = pack_plaintext(50, 0).unwrap();
    let (y2, t2) = unpack_plaintext(&m2).unwrap();
    assert_eq!((y2, t2), (0, 50));
}

#[test]
fn duplicate_nullifier_rejected_by_registry() {
    let mut rng = StdRng::seed_from_u64(1);
    let (pk, _) = keygen_for_tests(&mut rng);
    let ct = encrypt_packed(&pk, 10, 1, &mut rng).unwrap();
    let ct_bytes = pk.encode_ciphertext(&ct).unwrap().to_vec();
    let receipt = BallotReceipt {
        statement: BallotStatementV1 {
            protocol_version: 1,
            election_domain: [1u8; 32],
            eth_snapshot_root: [2u8; 32],
            sol_snapshot_root: [3u8; 32],
            credential_root: [4u8; 32],
            paillier_key_hash: *pk.fingerprint().as_bytes(),
            n_id: [9u8; 32],
            n_accounts: vec![[8u8; 32]; 4],
            ciphertext: ct_bytes,
        },
        nullifiers: PublicNullifiers {
            identity: [9u8; 32],
            accounts: vec![[8u8; 32]; 4],
        },
        receipt_hash: [7u8; 32],
    };
    let mut reg = BallotRegistry::new();
    reg.accept(receipt.clone()).unwrap();
    assert!(reg.accept(receipt).is_err());
}

#[test]
fn identity_nullifiers_differ_across_elections() {
    let mut rng = StdRng::seed_from_u64(3);
    let s = MasterSecret::random(&mut rng);
    let e1 = Digest32([1u8; 32]);
    let e2 = Digest32([2u8; 32]);
    let n1 = veilgov_identity::election_identity_nullifier(&s, &e1);
    let n2 = veilgov_identity::election_identity_nullifier(&s, &e2);
    assert_ne!(n1, n2);
}

#[test]
fn public_statement_layout_has_no_vote_or_weight_fields() {
    // Journal schema is fixed: version, domain, roots, key hash, nullifiers, ciphertext.
    // Vote bit and weights live only in the private witness / packed plaintext under Enc.
    let statement = BallotStatementV1 {
        protocol_version: 1,
        election_domain: [1u8; 32],
        eth_snapshot_root: [2u8; 32],
        sol_snapshot_root: [3u8; 32],
        credential_root: [4u8; 32],
        paillier_key_hash: [5u8; 32],
        n_id: [6u8; 32],
        n_accounts: vec![[7u8; 32]; 4],
        ciphertext: vec![0u8; 512],
    };
    let bytes = statement.canonical_bytes();
    let parsed = BallotStatementV1::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(parsed.protocol_version, 1);
    assert_eq!(parsed.ciphertext.len(), 512);
    assert_eq!(parsed.n_accounts.len(), 4);
    // No decoded vote/weight fields exist on the public statement type.
    let _ = parsed.n_id;
}

#[test]
fn account_secret_binds_scope() {
    let mut rng = StdRng::seed_from_u64(4);
    let s = MasterSecret::random(&mut rng);
    let rho = AccountRandomness::random(&mut rng);
    let s1 = Digest32([1u8; 32]);
    let s2 = Digest32([2u8; 32]);
    let x1 = account_secret(&s, &rho, &s1);
    let x2 = account_secret(&s, &rho, &s2);
    assert_ne!(account_commitment(x1), account_commitment(x2));
}
