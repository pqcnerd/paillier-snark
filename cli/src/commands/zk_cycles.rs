//! Execute the ballot guest without proving to report cycle counts.

use anyhow::{Context, Result};
use rand::rngs::StdRng;
use rand::SeedableRng;
use veilgov_ballot::{
    pad_witness_accounts, prove_ballot_native, AccountWitness, BallotProofInput, BallotPublicInputs,
    BallotWitness, EthereumSnapshotContext, SolanaSnapshotContext,
};
use veilgov_domains::bytes_to_fr;
use veilgov_encoding::Digest32;
use veilgov_enrollment::{EnrollmentRequest, RegistrarState};
use veilgov_identity::{
    account_commitment, account_secret, compute_scope, AccountRandomness, MasterSecret,
};
use veilgov_paillier::{keygen_for_tests, sample_randomness};
use veilgov_protocol_types::{ElectionConfig, ElectionId, VoteBit};
use veilgov_snapshot_ethereum::{
    build_eth_snapshot, demo_header, weight_policy_hash, EthHolder, EthTokenAdapter,
};
use veilgov_snapshot_solana::{
    build_sol_snapshot, demo_bank, weight_policy_hash as sol_policy_hash, SplHolder, SplTokenAdapter,
};
use veilgov_zk_ballot::{execute_ballot, BALLOT_IMAGE_ID_BYTES};

const CHAIN_ETH: u64 = 1;
const CHAIN_SOL: u64 = 2;

pub fn run() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, _) = keygen_for_tests(&mut rng);
    let election_id = ElectionId([0xE1; 32]);
    let header = demo_header();
    let bank = demo_bank();
    let eth_adapter = EthTokenAdapter::mock_gov();
    let sol_adapter = SplTokenAdapter::mock_gov();

    let alice_eth = [0xA1; 20];
    let bob_eth = [0xB1; 20];
    let alice_sol = [0xA2; 32];
    let bob_sol = [0xB2; 32];

    let eth_snap = build_eth_snapshot(
        election_id.0,
        &header,
        &eth_adapter,
        &[
            EthHolder {
                address: alice_eth,
                balance: 60,
            },
            EthHolder {
                address: bob_eth,
                balance: 20,
            },
        ],
    )?;
    let sol_snap = build_sol_snapshot(
        election_id.0,
        &bank,
        &sol_adapter,
        &[
            SplHolder {
                authority: alice_sol,
                amount: 40,
            },
            SplHolder {
                authority: bob_sol,
                amount: 30,
            },
        ],
    )?;

    let eth_policy = weight_policy_hash(&eth_adapter);
    let sol_policy = sol_policy_hash(&sol_adapter);
    let eth_scope = compute_scope(
        &header.genesis_hash,
        Some(header.chain_id),
        &election_id.0,
        &eth_adapter.token_address,
        &eth_policy,
    );
    let sol_scope = compute_scope(
        &bank.genesis_hash,
        None,
        &election_id.0,
        &sol_adapter.mint,
        &sol_policy,
    );

    let alice_s = MasterSecret::random(&mut rng);
    let alice_rho_eth = AccountRandomness::random(&mut rng);
    let alice_rho_sol = AccountRandomness::random(&mut rng);
    let mut registrar = RegistrarState::new();

    let alice_eth_leaf =
        bytes_to_fr(&eth_snap.records.iter().find(|r| r.owner == alice_eth).unwrap().leaf);
    let alice_sol_leaf =
        bytes_to_fr(&sol_snap.records.iter().find(|r| r.owner == alice_sol).unwrap().leaf);

    macro_rules! enroll {
        ($s:expr, $rho:expr, $scope:expr, $owner:expr, $amount:expr, $snap_leaf:expr, $tag:expr) => {{
            let x = account_secret($s, $rho, $scope);
            let a = account_commitment(x);
            let a_bytes = veilgov_domains::fr_to_bytes(&a);
            let snap_bytes = veilgov_domains::fr_to_bytes($snap_leaf);
            let req = EnrollmentRequest {
                scope: $scope.clone(),
                chain_tag: $tag,
                owner: $owner.to_vec(),
                amount: $amount,
                account_commitment: a_bytes,
                snapshot_leaf: snap_bytes,
                nonce: 1,
                expiry_unix: u64::MAX,
            };
            registrar.enroll(req, a, *$snap_leaf, 1)?
        }};
    }

    let alice_cred_eth = enroll!(
        &alice_s,
        &alice_rho_eth,
        &eth_scope,
        alice_eth,
        60u64,
        &alice_eth_leaf,
        CHAIN_ETH
    );
    let alice_cred_sol = enroll!(
        &alice_s,
        &alice_rho_sol,
        &sol_scope,
        alice_sol,
        40u64,
        &alice_sol_leaf,
        CHAIN_SOL
    );

    // Also enroll Bob so the credential tree shape matches the demo.
    let bob_s = MasterSecret::random(&mut rng);
    let bob_rho_eth = AccountRandomness::random(&mut rng);
    let bob_rho_sol = AccountRandomness::random(&mut rng);
    let bob_eth_leaf =
        bytes_to_fr(&eth_snap.records.iter().find(|r| r.owner == bob_eth).unwrap().leaf);
    let bob_sol_leaf =
        bytes_to_fr(&sol_snap.records.iter().find(|r| r.owner == bob_sol).unwrap().leaf);
    let _ = enroll!(
        &bob_s,
        &bob_rho_eth,
        &eth_scope,
        bob_eth,
        20u64,
        &bob_eth_leaf,
        CHAIN_ETH
    );
    let _ = enroll!(
        &bob_s,
        &bob_rho_sol,
        &sol_scope,
        bob_sol,
        30u64,
        &bob_sol_leaf,
        CHAIN_SOL
    );

    let (cred_tree, cred_batch) = registrar.seal_batch(&mut rng)?;
    let find_cred_idx = |leaf: [u8; 32]| -> usize {
        cred_batch
            .iter()
            .position(|c| c.credential_leaf == leaf)
            .expect("credential in batch")
    };

    let mut config = ElectionConfig::demo(election_id.clone());
    config.eth_snapshot_root = Digest32(eth_snap.manifest.root);
    config.sol_snapshot_root = Digest32(sol_snap.manifest.root);
    config.credential_root = Digest32(cred_tree.root_bytes());
    config.eth_manifest_hash = eth_snap.manifest.digest();
    config.sol_manifest_hash = sol_snap.manifest.digest();
    config.paillier_key_hash = pk.fingerprint();
    config.eligible_total_weight = 150;
    config.verifier_id = BALLOT_IMAGE_ID_BYTES;

    let inputs = BallotPublicInputs {
        config: config.clone(),
        ethereum: EthereumSnapshotContext {
            genesis_hash: header.genesis_hash,
            chain_id: header.chain_id,
            block_hash: header.block_hash,
            asset_id: eth_adapter.token_address.to_vec(),
            weight_policy_hash: eth_policy,
        },
        solana: SolanaSnapshotContext {
            genesis_hash: bank.genesis_hash,
            slot: bank.slot,
            asset_id: sol_adapter.mint.to_vec(),
            weight_policy_hash: sol_policy,
        },
        paillier_modulus: pk.encode_modulus()?.to_vec(),
    };

    let mut witness = BallotWitness {
        master_secret: alice_s.to_bytes(),
        vote: VoteBit::yes().0,
        accounts: vec![
            AccountWitness {
                active: true,
                rho: veilgov_domains::fr_to_bytes(&alice_rho_eth.fr),
                scope: eth_scope.clone(),
                chain_tag: CHAIN_ETH,
                owner: alice_eth.to_vec(),
                amount: 60,
                snapshot_leaf: veilgov_domains::fr_to_bytes(&alice_eth_leaf),
                snapshot_proof: eth_snap
                    .tree
                    .prove(
                        eth_snap
                            .records
                            .iter()
                            .position(|r| r.owner == alice_eth)
                            .unwrap(),
                    )
                    .unwrap(),
                credential_leaf: alice_cred_eth.credential_leaf,
                credential_proof: cred_tree
                    .prove(find_cred_idx(alice_cred_eth.credential_leaf))
                    .unwrap(),
            },
            AccountWitness {
                active: true,
                rho: veilgov_domains::fr_to_bytes(&alice_rho_sol.fr),
                scope: sol_scope.clone(),
                chain_tag: CHAIN_SOL,
                owner: alice_sol.to_vec(),
                amount: 40,
                snapshot_leaf: veilgov_domains::fr_to_bytes(&alice_sol_leaf),
                snapshot_proof: sol_snap
                    .tree
                    .prove(
                        sol_snap
                            .records
                            .iter()
                            .position(|r| r.owner == alice_sol)
                            .unwrap(),
                    )
                    .unwrap(),
                credential_leaf: alice_cred_sol.credential_leaf,
                credential_proof: cred_tree
                    .prove(find_cred_idx(alice_cred_sol.credential_leaf))
                    .unwrap(),
            },
        ],
        paillier_randomness: sample_randomness(&pk, &mut rng).to_bytes_be(),
    };
    pad_witness_accounts(&mut witness)?;
    let native = prove_ballot_native(&inputs, &witness).context("native")?;
    let input = BallotProofInput {
        public: inputs,
        witness,
    };
    let (statement, cycles, segments) = execute_ballot(&input)?;
    assert_eq!(statement.canonical_bytes(), native.statement.canonical_bytes());
    println!("guest_user_cycles={cycles}");
    println!("guest_segments_estimate={segments}");
    println!("segment_limit_po2=22");
    println!("private_weight={}", native.private_weight);
    Ok(())
}
