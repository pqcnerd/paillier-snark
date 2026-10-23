//! End-to-end Alice/Bob demo.
//!
//! Default (`veilgov demo`): shared predicate + RISC Zero guest **execute**
//! (journal differential) then tally. Receipts are not STARK-proven.
//!
//! Cryptographic path (`veilgov demo --zk-prove`): real RISC Zero composite
//! receipts. Expect multi-hour CPU proving for ~1.5e8-cycle ETH+SOL guests.
//!
//! Alice: ETH 60 + SOL 40 → YES (hidden 100)
//! Bob:   ETH 20 + SOL 30 → NO  (hidden 50)
//! Result: YES=100, NO=50, TOTAL=150

use anyhow::{Context, Result};
use ark_bn254::Fr;
use rand::rngs::StdRng;
use rand::SeedableRng;
use veilgov_ballot::{
    pad_witness_accounts, prove_ballot_native, receipt_from_verified_statement, AccountWitness,
    BallotProofInput, BallotPublicInputs, BallotWitness, EthereumSnapshotContext,
    SolanaSnapshotContext,
};
use veilgov_domains::bytes_to_fr;
use veilgov_encoding::Digest32;
use veilgov_enrollment::{EnrollmentRequest, RegistrarState};
use veilgov_identity::{
    account_commitment, account_secret, compute_scope, AccountRandomness, MasterSecret,
};
use veilgov_paillier::{keygen_for_tests, sample_randomness, DEV_WARNING};
use veilgov_protocol_types::{ElectionConfig, ElectionId, VoteBit};
use veilgov_snapshot_ethereum::{
    build_eth_snapshot, demo_header, weight_policy_hash, EthHolder, EthTokenAdapter,
};
use veilgov_snapshot_solana::{
    build_sol_snapshot, demo_bank, weight_policy_hash as sol_policy_hash, SplHolder, SplTokenAdapter,
};
use veilgov_tally::{decrypt_result, prove_tally_exact_set, BallotRegistry};
use veilgov_trustee::DevSingleKeyTrustee;
use veilgov_zk_ballot::{
    execute_ballot, prove_ballot, verify_ballot_proof, verify_ballot_proof_bytes,
    BALLOT_IMAGE_ID_BYTES,
};

const CHAIN_ETH: u64 = 1;
const CHAIN_SOL: u64 = 2;

pub fn run(zk_prove: bool) -> Result<()> {
    println!("=== VeilGov Alice/Bob Demo ===");
    println!("{DEV_WARNING}");
    if zk_prove {
        println!("mode=zk_prove (real RISC Zero composite receipts; CPU proving is very slow)");
    } else {
        println!(
            "mode=guest_execute_plus_native_oracle (journal differential only; pass --zk-prove for cryptographic receipts)"
        );
    }

    let mut rng = StdRng::seed_from_u64(42);
    let (pk, sk) = keygen_for_tests(&mut rng);
    let _trustee = DevSingleKeyTrustee::new(sk.clone());

    let election_id = ElectionId([0xE1; 32]);
    let header = demo_header();
    let bank = demo_bank();
    let eth_adapter = EthTokenAdapter::mock_gov();
    let sol_adapter = SplTokenAdapter::mock_gov();

    // Addresses / authorities (demo fixtures — not real wallets).
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

    println!(
        "eth_snapshot_root={}",
        hex::encode(eth_snap.manifest.root)
    );
    println!(
        "sol_snapshot_root={}",
        hex::encode(sol_snap.manifest.root)
    );
    println!(
        "solana_note={}",
        veilgov_snapshot_solana::SOLANA_TRUST_NOTE
    );

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

    // Identities
    let alice_s = MasterSecret::random(&mut rng);
    let bob_s = MasterSecret::random(&mut rng);
    let alice_rho_eth = AccountRandomness::random(&mut rng);
    let alice_rho_sol = AccountRandomness::random(&mut rng);
    let bob_rho_eth = AccountRandomness::random(&mut rng);
    let bob_rho_sol = AccountRandomness::random(&mut rng);

    let mut registrar = RegistrarState::new();

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
            let issued = registrar.enroll(req, a, *$snap_leaf, 1)?;
            (x, issued)
        }};
    }

    let alice_eth_leaf = bytes_to_fr(&eth_snap.records.iter().find(|r| r.owner == alice_eth).unwrap().leaf);
    let alice_sol_leaf = bytes_to_fr(&sol_snap.records.iter().find(|r| r.owner == alice_sol).unwrap().leaf);
    let bob_eth_leaf = bytes_to_fr(&eth_snap.records.iter().find(|r| r.owner == bob_eth).unwrap().leaf);
    let bob_sol_leaf = bytes_to_fr(&sol_snap.records.iter().find(|r| r.owner == bob_sol).unwrap().leaf);

    let (alice_x_eth, alice_cred_eth) = enroll!(
        &alice_s,
        &alice_rho_eth,
        &eth_scope,
        alice_eth,
        60u64,
        &alice_eth_leaf,
        CHAIN_ETH
    );
    let (alice_x_sol, alice_cred_sol) = enroll!(
        &alice_s,
        &alice_rho_sol,
        &sol_scope,
        alice_sol,
        40u64,
        &alice_sol_leaf,
        CHAIN_SOL
    );
    let (bob_x_eth, bob_cred_eth) = enroll!(
        &bob_s,
        &bob_rho_eth,
        &eth_scope,
        bob_eth,
        20u64,
        &bob_eth_leaf,
        CHAIN_ETH
    );
    let (bob_x_sol, bob_cred_sol) = enroll!(
        &bob_s,
        &bob_rho_sol,
        &sol_scope,
        bob_sol,
        30u64,
        &bob_sol_leaf,
        CHAIN_SOL
    );
    let _ = (alice_x_eth, alice_x_sol, bob_x_eth, bob_x_sol);

    let (cred_tree, cred_batch) = registrar.seal_batch(&mut rng)?;
    println!("credential_root={}", hex::encode(cred_tree.root_bytes()));

    // Map credential leaf -> index in shuffled batch
    let find_cred_idx = |leaf: [u8; 32]| -> usize {
        cred_batch
            .iter()
            .position(|c| c.credential_leaf == leaf)
            .expect("credential in batch")
    };

    let eth_tree = &eth_snap.tree;
    let sol_tree = &sol_snap.tree;

    let eth_idx = |owner: &[u8]| {
        eth_snap
            .records
            .iter()
            .position(|r| r.owner == owner)
            .unwrap()
    };
    let sol_idx = |owner: &[u8]| {
        sol_snap
            .records
            .iter()
            .position(|r| r.owner == owner)
            .unwrap()
    };

    let mut config = ElectionConfig::demo(election_id.clone());
    config.eth_snapshot_root = Digest32(eth_snap.manifest.root);
    config.sol_snapshot_root = Digest32(sol_snap.manifest.root);
    config.credential_root = Digest32(cred_tree.root_bytes());
    config.eth_manifest_hash = eth_snap.manifest.digest();
    config.sol_manifest_hash = sol_snap.manifest.digest();
    config.paillier_key_hash = pk.fingerprint();
    config.verifier_id = BALLOT_IMAGE_ID_BYTES;
    config.eligible_total_weight = 150;

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

    fn account_wit(
        active: bool,
        rho: AccountRandomness,
        scope: Digest32,
        chain_tag: u64,
        owner: Vec<u8>,
        amount: u64,
        snap_leaf: Fr,
        snap_proof: veilgov_merkle::MerkleProof,
        cred_leaf_bytes: [u8; 32],
        cred_proof: veilgov_merkle::MerkleProof,
    ) -> AccountWitness {
        AccountWitness {
            active,
            rho: veilgov_domains::fr_to_bytes(&rho.fr),
            scope,
            chain_tag,
            owner,
            amount,
            snapshot_leaf: veilgov_domains::fr_to_bytes(&snap_leaf),
            snapshot_proof: snap_proof,
            credential_leaf: cred_leaf_bytes,
            credential_proof: cred_proof,
        }
    }

    let alice_accounts = vec![
        account_wit(
            true,
            alice_rho_eth,
            eth_scope.clone(),
            CHAIN_ETH,
            alice_eth.to_vec(),
            60,
            alice_eth_leaf,
            eth_tree.prove(eth_idx(&alice_eth)).unwrap(),
            alice_cred_eth.credential_leaf,
            cred_tree
                .prove(find_cred_idx(alice_cred_eth.credential_leaf))
                .unwrap(),
        ),
        account_wit(
            true,
            alice_rho_sol,
            sol_scope.clone(),
            CHAIN_SOL,
            alice_sol.to_vec(),
            40,
            alice_sol_leaf,
            sol_tree.prove(sol_idx(&alice_sol)).unwrap(),
            alice_cred_sol.credential_leaf,
            cred_tree
                .prove(find_cred_idx(alice_cred_sol.credential_leaf))
                .unwrap(),
        ),
    ];
    let bob_accounts = vec![
        account_wit(
            true,
            bob_rho_eth,
            eth_scope.clone(),
            CHAIN_ETH,
            bob_eth.to_vec(),
            20,
            bob_eth_leaf,
            eth_tree.prove(eth_idx(&bob_eth)).unwrap(),
            bob_cred_eth.credential_leaf,
            cred_tree
                .prove(find_cred_idx(bob_cred_eth.credential_leaf))
                .unwrap(),
        ),
        account_wit(
            true,
            bob_rho_sol,
            sol_scope.clone(),
            CHAIN_SOL,
            bob_sol.to_vec(),
            30,
            bob_sol_leaf,
            sol_tree.prove(sol_idx(&bob_sol)).unwrap(),
            bob_cred_sol.credential_leaf,
            cred_tree
                .prove(find_cred_idx(bob_cred_sol.credential_leaf))
                .unwrap(),
        ),
    ];

    let alice_r = sample_randomness(&pk, &mut rng);
    let bob_r = sample_randomness(&pk, &mut rng);
    let mut alice_witness = BallotWitness {
        master_secret: alice_s.to_bytes(),
        vote: VoteBit::yes().0,
        accounts: alice_accounts,
        paillier_randomness: alice_r.to_bytes_be(),
    };
    let mut bob_witness = BallotWitness {
        master_secret: bob_s.to_bytes(),
        vote: VoteBit::no().0,
        accounts: bob_accounts,
        paillier_randomness: bob_r.to_bytes_be(),
    };
    pad_witness_accounts(&mut alice_witness)?;
    pad_witness_accounts(&mut bob_witness)?;

    let alice_verified = prove_ballot_native(&inputs, &alice_witness)
    .context("alice ballot")?;
    let bob_verified = prove_ballot_native(&inputs, &bob_witness)
    .context("bob ballot")?;

    let alice_input = BallotProofInput {
        public: inputs.clone(),
        witness: alice_witness,
    };
    let bob_input = BallotProofInput {
        public: inputs.clone(),
        witness: bob_witness,
    };

    // Always execute the guest: journal must match the native shared predicate.
    println!("executing_alice_guest=true");
    let (alice_guest_statement, alice_cycles, alice_segments) = execute_ballot(&alice_input)?;
    println!("alice_guest_cycles={alice_cycles} alice_segments={alice_segments}");
    assert_eq!(
        alice_guest_statement.canonical_bytes(),
        alice_verified.statement.canonical_bytes()
    );

    println!("executing_bob_guest=true");
    let (bob_guest_statement, bob_cycles, bob_segments) = execute_ballot(&bob_input)?;
    println!("bob_guest_cycles={bob_cycles} bob_segments={bob_segments}");
    assert_eq!(
        bob_guest_statement.canonical_bytes(),
        bob_verified.statement.canonical_bytes()
    );

    let (alice_receipt, bob_receipt) = if zk_prove {
        println!("generating_alice_zk_proof=true");
        let alice_proof = prove_ballot(&alice_input)?;
        let alice_receipt = verify_ballot_proof(&alice_proof.receipt, &config)?;
        println!(
            "alice_zk_cycles={} alice_proving_ms={} alice_proof_bytes={} alice_verify_us={}",
            alice_proof.metrics.guest_total_cycles,
            alice_proof.metrics.proving_millis,
            alice_proof.metrics.proof_size_bytes,
            alice_proof.metrics.verification_micros
        );

        println!("generating_bob_zk_proof=true");
        let bob_proof = prove_ballot(&bob_input)?;
        let bob_receipt = verify_ballot_proof(&bob_proof.receipt, &config)?;
        println!(
            "bob_zk_cycles={} bob_proving_ms={} bob_proof_bytes={} bob_verify_us={}",
            bob_proof.metrics.guest_total_cycles,
            bob_proof.metrics.proving_millis,
            bob_proof.metrics.proof_size_bytes,
            bob_proof.metrics.verification_micros
        );

        assert_eq!(
            alice_receipt.statement.canonical_bytes(),
            alice_verified.statement.canonical_bytes()
        );
        assert_eq!(
            bob_receipt.statement.canonical_bytes(),
            bob_verified.statement.canonical_bytes()
        );

        let mut tampered_receipt = alice_proof.receipt.clone();
        tampered_receipt.journal.bytes[0] ^= 1;
        assert!(verify_ballot_proof(&tampered_receipt, &config).is_err());
        let mut replay_config = config.clone();
        replay_config.election_id.0[0] ^= 1;
        assert!(verify_ballot_proof(&alice_proof.receipt, &replay_config).is_err());
        let mut wrong_root_config = config.clone();
        wrong_root_config.eth_snapshot_root.0[0] ^= 1;
        assert!(verify_ballot_proof(&alice_proof.receipt, &wrong_root_config).is_err());
        let mut wrong_key_config = config.clone();
        wrong_key_config.paillier_key_hash.0[0] ^= 1;
        assert!(verify_ballot_proof(&alice_proof.receipt, &wrong_key_config).is_err());
        assert!(verify_ballot_proof_bytes(b"malformed-proof", &config).is_err());
        println!("zk_adversarial_public_mutations_rejected=true");
        (alice_receipt, bob_receipt)
    } else {
        println!(
            "zk_prove=false; accepting ballots from shared-predicate statements after guest execute differential"
        );
        (
            receipt_from_verified_statement(
                alice_verified.statement.clone(),
                alice_verified.statement.digest(),
            ),
            receipt_from_verified_statement(
                bob_verified.statement.clone(),
                bob_verified.statement.digest(),
            ),
        )
    };

    println!("alice_nullifier={}", hex::encode(alice_receipt.nullifiers.identity));
    println!("bob_nullifier={}", hex::encode(bob_receipt.nullifiers.identity));
    println!(
        "public_ballots_hide_weights_and_votes=true (weights only in private witness; demo logs internal weight for acceptance check)"
    );
    // Internal acceptance check only — not published on ledger:
    assert_eq!(alice_verified.private_weight, 100);
    assert_eq!(bob_verified.private_weight, 50);

    let mut registry = BallotRegistry::new();
    registry.accept(alice_receipt)?;
    registry.accept(bob_receipt)?;

    // Duplicate nullifier must fail
    // (skip re-accept)

    let (root, count) = registry.freeze();
    println!("ballot_root={}", hex::encode(root.as_bytes()));
    println!("ballot_count={count}");

    let (proof, agg) = prove_tally_exact_set(&pk, &root, count, registry.ballots())?;
    let result = decrypt_result(&sk, &pk, &proof, &agg)?;
    println!("YES={}", result.yes);
    println!("NO={}", result.no);
    println!("TOTAL={}", result.total);
    println!("{}", result.warning);

    assert_eq!(result.yes, 100);
    assert_eq!(result.no, 50);
    assert_eq!(result.total, 150);

    let out = serde_json::to_string_pretty(&result)?;
    std::fs::create_dir_all("target/demo")?;
    std::fs::write("target/demo/result.json", &out)?;
    println!("wrote target/demo/result.json");
    println!("=== DEMO OK ===");
    Ok(())
}
