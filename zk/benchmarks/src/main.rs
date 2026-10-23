//! Native host benchmarks. RISC Zero / SP1 spikes require separate toolchains.
//!
//! See docs/benchmarks.md for the comparison plan.

use ark_bn254::Fr;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::Instant;
use veilgov_domains::MERKLE_DEPTH;
use veilgov_merkle::PoseidonTree;
use veilgov_paillier::{aggregate, encrypt_packed, keygen_for_tests};

fn main() {
    let mut rng = StdRng::seed_from_u64(1);
    let (pk, sk) = keygen_for_tests(&mut rng);

    let leaves: Vec<Fr> = (0..64).map(|i| Fr::from(i as u64)).collect();
    let t0 = Instant::now();
    let tree = PoseidonTree::with_leaves(MERKLE_DEPTH, &leaves).unwrap();
    let _ = tree.prove(7).unwrap();
    println!(
        "poseidon_tree_depth{MERKLE_DEPTH}_64leaves_us={}",
        t0.elapsed().as_micros()
    );

    let t1 = Instant::now();
    let mut cts = Vec::new();
    for i in 0..16u128 {
        cts.push(encrypt_packed(&pk, i + 1, (i % 2) as u8, &mut rng).unwrap());
    }
    println!("paillier_encrypt_x16_us={}", t1.elapsed().as_micros());

    let t2 = Instant::now();
    let agg = aggregate(&pk, &cts).unwrap();
    println!("paillier_aggregate_x16_us={}", t2.elapsed().as_micros());
    let _ = veilgov_paillier::decrypt(&sk, &agg).unwrap();

    println!("zkvm_status=pending_toolchain");
    println!("risc_zero_spike=zk/ballot-guest (stub)");
    println!("sp1_spike=zk/methods (stub)");
    println!("go_no_go=native_predicate_ok; pin zkVM after install + cycle benchmarks");
}
