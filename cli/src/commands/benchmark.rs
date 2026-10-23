use anyhow::Result;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::json;
use std::time::Instant;
use veilgov_paillier::{aggregate, encrypt_packed, keygen_for_tests};

pub fn run() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(99);
    let (pk, sk) = keygen_for_tests(&mut rng);

    let t0 = Instant::now();
    let mut cts = Vec::new();
    for i in 0..32u128 {
        cts.push(encrypt_packed(&pk, 10 + i, (i % 2) as u8, &mut rng)?);
    }
    let enc_ms = t0.elapsed().as_millis();

    let t1 = Instant::now();
    let agg = aggregate(&pk, &cts)?;
    let agg_ms = t1.elapsed().as_millis();

    let t2 = Instant::now();
    let _ = veilgov_paillier::decrypt(&sk, &agg)?;
    let dec_ms = t2.elapsed().as_millis();

    let report = json!({
        "benchmark_backend": "native_host_plus_zk_guest_execute",
        "paillier_encrypt_x32_ms": enc_ms,
        "paillier_aggregate_x32_ms": agg_ms,
        "paillier_decrypt_ms": dec_ms,
        "zkvm": "risc0-3.0.6",
        "note": "Run `veilgov zk-cycles` and `veilgov demo` for guest cycles / proving metrics",
        "guest_cycle_command": "veilgov zk-cycles",
        "proof_command": "veilgov demo",
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    println!("human=paillier_encrypt_x32_ms={enc_ms} aggregate_ms={agg_ms} decrypt_ms={dec_ms}");
    println!("human=zk_metrics_via=veilgov zk-cycles | veilgov demo");
    Ok(())
}
