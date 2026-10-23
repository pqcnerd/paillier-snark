use anyhow::Result;
use rand::SeedableRng;
use rand::rngs::StdRng;
use veilgov_paillier::{keygen_for_tests, DEV_WARNING};

pub fn run() -> Result<()> {
    println!("{DEV_WARNING}");
    let mut rng = StdRng::seed_from_u64(0x5E11_60F1);
    let (pk, _sk) = keygen_for_tests(&mut rng);
    let fp = pk.fingerprint();
    println!("paillier_key_hash={}", hex::encode(fp.as_bytes()));
    println!("n_bits={}", pk.n.bits());
    println!("Stored secret key path should be set via VEILGOV_PAILLIER_SK (never commit).");
    println!("MVP uses in-process test keys for `veilgov demo`.");
    Ok(())
}
