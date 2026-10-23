use anyhow::Result;
use rand::rngs::OsRng;
use veilgov_identity::MasterSecret;

pub fn run() -> Result<()> {
    let s = MasterSecret::random(&mut OsRng);
    let id = s.identity_commitment();
    println!("master_secret={}", hex::encode(s.to_bytes()));
    println!(
        "identity_commitment={}",
        hex::encode(veilgov_domains::fr_to_bytes(&id))
    );
    println!("Keep master_secret offline. Identity commitment is not published during MVP enrollment.");
    Ok(())
}
