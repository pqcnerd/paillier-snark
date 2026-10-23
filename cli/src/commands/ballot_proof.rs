use anyhow::{Context, Result};
use std::fs;
use veilgov_ballot::BallotProofInput;
use veilgov_protocol_types::ElectionConfig;
use veilgov_zk_ballot::{
    encode_receipt, prove_ballot, verify_ballot_proof_bytes,
};

pub fn prove(input_path: &str, proof_path: &str, statement_path: &str) -> Result<()> {
    let input: BallotProofInput = serde_json::from_slice(
        &fs::read(input_path).with_context(|| format!("read {input_path}"))?,
    )
    .context("decode BallotProofInput JSON")?;
    let generated = prove_ballot(&input)?;
    fs::write(proof_path, encode_receipt(&generated.receipt)?)
        .with_context(|| format!("write {proof_path}"))?;
    fs::write(
        statement_path,
        serde_json::to_vec_pretty(&generated.ballot_receipt.statement)?,
    )
    .with_context(|| format!("write {statement_path}"))?;
    println!("{}", serde_json::to_string_pretty(&generated.metrics)?);
    Ok(())
}

pub fn verify(proof_path: &str, config_path: &str) -> Result<()> {
    let config: ElectionConfig = serde_json::from_slice(
        &fs::read(config_path).with_context(|| format!("read {config_path}"))?,
    )
    .context("decode ElectionConfig JSON")?;
    let proof = fs::read(proof_path).with_context(|| format!("read {proof_path}"))?;
    let verified = verify_ballot_proof_bytes(&proof, &config)?;
    println!("{}", serde_json::to_string_pretty(&verified.statement)?);
    Ok(())
}
