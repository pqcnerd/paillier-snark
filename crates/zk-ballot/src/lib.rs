//! Real RISC Zero proof generation and public-only verification for VeilGov ballots.

use anyhow::{anyhow, Context, Result};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts, Receipt, ReceiptKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use veilgov_ballot::{
    receipt_from_verified_statement, verify_ballot_statement, BallotProofInput, BallotReceipt,
    BallotStatementV1,
};
use veilgov_protocol_types::ElectionConfig;
use veilgov_zk_methods::{VEILGOV_BALLOT_GUEST_ELF, VEILGOV_BALLOT_GUEST_ID};

/// Segment size used for local CPU proving. Lower values cut peak RAM roughly in half
/// per decrement of the power-of-two.
/// Segment size for local CPU proving on high-RAM hosts.
/// RISC Zero's default prover max is po2=22 (4M cycles/segment).
/// ~153M guest cycles → ~37 segments; expect tens of GiB peak RSS.
const SEGMENT_LIMIT_PO2: u32 = 22;

pub const BALLOT_IMAGE_ID_BYTES: [u8; 32] = [
    0xa7, 0x24, 0x9b, 0xd0, 0x91, 0xe1, 0xad, 0xcc, 0xfc, 0x9c, 0x02, 0x24, 0xa1, 0xd3,
    0xa6, 0xe4, 0x10, 0x5e, 0x74, 0xb0, 0x4f, 0x8f, 0xae, 0x39, 0x28, 0x62, 0x62, 0x1d,
    0x18, 0x86, 0x57, 0xa7,
];

pub const PUBLIC_JOURNAL_FIELDS: &[&str] = &[
    "protocol_version",
    "election_domain",
    "ethereum_snapshot_root",
    "solana_snapshot_root",
    "credential_root",
    "paillier_key_hash",
    "identity_nullifier",
    "account_nullifiers[4]",
    "paillier_ciphertext[512]",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetrics {
    pub guest_total_cycles: u64,
    pub guest_user_cycles: u64,
    pub segments: usize,
    pub proving_millis: u128,
    pub verification_micros: u128,
    pub proof_size_bytes: usize,
    pub journal_size_bytes: usize,
}

pub struct GeneratedBallotProof {
    pub receipt: Receipt,
    pub ballot_receipt: BallotReceipt,
    pub metrics: ProofMetrics,
}

fn reject_dev_mode() -> Result<()> {
    if std::env::var_os("RISC0_DEV_MODE").is_some_and(|value| value != "0") {
        return Err(anyhow!(
            "RISC0_DEV_MODE must be unset or 0; fake development receipts are forbidden"
        ));
    }
    Ok(())
}

fn build_env(input: &BallotProofInput) -> Result<ExecutorEnv<'static>> {
    ExecutorEnv::builder()
        .segment_limit_po2(SEGMENT_LIMIT_PO2)
        .write(input)
        .context("serialize private ballot input")?
        .build()
        .context("build RISC Zero execution environment")
}

/// Execute the guest without proving. Useful for cycle measurement.
pub fn execute_ballot(input: &BallotProofInput) -> Result<(BallotStatementV1, u64, u64)> {
    reject_dev_mode()?;
    if input.public.config.verifier_id != BALLOT_IMAGE_ID_BYTES {
        return Err(anyhow!("election verifier_id does not match ballot guest image ID"));
    }
    let expected = verify_ballot_statement(&input.public, &input.witness)
        .context("native ballot predicate rejected witness")?;
    let env = build_env(input)?;
    let session = default_executor()
        .execute(env, VEILGOV_BALLOT_GUEST_ELF)
        .context("RISC Zero ballot guest execution failed")?;
    let statement = BallotStatementV1::from_canonical_bytes(&session.journal.bytes)
        .context("decode canonical ballot journal")?;
    if statement.canonical_bytes() != expected.statement.canonical_bytes() {
        return Err(anyhow!("native and zkVM ballot statements differ"));
    }
    Ok((
        statement,
        session.cycles(),
        session.segments.len() as u64,
    ))
}

/// Generate a real cryptographic RISC Zero receipt. Development mode is
/// explicitly rejected because it produces no cryptographic proof.
pub fn prove_ballot(input: &BallotProofInput) -> Result<GeneratedBallotProof> {
    reject_dev_mode()?;
    if input.public.config.verifier_id != BALLOT_IMAGE_ID_BYTES {
        return Err(anyhow!("election verifier_id does not match ballot guest image ID"));
    }

    // Native differential oracle: the exact same function runs in the guest.
    let expected = verify_ballot_statement(&input.public, &input.witness)
        .context("native ballot predicate rejected witness")?;

    let env = build_env(input)?;
    // Default ProverOpts already allow segment_limit_po2 up to 22.
    let opts = ProverOpts::default()
        .with_receipt_kind(ReceiptKind::Composite)
        .with_dev_mode(false);

    let proving_started = Instant::now();
    let prove_info = default_prover()
        .prove_with_opts(env, VEILGOV_BALLOT_GUEST_ELF, &opts)
        .context("RISC Zero ballot proving failed")?;
    let proving_elapsed = proving_started.elapsed();
    let receipt = prove_info.receipt;

    let verification_started = Instant::now();
    receipt
        .verify(VEILGOV_BALLOT_GUEST_ID)
        .context("RISC Zero ballot receipt verification failed")?;
    let verification_elapsed = verification_started.elapsed();

    let statement = BallotStatementV1::from_canonical_bytes(&receipt.journal.bytes)
        .context("decode canonical ballot journal")?;
    statement
        .validate_public_context(&input.public.config)
        .context("journal does not match election public context")?;
    if statement.canonical_bytes() != expected.statement.canonical_bytes() {
        return Err(anyhow!("native and zkVM ballot statements differ"));
    }

    let serialized_receipt =
        bincode::serialize(&receipt).context("serialize RISC Zero receipt")?;
    let proof_commitment = proof_commitment(&serialized_receipt);
    let ballot_receipt = receipt_from_verified_statement(statement, proof_commitment);

    Ok(GeneratedBallotProof {
        metrics: ProofMetrics {
            guest_total_cycles: prove_info.stats.total_cycles,
            guest_user_cycles: prove_info.stats.user_cycles,
            segments: prove_info.stats.segments,
            proving_millis: proving_elapsed.as_millis(),
            verification_micros: verification_elapsed.as_micros(),
            proof_size_bytes: serialized_receipt.len(),
            journal_size_bytes: receipt.journal.bytes.len(),
        },
        receipt,
        ballot_receipt,
    })
}

/// Verify using only the cryptographic receipt and expected public election
/// context. No private witness is accepted by this API.
pub fn verify_ballot_proof(
    receipt: &Receipt,
    expected_config: &ElectionConfig,
) -> Result<BallotReceipt> {
    if std::env::var_os("RISC0_DEV_MODE").is_some_and(|value| value != "0") {
        return Err(anyhow!(
            "RISC0_DEV_MODE must be unset or 0 when verifying protocol proofs"
        ));
    }
    if expected_config.verifier_id != BALLOT_IMAGE_ID_BYTES {
        return Err(anyhow!("election verifier_id does not match ballot guest image ID"));
    }
    receipt
        .verify(VEILGOV_BALLOT_GUEST_ID)
        .context("invalid RISC Zero ballot receipt")?;
    let statement = BallotStatementV1::from_canonical_bytes(&receipt.journal.bytes)
        .context("invalid ballot journal")?;
    statement
        .validate_public_context(expected_config)
        .context("proof journal public context mismatch")?;

    let serialized_receipt =
        bincode::serialize(receipt).context("serialize verified RISC Zero receipt")?;
    Ok(receipt_from_verified_statement(
        statement,
        proof_commitment(&serialized_receipt),
    ))
}

pub fn encode_receipt(receipt: &Receipt) -> Result<Vec<u8>> {
    bincode::serialize(receipt).context("serialize RISC Zero receipt")
}

pub fn verify_ballot_proof_bytes(
    bytes: &[u8],
    expected_config: &ElectionConfig,
) -> Result<BallotReceipt> {
    let receipt: Receipt =
        bincode::deserialize(bytes).context("deserialize RISC Zero receipt")?;
    verify_ballot_proof(&receipt, expected_config)
}

pub fn inspect_public_journal(bytes: &[u8]) -> Result<BallotStatementV1> {
    BallotStatementV1::from_canonical_bytes(bytes).context("decode public ballot journal")
}

pub fn proof_commitment(serialized_receipt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"VEILGOV_RISC0_RECEIPT_V1");
    hasher.update(serialized_receipt);
    hasher.finalize().into()
}

pub fn image_id_hex() -> String {
    hex_words(&VEILGOV_BALLOT_GUEST_ID)
}

fn hex_words(words: &[u32; 8]) -> String {
    let mut out = String::with_capacity(64);
    for word in words {
        out.push_str(&format!("{word:08x}"));
    }
    out
}

pub fn duration_millis(duration: Duration) -> u128 {
    duration.as_millis()
}
