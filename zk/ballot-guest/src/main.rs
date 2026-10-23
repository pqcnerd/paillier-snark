#![no_main]

use risc0_zkvm::guest::env;
use veilgov_ballot::{verify_ballot_statement, BallotProofInput};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: BallotProofInput = env::read();
    let verified = verify_ballot_statement(&input.public, &input.witness)
        .expect("invalid VeilGov ballot witness");

    // The only public output is the authoritative fixed-width statement.
    // No address, balance, aggregate weight, vote, secret, path, or Paillier
    // randomness is committed.
    env::commit_slice(&verified.statement.canonical_bytes());
}
