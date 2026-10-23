# VeilGov

Experimental research prototype for **unlinkable heterogeneous cross-chain voting power consolidation** (Ethereum + Solana → one anonymous exact-once ballot on an EVM registry).

> Not production cryptography. Single Paillier keys are **DEVELOPMENT ONLY**. Solana snapshots are **quorum-attested**, not trustlessly state-proven.

## Enforceable claim

Each uniquely issued account credential contributes snapshotted weight at most once per election on the canonical EVM ledger.

## Not claimed

- One human, one identity
- Completeness of a person's holdings
- Trustless Solana historical inclusion proofs
- Novelty / “first system”

See [docs/protocol.md](docs/protocol.md).

## Confidential ballot path (ZK milestone)

**Before:** native `prove_ballot_native` oracle trusted by the demo/registry path.

**After:** one shared predicate `verify_ballot_statement` runs in a **real RISC Zero 3.0.6** guest; journal = `BallotStatementV1::canonical_bytes()`; host samples Paillier `r`; verifier APIs take only the receipt + public `ElectionConfig`.

```text
witness (private) → verify_ballot_statement → BallotStatementV1 journal
host samples Paillier r → guest checks Enc(pk, pack(w,v); r) == ciphertext
verifier receives only the receipt + public election context
```

`RISC0_DEV_MODE` is rejected. Fake/`NATV` proofs are not accepted as cryptographic verification.

**Honest status:** guest execute + journal differential are wired and measured (~1.5×10⁸ cycles / ballot). Full dual-ballot CPU composite proving was started and aborted (~1h35m on Alice); fill [docs/zk-benchmarks.md](docs/zk-benchmarks.md) after `demo --zk-prove` completes. On-chain Groth16 seal verification is deferred (adapter ABI only).

## Quick start

```bash
# Host toolchain (workspace)
rustup show   # pin: rust-toolchain.toml (1.90.0)

# RISC Zero guest toolchain (required for guest execute / prove)
curl -L https://risczero.com/install | bash
rzup install cargo-risczero 3.0.6
rzup install rust 1.97.0
export PATH="$HOME/.risc0/bin:$PATH"
unset RISC0_DEV_MODE

cargo test --workspace
cargo run --release -p veilgov -- zk-cycles   # guest execute / cycle count
cargo run --release -p veilgov -- demo        # execute differential + tally
cargo run --release -p veilgov -- demo --zk-prove  # real receipts (multi-hour CPU)
```

Expected demo result: `YES=100`, `NO=50`, `TOTAL=150` (Alice 60+40 YES, Bob 20+30 NO).

See [docs/zk-benchmarks.md](docs/zk-benchmarks.md) and [docs/zk-integration-plan.md](docs/zk-integration-plan.md).

## CLI

```text
veilgov setup
veilgov create-identity
veilgov demo [--zk-prove]
veilgov zk-cycles
veilgov prove-ballot <input.json> <proof.bin> <statement.json>
veilgov verify-ballot <proof.bin> <config.json>
veilgov benchmark
veilgov verify-result target/demo/result.json
```

## Layout

- `crates/` — protocol, identity, merkle, snapshots, enrollment, Paillier, ballot, tally, zk-ballot
- `zk/methods` + `zk/ballot-guest` — pinned RISC Zero guest ELF / image ID
- `contracts/evm/` — Foundry election registry + RISC Zero verifier adapter
- `docs/` — protocol, threat, privacy, trust, zk integration / benchmarks

## License

MIT OR Apache-2.0
