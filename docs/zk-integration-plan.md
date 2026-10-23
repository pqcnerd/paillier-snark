# VeilGov ZK Integration Plan

Status: implementation audit completed before refactoring.

## Current statement and predicate

The current host-side confidential ballot computation is
`veilgov_ballot::prove_ballot_native` in `crates/ballot/src/lib.rs`. It takes:

- `BallotPublicInputs`: election configuration, Ethereum/Solana snapshot roots,
  credential root, and Paillier public key.
- `BallotWitness`: master identity secret, binary vote, and account witnesses.
- A host RNG used to sample Paillier randomness.

It returns `BallotReceipt`, whose public statement contains protocol version,
election domain, snapshot and credential roots, Paillier key fingerprint,
identity/account nullifiers, and a fixed-width Paillier ciphertext.

The function is the reference semantics that the proof must attest to, but the
audit found that its current implementation is incomplete and therefore unsafe
to prove unchanged:

1. It verifies Merkle membership of witness-supplied leaf hashes but does not
   recompute Ethereum/Solana leaves from owner, amount, asset, and snapshot
   context.
2. It computes the account commitment but does not recompute the credential
   leaf from scope, owner, amount, commitment, and snapshot leaf.
3. It does not bind separate `BallotPublicInputs` roots/key to the roots/key
   frozen in `ElectionConfig`.
4. It does not enforce per-account or election-total weight limits.
5. Paillier randomness is sampled by the host and is not part of the witness,
   so a deterministic guest cannot verify the encryption relation.
6. `BallotStatementV1::digest()` hashes JSON while `receipt_hash` hashes the
   fixed-width encoding. Consensus-relevant statement hashing needs one
   authoritative encoding.

These are correctness fixes to the documented current protocol, not a protocol
redesign.

## Intended shared predicate

Refactor to one deterministic function:

```rust
verify_ballot_statement(
    public: &BallotPublicInputs,
    witness: &BallotWitness,
) -> Result<VerifiedBallot, BallotError>
```

The witness will contain Paillier randomness `r`; the function will perform no
network, filesystem, clock, environment, or randomness access. Native tests and
the zkVM guest call this exact function. A host-only builder samples `r` and
then invokes the shared predicate.

The shared predicate will:

1. bind configuration roots and key fingerprint;
2. recompute source snapshot leaf preimages;
3. verify source membership;
4. derive `x`, account commitment, and credential leaf;
5. verify credential membership;
6. reject duplicate active credentials;
7. derive election/account nullifiers;
8. enforce `u64` source amounts, checked `u128` sum, configured bounds, and
   `v ∈ {0,1}`;
9. compute packed `m = w*v + 2^128*w`;
10. verify `C = (1+n)^m * r^n mod n²` using private `r`; and
11. emit only `BallotStatementV1`.

`BallotStatementV1::canonical_bytes()` is the journal and statement digest
source. The journal does not contain addresses, balances, aggregate weight,
vote, identity secret, paths, or encryption randomness.

## zkVM selection

Selected: **RISC Zero 3.0.6**.

RISC Zero and SP1 both reuse Rust and support compressed/EVM-oriented proofs.
RISC Zero is selected because the current Paillier relation needs arbitrary
modular exponentiation modulo a roughly 4096-bit `n²`, and RISC Zero has the
clearest documented path for accelerated 4096-bit modular exponentiation.
SP1's documented general bigint acceleration does not establish equivalent
support for this Paillier workload.

Exact versions to pin:

- `risc0-zkvm = 3.0.6`
- `risc0-build = 3.0.6`
- `cargo-risczero` / `r0vm = 3.0.6`
- EVM integration dependency only after off-chain proof verification is stable.

The initial real-proof path uses a locally verified RISC Zero receipt. EVM
verification follows only after the actual supported verifier router and
Groth16 seal path are available; no hash-only or `NATV` bypass will be described
as cryptographic verification.

## Guest compatibility concerns

- `rand` and key generation remain host-only. The guest receives `r`.
- `serde_json`, filesystem, and CLI code are excluded from the guest.
- `std::sync::OnceLock` in Poseidon may compile, but a guest-safe deterministic
  parameter strategy is preferred if it does not.
- `num-bigint::BigUint::modpow` is functionally reusable but may be too
  expensive without replacing the guest implementation with RISC Zero's
  accelerated fixed-width modular exponentiation.
- Arkworks BN254/Poseidon code must compile for the RISC-V guest and is expected
  to be cycle-heavy; measure it separately.
- Error strings and host conveniences must not become public journal data.
- Guest input uses an explicitly pinned serializer; the public journal uses
  VeilGov fixed-width canonical bytes.

## Paillier feasibility gate

First prove the full current development-key relation with ordinary guest
bigint arithmetic and measure cycles/time. The demo currently uses a 256-bit
test key despite protocol documentation targeting a 2048-bit development key;
benchmarks must distinguish both.

Before claiming full 2048-bit proof support:

1. execute and prove one 2048-bit encryption in the guest;
2. record guest cycles, peak host memory, proving time, verification time, and
   proof size; and
3. switch to the accelerated 4096-bit modular exponentiation path if the generic
   path is prohibitive.

If the 2048-bit path remains impractical, stop at the measured blocker rather
than introducing an equality-of-plaintext redesign in this milestone.

## Implementation phases and files

### Z1 — deterministic shared core

- `crates/ballot/src/lib.rs`: split host builder from pure verifier; add
  Paillier randomness to witness; remove JSON statement digest.
- `crates/paillier-adapter/src/lib.rs`: expose deterministic encryption with
  explicit `r` and validate `r ∈ Z_n*`.
- `crates/protocol-types/src/lib.rs`: include the source snapshot metadata
  required to recompute leaf preimages, and bind roots in the election domain.
- `crates/enrollment/src/lib.rs`: enforce request/field-element consistency.
- `cli/src/commands/demo.rs`: construct complete witnesses.

### Z2/Z3 — real RISC Zero guest and host

- `zk/ballot-guest/`: actual `#![no_main]` guest calling the shared predicate.
- `zk/methods/`: RISC Zero methods build crate and generated ELF/image ID.
- new `crates/zk-ballot/`: host proof generation, receipt verification, journal
  decoding, and proof metrics.
- root `Cargo.toml` / `Cargo.lock` / toolchain docs: exact pins and features.

### Z4 — adversarial and privacy tests

- `integration-tests/`: valid cross-chain proof, all requested public/witness
  mutations, malformed proof, replay, differential native/guest result, and
  decoded-journal privacy inspection.

### Z5/Z6 — CLI and benchmarks

- `cli/src/commands/demo.rs`: default = guest execute + predicate tally;
  `--zk-prove` = real composite receipts + public-only verify before registry
  acceptance.
- `cli/src/commands/ballot_proof.rs`, `zk_cycles.rs`, `benchmark.rs`.
- `docs/zk-benchmarks.md`: reproducible machine/hardware/version/results
  (execute measured; dual-ballot prove aborted mid-run — see that doc).

### Z7 — EVM

- `contracts/evm/src/VerifierAdapter.sol`: the native bypass is removed; the
  adapter calls the actual RISC Zero verifier-router ABI with pinned image ID.
- `contracts/evm/src/VeilGovElection.sol`: reconstruct the exact canonical
  journal, bind it to frozen election state, and verify before consuming
  nullifiers.
- `contracts/evm/test/`: proof/public-input mutation tests if the supported EVM
  proof artifacts can be generated in this environment.

## EVM verification status (Z7)

### Implemented off-chain

- Real RISC Zero composite receipt generation and `receipt.verify(image_id)`
- Canonical journal = `BallotStatementV1::canonical_bytes()`
- Public-only verify API (`verify_ballot_proof`)
- Pinned guest image ID in `zk/methods/IMAGE_IDS.toml`

### Implemented on-chain wiring (not cryptographic Groth16 yet)

- `VerifierAdapter` calls `IRiscZeroVerifier.verify(seal, imageId, journalDigest)` and no longer accepts `NATV` bypasses
- `VeilGovElection.acceptBallot` reconstructs the expected journal from frozen election public data, checks statement digest and receipt commitment, then requires adapter verification before nullifier consumption
- Foundry tests cover invalid proof / mutated public inputs with a **mock** router

### Blocker for real on-chain cryptographic verification

Local CPU demos produce **composite** STARK receipts. Ethereum verification requires:

1. `ProverOpts::groth16()` (or Bonsai) to produce a Groth16 seal
2. `risc0-ethereum-contracts::encode_seal`
3. A deployed RISC Zero 3.0 verifier router on the target chain
4. Cross-language golden vectors for journal bytes ↔ Solidity packing

Until those artifacts are produced in CI/hardware, do **not** claim that `VerifierAdapter` cryptographically verifies a STARK composite receipt on-chain. Off-chain verification remains the authoritative cryptographic check for this milestone.


### Z8 — documentation and reproducibility

- `README.md`, `docs/cryptography.md`, `docs/serialization.md`,
  `docs/privacy-model.md`, and CI/setup scripts.

## Non-goals retained

No threshold Paillier, frontend, new chain, one-human-one-identity claim, or
trustless Solana snapshot claim is introduced by this milestone.
