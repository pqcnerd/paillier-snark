# VeilGov Protocol Specification (v0.1.0)

**Status:** Experimental research prototype  
**Protocol version:** `VEILGOV_PROTOCOL_V1`  
**Encoding version:** `1`

## Thesis

VeilGov privately conserves and optionally consolidates voting power from independently controlled accounts on heterogeneous chains (Ethereum + Solana MVP). A voter proves that hidden accounts appear in election snapshots, that each account was uniquely enrolled, that selected credentials bind to one secret identity, and that bounded weights produce one valid Paillier-encrypted ballot. An EVM registry atomically consumes nullifiers and commits accepted ballots.

**Enforceable claim:** each uniquely issued account credential contributes snapshot weight at most once per election on the canonical EVM ledger.

**Not claimed:** one-human-one-identity; completeness of a person's holdings; trustless Solana historical state proofs; production-ready cryptography.

## Actors

| Actor | Role |
|-------|------|
| Voter | Holds chain keys + master secret `s`; enrolls; casts ballot |
| Snapshot builders (quorum) | Produce deterministic Merkle roots + signed manifests |
| Enrollment registrars (quorum) | Verify native ownership; enforce one-account-one-credential; issue shuffled credential roots |
| EVM registry | Canonical ballot/nullifier ledger |
| Tally aggregator | Permissionless; proves exact-set product of accepted ciphertexts |
| Trustees | Threshold Paillier (production); single DEVELOPMENT key in MVP |
| Relayer (optional) | Submits ballots; availability only |

## Phases

1. **Configure** — Freeze election ID, config hash, finalized ETH block, SOL slot, assets, limits, Paillier key fingerprint, verifier/image ID, deadlines, registrar/trustee sets.
2. **Snapshot** — Build Poseidon trees over eligible accounts; publish signed manifests.
3. **Enroll** — Native wallets authorize randomized account commitments; registrars issue credential leaves; uniqueness enforced privately via `U_i`.
4. **Vote** — Private ballot witness → RISC Zero guest runs `verify_ballot_statement` → public journal + receipt; EVM registry verifies (off-chain composite today; on-chain Groth16 deferred), consumes nullifiers, appends ballot leaf.
5. **Close** — Freeze `(ballotRoot, ballotCount)`.
6. **Tally** — Exact-list scan proves `C_agg`; decrypt to YES / TOTAL / NO.

## Invariants

1. `N_id` and all active `N_i` are unused before acceptance and marked used atomically.
2. Each credential leaf appears under an authorized credential root for the election.
3. Snapshot leaf amounts equal credential amounts for the same account/scope.
4. Weights are `u64`; aggregate is checked `u128`; packed plaintext uses `B = 2^128`.
5. Vote bit `v ∈ {0,1}`; `m = (w·v) + B·w`; `m < n`.
6. Ballot leaf commits to exact ciphertext bytes and nullifier vector.
7. Tally product uses exactly records `0..count-1` under frozen root.

## Failure semantics

| Failure | Effect |
|---------|--------|
| Invalid proof / malformed ciphertext | Reject; no state change |
| Duplicate nullifier | Reject |
| Post-deadline submission | Reject |
| Snapshot equivocation | Election cancelled or pinned to first quorum-signed manifest |
| Insufficient trustee shares | Tally cannot finalize (availability) |
| Registrar censorship | Enrollment unavailable; correctness of accepted set preserved |

## Claims we may make

- Per-account conservation under stated trust assumptions.
- Hidden addresses, component/combined weights, and votes in public protocol data.
- Aggregate bound exactly to frozen ballot root/count.

## Claims we must NOT make

- Novelty / “first” without literature review.
- One person, one vote from wallet keys alone.
- Trustless MVP snapshots or trustless Solana historical inclusion proofs.
- Production Paillier, threshold crypto, coercion resistance, or network anonymity.
- That default `veilgov demo` (without `--zk-prove`) cryptographically verifies STARK receipts — that path uses guest **execute** differential plus the shared predicate.
- That `VerifierAdapter` verifies local composite STARK receipts on-chain (needs Groth16 seal + deployed router).

## ZK path status (milestone)

| Capability | Status |
|------------|--------|
| Shared deterministic ballot predicate + Paillier `r` binding | Done |
| Real RISC Zero 3.0.6 guest / pinned image ID | Done |
| Guest execute + native journal differential | Done / measured |
| Dual-ballot composite prove + public-only verify CLI | Implemented; full CPU prove not completed on measurement host |
| EVM journal reconstruction + mock-router tests | Done |
| On-chain Groth16 verification | Deferred |
