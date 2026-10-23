# Cryptography

## Field and hash

- Identity / credential Poseidon hashes use a **BN254 scalar field**-compatible Poseidon (arity 2 absorb, sponge-style domain-separated absorption of tagged field elements).  
- MVP implementation: `veilgov-domains` Poseidon over `ark-bn254::Fr` with fixed round constants generated from `"VEILGOV_POSEIDON_V1"`.  
- Outside circuits: SHA-256 and Keccak-256 only for EVM-facing / scope / election-domain digests.

**Do not mix** Poseidon and SHA/Keccak casually. Snapshot/credential trees = Poseidon. Ballot leaves/root = Keccak-256 (EVM registry).

## Packed Paillier ballot

```
B = 2^128
y = w * v
t = w
m = y + B * t
C = (1+n)^m * r^n  mod n^2
```

After aggregate decrypt `M`: `YES = M mod B`, `TOTAL = floor(M/B)`, `NO = TOTAL - YES`.

MVP modulus: **2048-bit**, `g = 1+n`, ciphertext **512 bytes** big-endian. Label: **EXPERIMENTAL / DEVELOPMENT ONLY**. Production target ≥ 3072 bits.

## Nullifiers

| Name | Formula | Prevents |
|------|---------|----------|
| `N_id` | `Poseidon("VEILGOV_ELECTION_ID_NULLIFIER_V1", s, E_field)` | Multiple ballots per identity |
| `N_i` | `Poseidon("VEILGOV_ACCOUNT_SPEND_V1", x_i, E_field)` | Credential reuse |
| `U_i` | `SHA256("VEILGOV_REG_UNIQUENESS_V1" \|\| scope \|\| owner)` | Duplicate enrollment (private) |

## Proof ABI

Public `BallotStatementV1` journal fields use one fixed-order canonical encoding.
All integers and field elements are fixed-width **big-endian**:

1. `protocol_version` (u32)  
2. `election_domain` (32 bytes)  
3. `eth_snapshot_root` (32 bytes Fr BE)  
4. `sol_snapshot_root` (32 bytes Fr BE)  
5. `credential_root` (32 bytes Fr BE)  
6. `paillier_key_hash` (32 bytes)  
7. `N_id` (32 bytes Fr BE)  
8. `N[0..K)` (K × 32 bytes; K=4 fixed capacity)  
9. `ciphertext` (512 bytes)  

Private witness: `s`, `rho_i`, owners, amounts, paths, vote, `r`, active flags.

The RISC Zero journal is exactly `BallotStatementV1::canonical_bytes()`. Its
statement digest is domain-separated SHA-256 over those bytes. JSON is not a
consensus or proof-journal encoding.

## Paillier–ZK binding (MVP)

The RISC Zero guest calls the same deterministic Rust predicate as native
differential tests and proves the encryption relation using witness-supplied
`r`. Randomness is sampled on the host; the guest checks `r ∈ Z_n*` and computes
the ciphertext deterministically. Do **not** put full Paillier in a separately
maintained Groth16 R1CS for MVP. A Sigma Paillier–Pedersen bridge remains
research-only until reviewed.

Default CLI demo runs guest **execute** (journal must match native) then tallies
from predicate-derived receipts. Cryptographic composite receipts require
`veilgov demo --zk-prove` or `veilgov prove-ballot`. Local proofs are RISC Zero
**composite** STARKs; Ethereum needs a separate Groth16 seal (see
`docs/zk-integration-plan.md`).
