# Exact-Once Voting-Power Model

## Policy (MVP)

**Account conservation:** each eligible source account's snapshotted weight is usable at most once per election. Multiple accounts may be combined under one master secret `s`. The protocol does **not** claim complete one-human consolidation.

## Rejected: identity-only

A Semaphore-style identity nullifier alone allows one Ethereum/Solana account to register many identities and spend the same balance repeatedly.

## Chosen: account-backed credentials + dual nullifiers

1. Enrollment deduplicates `(scope, canonical_owner)` via private uniqueness key  
   `U = SHA256("VEILGOV_REG_UNIQUENESS_V1" || scope || owner)`.
2. Credential binds randomized account secret  
   `x = Poseidon(TAG_ACCOUNT_SECRET, s, rho, scope_field)`  
   `A = Poseidon(TAG_ACCOUNT_COMMIT, x)`.
3. Voting outputs:
   - `N_id = Poseidon(TAG_ELECTION_ID_NULLIFIER, s, E)` — one ballot per `s` per election.
   - `N_i = Poseidon(TAG_ACCOUNT_SPEND, x_i, E)` — each credential spent once.

EVM registry consumes `N_id` and all `N_i` atomically.

## Deferred: custody note model

Locking/burning assets into shielded notes gives stronger conservation but changes snapshot governance into a bridge/custody protocol.

## What is and is not prevented

| Attack | Prevented? | Mechanism |
|--------|------------|-----------|
| Same account → many credentials | Yes (honest registrar quorum) | Private `U` dedup |
| Same credential → many votes | Yes | `N_i` |
| Same `s` → multiple subset ballots | Yes | `N_id` |
| Different accounts → different `s` ballots | No weight inflation; multiple ballots allowed | Policy choice |
| Force all personal accounts consolidated | No | Needs personhood authority |

## Registrar trust residual

Malicious enrollment quorum can inflate credentials or link accounts. Blind/OPRF uniqueness is a research extension.
