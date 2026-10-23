# Privacy Model

## Hidden from the public (under ZK + Poseidon + Paillier assumptions)

- Ethereum address / Solana pubkey  
- Cross-chain linkage  
- Per-chain and combined voting weights  
- Ballot bit `v`  
- Paillier plaintext and randomness  
- Master secret `s`, account secrets `x_i`, Merkle paths  

## Public / linkable

- Election ID, protocol versions, roots, manifests  
- Fixed-length nullifier vector per ballot  
- Ciphertext bytes, ballot index, acceptance time  
- Tx sender or relayer, gas payer  
- Frozen ballot count and final YES/TOTAL/NO  

## Registrar knowledge (MVP)

Registrars learn account ↔ commitment linkage, balances, timing, and network metadata. Colluding ETH/SOL registrars may reconstruct cross-chain enrollment linkage.

## Not provided

- Network anonymity  
- Receipt-freeness / coercion resistance  
- Unlinkability against the enrollment quorum  
- Privacy of aggregate participation count or cohort size  

Cryptographic anonymity ≠ network anonymity.

## Proof journal inspection

The RISC Zero guest commits only the canonical `BallotStatementV1` fields:
protocol version, election domain, three roots, Paillier key fingerprint,
identity/account nullifiers, and the 512-byte ciphertext. Shared-predicate and
integration tests parse the journal and check that fixture addresses, identity
secret, and Paillier randomness are absent; vote/weight are not public fields.

The receipt verifier accepts only the receipt plus expected public
`ElectionConfig`; it has no witness parameter. A host may temporarily hold the
private witness while proving, so operational code must discard that input and
avoid logging or persisting it.
