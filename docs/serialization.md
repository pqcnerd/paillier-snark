# Canonical Serialization

All consensus encodings are **fixed-width big-endian** unless noted. No JSON, ABI dynamic types, Borsh, or base58 as consensus inputs.

`BallotStatementV1::canonical_bytes()` is the authoritative ballot proof
journal encoding. The RISC Zero guest commits those bytes directly. Private
guest input serialization is an implementation transport and is not a
consensus encoding.

## Primitive widths

| Type | Width | Endian |
|------|-------|--------|
| `u8` / tag | 1 | — |
| `u32` / version | 4 | BE |
| `u64` amount / slot | 8 | BE |
| `u128` weight | 16 | BE |
| `bytes20` ETH address | 20 | — |
| `bytes32` digests / Fr BE | 32 | BE |
| Paillier modulus `n` | 256 | BE |
| Paillier ciphertext | 512 | BE |

## Domain tags (ASCII, length-prefixed)

Each tagged hash is:

```
SHA256( len(tag)||tag || payload )
```

or Poseidon absorption of `tag_to_field(tag)` then payload field elements.

Reserved tags (see `veilgov-domains`):

- `VEILGOV_PROTOCOL_V1`
- `VEILGOV_SCOPE_V1`
- `VEILGOV_ID_V1`
- `VEILGOV_ACCOUNT_SECRET_V1`
- `VEILGOV_ACCOUNT_COMMIT_V1`
- `VEILGOV_ETH_SNAPSHOT_V1`
- `VEILGOV_SOL_SNAPSHOT_V1`
- `VEILGOV_CREDENTIAL_V1`
- `VEILGOV_ELECTION_V1`
- `VEILGOV_ELECTION_ID_NULLIFIER_V1`
- `VEILGOV_ACCOUNT_SPEND_V1`
- `VEILGOV_REG_UNIQUENESS_V1`
- `VEILGOV_BALLOT_LEAF_V1`
- `VEILGOV_ENROLL_ETH_V1`
- `VEILGOV_ENROLL_SOL_V1`

## Merkle rules

- Indexed binary trees; left/right determined by path bits (LSB = leaf sibling side).  
- Empty leaf = Poseidon(`EMPTY_LEAF_DOMAIN`, depth_index) or fixed zero for Keccak ballot tree.  
- No sorted-pair hashing.  
- Depth fixed per tree type (MVP snapshot/credential depth = 8; production may use 16/24/32 with identical padding rules).

## Field encoding

`bytes32 → Fr`: interpret as big-endian integer mod `r` (BN254 scalar). Scope digests are reduced mod `r` before Poseidon absorption.
