# Trust Model

| Component | Trust required? | Failure mode | Future improvement |
|-----------|-----------------|--------------|--------------------|
| Source chain finality | Yes (after delay) | Reorg invalidates snapshot | Configurable delay; fork cancel |
| Ethereum RPC | Partial | Censorship/withhold | Multi-archive + EIP-1186 audit |
| Solana RPC / retained bank | Yes (quorum) | Forged snapshot | Validator commitments |
| Snapshot builders | Quorum | Incomplete/biased root | Reproducible artifacts |
| Enrollment registrars | Quorum | Inflate/link/censor | Blind credentials / OPRF |
| EVM registry | Code + chain | Bug / upgrade abuse | Immutable audit; timelock |
| zkVM / wrapper | Crypto + ceremony | Soundness break | Audits; pinned image |
| Paillier trustees | Threshold honesty | Early decrypt / stall | DKG; share proofs |
| Tally aggregator | No (correctness) | Delay only | Permissionless recompute |
| Frontend / RPC / relayer | Privacy only | Deanonymize / misdisplay | Local CLI proving |

## MVP labels

- Single Paillier key: **DEVELOPMENT ONLY**
- Solana snapshot root: **quorum-attested, not trustlessly state-proven**
- Enrollment uniqueness: **registrar-enforced**
