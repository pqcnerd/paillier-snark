# Ceremonies and Key Management

## DEVELOPMENT ONLY (MVP)

- Single Paillier key generated offline by `veilgov setup`.  
- Private key stored outside the repository (path via env `VEILGOV_PAILLIER_SK`).  
- Every CLI output involving decryption prints `DEVELOPMENT ONLY`.  
- Groth16/RISC Zero wrapper ceremonies: use vendor-documented setups; pin image IDs in `zk/methods`.

## Production (not implemented)

- Threshold Paillier 3-of-5 with DKG and share correctness proofs.  
- Transcript domain: `(E, ballotRoot, count, C_agg)`.  
- Per-circuit phase-2 (if custom Groth16 eligibility) with public transcript.  
- Timelocked VK/image upgrades on the EVM registry.

## Rotation

Key/trustee rotation applies only to **future** elections. In-flight elections keep frozen key fingerprints.
