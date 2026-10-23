# Threat Model

Format: attack → defense → residual assumption.

1. **Double vote** → `N_id` map → deterministic derivation + EVM finality  
2. **Cross-chain double vote** → one EVM ledger → registry availability  
3. **Account → many identities** → private `U` dedup → honest registrar quorum  
4. **Balance → many credentials** → issuance totals / dedup → quorum honesty  
5. **Split identities** → no weight inflation; multiple ballots allowed by policy  
6. **Forged ETH ownership** → EIP-712 / registration tx → wallet/adapter correctness  
7. **Forged SOL ownership** → Ed25519 / registration signer → supported authorities only  
8. **Forged balance** → snapshot quorum + artifacts → builder honesty (esp. Solana)  
9. **Snapshot equivocation** → pin one signed manifest → non-equivocating quorum  
10. **Stale snapshot** → pinned anchors + deadlines → correct governance choice  
11. **Reorg** → finalized + delay → chain finality  
12. **Cross-election replay** → `E` in domains → collision resistance  
13. **Ciphertext substitution** → statement/leaf bind bytes → verifier correctness  
14. **Malformed ciphertext** → range/gcd/canonical checks → bigint correctness  
15. **Invalid vote** → `v ∈ {0,1}` constraint → guest soundness  
16. **Overflow** → `u64/u128`, `B`, `m < n` → config limits enforced  
17. **Invalid weight** → equal snapshot/credential witnesses → correct roots  
18. **Nullifier domain collision** → unique tags + vectors → hash collision resistance  
19. **Ballot omission** → frozen root/count + exact tally → data availability  
20. **Ballot duplication** → dense indices + nullifiers → contract correctness  
21. **Malicious aggregator** → zkVM exact product → proof soundness + DA  
22. **Malicious trustee** → share proofs → threshold scheme soundness  
23. **Colluding trustees** → threshold `t` → fewer than `t` collude  
24. **Metadata correlation** → batching / relayers → residual timing leakage  
25. **Timing correlation** → delayed windows → traffic analysis remains  
26. **Frontend deanonymization** → CLI-first local proving → endpoint security  
27. **RPC deanonymization** → local/multi RPC → network metadata  
28. **Proof replay** → nullifiers consume once → mempool censorship residual  
29. **Registration replay** → nonce/expiry → registrar state honesty  
30. **DoS** → capacity limits / fees / permissionless tally → liveness not guaranteed  
