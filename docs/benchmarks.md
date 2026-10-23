# Benchmark Plan

## Workloads

| Dimension | Values |
|-----------|--------|
| Account capacity K | 2, 4, 8 |
| Merkle depth | 16, 24, 32 |
| Ballot set size | 2, 10, 100, 1000 |
| Paillier | 2048-bit (MVP), 3072-bit (target) |

## Metrics

- Proof generation (cold/warm)  
- Verification latency  
- zkVM cycles / constraint count  
- Proof + VK size  
- Peak memory  
- Paillier encrypt time  
- Aggregate mul/s  
- Ballot calldata size  
- Merkle path size  
- Solidity verify/accept gas  

## Backends

1. Pure Rust shared predicate (differential correctness oracle)  
2. RISC Zero 3.0.6 guest (selected backend)  

## Go / no-go (pre-production)

Measured proof results and reproduction details live in
`docs/zk-benchmarks.md`. SP1 is not implemented in parallel.

## Current MVP results

See `docs/zk-benchmarks.md`, the `zk/benchmarks` crate, and the proof metrics
printed by `veilgov demo`.
