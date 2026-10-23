# VeilGov ZK Benchmarks

Status: guest **execution** measured on the demo ETH+SOL ballot. Full composite
**proving** of Alice’s ballot was started on CPU and **aborted** before
completion (wall ~1h35m). Dual-ballot cryptographic demo metrics are therefore
not claimed. `RISC0_DEV_MODE` receipts are rejected.

## Reproduction

```sh
curl -L https://risczero.com/install | bash
rzup install cargo-risczero 3.0.6
rzup install rust 1.97.0
export PATH="$HOME/.risc0/bin:$PATH"
unset RISC0_DEV_MODE

# Guest execute only (seconds):
RAYON_NUM_THREADS=8 cargo run --release -p veilgov -- zk-cycles

# Default demo: native predicate + guest execute differential + tally (no STARK prove):
RAYON_NUM_THREADS=8 cargo run --release -p veilgov -- demo

# Cryptographic dual-ballot prove (expect multi-hour CPU; optional):
RAYON_NUM_THREADS=8 /usr/bin/time -v cargo run --release -p veilgov -- demo --zk-prove
```

Pinned crates:

- `risc0-zkvm = 3.0.6`
- `risc0-build = 3.0.6`
- guest image ID: `a7249bd091e1adccfc9c0224a1d3a6e4105e74b04f8fae392862621d188657a7`
  (`zk/methods/IMAGE_IDS.toml`)

## Hardware (measurement host)

- OS: Linux 7.0.0-31-generic, x86_64
- CPU: AMD Ryzen AI 9 HX 370, 12 cores / 24 threads
- RAM: 93 GiB
- GPU: none (CPU proving)
- Host Rust: 1.90.0
- Guest Rust (rzup): 1.97.0
- Build: `--release`, composite receipt, prover `segment_limit_po2` max **22**
- Prover threads observed: `RAYON_NUM_THREADS=8` / `16`

## Guest execution (no prove)

Alice ETH+SOL ballot (demo fixture, 256-bit educational Paillier key):

| Metric | Value |
|--------|------:|
| Guest user cycles | 153,366,836 |
| Segments @ po2=22 (prove path) | 38 |
| Segments @ po2=19 (execute report) | 323 |
| Execute wall time | ~6–10 s (release) |

Most expensive guest work (estimated): BN254 Poseidon Merkle membership + leaf
preimages, then Paillier `r^n mod n²` via `num-bigint`.

## Proving (CPU) — incomplete

| Attempt | Observation |
|---------|-------------|
| Early run | Peak RSS ~9–10 GiB; SIGKILL ~15 min (likely env timeout, not OOM on 93 GiB host) |
| Alice composite prove | Running ~1h35m wall on CPU; **aborted by operator** before receipt |
| Bob prove | Not started |
| Dual-ballot demo `--zk-prove` | **Not completed** on this host |

Fill after a successful `demo --zk-prove`:

| Ballot | total_cycles | user_cycles | segments | prove_ms | verify_µs | proof_bytes | peak_RSS |
|--------|-------------:|------------:|---------:|---------:|----------:|------------:|---------:|
| Alice | TBD | ~153M | 38 @ po2=22 | TBD | TBD | TBD | TBD |
| Bob | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

Recommendations for completion: leave a release `demo --zk-prove` running
unattended for several hours; or use Bonsai / GPU acceleration; keep
`RISC0_DEV_MODE` unset.

## 2048-bit Paillier gate

The demo currently uses the educational 256-bit test key. A separate 2048-bit
modulus run is required before claiming production-sized Paillier proving cost.
Expect a roughly 4096-bit modular exponentiation; accelerate with `risc0-crypto`
guest-only modexp if generic `num-bigint` is prohibitive.

## EVM gas

On-chain Groth16 verification is **not** measured in this milestone. Local
composite receipts are verified off-chain. Groth16 + `IRiscZeroVerifier` router
integration is documented in `docs/zk-integration-plan.md` as a follow-up;
`VerifierAdapter` is ABI-wired but must not be described as verifying composite
STARKs on-chain today.
