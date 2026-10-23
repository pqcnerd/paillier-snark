# Registrar service (MVP)

In-process registrar logic lives in `veilgov-enrollment`.

A future networked registrar should:

1. Verify native ETH/SOL enrollment signatures
2. Enforce private uniqueness keys `U_i`
3. Batch/shuffle credential leaves
4. Publish signed credential roots

Do not expose `U_i` publicly (dictionary attacks on addresses).
