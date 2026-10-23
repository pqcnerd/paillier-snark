//! Optional Solana enrollment program placeholder.
//! Ballot ledger remains on EVM. This module documents the intended
//! registration instruction shape for a future on-chain enrollment adapter.

pub const PROGRAM_NOTE: &str = "Solana enrollment adapter — not the canonical ballot ledger";

pub struct EnrollIx {
    pub scope: [u8; 32],
    pub account_commitment: [u8; 32],
    pub nonce: u64,
    pub expiry: u64,
}
