//! Trustee decryption API.
//!
//! MVP: single development key.
//! Production: threshold Paillier (3-of-5) — trait stub only.

use num_bigint::BigUint;
use thiserror::Error;
use veilgov_paillier::{decrypt, unpack_plaintext, SecretKey, DEV_WARNING};

#[derive(Debug, Error)]
pub enum TrusteeError {
    #[error("insufficient shares")]
    InsufficientShares,
    #[error("invalid share")]
    InvalidShare,
    #[error("paillier: {0}")]
    Paillier(String),
    #[error("not implemented")]
    NotImplemented,
}

pub trait DecryptionTrustee {
    fn partial_decrypt(&self, ciphertext: &BigUint) -> Result<PartialDecryption, TrusteeError>;
}

#[derive(Clone, Debug)]
pub struct PartialDecryption {
    pub trustee_id: u32,
    pub share: BigUint,
    pub proof: Vec<u8>,
}

/// DEVELOPMENT ONLY single-key trustee.
pub struct DevSingleKeyTrustee {
    pub sk: SecretKey,
}

impl DevSingleKeyTrustee {
    pub fn new(sk: SecretKey) -> Self {
        eprintln!("{DEV_WARNING}");
        Self { sk }
    }

    pub fn decrypt_full(&self, ciphertext: &BigUint) -> Result<(u128, u128, u128), TrusteeError> {
        let m = decrypt(&self.sk, ciphertext).map_err(|e| TrusteeError::Paillier(e.to_string()))?;
        let (yes, total) =
            unpack_plaintext(&m).map_err(|e| TrusteeError::Paillier(e.to_string()))?;
        Ok((yes, total - yes, total))
    }
}

impl DecryptionTrustee for DevSingleKeyTrustee {
    fn partial_decrypt(&self, ciphertext: &BigUint) -> Result<PartialDecryption, TrusteeError> {
        let m = decrypt(&self.sk, ciphertext).map_err(|e| TrusteeError::Paillier(e.to_string()))?;
        Ok(PartialDecryption {
            trustee_id: 0,
            share: m,
            proof: b"DEV_SINGLE_KEY_NO_PROOF".to_vec(),
        })
    }
}

/// Future threshold combiner — not implemented in MVP.
pub struct ThresholdCombiner {
    pub threshold: usize,
    pub n: usize,
}

impl ThresholdCombiner {
    pub fn combine(&self, _shares: &[PartialDecryption]) -> Result<BigUint, TrusteeError> {
        let _ = (self.threshold, self.n);
        Err(TrusteeError::NotImplemented)
    }
}
