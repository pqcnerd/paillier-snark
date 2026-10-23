//! Canonical fixed-width big-endian encodings.
//! Consensus inputs must not use JSON, ABI dynamic types, or Borsh.

use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const HASH_LEN: usize = 32;
pub const ETH_ADDR_LEN: usize = 20;
pub const SOL_PUBKEY_LEN: usize = 32;
pub const PAILLIER_N_LEN: usize = 256;
pub const PAILLIER_CT_LEN: usize = 512;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncodingError {
    #[error("buffer too short: need {need}, have {have}")]
    BufferTooShort { need: usize, have: usize },
    #[error("unexpected trailing bytes: {0}")]
    TrailingBytes(usize),
    #[error("invalid length prefix")]
    InvalidLengthPrefix,
}

pub type Result<T> = std::result::Result<T, EncodingError>;

/// Length-prefixed ASCII domain tag || payload for SHA-family hashes.
pub fn tagged_payload(tag: &str, payload: &[u8]) -> Vec<u8> {
    let tag_bytes = tag.as_bytes();
    let mut out = Vec::with_capacity(4 + tag_bytes.len() + payload.len());
    out.extend_from_slice(&(tag_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(tag_bytes);
    out.extend_from_slice(payload);
    out
}

pub fn encode_u32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

pub fn encode_u64(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

pub fn encode_u128(v: u128) -> [u8; 16] {
    v.to_be_bytes()
}

pub fn decode_u32(buf: &[u8]) -> Result<(u32, &[u8])> {
    if buf.len() < 4 {
        return Err(EncodingError::BufferTooShort {
            need: 4,
            have: buf.len(),
        });
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&buf[..4]);
    Ok((u32::from_be_bytes(arr), &buf[4..]))
}

pub fn decode_u64(buf: &[u8]) -> Result<(u64, &[u8])> {
    if buf.len() < 8 {
        return Err(EncodingError::BufferTooShort {
            need: 8,
            have: buf.len(),
        });
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&buf[..8]);
    Ok((u64::from_be_bytes(arr), &buf[8..]))
}

pub fn take_bytes<'a>(buf: &'a [u8], n: usize) -> Result<(&'a [u8], &'a [u8])> {
    if buf.len() < n {
        return Err(EncodingError::BufferTooShort {
            need: n,
            have: buf.len(),
        });
    }
    Ok((&buf[..n], &buf[n..]))
}

pub fn require_exact(buf: &[u8]) -> Result<()> {
    if buf.is_empty() {
        Ok(())
    } else {
        Err(EncodingError::TrailingBytes(buf.len()))
    }
}

/// Fixed 32-byte digest wrapper.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Digest32(pub [u8; HASH_LEN]);

impl Digest32 {
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        if s.len() != HASH_LEN {
            return Err(EncodingError::BufferTooShort {
                need: HASH_LEN,
                have: s.len(),
            });
        }
        let mut a = [0u8; HASH_LEN];
        a.copy_from_slice(s);
        Ok(Self(a))
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest32({})", self.to_hex())
    }
}

impl AsRef<[u8]> for Digest32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn tagged_payload_is_length_prefixed() {
        let p = tagged_payload("AB", b"xy");
        assert_eq!(&p[..4], &2u32.to_be_bytes());
        assert_eq!(&p[4..6], b"AB");
        assert_eq!(&p[6..], b"xy");
    }

    #[test]
    fn roundtrip_u64() {
        let enc = encode_u64(0x0102_0304_0506_0708);
        let (v, rest) = decode_u64(&enc).unwrap();
        assert_eq!(v, 0x0102_0304_0506_0708);
        require_exact(rest).unwrap();
    }

    proptest! {
        #[test]
        fn prop_u32_roundtrip(v in any::<u32>()) {
            let enc = encode_u32(v);
            let (got, rest) = decode_u32(&enc).unwrap();
            assert_eq!(got, v);
            assert!(rest.is_empty());
        }
    }
}
