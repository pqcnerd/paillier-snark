//! EXPERIMENTAL / DEVELOPMENT ONLY Paillier implementation.
//!
//! This crate is an educational reference for VeilGov packed yes+total ballots.
//! Do **not** use it in production. Prefer a reviewed library after evaluation.
//!
//! Ciphertext: C = g^m * r^n mod n² with g = 1+n, fixed 512-byte BE encoding for 2048-bit n.

use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use rand::Rng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use veilgov_domains::{sha256_tagged, tags, PLAINTEXT_BASE_BITS};
use veilgov_encoding::{Digest32, PAILLIER_CT_LEN, PAILLIER_N_LEN};

pub const DEV_WARNING: &str = "DEVELOPMENT ONLY — experimental Paillier, not production-ready";

#[derive(Debug, Error)]
pub enum PaillierError {
    #[error("invalid ciphertext")]
    InvalidCiphertext,
    #[error("plaintext out of range")]
    PlaintextOutOfRange,
    #[error("key generation failed")]
    KeygenFailed,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("aggregation empty")]
    EmptyAggregate,
    #[error("{0}")]
    Msg(String),
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Modulus n (2048-bit for MVP).
    pub n: BigUint,
    /// n² cached.
    pub n2: BigUint,
}

impl PublicKey {
    pub fn from_n(n: BigUint) -> Result<Self, PaillierError> {
        // Educational keys may be 256-bit; production targets ≥2048.
        if n.bits() < 128 || !n.is_odd() {
            return Err(PaillierError::KeygenFailed);
        }
        let n2 = &n * &n;
        Ok(Self { n, n2 })
    }

    pub fn fingerprint(&self) -> Digest32 {
        let mut n_be = self.n.to_bytes_be();
        if n_be.len() > PAILLIER_N_LEN {
            return sha256_tagged(tags::PAILLIER_KEY, &n_be);
        }
        let mut fixed = vec![0u8; PAILLIER_N_LEN];
        let start = PAILLIER_N_LEN - n_be.len();
        fixed[start..].copy_from_slice(&n_be);
        n_be = fixed;
        sha256_tagged(tags::PAILLIER_KEY, &n_be)
    }

    /// Canonical fixed-width modulus encoding used by the ballot proof input.
    pub fn encode_modulus(&self) -> Result<[u8; PAILLIER_N_LEN], PaillierError> {
        let be = self.n.to_bytes_be();
        if be.len() > PAILLIER_N_LEN {
            return Err(PaillierError::KeygenFailed);
        }
        let mut out = [0u8; PAILLIER_N_LEN];
        out[PAILLIER_N_LEN - be.len()..].copy_from_slice(&be);
        Ok(out)
    }

    /// Parse the canonical fixed-width modulus used by the ballot proof input.
    pub fn decode_modulus(bytes: &[u8]) -> Result<Self, PaillierError> {
        if bytes.len() != PAILLIER_N_LEN {
            return Err(PaillierError::KeygenFailed);
        }
        Self::from_n(BigUint::from_bytes_be(bytes))
    }

    pub fn encode_ciphertext(&self, c: &BigUint) -> Result<[u8; PAILLIER_CT_LEN], PaillierError> {
        self.validate_ciphertext(c)?;
        let be = c.to_bytes_be();
        if be.len() > PAILLIER_CT_LEN {
            return Err(PaillierError::InvalidCiphertext);
        }
        let mut out = [0u8; PAILLIER_CT_LEN];
        out[PAILLIER_CT_LEN - be.len()..].copy_from_slice(&be);
        Ok(out)
    }

    pub fn decode_ciphertext(&self, bytes: &[u8]) -> Result<BigUint, PaillierError> {
        if bytes.len() != PAILLIER_CT_LEN {
            return Err(PaillierError::InvalidCiphertext);
        }
        let c = BigUint::from_bytes_be(bytes);
        self.validate_ciphertext(&c)?;
        Ok(c)
    }

    pub fn validate_ciphertext(&self, c: &BigUint) -> Result<(), PaillierError> {
        if c.is_zero() || c >= &self.n2 {
            return Err(PaillierError::InvalidCiphertext);
        }
        if c.gcd(&self.n) != BigUint::one() {
            return Err(PaillierError::InvalidCiphertext);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct SecretKey {
    pub p: BigUint,
    pub q: BigUint,
    pub lambda: BigUint,
    pub mu: BigUint,
    pub pk: PublicKey,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Best-effort wipe of heap limbs (educational; not a constant-time guarantee).
        self.p = BigUint::zero();
        self.q = BigUint::zero();
        self.lambda = BigUint::zero();
        self.mu = BigUint::zero();
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([DEVELOPMENT ONLY redacted])")
    }
}

fn l_function(u: &BigUint, n: &BigUint) -> BigUint {
    (u - 1u32) / n
}

/// Generate an experimental key. For tests use `keygen_for_tests`.
pub fn keygen(rng: &mut impl Rng, bits: u64) -> Result<(PublicKey, SecretKey), PaillierError> {
    if bits < 256 || bits % 2 != 0 {
        return Err(PaillierError::KeygenFailed);
    }
    let half = bits / 2;
    for _attempt in 0..64 {
        let p = next_probable_prime(rng.gen_biguint(half) | BigUint::one());
        let q = next_probable_prime(rng.gen_biguint(half) | BigUint::one());
        if p == q {
            continue;
        }
        let n = &p * &q;
        let pk = match PublicKey::from_n(n.clone()) {
            Ok(pk) => pk,
            Err(_) => continue,
        };
        let lambda = lcm(&(&p - 1u32), &(&q - 1u32));
        let g = &n + 1u32;
        let g_lambda = modpow(&g, &lambda, &pk.n2);
        let l = l_function(&g_lambda, &n);
        let Some(mu) = modinv(&l, &n) else {
            continue;
        };
        let sk = SecretKey {
            p,
            q,
            lambda,
            mu,
            pk: pk.clone(),
        };
        return Ok((pk, sk));
    }
    Err(PaillierError::KeygenFailed)
}

/// Faster small keys for unit tests (NOT secure).
pub fn keygen_for_tests(rng: &mut impl Rng) -> (PublicKey, SecretKey) {
    keygen(rng, 256).expect("test keygen")
}

/// MVP-sized keygen (slow). Prefer loading fixtures in demos when possible.
pub fn keygen_mvp(rng: &mut impl Rng) -> Result<(PublicKey, SecretKey), PaillierError> {
    keygen(rng, 2048)
}

fn next_probable_prime(mut x: BigUint) -> BigUint {
    if x.is_even() {
        x += 1u32;
    }
    loop {
        if is_probable_prime(&x) {
            return x;
        }
        x += 2u32;
    }
}

fn is_probable_prime(n: &BigUint) -> bool {
    // Simple Miller-Rabin with fixed bases — educational.
    if *n < BigUint::from(2u32) {
        return false;
    }
    if *n == BigUint::from(2u32) || *n == BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }
    let bases: [u64; 8] = [2, 3, 5, 7, 11, 13, 17, 19];
    let one = BigUint::one();
    let nm1 = n - &one;
    let mut d = nm1.clone();
    let mut s = 0u32;
    while d.is_even() {
        d >>= 1;
        s += 1;
    }
    'next_base: for &a in &bases {
        if BigUint::from(a) >= *n {
            continue;
        }
        let mut x = modpow(&BigUint::from(a), &d, n);
        if x == one || x == nm1 {
            continue;
        }
        for _ in 1..s {
            x = (&x * &x) % n;
            if x == nm1 {
                continue 'next_base;
            }
        }
        return false;
    }
    true
}

fn lcm(a: &BigUint, b: &BigUint) -> BigUint {
    if a.is_zero() || b.is_zero() {
        return BigUint::zero();
    }
    (a / a.gcd(b)) * b
}

fn modpow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exp, modulus)
}

fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let ai = BigInt::from_biguint(Sign::Plus, a.clone());
    let mi = BigInt::from_biguint(Sign::Plus, m.clone());
    let egcd = ai.extended_gcd(&mi);
    if egcd.gcd != BigInt::one() {
        return None;
    }
    let mut x = egcd.x % &mi;
    if x.is_negative() {
        x += &mi;
    }
    Some(x.to_biguint().unwrap())
}

/// Pack m = y + 2^128 * t with y = w*v, t = w.
pub fn pack_plaintext(weight: u128, vote: u8) -> Result<BigUint, PaillierError> {
    if vote > 1 {
        return Err(PaillierError::PlaintextOutOfRange);
    }
    let y = if vote == 1 { weight } else { 0 };
    let t = weight;
    let mut m = BigUint::from(t);
    m <<= PLAINTEXT_BASE_BITS;
    m += BigUint::from(y);
    Ok(m)
}

pub fn unpack_plaintext(m: &BigUint) -> Result<(u128, u128), PaillierError> {
    let mask = (BigUint::one() << PLAINTEXT_BASE_BITS) - 1u32;
    let y = m & &mask;
    let t = m >> PLAINTEXT_BASE_BITS;
    let y_u = big_to_u128(&y)?;
    let t_u = big_to_u128(&t)?;
    if y_u > t_u {
        return Err(PaillierError::PlaintextOutOfRange);
    }
    Ok((y_u, t_u))
}

fn big_to_u128(x: &BigUint) -> Result<u128, PaillierError> {
    let be = x.to_bytes_be();
    if be.len() > 16 {
        return Err(PaillierError::PlaintextOutOfRange);
    }
    let mut arr = [0u8; 16];
    arr[16 - be.len()..].copy_from_slice(&be);
    Ok(u128::from_be_bytes(arr))
}

pub fn encrypt(
    pk: &PublicKey,
    plaintext: &BigUint,
    rng: &mut impl Rng,
) -> Result<BigUint, PaillierError> {
    if plaintext >= &pk.n {
        return Err(PaillierError::PlaintextOutOfRange);
    }
    // Sample r in Z_n*
    let r = sample_randomness(pk, rng);
    encrypt_with_randomness(pk, plaintext, &r)
}

pub fn encrypt_packed(
    pk: &PublicKey,
    weight: u128,
    vote: u8,
    rng: &mut impl Rng,
) -> Result<BigUint, PaillierError> {
    let m = pack_plaintext(weight, vote)?;
    encrypt(pk, &m, rng)
}

/// Sample Paillier randomness on the host. The resulting value is private
/// witness data; deterministic verification must use `encrypt_with_randomness`.
pub fn sample_randomness(pk: &PublicKey, rng: &mut impl Rng) -> BigUint {
    sample_unit(rng, &pk.n)
}

/// Deterministically verify/compute Paillier encryption using explicit private
/// randomness `r`. This is the guest-safe cryptographic statement.
pub fn encrypt_with_randomness(
    pk: &PublicKey,
    plaintext: &BigUint,
    r: &BigUint,
) -> Result<BigUint, PaillierError> {
    if plaintext >= &pk.n {
        return Err(PaillierError::PlaintextOutOfRange);
    }
    if r.is_zero() || r >= &pk.n || r.gcd(&pk.n) != BigUint::one() {
        return Err(PaillierError::InvalidCiphertext);
    }
    let g = &pk.n + 1u32;
    let gm = modpow(&g, plaintext, &pk.n2);
    let rn = modpow(r, &pk.n, &pk.n2);
    let ciphertext = (gm * rn) % &pk.n2;
    pk.validate_ciphertext(&ciphertext)?;
    Ok(ciphertext)
}

pub fn encrypt_packed_with_randomness(
    pk: &PublicKey,
    weight: u128,
    vote: u8,
    r: &BigUint,
) -> Result<BigUint, PaillierError> {
    let m = pack_plaintext(weight, vote)?;
    encrypt_with_randomness(pk, &m, r)
}

pub fn decrypt(sk: &SecretKey, ciphertext: &BigUint) -> Result<BigUint, PaillierError> {
    sk.pk.validate_ciphertext(ciphertext)?;
    let u = modpow(ciphertext, &sk.lambda, &sk.pk.n2);
    let l = l_function(&u, &sk.pk.n);
    Ok((l * &sk.mu) % &sk.pk.n)
}

pub fn aggregate(pk: &PublicKey, ciphertexts: &[BigUint]) -> Result<BigUint, PaillierError> {
    if ciphertexts.is_empty() {
        return Err(PaillierError::EmptyAggregate);
    }
    let mut acc = BigUint::one();
    for c in ciphertexts {
        pk.validate_ciphertext(c)?;
        acc = (acc * c) % &pk.n2;
    }
    Ok(acc)
}

fn sample_unit(rng: &mut impl Rng, n: &BigUint) -> BigUint {
    loop {
        let r = rng.gen_biguint_below(n);
        if r > BigUint::zero() && r.gcd(n) == BigUint::one() {
            return r;
        }
    }
}

/// Deterministic test vector helper: hash seed to r then encrypt (for vectors only).
pub fn encrypt_with_seed_r(
    pk: &PublicKey,
    plaintext: &BigUint,
    seed: &[u8],
) -> Result<BigUint, PaillierError> {
    let mut h = Sha256::digest(seed);
    let mut r = BigUint::from_bytes_be(&h);
    r %= &pk.n;
    if r.is_zero() {
        r = BigUint::one();
    }
    while r.gcd(&pk.n) != BigUint::one() {
        h = Sha256::digest(&r.to_bytes_be());
        r = BigUint::from_bytes_be(&h) % &pk.n;
        if r.is_zero() {
            r = BigUint::one();
        }
    }
    let g = &pk.n + 1u32;
    let gm = modpow(&g, plaintext, &pk.n2);
    let rn = modpow(&r, &pk.n, &pk.n2);
    Ok((gm * rn) % &pk.n2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn encrypt_decrypt_packed() {
        let mut rng = StdRng::seed_from_u64(42);
        let (pk, sk) = keygen_for_tests(&mut rng);
        let c = encrypt_packed(&pk, 100, 1, &mut rng).unwrap();
        let m = decrypt(&sk, &c).unwrap();
        let (yes, total) = unpack_plaintext(&m).unwrap();
        assert_eq!(yes, 100);
        assert_eq!(total, 100);
    }

    #[test]
    fn homomorphic_alice_bob() {
        let mut rng = StdRng::seed_from_u64(7);
        let (pk, sk) = keygen_for_tests(&mut rng);
        let c_alice = encrypt_packed(&pk, 100, 1, &mut rng).unwrap();
        let c_bob = encrypt_packed(&pk, 50, 0, &mut rng).unwrap();
        let agg = aggregate(&pk, &[c_alice, c_bob]).unwrap();
        let m = decrypt(&sk, &agg).unwrap();
        let (yes, total) = unpack_plaintext(&m).unwrap();
        assert_eq!(yes, 100);
        assert_eq!(total, 150);
        assert_eq!(total - yes, 50);
    }

    #[test]
    fn rejects_invalid_ciphertext() {
        let mut rng = StdRng::seed_from_u64(1);
        let (pk, _) = keygen_for_tests(&mut rng);
        assert!(pk.validate_ciphertext(&BigUint::zero()).is_err());
        assert!(pk.validate_ciphertext(&pk.n2).is_err());
    }

    #[test]
    fn fingerprint_stable() {
        let mut rng = StdRng::seed_from_u64(9);
        let (pk, _) = keygen_for_tests(&mut rng);
        assert_eq!(pk.fingerprint(), pk.fingerprint());
    }
}
