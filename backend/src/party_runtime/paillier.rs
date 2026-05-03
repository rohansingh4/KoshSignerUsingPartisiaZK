use anyhow::{anyhow, Context, Result};
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierPublicKey {
    pub bit_length: u16,
    pub key_id: String,
    pub n_hex: String,
    pub n2_hex: String,
    pub g_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierPrivateKey {
    pub key_id: String,
    pub lambda_hex: String,
    pub mu_hex: String,
    pub p_hex: String,
    pub q_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierKeyPair {
    pub public_key: PaillierPublicKey,
    pub private_key: PaillierPrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierCiphertext {
    pub key_id: String,
    pub value_hex: String,
}

pub fn paillier_keygen(bit_length: u16) -> Result<PaillierKeyPair> {
    let p = generate_prime(bit_length as usize)?;
    let mut q = generate_prime(bit_length as usize)?;
    while q == p {
        q = generate_prime(bit_length as usize)?;
    }

    let n = &p * &q;
    let n2 = &n * &n;
    let g = &n + BigUint::one();
    let p1 = &p - BigUint::one();
    let q1 = &q - BigUint::one();
    let lambda = lcm(&p1, &q1);
    let g_lambda = mod_pow(&g, &lambda, &n2);
    let l_value = l_function(&g_lambda, &n)?;
    let mu = mod_inverse(&l_value, &n)?;
    let key_id = random_hex(16);

    Ok(PaillierKeyPair {
        public_key: PaillierPublicKey {
            bit_length,
            key_id: key_id.clone(),
            n_hex: hex_biguint(&n),
            n2_hex: hex_biguint(&n2),
            g_hex: hex_biguint(&g),
        },
        private_key: PaillierPrivateKey {
            key_id,
            lambda_hex: hex_biguint(&lambda),
            mu_hex: hex_biguint(&mu),
            p_hex: hex_biguint(&p),
            q_hex: hex_biguint(&q),
        },
    })
}

pub fn wrap_cleartext(public_key: &PaillierPublicKey, value_hex: String) -> PaillierCiphertext {
    PaillierCiphertext {
        key_id: public_key.key_id.clone(),
        value_hex,
    }
}

pub fn paillier_encrypt(
    public_key: &PaillierPublicKey,
    message: &BigUint,
) -> Result<PaillierCiphertext> {
    let n = parse_biguint(&public_key.n_hex)?;
    let n2 = parse_biguint(&public_key.n2_hex)?;
    let g = parse_biguint(&public_key.g_hex)?;
    let m = message.mod_floor(&n);
    let r = random_coprime_with_n(&n);
    let gm = mod_pow(&g, &m, &n2);
    let rn = mod_pow(&r, &n, &n2);
    Ok(PaillierCiphertext {
        key_id: public_key.key_id.clone(),
        value_hex: hex_biguint(&((gm * rn) % &n2)),
    })
}

pub fn paillier_decrypt(
    public_key: &PaillierPublicKey,
    private_key: &PaillierPrivateKey,
    ciphertext: &PaillierCiphertext,
) -> Result<BigUint> {
    let n = parse_biguint(&public_key.n_hex)?;
    let n2 = parse_biguint(&public_key.n2_hex)?;
    let lambda = parse_biguint(&private_key.lambda_hex)?;
    let mu = parse_biguint(&private_key.mu_hex)?;
    let c = parse_biguint(&ciphertext.value_hex)?;
    let c_lambda = mod_pow(&c, &lambda, &n2);
    let l_value = l_function(&c_lambda, &n)?;
    Ok((l_value * mu) % n)
}

pub fn paillier_add(
    public_key: &PaillierPublicKey,
    c1: &PaillierCiphertext,
    c2: &PaillierCiphertext,
) -> Result<PaillierCiphertext> {
    let n2 = parse_biguint(&public_key.n2_hex)?;
    let left = parse_biguint(&c1.value_hex)?;
    let right = parse_biguint(&c2.value_hex)?;
    Ok(PaillierCiphertext {
        key_id: public_key.key_id.clone(),
        value_hex: hex_biguint(&((left * right) % n2)),
    })
}

pub fn paillier_scalar_mul(
    public_key: &PaillierPublicKey,
    ciphertext: &PaillierCiphertext,
    scalar: &BigUint,
) -> Result<PaillierCiphertext> {
    let n = parse_biguint(&public_key.n_hex)?;
    let n2 = parse_biguint(&public_key.n2_hex)?;
    let c = parse_biguint(&ciphertext.value_hex)?;
    let exponent = scalar.mod_floor(&n);
    Ok(PaillierCiphertext {
        key_id: public_key.key_id.clone(),
        value_hex: hex_biguint(&mod_pow(&c, &exponent, &n2)),
    })
}

pub fn signed_from_decrypted(
    public_key: &PaillierPublicKey,
    decrypted: &BigUint,
) -> Result<BigInt> {
    let n = parse_biguint(&public_key.n_hex)?;
    let half = &n >> 1usize;
    if decrypted > &half {
        Ok(BigInt::from_biguint(Sign::Plus, decrypted.clone())
            - BigInt::from_biguint(Sign::Plus, n))
    } else {
        Ok(BigInt::from_biguint(Sign::Plus, decrypted.clone()))
    }
}

pub fn parse_biguint(value: &str) -> Result<BigUint> {
    BigUint::parse_bytes(value.trim_start_matches("0x").as_bytes(), 16)
        .ok_or_else(|| anyhow!("invalid bigint hex"))
}

pub fn hex_biguint(value: &BigUint) -> String {
    let hex = value.to_str_radix(16);
    if hex.len() % 2 == 0 {
        hex
    } else {
        format!("0{hex}")
    }
}

fn random_hex(size: usize) -> String {
    let mut bytes = vec![0_u8; size];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn l_function(x: &BigUint, n: &BigUint) -> Result<BigUint> {
    if x <= &BigUint::one() {
        return Err(anyhow!("invalid L function input"));
    }
    Ok((x - BigUint::one()) / n)
}

fn gcd_biguint(a: &BigUint, b: &BigUint) -> BigUint {
    a.gcd(b)
}

fn lcm(a: &BigUint, b: &BigUint) -> BigUint {
    (a * b) / gcd_biguint(a, b)
}

fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exp, modulus)
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Result<BigUint> {
    let a_big = BigInt::from_biguint(Sign::Plus, a.clone());
    let m_big = BigInt::from_biguint(Sign::Plus, m.clone());
    let (g, x, _) = extended_gcd(&a_big, &m_big);
    if g != BigInt::one() {
        return Err(anyhow!("modular inverse does not exist"));
    }
    let inv = ((x % &m_big) + &m_big) % &m_big;
    inv.to_biguint()
        .ok_or_else(|| anyhow!("modular inverse conversion failed"))
}

fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        return (b.clone(), BigInt::zero(), BigInt::one());
    }
    let (g, x1, y1) = extended_gcd(&(b % a), a);
    (g, y1 - (b / a) * &x1, x1)
}

fn random_coprime_with_n(n: &BigUint) -> BigUint {
    let mut rng = OsRng;
    loop {
        let candidate = rng.gen_biguint_below(n);
        if candidate > BigUint::one() && gcd_biguint(&candidate, n) == BigUint::one() {
            return candidate;
        }
    }
}

fn generate_prime(bit_length: usize) -> Result<BigUint> {
    let mut rng = OsRng;
    let one = BigUint::one();
    loop {
        let mut candidate = rng.gen_biguint(bit_length as u64);
        candidate |= &one;
        candidate |= &one << (bit_length - 1);
        if is_probable_prime(&candidate, 16)? {
            return Ok(candidate);
        }
    }
}

fn is_probable_prime(n: &BigUint, rounds: usize) -> Result<bool> {
    let two = BigUint::from(2u8);
    let three = BigUint::from(3u8);
    if *n < two {
        return Ok(false);
    }
    if *n == two || *n == three {
        return Ok(true);
    }
    if n.is_even() {
        return Ok(false);
    }

    let one = BigUint::one();
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut r = 0usize;
    while d.is_even() {
        d >>= 1usize;
        r += 1;
    }

    let mut rng = OsRng;
    'witness: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&two, &(n - &two));
        let mut x = mod_pow(&a, &d, n);
        if x == one || x == n_minus_one {
            continue;
        }
        for _ in 0..r.saturating_sub(1) {
            x = mod_pow(&x, &two, n);
            if x == n_minus_one {
                continue 'witness;
            }
        }
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{
        paillier_add, paillier_decrypt, paillier_encrypt, paillier_keygen, paillier_scalar_mul,
    };
    use num_bigint::BigUint;

    #[test]
    fn paillier_roundtrip_and_homomorphism() {
        let keys = paillier_keygen(64).unwrap();
        let a = BigUint::from(12u32);
        let b = BigUint::from(19u32);

        let enc_a = paillier_encrypt(&keys.public_key, &a).unwrap();
        let enc_b = paillier_encrypt(&keys.public_key, &b).unwrap();
        let dec_a = paillier_decrypt(&keys.public_key, &keys.private_key, &enc_a).unwrap();
        assert_eq!(dec_a, a);

        let enc_sum = paillier_add(&keys.public_key, &enc_a, &enc_b).unwrap();
        let dec_sum = paillier_decrypt(&keys.public_key, &keys.private_key, &enc_sum).unwrap();
        assert_eq!(dec_sum, BigUint::from(31u32));

        let enc_scaled =
            paillier_scalar_mul(&keys.public_key, &enc_a, &BigUint::from(7u32)).unwrap();
        let dec_scaled =
            paillier_decrypt(&keys.public_key, &keys.private_key, &enc_scaled).unwrap();
        assert_eq!(dec_scaled, BigUint::from(84u32));
    }
}
