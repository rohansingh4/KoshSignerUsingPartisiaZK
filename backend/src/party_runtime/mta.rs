use crate::party_runtime::paillier::{
    paillier_add, paillier_decrypt, paillier_encrypt, paillier_scalar_mul, signed_from_decrypted,
    PaillierCiphertext, PaillierPrivateKey, PaillierPublicKey,
};
use anyhow::Result;
use k256::{
    elliptic_curve::{bigint::U256, ff::Field, ops::Reduce},
    Scalar,
};
use num_bigint::{BigInt, BigUint, Sign};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MtASessionContext {
    pub key_id: u32,
    pub task_id: u32,
    pub round: u8,
    pub sender: u8,
    pub receiver: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtAMessage1 {
    pub encrypted_a: PaillierCiphertext,
    pub paillier_pk: PaillierPublicKey,
    pub session: Option<MtASessionContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtAMessage2 {
    pub encrypted_result: PaillierCiphertext,
    pub session: Option<MtASessionContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtAOutputA {
    pub alpha_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtAOutputB {
    pub beta_hex: String,
}

pub fn mta_round1_a(
    a_hex: &str,
    paillier_pk: PaillierPublicKey,
    session: Option<MtASessionContext>,
) -> Result<MtAMessage1> {
    let a = scalar_from_hex(a_hex)?;
    let a_uint = BigUint::from_bytes_be(&a.to_bytes());
    let encrypted_a = paillier_encrypt(&paillier_pk, &a_uint)?;
    Ok(MtAMessage1 {
        encrypted_a,
        paillier_pk,
        session,
    })
}

pub fn mta_round2_b(
    msg1: &MtAMessage1,
    b_hex: &str,
    expected_session: Option<&MtASessionContext>,
) -> Result<(MtAMessage2, MtAOutputB)> {
    validate_session(msg1.session.as_ref(), expected_session)?;
    let b = scalar_from_hex(b_hex)?;
    let beta = Scalar::random(OsRng);
    let b_uint = BigUint::from_bytes_be(&b.to_bytes());
    let enc_ab = paillier_scalar_mul(&msg1.paillier_pk, &msg1.encrypted_a, &b_uint)?;

    let n = crate::party_runtime::paillier::parse_biguint(&msg1.paillier_pk.n_hex)?;
    let beta_mod_n = BigUint::from_bytes_be(&beta.to_bytes()) % &n;
    let neg_beta = if beta_mod_n == BigUint::from(0u8) {
        BigUint::from(0u8)
    } else {
        &n - beta_mod_n
    };
    let enc_neg_beta = paillier_encrypt(&msg1.paillier_pk, &neg_beta)?;
    let encrypted_result = paillier_add(&msg1.paillier_pk, &enc_ab, &enc_neg_beta)?;

    Ok((
        MtAMessage2 {
            encrypted_result,
            session: msg1.session.clone(),
        },
        MtAOutputB {
            beta_hex: scalar_to_hex(&beta),
        },
    ))
}

pub fn mta_finalize_a(
    msg2: &MtAMessage2,
    paillier_pk: &PaillierPublicKey,
    paillier_sk: &PaillierPrivateKey,
    expected_session: Option<&MtASessionContext>,
) -> Result<MtAOutputA> {
    validate_session(msg2.session.as_ref(), expected_session)?;
    let decrypted = paillier_decrypt(paillier_pk, paillier_sk, &msg2.encrypted_result)?;
    let signed = signed_from_decrypted(paillier_pk, &decrypted)?;
    let alpha = big_int_to_scalar(&signed)?;
    Ok(MtAOutputA {
        alpha_hex: scalar_to_hex(&alpha),
    })
}

pub fn run_mta(
    a_hex: &str,
    b_hex: &str,
    paillier_pk: PaillierPublicKey,
    paillier_sk: &PaillierPrivateKey,
) -> Result<(MtAOutputA, MtAOutputB)> {
    let msg1 = mta_round1_a(a_hex, paillier_pk.clone(), None)?;
    let (msg2, output_b) = mta_round2_b(&msg1, b_hex, None)?;
    let output_a = mta_finalize_a(&msg2, &paillier_pk, paillier_sk, None)?;
    Ok((output_a, output_b))
}

fn validate_session(
    actual: Option<&MtASessionContext>,
    expected: Option<&MtASessionContext>,
) -> Result<()> {
    if let Some(expected) = expected {
        let actual =
            actual.ok_or_else(|| anyhow::anyhow!("MtA message missing session binding"))?;
        if actual != expected {
            anyhow::bail!("MtA session mismatch");
        }
    }
    Ok(())
}

pub fn scalar_from_hex(value: &str) -> Result<Scalar> {
    let normalized = normalize_hex(value)?;
    let bytes = hex::decode(normalized)?;
    if bytes.len() > 32 {
        anyhow::bail!("scalar hex too long");
    }
    let mut wide = [0_u8; 32];
    wide[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(<Scalar as Reduce<U256>>::reduce_bytes((&wide).into()))
}

pub fn scalar_to_hex(value: &Scalar) -> String {
    hex::encode(value.to_bytes())
}

fn normalize_hex(value: &str) -> Result<String> {
    let trimmed = value.trim_start_matches("0x");
    if trimmed.is_empty() {
        anyhow::bail!("empty hex string");
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn big_int_to_scalar(value: &BigInt) -> Result<Scalar> {
    let order = BigInt::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .ok_or_else(|| anyhow::anyhow!("failed to parse curve order"))?;
    let reduced = ((value % &order) + &order) % &order;
    let magnitude = reduced
        .to_biguint()
        .ok_or_else(|| anyhow::anyhow!("bigint conversion failed"))?;
    let wide = magnitude.to_bytes_be();
    let mut buf = [0u8; 32];
    if wide.len() > 32 {
        anyhow::bail!("reduced scalar wider than 32 bytes");
    }
    buf[32 - wide.len()..].copy_from_slice(&wide);
    let scalar = <Scalar as Reduce<U256>>::reduce_bytes((&buf).into());
    Ok(scalar)
}

#[cfg(test)]
mod tests {
    use super::run_mta;
    use crate::party_runtime::paillier::paillier_keygen;
    use k256::{elliptic_curve::bigint::U256, elliptic_curve::ops::Reduce, Scalar};

    #[test]
    fn mta_outputs_sum_to_product_mod_curve_order() {
        let keys = paillier_keygen(256).unwrap();
        let a = Scalar::from(9u64);
        let b = Scalar::from(13u64);
        let (alpha, beta) = run_mta(
            &hex::encode(a.to_bytes()),
            &hex::encode(b.to_bytes()),
            keys.public_key,
            &keys.private_key,
        )
        .unwrap();
        let alpha_s = super::scalar_from_hex(&alpha.alpha_hex).unwrap();
        let beta_s = super::scalar_from_hex(&beta.beta_hex).unwrap();
        assert_eq!(alpha_s + beta_s, a * b);
    }
}
