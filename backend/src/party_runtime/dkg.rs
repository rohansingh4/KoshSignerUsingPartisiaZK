use anyhow::{anyhow, Result};
use k256::{
    elliptic_curve::{ff::PrimeField, group::GroupEncoding, ops::Reduce, sec1::FromEncodedPoint},
    FieldBytes, ProjectivePoint, Scalar,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgShare {
    pub secret_scalar_hex: String,
    pub public_key_share_hex: String,
    pub commitment_hash_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdDkgShare {
    pub party_index: u8,
    pub secret_scalar_hex: String,
    pub slope_hex: String,
    pub public_key_share_hex: String,
    pub commitment_hash_hex: String,
    pub c_i0_hex: String,
    pub c_i1_hex: String,
    pub subshares_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShamirShare {
    pub party_index: u8,
    pub share_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrProof {
    pub r_hex: String,
    pub z_hex: String,
}

pub fn generate_threshold_dkg_share(
    party_index: u8,
    num_parties: u8,
    seed: Option<&[u8]>,
) -> Result<ThresholdDkgShare> {
    if party_index == 0 || num_parties < 2 || party_index > num_parties {
        return Err(anyhow!("invalid party parameters"));
    }

    let secret_scalar = seeded_scalar(seed, b"secret", party_index)?;
    let slope = seeded_scalar(seed, b"slope", party_index)?;

    let c_i0 = (ProjectivePoint::GENERATOR * secret_scalar)
        .to_affine()
        .to_bytes();
    let c_i1 = (ProjectivePoint::GENERATOR * slope).to_affine().to_bytes();
    let commitment_hash = Sha256::digest(c_i0);

    let mut subshares_hex = Vec::with_capacity(num_parties as usize);
    for j in 1..=num_parties {
        let x = Scalar::from(j as u64);
        let share = secret_scalar + (slope * x);
        subshares_hex.push(hex::encode(share.to_bytes()));
    }

    Ok(ThresholdDkgShare {
        party_index,
        secret_scalar_hex: hex::encode(secret_scalar.to_bytes()),
        slope_hex: hex::encode(slope.to_bytes()),
        public_key_share_hex: hex::encode(c_i0),
        commitment_hash_hex: hex::encode(commitment_hash),
        c_i0_hex: hex::encode(c_i0),
        c_i1_hex: hex::encode(c_i1),
        subshares_hex,
    })
}

pub fn combine_shamir_shares(party_index: u8, shares: &[ThresholdDkgShare]) -> Result<ShamirShare> {
    if shares.is_empty() {
        return Err(anyhow!("no shares supplied"));
    }
    let mut total = Scalar::ZERO;
    for share in shares {
        let idx = usize::from(party_index.saturating_sub(1));
        let hex = share
            .subshares_hex
            .get(idx)
            .ok_or_else(|| anyhow!("missing subshare"))?;
        total += scalar_from_hex(hex)?;
    }
    Ok(ShamirShare {
        party_index,
        share_hex: hex::encode(total.to_bytes()),
    })
}

pub fn compute_combined_public_key(shares: &[ThresholdDkgShare]) -> Result<String> {
    if shares.len() < 2 {
        return Err(anyhow!("need at least 2 shares"));
    }
    let mut total = ProjectivePoint::IDENTITY;
    for share in shares {
        let point = point_from_hex(&share.public_key_share_hex)?;
        total += point;
    }
    Ok(hex::encode(total.to_affine().to_bytes()))
}

pub fn verify_feldman_subshare(
    subshare_hex: &str,
    c_i0_hex: &str,
    c_i1_hex: &str,
    j: u8,
) -> Result<bool> {
    let left = ProjectivePoint::GENERATOR * scalar_from_hex(subshare_hex)?;
    let c_i0 = point_from_hex(c_i0_hex)?;
    let c_i1 = point_from_hex(c_i1_hex)?;
    let right = c_i0 + (c_i1 * Scalar::from(j as u64));
    Ok(left == right)
}

pub fn compute_lagrange_coefficient(party_index: u8, signing_subset: &[u8]) -> Result<Scalar> {
    if signing_subset.is_empty() {
        return Err(anyhow!("signing subset must not be empty"));
    }
    let i = Scalar::from(party_index as u64);
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    for &other_idx in signing_subset {
        if other_idx == party_index {
            continue;
        }
        let j = Scalar::from(other_idx as u64);
        numerator *= -j;
        denominator *= i - j;
    }

    let denominator_inv = Option::<Scalar>::from(denominator.invert())
        .ok_or_else(|| anyhow!("lagrange denominator is not invertible"))?;
    Ok(numerator * denominator_inv)
}

pub fn compute_adjusted_share(
    shamir_share_hex: &str,
    party_index: u8,
    signing_subset: &[u8],
) -> Result<String> {
    let share = scalar_from_hex(shamir_share_hex)?;
    let lambda = compute_lagrange_coefficient(party_index, signing_subset)?;
    Ok(hex::encode((lambda * share).to_bytes()))
}

pub fn generate_schnorr_proof(
    secret_scalar_hex: &str,
    public_key_share_hex: &str,
    party_index: u8,
) -> Result<SchnorrProof> {
    let secret_scalar = scalar_from_hex(secret_scalar_hex)?;
    let public_key = hex::decode(public_key_share_hex)?;
    let nonce = seeded_scalar(Some(&public_key), b"schnorr", party_index)?;
    let r_point = (ProjectivePoint::GENERATOR * nonce).to_affine().to_bytes();

    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(ProjectivePoint::GENERATOR.to_affine().to_bytes().as_slice());
    challenge_input.extend_from_slice(&public_key);
    challenge_input.extend_from_slice(r_point.as_slice());
    challenge_input.push(party_index);
    let challenge = scalar_from_digest(Sha256::digest(challenge_input));
    let z = nonce + (challenge * secret_scalar);

    Ok(SchnorrProof {
        r_hex: hex::encode(r_point),
        z_hex: hex::encode(z.to_bytes()),
    })
}

fn seeded_scalar(seed: Option<&[u8]>, label: &[u8], party_index: u8) -> Result<Scalar> {
    let mut bytes = [0u8; 32];
    if let Some(seed) = seed {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(label);
        hasher.update([party_index]);
        bytes.copy_from_slice(&hasher.finalize()[..32]);
    } else {
        rand::thread_rng().fill_bytes(&mut bytes);
    }
    Ok(scalar_from_digest(bytes))
}

fn scalar_from_digest<D: AsRef<[u8]>>(bytes: D) -> Scalar {
    let fb = FieldBytes::clone_from_slice(bytes.as_ref());
    <Scalar as Reduce<k256::elliptic_curve::bigint::U256>>::reduce_bytes(&fb)
}

fn scalar_from_hex(hex_str: &str) -> Result<Scalar> {
    let bytes = hex::decode(hex_str)?;
    let fb = FieldBytes::from_slice(&bytes);
    let scalar = Scalar::from_repr(*fb)
        .into_option()
        .ok_or_else(|| anyhow!("invalid scalar"))?;
    Ok(scalar)
}

fn point_from_hex(hex_str: &str) -> Result<ProjectivePoint> {
    let bytes = hex::decode(hex_str)?;
    let enc = k256::EncodedPoint::from_bytes(&bytes).map_err(|_| anyhow!("invalid point bytes"))?;
    let affine = k256::AffinePoint::from_encoded_point(&enc)
        .into_option()
        .ok_or_else(|| anyhow!("invalid curve point"))?;
    Ok(ProjectivePoint::from(affine))
}

#[cfg(test)]
mod tests {
    use super::{
        combine_shamir_shares, compute_adjusted_share, compute_combined_public_key,
        compute_lagrange_coefficient, generate_threshold_dkg_share, verify_feldman_subshare,
    };

    #[test]
    fn generated_subshares_verify_and_combine() {
        let share1 = generate_threshold_dkg_share(1, 3, Some(b"seed-1")).unwrap();
        let share2 = generate_threshold_dkg_share(2, 3, Some(b"seed-2")).unwrap();
        let share3 = generate_threshold_dkg_share(3, 3, Some(b"seed-3")).unwrap();
        let shares = vec![share1.clone(), share2.clone(), share3.clone()];

        assert!(verify_feldman_subshare(
            &share1.subshares_hex[1],
            &share1.c_i0_hex,
            &share1.c_i1_hex,
            2
        )
        .unwrap());

        let combined = combine_shamir_shares(1, &shares).unwrap();
        assert_eq!(combined.party_index, 1);
        assert!(!combined.share_hex.is_empty());

        let public_key = compute_combined_public_key(&shares).unwrap();
        assert!(!public_key.is_empty());
    }

    #[test]
    fn lagrange_coefficients_for_subset_1_2_sum_to_secret_basis() {
        let lambda1 = compute_lagrange_coefficient(1, &[1, 2]).unwrap();
        let lambda2 = compute_lagrange_coefficient(2, &[1, 2]).unwrap();
        assert_eq!(
            hex::encode(lambda1.to_bytes()),
            "0000000000000000000000000000000000000000000000000000000000000002"
        );
        assert_eq!(
            hex::encode(lambda2.to_bytes()),
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        );
    }

    #[test]
    fn adjusted_share_is_derived_from_subset() {
        let share = generate_threshold_dkg_share(1, 3, Some(b"seed-1")).unwrap();
        let combined = combine_shamir_shares(1, &[share]).unwrap();
        let adjusted = compute_adjusted_share(&combined.share_hex, 1, &[1, 2]).unwrap();
        assert!(!adjusted.is_empty());
    }
}
