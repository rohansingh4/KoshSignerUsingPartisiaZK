use crate::party_runtime::{
    mta::{run_mta, scalar_from_hex, scalar_to_hex},
    paillier::{paillier_keygen, PaillierKeyPair},
};
use k256::{
    ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
    elliptic_curve::{
        bigint::U256, ff::Field, ops::Reduce, point::AffineCoordinates, sec1::ToEncodedPoint,
    },
    ProjectivePoint, PublicKey, Scalar,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GG20PartyState {
    pub party_index: u8,
    pub x_i_hex: String,
    pub k_i_hex: String,
    pub gamma_i_hex: String,
    pub gamma_i_point_hex: String,
    pub paillier_keys: PaillierKeyPair,
    pub delta_i_hex: String,
    pub sigma_i_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GG20PartialSignature {
    pub party_index: u8,
    pub s_i_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GG20DeltaShare {
    pub party_index: u8,
    pub delta_i_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GG20SignatureData {
    pub r_hex: String,
    pub r_bytes_hex: String,
    pub r_point_compressed_hex: String,
    pub recovery_id: u8,
    pub partials: Vec<GG20PartialSignature>,
    pub deltas: Vec<GG20DeltaShare>,
    pub gamma_points_hex: Vec<String>,
}

pub fn gg20_init_party(
    party_index: u8,
    x_i_hex: &str,
    msg_hash_hex: Option<&str>,
    session_id: Option<u32>,
) -> anyhow::Result<GG20PartyState> {
    let x_i = scalar_from_hex(x_i_hex)?;
    let msg_hash = msg_hash_hex.unwrap_or("00");
    let k_i = deterministic_nonce(&x_i, msg_hash, &format!("k_{party_index}"), session_id)?;
    let gamma_i = deterministic_nonce(&x_i, msg_hash, &format!("gamma_{party_index}"), session_id)?;
    let gamma_point = (ProjectivePoint::GENERATOR * gamma_i)
        .to_affine()
        .to_encoded_point(true);

    Ok(GG20PartyState {
        party_index,
        x_i_hex: scalar_to_hex(&x_i),
        k_i_hex: scalar_to_hex(&k_i),
        gamma_i_hex: scalar_to_hex(&gamma_i),
        gamma_i_point_hex: hex::encode(gamma_point.as_bytes()),
        paillier_keys: paillier_keygen(1024)?,
        delta_i_hex: scalar_to_hex(&(k_i * gamma_i)),
        sigma_i_hex: scalar_to_hex(&(k_i * x_i)),
    })
}

pub fn gg20_run_mta_rounds(parties: &mut [GG20PartyState]) -> anyhow::Result<()> {
    for i in 0..parties.len() {
        for j in 0..parties.len() {
            if i == j {
                continue;
            }
            let k_i = parties[i].k_i_hex.clone();
            let gamma_j = parties[j].gamma_i_hex.clone();
            let x_j = parties[j].x_i_hex.clone();
            let paillier_pk = parties[i].paillier_keys.public_key.clone();
            let paillier_sk = parties[i].paillier_keys.private_key.clone();

            let (alpha_delta, beta_delta) =
                run_mta(&k_i, &gamma_j, paillier_pk.clone(), &paillier_sk)?;
            let (alpha_sigma, beta_sigma) = run_mta(&k_i, &x_j, paillier_pk, &paillier_sk)?;

            let delta_i = scalar_from_hex(&parties[i].delta_i_hex)?
                + scalar_from_hex(&alpha_delta.alpha_hex)?;
            let sigma_i = scalar_from_hex(&parties[i].sigma_i_hex)?
                + scalar_from_hex(&alpha_sigma.alpha_hex)?;
            let delta_j =
                scalar_from_hex(&parties[j].delta_i_hex)? + scalar_from_hex(&beta_delta.beta_hex)?;
            let sigma_j =
                scalar_from_hex(&parties[j].sigma_i_hex)? + scalar_from_hex(&beta_sigma.beta_hex)?;

            parties[i].delta_i_hex = scalar_to_hex(&delta_i);
            parties[i].sigma_i_hex = scalar_to_hex(&sigma_i);
            parties[j].delta_i_hex = scalar_to_hex(&delta_j);
            parties[j].sigma_i_hex = scalar_to_hex(&sigma_j);
        }
    }
    Ok(())
}

pub fn gg20_compute_r(parties: &[GG20PartyState]) -> anyhow::Result<(String, String, String, u8)> {
    if parties.is_empty() {
        anyhow::bail!("at least one party is required");
    }

    let mut delta = Scalar::ZERO;
    let mut gamma_point = ProjectivePoint::IDENTITY;
    for party in parties {
        delta += scalar_from_hex(&party.delta_i_hex)?;
        let gamma_i = scalar_from_hex(&party.gamma_i_hex)?;
        gamma_point += ProjectivePoint::GENERATOR * gamma_i;
    }

    let delta_inv = delta
        .invert()
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("delta has no inverse"))?;
    let r_point = gamma_point * delta_inv;
    let affine = r_point.to_affine();
    let encoded = affine.to_encoded_point(true);
    let x = affine.x();
    let r = <Scalar as Reduce<U256>>::reduce_bytes(&x);
    let recovery_id = match encoded.as_bytes().first().copied().unwrap_or(0x02) {
        0x03 => 1,
        _ => 0,
    };

    Ok((
        scalar_to_hex(&r),
        hex::encode(x),
        hex::encode(encoded.as_bytes()),
        recovery_id,
    ))
}

pub fn gg20_compute_partials(
    parties: &[GG20PartyState],
    msg_hash_hex: &str,
    r_hex: &str,
) -> anyhow::Result<Vec<GG20PartialSignature>> {
    let msg = scalar_from_hash_hex(msg_hash_hex)?;
    let r = scalar_from_hex(r_hex)?;
    let mut partials = Vec::with_capacity(parties.len());
    for party in parties {
        let k_i = scalar_from_hex(&party.k_i_hex)?;
        let sigma_i = scalar_from_hex(&party.sigma_i_hex)?;
        let s_i = (msg * k_i) + (r * sigma_i);
        partials.push(GG20PartialSignature {
            party_index: party.party_index,
            s_i_hex: scalar_to_hex(&s_i),
        });
    }
    Ok(partials)
}

pub fn gg20_sign_foundation(
    party_inputs: &[(u8, String)],
    msg_hash_hex: &str,
    session_id: Option<u32>,
) -> anyhow::Result<GG20SignatureData> {
    let mut parties = Vec::with_capacity(party_inputs.len());
    for (party_index, x_i_hex) in party_inputs {
        parties.push(gg20_init_party(
            *party_index,
            x_i_hex,
            Some(msg_hash_hex),
            session_id,
        )?);
    }
    gg20_run_mta_rounds(&mut parties)?;
    let (r_hex, r_bytes_hex, r_point_compressed_hex, recovery_id) = gg20_compute_r(&parties)?;
    let partials = gg20_compute_partials(&parties, msg_hash_hex, &r_hex)?;
    let deltas = parties
        .iter()
        .map(|p| GG20DeltaShare {
            party_index: p.party_index,
            delta_i_hex: p.delta_i_hex.clone(),
        })
        .collect();
    let gamma_points_hex = parties
        .iter()
        .map(|p| p.gamma_i_point_hex.clone())
        .collect();
    Ok(GG20SignatureData {
        r_hex,
        r_bytes_hex,
        r_point_compressed_hex,
        recovery_id,
        partials,
        deltas,
        gamma_points_hex,
    })
}

pub fn gg20_combine_partials(partials: &[GG20PartialSignature]) -> anyhow::Result<String> {
    let mut combined = Scalar::ZERO;
    for partial in partials {
        combined += scalar_from_hex(&partial.s_i_hex)?;
    }
    Ok(scalar_to_hex(&combined))
}

pub fn gg20_verify_locally(public_key_hex: &str, msg_hash_hex: &str, r_hex: &str, s_hex: &str) -> anyhow::Result<bool> {
    let public_key_bytes = hex::decode(public_key_hex.trim_start_matches("0x"))?;
    let public_key = k256::PublicKey::from_sec1_bytes(&public_key_bytes)?;
    let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);

    let r_bytes = hex::decode(r_hex.trim_start_matches("0x"))?;
    let s_bytes = hex::decode(s_hex.trim_start_matches("0x"))?;
    if r_bytes.len() != 32 || s_bytes.len() != 32 {
        anyhow::bail!("r/s must be 32 bytes");
    }
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s_bytes);
    let signature = k256::ecdsa::Signature::try_from(&sig[..])?;

    let msg_bytes = hex::decode(msg_hash_hex.trim_start_matches("0x"))?;
    verifying_key.verify_prehash(&msg_bytes, &signature).map(|_| true).or_else(|_| Ok(false))
}

pub fn derive_public_key_from_shares(party_inputs: &[(u8, String)]) -> anyhow::Result<String> {
    let mut point = ProjectivePoint::IDENTITY;
    for (_, share_hex) in party_inputs {
        let share = scalar_from_hex(share_hex)?;
        point += ProjectivePoint::GENERATOR * share;
    }
    Ok(format!("0x{}", hex::encode(point.to_affine().to_encoded_point(true).as_bytes())))
}

fn deterministic_nonce(
    x_i: &Scalar,
    msg_hash_hex: &str,
    label: &str,
    session_id: Option<u32>,
) -> anyhow::Result<Scalar> {
    let mut hasher = Sha256::new();
    hasher.update(x_i.to_bytes());
    hasher.update(hex::decode(msg_hash_hex.trim_start_matches("0x"))?);
    hasher.update(label.as_bytes());
    if let Some(session_id) = session_id {
        hasher.update(session_id.to_be_bytes());
    }
    hasher.update(Scalar::random(OsRng).to_bytes());
    let digest = hasher.finalize();
    Ok(<Scalar as Reduce<U256>>::reduce_bytes(
        (&digest[..32]).into(),
    ))
}

fn scalar_from_hash_hex(value: &str) -> anyhow::Result<Scalar> {
    let normalized = value.trim_start_matches("0x");
    let bytes = hex::decode(normalized)?;
    let mut wide = [0_u8; 32];
    let src = if bytes.len() > 32 {
        &bytes[bytes.len() - 32..]
    } else {
        &bytes
    };
    wide[32 - src.len()..].copy_from_slice(src);
    Ok(<Scalar as Reduce<U256>>::reduce_bytes((&wide).into()))
}

#[cfg(test)]
mod tests {
    use super::{derive_public_key_from_shares, gg20_combine_partials, gg20_verify_locally};
    use k256::Scalar;
    use crate::party_runtime::dkg::{combine_shamir_shares, compute_adjusted_share, compute_combined_public_key, generate_threshold_dkg_share};

    #[test]
    fn gg20_sign_foundation_verifies_locally_for_2_of_3_subset() {
        let share1 = generate_threshold_dkg_share(1, 3, Some(b"seed-1")).unwrap();
        let share2 = generate_threshold_dkg_share(2, 3, Some(b"seed-2")).unwrap();
        let share3 = generate_threshold_dkg_share(3, 3, Some(b"seed-3")).unwrap();
        let shares = vec![share1, share2, share3];
        let combined_pk = format!("0x{}", compute_combined_public_key(&shares).unwrap());
        let shamir1 = combine_shamir_shares(1, &shares).unwrap();
        let shamir2 = combine_shamir_shares(2, &shares).unwrap();
        let adjusted1 = compute_adjusted_share(&shamir1.share_hex, 1, &[1,2]).unwrap();
        let adjusted2 = compute_adjusted_share(&shamir2.share_hex, 2, &[1,2]).unwrap();
        let party_inputs = vec![(1u8, adjusted1), (2u8, adjusted2)];
        let derived = derive_public_key_from_shares(&party_inputs).unwrap();
        assert_eq!(derived, combined_pk);
        let msg = "0xc9b03991a1a3fa025eebe1fe2c9186e0a4d1b275f5eb8369e4f4429416655735";
        let mut parties = vec![
            super::gg20_init_party(1, &party_inputs[0].1, Some(msg), Some(1)).unwrap(),
            super::gg20_init_party(2, &party_inputs[1].1, Some(msg), Some(1)).unwrap(),
        ];
        super::gg20_run_mta_rounds(&mut parties).unwrap();
        let mut k = Scalar::ZERO;
        let mut gamma = Scalar::ZERO;
        let mut x = Scalar::ZERO;
        let mut delta = Scalar::ZERO;
        let mut sigma = Scalar::ZERO;
        for (idx, p) in parties.iter().enumerate() {
            k += super::scalar_from_hex(&p.k_i_hex).unwrap();
            gamma += super::scalar_from_hex(&p.gamma_i_hex).unwrap();
            x += super::scalar_from_hex(&party_inputs[idx].1).unwrap();
            delta += super::scalar_from_hex(&p.delta_i_hex).unwrap();
            sigma += super::scalar_from_hex(&p.sigma_i_hex).unwrap();
        }
        // pairwise MtA invariants
        for i in 0..parties.len() {
            for j in 0..parties.len() {
                if i == j { continue; }
                let a = super::scalar_from_hex(&parties[i].k_i_hex).unwrap();
                let b = super::scalar_from_hex(&parties[j].gamma_i_hex).unwrap();
                let (alpha, beta) = crate::party_runtime::mta::run_mta(&super::scalar_to_hex(&a), &super::scalar_to_hex(&b), parties[i].paillier_keys.public_key.clone(), &parties[i].paillier_keys.private_key).unwrap();
                let aa = super::scalar_from_hex(&alpha.alpha_hex).unwrap();
                let bb = super::scalar_from_hex(&beta.beta_hex).unwrap();
                assert_eq!(aa + bb, a * b, "mta kg invariant failed i={} j={}", i, j);
            }
        }
        assert_eq!(delta, k * gamma);
        assert_eq!(sigma, k * x);
        let (r_hex, _, _, _) = super::gg20_compute_r(&parties).unwrap();
        let partials = super::gg20_compute_partials(&parties, msg, &r_hex).unwrap();
        let s = gg20_combine_partials(&partials).unwrap();
        assert!(gg20_verify_locally(&combined_pk, msg, &r_hex, &s).unwrap());
    }
}
