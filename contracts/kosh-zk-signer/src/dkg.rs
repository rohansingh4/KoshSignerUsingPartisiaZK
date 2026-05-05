//! Distributed Key Generation (DKG) for secp256k1 ECDSA.
//!
//! Protocol:
//! 1. Each party generates a random scalar s_i and computes P_i = s_i × G
//! 2. Commit phase: each party submits SHA-256(compressed_P_i) on-chain
//! 3. Reveal phase: each party reveals compressed_P_i; contract verifies against commitment
//! 4. Finalize: contract computes combined public key P = P₁ + P₂ + ... + Pₙ
//!
//! The private key s = s₁ + s₂ + ... + sₙ is NEVER computed or assembled anywhere.
//! Each s_i is subsequently stored as a ZK secret input (existing flow).

use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint};

use crate::signing_state::ZkKeyState;

/// Verify that a revealed public key share matches its commitment hash.
pub fn verify_commitment(commitment_hash: &[u8], public_key_share: &[u8]) -> bool {
    let computed_hash = sha256(public_key_share);
    commitment_hash == computed_hash
}

/// Combine multiple compressed public key shares into a single combined public key.
/// Performs EC point addition: P = P₁ + P₂ + ... + Pₙ
pub fn combine_public_keys(pubkeys: &[Vec<u8>]) -> Vec<u8> {
    assert!(pubkeys.len() >= 2, "Need at least 2 parties for DKG");

    let mut combined = ProjectivePoint::IDENTITY;
    for pk_bytes in pubkeys {
        let encoded = EncodedPoint::from_bytes(pk_bytes).expect("Invalid encoded point bytes");
        let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
            .expect("Failed to decompress public key share");
        combined += ProjectivePoint::from(point);
    }

    assert!(
        combined != ProjectivePoint::IDENTITY,
        "Combined public key is the identity point — keys cancel out"
    );

    let affine = combined.to_affine();
    let encoded = EncodedPoint::from(affine);
    encoded.compress().as_bytes().to_vec()
}

/// Add a DKG commitment. Returns true if all commitments are collected.
pub fn add_commitment(
    key_state: &mut ZkKeyState,
    party_index: u8,
    commitment_hash: Vec<u8>,
) -> bool {
    assert!(
        !key_state
            .dkg_commit_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} has already committed",
        party_index
    );
    assert_eq!(
        commitment_hash.len(),
        32,
        "Commitment hash must be 32 bytes (SHA-256)"
    );

    key_state.dkg_commit_indices.push(party_index);
    key_state.dkg_commitment_hashes.push(commitment_hash);

    key_state.dkg_commit_indices.len() as u8 >= key_state.dkg_num_parties
}

/// Add a DKG reveal. Returns true if all reveals are collected.
pub fn add_reveal(key_state: &mut ZkKeyState, party_index: u8, public_key_share: Vec<u8>) -> bool {
    assert!(
        !key_state
            .dkg_reveal_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} has already revealed",
        party_index
    );
    assert_eq!(
        public_key_share.len(),
        33,
        "Public key share must be 33 bytes (compressed secp256k1)"
    );

    // Find this party's commitment hash
    let commit_idx = key_state
        .dkg_commit_indices
        .iter()
        .position(|&idx| idx == party_index)
        .expect("Party did not commit — cannot reveal");
    let commitment_hash = &key_state.dkg_commitment_hashes[commit_idx];

    assert!(
        verify_commitment(commitment_hash, &public_key_share),
        "Reveal does not match commitment hash"
    );

    // Validate it's a real EC point
    let encoded =
        EncodedPoint::from_bytes(&public_key_share).expect("Invalid encoded point format");
    let _point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .expect("Invalid secp256k1 point");

    key_state.dkg_reveal_indices.push(party_index);
    key_state.dkg_reveal_pubkeys.push(public_key_share);

    key_state.dkg_reveal_indices.len() as u8 >= key_state.dkg_num_parties
}

/// Simple SHA-256 implementation for contract environment.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, &val) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

/// Verify a Schnorr proof of knowledge of the discrete log of a public key share.
///
/// Proves: "I know s_i such that C_i0 = s_i * G"
///
/// Protocol:
///   1. Prover picks random r, computes R = r * G
///   2. Challenge: e = SHA-256(G_compressed || C_i0 || R || party_index)
///   3. Response: z = r + e * s_i mod N
///   4. Verifier checks: z * G == R + e * C_i0
///
/// This prevents the rogue key attack where a party crafts their public key
/// as a function of other parties' keys to control the combined key.
pub fn verify_schnorr_proof(
    public_key_share: &[u8], // C_i0 = s_i * G (33 bytes compressed)
    schnorr_r: &[u8],        // R = r * G (33 bytes compressed)
    schnorr_z: &[u8],        // z = r + e * s_i (32 bytes scalar)
    party_index: u8,
) -> bool {
    use k256::{FieldBytes, Scalar};

    // Parse points
    let c_i0 = match parse_point(public_key_share) {
        Some(p) => p,
        None => return false,
    };
    let r_point = match parse_point(schnorr_r) {
        Some(p) => p,
        None => return false,
    };

    // Parse z scalar
    if schnorr_z.len() != 32 {
        return false;
    }
    let z_fb = FieldBytes::from_slice(schnorr_z);
    let z_scalar = match Option::<Scalar>::from(Scalar::from_repr(*z_fb)) {
        Some(s) => s,
        None => return false,
    };

    // Compute challenge: e = SHA-256(G_compressed || C_i0 || R || party_index)
    let g_affine = ProjectivePoint::GENERATOR.to_affine();
    let g_bytes = EncodedPoint::from(g_affine).compress();

    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(g_bytes.as_bytes());
    challenge_input.extend_from_slice(public_key_share);
    challenge_input.extend_from_slice(schnorr_r);
    challenge_input.push(party_index);
    let e_hash = sha256(&challenge_input);

    // Reduce e_hash to scalar (may be >= N, so use reduce)
    let e_fb = FieldBytes::from_slice(&e_hash);
    let e_scalar = match Option::<Scalar>::from(Scalar::from_repr(*e_fb)) {
        Some(s) => s,
        // If hash >= N, wrap it by trying a simple subtraction-based reduce
        None => {
            // Fallback: just use it mod N by treating as field bytes
            // This edge case is extremely rare for SHA-256 output vs secp256k1 N
            return false;
        }
    };

    // z * G
    let left = ProjectivePoint::GENERATOR * z_scalar;

    // R + e * C_i0
    let right = r_point + c_i0 * e_scalar;

    left == right
}

/// Parse a compressed EC point from bytes.
fn parse_point(bytes: &[u8]) -> Option<ProjectivePoint> {
    let encoded = EncodedPoint::from_bytes(bytes).ok()?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))?;
    Some(ProjectivePoint::from(affine))
}

/// Verify a Feldman sub-share.
///
/// Checks: f_i(j) * G == C_i0 + j * C_i1
///
/// Where:
///   f_i(j) = s_i + a_i * j (the sub-share from party i to party j)
///   C_i0 = s_i * G (commitment to the secret)
///   C_i1 = a_i * G (commitment to the slope)
///
/// This proves party i sent the correct sub-share without revealing s_i or a_i.
pub fn verify_feldman_subshare(
    subshare_bytes: &[u8], // f_i(j) as 32-byte scalar
    c_i0_bytes: &[u8],     // C_i0 = s_i * G (33 bytes compressed)
    c_i1_bytes: &[u8],     // C_i1 = a_i * G (33 bytes compressed)
    j: u8,                 // recipient party index (1-based)
) -> bool {
    use k256::{FieldBytes, Scalar};

    // Parse sub-share scalar
    if subshare_bytes.len() != 32 {
        return false;
    }
    let fb = FieldBytes::from_slice(subshare_bytes);
    let subshare_scalar = match Option::<Scalar>::from(Scalar::from_repr(*fb)) {
        Some(s) => s,
        None => return false,
    };

    // Left side: f_i(j) * G
    let left = ProjectivePoint::GENERATOR * subshare_scalar;

    // Parse C_i0 and C_i1
    let c_i0 = match parse_point(c_i0_bytes) {
        Some(p) => p,
        None => return false,
    };
    let c_i1 = match parse_point(c_i1_bytes) {
        Some(p) => p,
        None => return false,
    };

    // j as scalar
    let mut j_bytes = [0u8; 32];
    j_bytes[31] = j;
    let j_fb = FieldBytes::from_slice(&j_bytes);
    let j_scalar = match Option::<Scalar>::from(Scalar::from_repr(*j_fb)) {
        Some(s) => s,
        None => return false,
    };

    // Right side: C_i0 + j * C_i1
    let right = c_i0 + c_i1 * j_scalar;

    left == right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_verify_commitment() {
        let test_data = [0x02u8; 33];
        let hash = sha256(&test_data);
        assert!(verify_commitment(&hash, &test_data));
        assert!(!verify_commitment(&[0u8; 32], &test_data));
    }
}
