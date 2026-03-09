//! Shamir's Secret Sharing over the secp256k1 scalar field.
//!
//! Splits a 256-bit ECDSA private key into n shares with a t-of-n threshold,
//! and reconstructs the secret from any t shares via Lagrange interpolation.
//!
//! Uses k256::Scalar for all arithmetic (mod secp256k1 group order).

use k256::elliptic_curve::ff::PrimeField;
use k256::{FieldBytes, Scalar};

/// A single Shamir share: evaluation of the secret polynomial at x = index.
pub struct ShamirShare {
    /// 1-based x-coordinate (evaluator index).
    pub index: u8,
    /// y = f(index), the share value.
    pub value: Scalar,
}

/// Split a secret into `num_shares` Shamir shares with threshold `threshold`.
///
/// The polynomial is: f(x) = secret + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
/// Shares are evaluated at x = 1, 2, ..., num_shares using Horner's method.
///
/// # Arguments
/// * `secret` - The secret scalar (ECDSA private key)
/// * `threshold` - Minimum shares needed to reconstruct (t)
/// * `num_shares` - Total number of shares to generate (n)
/// * `random_coeffs` - t-1 random scalar coefficients for the polynomial
pub fn split(
    secret: Scalar,
    threshold: usize,
    num_shares: usize,
    random_coeffs: Vec<Scalar>,
) -> Vec<ShamirShare> {
    assert!(threshold >= 2, "Threshold must be at least 2");
    assert!(
        num_shares >= threshold,
        "Number of shares must be >= threshold"
    );
    assert_eq!(
        random_coeffs.len(),
        threshold - 1,
        "Need exactly t-1 random coefficients"
    );

    // Polynomial coefficients: [secret, a_1, a_2, ..., a_{t-1}]
    let mut coeffs = Vec::with_capacity(threshold);
    coeffs.push(secret);
    coeffs.extend(random_coeffs);

    (1..=num_shares as u64)
        .map(|i| {
            let x = Scalar::from(i);
            // Horner's method: start from highest degree coefficient
            // f(x) = (...((a_{t-1} * x + a_{t-2}) * x + a_{t-3}) * x + ...) * x + a_0
            let mut y = *coeffs.last().expect("coefficients must not be empty");
            for j in (0..coeffs.len() - 1).rev() {
                y = y * x + coeffs[j];
            }
            ShamirShare {
                index: i as u8,
                value: y,
            }
        })
        .collect()
}

/// Reconstruct the secret from threshold shares via Lagrange interpolation.
///
/// Computes: secret = f(0) = sum_i ( y_i * L_i(0) )
/// where L_i(0) = product_{j != i} ( -x_j / (x_i - x_j) )
///
/// Uses `Scalar::invert()` for modular division over secp256k1 field order.
pub fn reconstruct(shares: &[ShamirShare]) -> Scalar {
    assert!(shares.len() >= 2, "Need at least 2 shares to reconstruct");

    let mut secret = Scalar::ZERO;

    for (i, share_i) in shares.iter().enumerate() {
        let xi = Scalar::from(share_i.index as u64);

        // Compute Lagrange basis polynomial L_i(0)
        let mut li = Scalar::ONE;
        for (j, share_j) in shares.iter().enumerate() {
            if i != j {
                let xj = Scalar::from(share_j.index as u64);
                // L_i(0) *= (0 - x_j) / (x_i - x_j) = -x_j / (x_i - x_j)
                let numerator = Scalar::ZERO - xj;
                let denominator = xi - xj;
                let denom_inv = Option::<Scalar>::from(denominator.invert())
                    .expect("Denominator must be non-zero (duplicate share indices?)");
                li = li * numerator * denom_inv;
            }
        }

        secret = secret + share_i.value * li;
    }

    secret
}

/// Split a 256-bit scalar into two 128-bit halves (big-endian byte representation).
///
/// Returns (high_bytes, low_bytes) where each is 16 bytes.
/// high_bytes = scalar_bytes[0..16], low_bytes = scalar_bytes[16..32]
pub fn scalar_to_halves(scalar: &Scalar) -> ([u8; 16], [u8; 16]) {
    let bytes = scalar.to_bytes();
    let mut high = [0u8; 16];
    let mut low = [0u8; 16];
    high.copy_from_slice(&bytes[0..16]);
    low.copy_from_slice(&bytes[16..32]);
    (high, low)
}

/// Reassemble a 256-bit scalar from two 128-bit halves (big-endian byte representation).
pub fn halves_to_scalar(high: &[u8], low: &[u8]) -> Scalar {
    assert_eq!(high.len(), 16, "High half must be 16 bytes");
    assert_eq!(low.len(), 16, "Low half must be 16 bytes");

    let mut bytes = [0u8; 32];
    bytes[0..16].copy_from_slice(high);
    bytes[16..32].copy_from_slice(low);

    let field_bytes = FieldBytes::from(bytes);
    Option::<Scalar>::from(Scalar::from_repr(field_bytes))
        .expect("Invalid scalar: combined halves exceed secp256k1 field order")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_from_u64(n: u64) -> Scalar {
        Scalar::from(n)
    }

    #[test]
    fn test_split_and_reconstruct_2_of_3() {
        let secret = scalar_from_u64(42);
        let coeffs = vec![scalar_from_u64(7)]; // t-1 = 1 random coeff
        let shares = split(secret, 2, 3, coeffs);
        assert_eq!(shares.len(), 3);

        // Reconstruct from any 2 shares
        let reconstructed = reconstruct(&shares[0..2]);
        assert_eq!(reconstructed, secret);

        let reconstructed2 = reconstruct(&shares[1..3]);
        assert_eq!(reconstructed2, secret);

        let reconstructed3 = reconstruct(&[shares[0].clone_share(), shares[2].clone_share()]);
        assert_eq!(reconstructed3, secret);
    }

    #[test]
    fn test_split_and_reconstruct_3_of_5() {
        let secret = scalar_from_u64(123456789);
        let coeffs = vec![scalar_from_u64(11), scalar_from_u64(23)];
        let shares = split(secret, 3, 5, coeffs);
        assert_eq!(shares.len(), 5);

        // Any 3 shares should reconstruct
        let r1 = reconstruct(&shares[0..3]);
        assert_eq!(r1, secret);

        let r2 = reconstruct(&shares[2..5]);
        assert_eq!(r2, secret);

        let r3 = reconstruct(&[
            shares[0].clone_share(),
            shares[2].clone_share(),
            shares[4].clone_share(),
        ]);
        assert_eq!(r3, secret);
    }

    #[test]
    fn test_scalar_halves_roundtrip() {
        let secret = scalar_from_u64(0xDEADBEEFCAFEBABE);
        let (high, low) = scalar_to_halves(&secret);
        let reconstructed = halves_to_scalar(&high, &low);
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_large_scalar_halves() {
        // Use a scalar with non-zero high bits
        let mut bytes = [0u8; 32];
        bytes[0] = 0x7F; // high byte (must be < group order)
        bytes[15] = 0xAB;
        bytes[16] = 0xCD;
        bytes[31] = 0xEF;
        let field_bytes = FieldBytes::from(bytes);
        let scalar = Option::<Scalar>::from(Scalar::from_repr(field_bytes)).unwrap();

        let (high, low) = scalar_to_halves(&scalar);
        let reconstructed = halves_to_scalar(&high, &low);
        assert_eq!(reconstructed, scalar);
    }

    #[test]
    fn test_shamir_with_halves_roundtrip() {
        // Full pipeline: split -> convert to halves -> reassemble -> reconstruct
        let secret = scalar_from_u64(999999999);
        let coeffs = vec![scalar_from_u64(42)];
        let shares = split(secret, 2, 3, coeffs);

        // Convert shares to halves and back
        let rebuilt_shares: Vec<ShamirShare> = shares
            .iter()
            .map(|s| {
                let (h, l) = scalar_to_halves(&s.value);
                let val = halves_to_scalar(&h, &l);
                ShamirShare {
                    index: s.index,
                    value: val,
                }
            })
            .collect();

        let reconstructed = reconstruct(&rebuilt_shares[0..2]);
        assert_eq!(reconstructed, secret);
    }

    impl ShamirShare {
        fn clone_share(&self) -> ShamirShare {
            ShamirShare {
                index: self.index,
                value: self.value,
            }
        }
    }
}
