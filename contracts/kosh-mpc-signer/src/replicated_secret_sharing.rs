//! Replicated secret sharing primitives for 3-party MPC on secp256k1.
//!
//! Provides secret share types, PRG-based share generation, and scalar/point
//! arithmetic needed for the distributed key generation and signing protocol.

use create_type_spec_derive::CreateTypeSpec;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, U256};
use pbc_contract_common::Hash;
use pbc_traits::{ReadRPC, ReadWriteState, WriteRPC};
use read_write_rpc_derive::ReadWriteRPC;
use read_write_state_derive::ReadWriteState;

/// A replicated secret share — each party holds two shares (left and right).
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone, Debug)]
pub struct ReplicatedSecretShare<T: ReadWriteState + Clone> {
    pub left: T,
    pub right: T,
}

/// Encoded elliptic curve point (33 bytes compressed).
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone, Debug)]
pub struct EncodedCurvePoint {
    pub bytes: Vec<u8>,
}

impl EncodedCurvePoint {
    /// Create from a ProjectivePoint.
    pub fn from_projective(point: &ProjectivePoint) -> Self {
        let affine = point.to_affine();
        let encoded = affine.to_encoded_point(true);
        Self {
            bytes: encoded.as_bytes().to_vec(),
        }
    }

    /// Convert to a ProjectivePoint.
    pub fn to_projective(&self) -> ProjectivePoint {
        let encoded = EncodedPoint::from_bytes(&self.bytes).expect("Invalid encoded point");
        let affine =
            AffinePoint::from_encoded_point(&encoded).expect("Invalid curve point");
        ProjectivePoint::from(affine)
    }
}

/// Convert a 32-byte array to a secp256k1 Scalar (mod n).
pub fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
    let uint = U256::from_be_slice(bytes);
    <Scalar as Reduce<U256>>::reduce(uint)
}

/// Convert a Scalar to a 32-byte big-endian array.
pub fn scalar_to_bytes(scalar: &Scalar) -> [u8; 32] {
    let bytes = scalar.to_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    result
}

/// Derive a pseudorandom scalar from a PRG seed and counter using HMAC-SHA256.
pub fn prg_scalar(seed: &[u8; 32], counter: u64) -> Scalar {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<k256::sha2::Sha256>;

    let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC key error");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result);
    bytes_to_scalar(&hash_bytes)
}

/// Compute a shared PRG seed from ECDH key exchange.
/// seed = SHA256(ECDH(my_secret, their_public))
pub fn derive_prg_seed(my_secret: &Scalar, their_public: &ProjectivePoint) -> [u8; 32] {
    let shared_point = their_public * my_secret;
    let affine = shared_point.to_affine();
    let encoded = affine.to_encoded_point(true);
    let hash = Hash::digest(encoded.as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(hash.as_ref());
    seed
}

/// Scalar multiplication on the generator point (G * scalar).
pub fn scalar_mul_generator(scalar: &Scalar) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * scalar
}

/// Encode a ProjectivePoint as a 33-byte compressed public key.
pub fn point_to_compressed(point: &ProjectivePoint) -> [u8; 33] {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut result = [0u8; 33];
    result.copy_from_slice(bytes);
    result
}

/// Decode a 33-byte compressed public key to a ProjectivePoint.
pub fn compressed_to_point(bytes: &[u8; 33]) -> ProjectivePoint {
    let encoded = EncodedPoint::from_bytes(bytes).expect("Invalid compressed point");
    let affine = AffinePoint::from_encoded_point(&encoded).expect("Invalid point");
    ProjectivePoint::from(affine)
}

/// Combine public key shares by summing ProjectivePoints.
pub fn combine_public_key_shares(shares: &[EncodedCurvePoint]) -> ProjectivePoint {
    let mut sum = ProjectivePoint::IDENTITY;
    for share in shares {
        sum += share.to_projective();
    }
    sum
}
