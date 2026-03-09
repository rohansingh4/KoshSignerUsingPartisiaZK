/**
 * Shamir's Secret Sharing over the secp256k1 scalar field (TypeScript port).
 *
 * Mirrors contracts/kosh-zk-signer/src/shamir.rs exactly:
 * - split() via Horner's method
 * - reconstruct() via Lagrange interpolation at x=0
 * - scalarToHalves / halvesToScalar for 256→2×128 bit splitting
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { mod, invert } from "@noble/curves/abstract/modular";

/** The secp256k1 group order. */
const N = secp256k1.CURVE.n;

/** A single Shamir share: y = f(index) evaluated at x = index. */
export interface ShamirShare {
  /** 1-based x-coordinate. */
  index: number;
  /** Share value (scalar mod N). */
  value: bigint;
}

/** Modular arithmetic helpers. */
function modN(a: bigint): bigint {
  return mod(a, N);
}

function invertN(a: bigint): bigint {
  return invert(a, N);
}

/**
 * Split a secret into `numShares` Shamir shares with the given threshold.
 *
 * Polynomial: f(x) = secret + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
 * Evaluated at x = 1, 2, ..., numShares using Horner's method.
 */
export function split(
  secret: bigint,
  threshold: number,
  numShares: number,
  randomCoeffs: bigint[]
): ShamirShare[] {
  if (threshold < 2) throw new Error("Threshold must be at least 2");
  if (numShares < threshold) throw new Error("numShares must be >= threshold");
  if (randomCoeffs.length !== threshold - 1)
    throw new Error("Need exactly t-1 random coefficients");

  // coeffs = [secret, a_1, ..., a_{t-1}]
  const coeffs = [modN(secret), ...randomCoeffs.map(modN)];

  const shares: ShamirShare[] = [];
  for (let i = 1; i <= numShares; i++) {
    const x = BigInt(i);
    // Horner's method: start from highest degree
    let y = coeffs[coeffs.length - 1];
    for (let j = coeffs.length - 2; j >= 0; j--) {
      y = modN(y * x + coeffs[j]);
    }
    shares.push({ index: i, value: y });
  }
  return shares;
}

/**
 * Reconstruct the secret from threshold shares via Lagrange interpolation at x=0.
 *
 * secret = f(0) = sum_i ( y_i * L_i(0) )
 * where L_i(0) = product_{j!=i} ( -x_j / (x_i - x_j) )
 */
export function reconstruct(shares: ShamirShare[]): bigint {
  if (shares.length < 2) throw new Error("Need at least 2 shares");

  let secret = 0n;
  for (let i = 0; i < shares.length; i++) {
    const xi = BigInt(shares[i].index);
    let li = 1n;
    for (let j = 0; j < shares.length; j++) {
      if (i === j) continue;
      const xj = BigInt(shares[j].index);
      // L_i(0) *= (0 - x_j) / (x_i - x_j) = -x_j / (x_i - x_j)
      const numerator = modN(-xj);
      const denominator = modN(xi - xj);
      li = modN(li * numerator * invertN(denominator));
    }
    secret = modN(secret + shares[i].value * li);
  }
  return secret;
}

/**
 * Split a 256-bit scalar into two 128-bit halves (big-endian).
 * Returns [highBytes(16), lowBytes(16)].
 */
export function scalarToHalves(scalar: bigint): [Uint8Array, Uint8Array] {
  const bytes = bigintTo32Bytes(scalar);
  const high = bytes.slice(0, 16);
  const low = bytes.slice(16, 32);
  return [high, low];
}

/**
 * Reassemble a 256-bit scalar from two 128-bit halves (big-endian).
 */
export function halvesToScalar(high: Uint8Array, low: Uint8Array): bigint {
  if (high.length !== 16 || low.length !== 16)
    throw new Error("Each half must be 16 bytes");
  const bytes = new Uint8Array(32);
  bytes.set(high, 0);
  bytes.set(low, 16);
  return bytesToBigint(bytes);
}

/** Convert a bigint to 32 big-endian bytes. */
export function bigintTo32Bytes(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Convert big-endian bytes to bigint. */
export function bytesToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

/** Generate a random scalar in [1, N-1] using crypto.getRandomValues. */
export function randomScalar(): bigint {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return modN(bytesToBigint(bytes) + 1n);
}
