/**
 * Scalar utility functions for secp256k1 DKG + threshold ECDSA.
 *
 * Provides:
 * - randomScalar: generate a random scalar mod N
 * - bigintTo32Bytes / bytesToBigint: byte conversion
 * - scalarToHalves / halvesToScalar: 256→2×128 bit splitting for ZK input
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { mod } from "@noble/curves/abstract/modular";

/** The secp256k1 group order. */
const N = secp256k1.CURVE.n;

/**
 * Split a 256-bit scalar into two 128-bit halves (big-endian).
 * Returns [highBytes(16), lowBytes(16)].
 * Used for submitting secret shares as ZK inputs (Sbi128 × 2).
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

/**
 * Generate a deterministic scalar from raw bytes (e.g. biometric-derived seed).
 * Reduces bytes mod N to produce a valid secp256k1 scalar.
 */
export function deterministicScalarFromBytes(bytes: Uint8Array): bigint {
  return mod(bytesToBigint(bytes) + 1n, N);
}

/** Generate a random scalar in [1, N-1] using crypto.getRandomValues. */
export function randomScalar(): bigint {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return mod(bytesToBigint(bytes) + 1n, N);
}

/**
 * Generate a deterministic scalar from a seed string.
 * Uses SHA-256(seed) to produce a 32-byte value, then reduces mod N.
 * Same seed always produces the same scalar.
 */
export async function deterministicScalar(seed: string): Promise<bigint> {
  const encoder = new TextEncoder();
  const hashBuffer = await globalThis.crypto.subtle.digest("SHA-256", encoder.encode(seed));
  const bytes = new Uint8Array(hashBuffer);
  return mod(bytesToBigint(bytes) + 1n, N);
}
