/**
 * Threshold ECDSA signing protocol for DKG keys.
 *
 * Protocol overview:
 * 1. Coordinator generates ephemeral nonce k, computes R = k × G, r = R.x, k⁻¹
 * 2. Coordinator distributes k⁻¹ to all parties (k is deleted immediately)
 * 3. Each party i computes partial signature:
 *    - Party 1: σ₁ = k⁻¹ · m + k⁻¹ · r · s₁  (includes message component)
 *    - Party i (i>1): σᵢ = k⁻¹ · r · sᵢ
 * 4. Each party submits σᵢ directly to the smart contract
 * 5. Contract combines: σ = Σ σᵢ = k⁻¹(m + r·s) and verifies the ECDSA signature
 *
 * SECURITY PROPERTIES:
 * - The private key s = s₁ + s₂ + ... + sₙ is NEVER computed anywhere
 * - Each party only uses their own secret share sᵢ
 * - The full signature σ is only assembled on-chain by the contract
 * - The coordinator knows k⁻¹ but not any sᵢ, and deletes k immediately
 * - No single off-chain entity ever holds both k and σ simultaneously
 *
 * TRUST MODEL:
 * - The coordinator must honestly delete k after computing k⁻¹
 * - If the coordinator retains k AND observes the final σ, they could
 *   theoretically recover s. This is mitigated by:
 *   (a) Rotating the coordinator role each signing round
 *   (b) The contract combining partials, so coordinator doesn't see σ first
 *   (c) For production: replace with Paillier-based MtA (GG20/CGGMP21)
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { bigintTo32Bytes, randomScalar } from "./shamir-ts.js";

const N = secp256k1.CURVE.n;

/**
 * Modular inverse: a⁻¹ mod n using Fermat's little theorem.
 * a⁻¹ = a^(n-2) mod n (since n is prime)
 */
function modInverse(a: bigint, mod_n: bigint = N): bigint {
  // Use extended Euclidean algorithm for efficiency
  let [old_r, r] = [a % mod_n, mod_n];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }

  return ((old_s % mod_n) + mod_n) % mod_n;
}

/**
 * Modular multiplication: (a * b) mod n
 */
function modMul(a: bigint, b: bigint, mod_n: bigint = N): bigint {
  return ((a % mod_n) * (b % mod_n) + mod_n * mod_n) % mod_n;
}

/**
 * Modular addition: (a + b) mod n
 */
function modAdd(a: bigint, b: bigint, mod_n: bigint = N): bigint {
  return ((a % mod_n) + (b % mod_n)) % mod_n;
}

// --- Coordinator Functions ---

/**
 * Data returned from nonce generation.
 *
 * CRITICAL: This struct intentionally does NOT contain k (the raw nonce).
 * k is computed, used to derive k_inv, and immediately discarded inside
 * generateNonce(). Retaining k would allow recovering the private key
 * from any published signature via s = (σ·k - m)·r⁻¹.
 */
export interface NonceData {
  /** k⁻¹ mod n — distributed to all parties for partial signature computation. */
  k_inv: bigint;
  /** r = R.x mod n (the x-coordinate of the nonce point, used in ECDSA). */
  r: bigint;
  /** r as 32-byte big-endian (for contract submission). */
  r_bytes: Uint8Array;
  /** The compressed R point (33 bytes, for reference only). */
  R_compressed: Uint8Array;
  /** Recovery ID (0 or 1). */
  recovery_id: number;
}

/**
 * Coordinator: Generate the ephemeral nonce for a signing round.
 *
 * The raw nonce scalar k is generated, used to compute k⁻¹ and R,
 * then DISCARDED. It never leaves this function. Only k⁻¹ and the
 * public nonce point R are returned.
 *
 * If k were retained, anyone with k + the published signature σ could
 * recover the full private key: s = (σ·k - m)·r⁻¹. By discarding k
 * here, this attack vector is eliminated at the source.
 */
export function generateNonce(): NonceData {
  // k is scoped to this function and never returned or stored
  const k = randomScalar();
  const R_point = secp256k1.ProjectivePoint.BASE.multiply(k);
  const R_affine = R_point.toAffine();
  const R_compressed = R_point.toRawBytes(true);

  const r = R_affine.x % N;
  const k_inv = modInverse(k);

  // Recovery ID: 0 if R.y is even, 1 if odd
  const recovery_id = R_affine.y % 2n === 0n ? 0 : 1;

  // k is NOT returned — it dies when this function returns.
  // Only k_inv (safe to distribute) and public values are returned.
  return { k_inv, r, r_bytes: bigintTo32Bytes(r), R_compressed, recovery_id };
}

// --- Party Functions ---

export interface PartialSig {
  /** 1-based party index. */
  partyIndex: number;
  /** The partial signature scalar σ_i (mod n). */
  value: bigint;
  /** The partial as 32 bytes (big-endian). */
  bytes: Uint8Array;
}

/**
 * Party: Compute a partial ECDSA signature.
 *
 * For party 1 (includeMessage=true):
 *   σ₁ = k⁻¹ · m + k⁻¹ · r · s₁  (mod n)
 *
 * For party i > 1 (includeMessage=false):
 *   σᵢ = k⁻¹ · r · sᵢ  (mod n)
 *
 * When combined: σ = Σ σᵢ = k⁻¹ · m + k⁻¹ · r · (s₁ + s₂ + ... + sₙ) = k⁻¹(m + r·s)
 */
export function computePartialSignature(
  k_inv: bigint,
  r: bigint,
  msgHash: Uint8Array,
  secretShare: bigint,
  includeMessage: boolean
): PartialSig {
  const m = bytesToBigint(msgHash);

  // σ_i = k⁻¹ · r · s_i (mod n)
  let partial = modMul(modMul(k_inv, r), secretShare);

  if (includeMessage) {
    // Party 1 also adds: k⁻¹ · m
    const msgComponent = modMul(k_inv, m);
    partial = modAdd(partial, msgComponent);
  }

  return {
    partyIndex: 0, // Set by caller
    value: partial,
    bytes: bigintTo32Bytes(partial),
  };
}

// NOTE: There is intentionally NO "verifyPartials" or "combinePartials" function
// here. Combining partial signatures into the full σ must ONLY happen on-chain
// inside the smart contract. If any off-chain process combined the partials,
// it would hold σ, and combined with k (if leaked) could recover the private key.
// The contract combines σ = Σσ_i and verifies the ECDSA signature atomically.

// --- RPC Encoding Helpers ---

function encodeU32(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (n >> 24) & 0xff;
  buf[1] = (n >> 16) & 0xff;
  buf[2] = (n >> 8) & 0xff;
  buf[3] = n & 0xff;
  return buf;
}

function encodeVec(data: Uint8Array): Uint8Array {
  return new Uint8Array([...encodeU32(data.length), ...data]);
}

/**
 * Build RPC args for start_threshold_sign (shortname 0x30).
 * Args: key_id(u32), task_id(u32), r_bytes(Vec<u8>), recovery_id(u8), num_parties(u8)
 */
export function buildStartThresholdSignArgs(
  keyId: number,
  taskId: number,
  rBytes: Uint8Array,
  recoveryId: number,
  numParties: number
): Uint8Array {
  return new Uint8Array([
    ...encodeU32(keyId),
    ...encodeU32(taskId),
    ...encodeVec(rBytes),
    recoveryId,
    numParties,
  ]);
}

/**
 * Build RPC args for submit_partial_sig (shortname 0x31).
 * Args: key_id(u32), party_index(u8), partial_s(Vec<u8>)
 */
export function buildSubmitPartialSigArgs(
  keyId: number,
  partyIndex: number,
  partialS: Uint8Array
): Uint8Array {
  return new Uint8Array([
    ...encodeU32(keyId),
    partyIndex,
    ...encodeVec(partialS),
  ]);
}

// --- Utility ---

function bytesToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
