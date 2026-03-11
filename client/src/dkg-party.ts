/**
 * DKG (Distributed Key Generation) party client for kosh-zk-signer.
 *
 * Each party:
 * 1. Generates a random secret scalar s_i
 * 2. Computes public key share P_i = s_i × G
 * 3. Commits SHA-256(compressed P_i) on-chain
 * 4. Reveals compressed P_i on-chain
 * 5. After finalization, submits s_i as ZK secret input
 *
 * The full private key s = s₁ + s₂ + ... + sₙ is NEVER computed anywhere.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { randomScalar, deterministicScalar, bigintTo32Bytes, scalarToHalves } from "./shamir-ts.js";

// --- Types ---

export interface DkgShare {
  /** The party's secret scalar s_i (NEVER shared or combined). */
  secretScalar: bigint;
  /** The compressed public key share P_i = s_i × G (33 bytes). */
  publicKeyShare: Uint8Array;
  /** SHA-256 commitment hash of the compressed public key share. */
  commitmentHash: Uint8Array;
}

// --- Core DKG Party Functions ---

/**
 * Generate a DKG share: secret scalar and corresponding public key share.
 *
 * If a seed is provided, the scalar is deterministic (same seed = same share).
 * If no seed, a random scalar is generated.
 *
 * The public key share is P_i = s_i × G (compressed, 33 bytes).
 * The commitment hash is SHA-256(P_i).
 */
export async function generateDkgShare(seed?: string): Promise<DkgShare> {
  const secretScalar = seed ? await deterministicScalar(seed) : randomScalar();
  const publicPoint = secp256k1.ProjectivePoint.BASE.multiply(secretScalar);
  const publicKeyShare = publicPoint.toRawBytes(true); // 33 bytes compressed

  // SHA-256 of the compressed public key share
  const hashBuffer = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new Uint8Array(publicKeyShare) as any
  );
  const commitmentHash = new Uint8Array(hashBuffer);

  return { secretScalar, publicKeyShare, commitmentHash };
}

/**
 * Get the two 128-bit halves (high, low) of a DKG secret scalar.
 * Used for submitting the share as ZK secret input (Sbi128 × 2).
 */
export function getShareHalves(share: DkgShare): [Uint8Array, Uint8Array] {
  return scalarToHalves(share.secretScalar);
}

/**
 * Compute the expected combined public key from all party reveals.
 * P = P₁ + P₂ + ... + Pₙ (EC point addition).
 *
 * This is used for client-side verification that the contract computed
 * the combined key correctly.
 */
export function computeCombinedPublicKey(
  publicKeyShares: Uint8Array[]
): Uint8Array {
  if (publicKeyShares.length < 2) {
    throw new Error("Need at least 2 public key shares");
  }

  let combined = secp256k1.ProjectivePoint.fromHex(publicKeyShares[0]);
  for (let i = 1; i < publicKeyShares.length; i++) {
    const point = secp256k1.ProjectivePoint.fromHex(publicKeyShares[i]);
    combined = combined.add(point);
  }

  return combined.toRawBytes(true); // 33 bytes compressed
}

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
 * Build RPC args for dkg_create_key (shortname 0x20).
 * Args: key_id(u32), num_parties(u8)
 */
export function buildDkgCreateKeyArgs(
  keyId: number,
  numParties: number
): Uint8Array {
  return new Uint8Array([...encodeU32(keyId), numParties]);
}

/**
 * Build RPC args for dkg_commit (shortname 0x21).
 * Args: key_id(u32), commitment_hash(Vec<u8>)
 */
export function buildDkgCommitArgs(
  keyId: number,
  commitmentHash: Uint8Array
): Uint8Array {
  return new Uint8Array([...encodeU32(keyId), ...encodeVec(commitmentHash)]);
}

/**
 * Build RPC args for dkg_reveal (shortname 0x22).
 * Args: key_id(u32), public_key_share(Vec<u8>)
 */
export function buildDkgRevealArgs(
  keyId: number,
  publicKeyShare: Uint8Array
): Uint8Array {
  return new Uint8Array([...encodeU32(keyId), ...encodeVec(publicKeyShare)]);
}

/**
 * Build RPC args for dkg_finalize (shortname 0x23).
 * Args: key_id(u32)
 */
export function buildDkgFinalizeArgs(keyId: number): Uint8Array {
  return encodeU32(keyId);
}

/**
 * Build RPC args for dkg_complete_keygen (shortname 0x24).
 * Args: key_id(u32)
 */
export function buildDkgCompleteKeygenArgs(keyId: number): Uint8Array {
  return encodeU32(keyId);
}

// --- Utility ---

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
