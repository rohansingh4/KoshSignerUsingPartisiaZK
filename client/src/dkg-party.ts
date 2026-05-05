/**
 * DKG (Distributed Key Generation) party client for kosh-zk-signer.
 *
 * Supports TWO modes:
 *
 * MODE 1 — Additive DKG (3-of-3, original):
 *   Each party picks random s_i, combined key P = Σ(s_i·G).
 *   All parties required to sign.
 *
 * MODE 2 — Pedersen/Feldman DKG (2-of-3 threshold):
 *   Each party picks polynomial f_i(x) = s_i + a_i·x.
 *   Sub-shares f_i(j) distributed to each party j.
 *   Final Shamir shares X_j = Σ f_i(j) lie on combined line F(x) = s + b·x.
 *   Any 2-of-3 can reconstruct s via Lagrange interpolation.
 *   Feldman commitments C_i0 = s_i·G, C_i1 = a_i·G allow verification.
 *
 * The full private key s = s₁ + s₂ + ... + sₙ is NEVER computed anywhere.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { mod } from "@noble/curves/abstract/modular";
import { randomScalar, deterministicScalar, bigintTo32Bytes, bytesToBigint, scalarToHalves } from "./shamir-ts.js";

const N = secp256k1.CURVE.n;
const G = secp256k1.ProjectivePoint.BASE;

// --- Types ---

export interface DkgShare {
  /** The party's secret scalar s_i (NEVER shared or combined). */
  secretScalar: bigint;
  /** The compressed public key share P_i = s_i × G (33 bytes). */
  publicKeyShare: Uint8Array;
  /** SHA-256 commitment hash of the compressed public key share. */
  commitmentHash: Uint8Array;
}

/** Extended DKG share for Pedersen/Feldman threshold mode. */
export interface ThresholdDkgShare extends DkgShare {
  /** The party's random slope a_i for polynomial f_i(x) = s_i + a_i·x. */
  slope: bigint;
  /** Feldman commitment C_i0 = s_i·G (same as publicKeyShare). */
  C_i0: Uint8Array;
  /** Feldman commitment C_i1 = a_i·G. */
  C_i1: Uint8Array;
  /** Sub-shares f_i(j) for each party j (index 1-based). */
  subShares: bigint[];
  /** Party index (1-based). */
  partyIndex: number;
}

/** Final Shamir share after combining sub-shares from all parties. */
export interface ShamirShare {
  /** Party index (1-based). */
  partyIndex: number;
  /** Final Shamir share X_j = Σ f_i(j). */
  share: bigint;
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

// --- Threshold DKG (Pedersen/Feldman) ---

/**
 * Generate a threshold DKG share with polynomial f_i(x) = s_i + a_i·x.
 *
 * Each party generates:
 * - s_i: random secret (constant term)
 * - a_i: random slope
 * - C_i0 = s_i·G, C_i1 = a_i·G (Feldman commitments)
 * - Sub-shares f_i(j) for j = 1..numParties
 */
export async function generateThresholdDkgShare(
  partyIndex: number,
  numParties: number,
  seed?: string
): Promise<ThresholdDkgShare> {
  const secretScalar = seed
    ? await deterministicScalar(`${seed}-secret`)
    : randomScalar();
  const slope = seed
    ? await deterministicScalar(`${seed}-slope`)
    : randomScalar();

  // Feldman commitments
  const C_i0_point = G.multiply(secretScalar);
  const C_i0 = C_i0_point.toRawBytes(true);
  const C_i1 = G.multiply(slope).toRawBytes(true);
  const publicKeyShare = C_i0; // same as s_i·G

  // Sub-shares: f_i(j) = s_i + a_i·j mod N for j = 1..numParties
  const subShares: bigint[] = [];
  for (let j = 1; j <= numParties; j++) {
    const fij = mod(secretScalar + slope * BigInt(j), N);
    subShares.push(fij);
  }

  // Commitment hash (same as additive DKG — SHA-256 of compressed C_i0)
  const hashBuffer = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new Uint8Array(publicKeyShare) as any
  );
  const commitmentHash = new Uint8Array(hashBuffer);

  return {
    secretScalar,
    publicKeyShare,
    commitmentHash,
    slope,
    C_i0,
    C_i1,
    subShares,
    partyIndex,
  };
}

/**
 * Combine sub-shares from all parties to compute final Shamir share X_j.
 *
 * X_j = f_1(j) + f_2(j) + ... + f_n(j)
 *     = F(j) — a point on the combined polynomial F(x) = s + b·x
 */
export function combineShamirShares(
  partyIndex: number,
  allParties: ThresholdDkgShare[]
): ShamirShare {
  let share = 0n;
  for (const party of allParties) {
    // party.subShares[partyIndex - 1] = f_party(partyIndex)
    share = mod(share + party.subShares[partyIndex - 1], N);
  }
  return { partyIndex, share };
}

/**
 * Verify a sub-share using Feldman verification.
 *
 * Checks: f_i(j)·G == C_i0 + j·C_i1
 *
 * This proves that party i sent the correct sub-share to party j,
 * without revealing s_i or a_i.
 */
export function verifyFeldmanSubshare(
  subshare: bigint,
  C_i0: Uint8Array,
  C_i1: Uint8Array,
  j: number
): boolean {
  // Left side: f_i(j) · G
  const left = G.multiply(subshare);

  // Right side: C_i0 + j · C_i1
  const ci0Point = secp256k1.ProjectivePoint.fromHex(C_i0);
  const ci1Point = secp256k1.ProjectivePoint.fromHex(C_i1);
  const right = ci0Point.add(ci1Point.multiply(BigInt(j)));

  return left.equals(right);
}

/**
 * Compute Lagrange coefficient λ_i for party i in signing subset S,
 * evaluated at x = 0 (to reconstruct the secret).
 *
 * λ_i = ∏(j ∈ S, j≠i) (0 - j) / (i - j)  mod N
 *
 * The x-coordinates are the party indices (1, 2, 3).
 */
export function computeLagrangeCoefficient(
  partyIndex: number,
  signingSubset: number[]
): bigint {
  let num = 1n;
  let den = 1n;
  const i = BigInt(partyIndex);

  for (const jIdx of signingSubset) {
    if (jIdx === partyIndex) continue;
    const j = BigInt(jIdx);
    num = mod(num * (0n - j), N);
    den = mod(den * (i - j), N);
  }

  // λ_i = num / den = num · den⁻¹ mod N
  const denInv = modInverse(den, N);
  return mod(num * denInv, N);
}

/**
 * Compute the adjusted share x̃_i = λ_i · X_i for threshold signing.
 *
 * The adjusted shares have the property: Σ x̃_i = s (the secret).
 */
export function computeAdjustedShare(
  shamirShare: ShamirShare,
  signingSubset: number[]
): bigint {
  const lambda = computeLagrangeCoefficient(shamirShare.partyIndex, signingSubset);
  return mod(lambda * shamirShare.share, N);
}

/**
 * Generate a Schnorr proof of knowledge of the discrete log of a public key.
 *
 * Proves: "I know s_i such that C_i0 = s_i · G"
 *
 * Protocol (non-interactive, Fiat-Shamir):
 *   1. Pick random r, compute R = r·G
 *   2. e = SHA-256(G_compressed || C_i0 || R || party_index)
 *   3. z = r + e·s_i mod N
 */
export async function generateSchnorrProof(
  secretScalar: bigint,
  publicKeyShare: Uint8Array,
  partyIndex: number
): Promise<{ R: Uint8Array; z: Uint8Array }> {
  // Pick random nonce r
  const r = randomScalar();
  const R_point = G.multiply(r);
  const R = R_point.toRawBytes(true); // 33 bytes compressed

  // Compute challenge: e = SHA-256(G || C_i0 || R || party_index)
  const G_compressed = G.toRawBytes(true);
  const challengeInput = new Uint8Array([
    ...G_compressed,
    ...publicKeyShare,
    ...R,
    partyIndex,
  ]);
  const eHash = await globalThis.crypto.subtle.digest("SHA-256", challengeInput as any);
  const e = mod(bytesToBigint(new Uint8Array(eHash)), N);

  // z = r + e * s_i mod N
  const z = mod(r + e * secretScalar, N);

  return { R, z: bigintTo32Bytes(z) };
}

function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r_val] = [((a % m) + m) % m, m];
  let [old_s, s_val] = [1n, 0n];
  while (r_val !== 0n) {
    const q = old_r / r_val;
    [old_r, r_val] = [r_val, old_r - q * r_val];
    [old_s, s_val] = [s_val, old_s - q * s_val];
  }
  return ((old_s % m) + m) % m;
}

/**
 * Get the two 128-bit halves (high, low) of a DKG secret scalar.
 * Used for submitting the share as ZK secret input (Sbi128 × 2).
 */
export function getShareHalves(share: DkgShare): [Uint8Array, Uint8Array] {
  return scalarToHalves(share.secretScalar);
}

/**
 * Get the two 128-bit halves of a Shamir share (for ZK secret input).
 */
export function getShamirShareHalves(share: ShamirShare): [Uint8Array, Uint8Array] {
  return scalarToHalves(share.share);
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
 * Args: key_id(u32), party_index(u8), commitment_hash(Vec<u8>),
 *       slope_commitment(Vec<u8>), schnorr_r(Vec<u8>), schnorr_z(Vec<u8>)
 *
 * Protection 3: Schnorr proof + Feldman slope commitment included.
 */
export function buildDkgCommitArgs(
  keyId: number,
  partyIndex: number,
  commitmentHash: Uint8Array,
  slopeCommitment?: Uint8Array,
  schnorrR?: Uint8Array,
  schnorrZ?: Uint8Array
): Uint8Array {
  // Default to dummy values for backward compatibility with additive DKG
  const slope = slopeCommitment ?? new Uint8Array(33);
  const sR = schnorrR ?? new Uint8Array(33);
  const sZ = schnorrZ ?? new Uint8Array(32);
  return new Uint8Array([
    ...encodeU32(keyId),
    partyIndex,
    ...encodeVec(commitmentHash),
    ...encodeVec(slope),
    ...encodeVec(sR),
    ...encodeVec(sZ),
  ]);
}

/**
 * Build RPC args for dkg_reveal (shortname 0x22).
 * Args: key_id(u32), party_index(u8), public_key_share(Vec<u8>)
 */
export function buildDkgRevealArgs(
  keyId: number,
  partyIndex: number,
  publicKeyShare: Uint8Array
): Uint8Array {
  return new Uint8Array([...encodeU32(keyId), partyIndex, ...encodeVec(publicKeyShare)]);
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
