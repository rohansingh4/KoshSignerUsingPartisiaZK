/**
 * Key Refresh (Protection 7) and Key Recovery (Protection 8).
 *
 * KEY REFRESH — Proactive Secret Sharing:
 *   All parties run a "re-sharing" protocol periodically (e.g., every 30 days).
 *   New shares X_i' are generated for the SAME key (same public key P, same ETH address).
 *   Old shares become useless → breaks slow-compromise attack window.
 *
 *   How: Each party generates a zero-secret polynomial g_i(x) = 0 + b_i·x.
 *   Sub-shares g_i(j) are distributed. Each party adds: X_j' = X_j + Σ g_i(j).
 *   Since g_i(0) = 0 for all i, the combined secret s = F(0) doesn't change.
 *
 * KEY RECOVERY — Party Replacement:
 *   When a party permanently loses their share, the remaining t parties
 *   can re-share to create a new share for a replacement party.
 *   Same public key, same address, restored fault tolerance.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { mod } from "@noble/curves/abstract/modular";
import { randomScalar, bigintTo32Bytes, bytesToBigint } from "./shamir-ts.js";
import {
  verifyFeldmanSubshare,
  computeLagrangeCoefficient,
  type ShamirShare,
} from "./dkg-party.js";

const N = secp256k1.CURVE.n;
const G = secp256k1.ProjectivePoint.BASE;

// ==========================================================================
// KEY REFRESH (Protection 7)
// ==========================================================================

/** A refresh polynomial with zero constant term: g_i(x) = 0 + b_i·x */
export interface RefreshPolynomial {
  /** Party index (1-based) */
  partyIndex: number;
  /** Random slope b_i (the only coefficient — constant term is 0) */
  slope: bigint;
  /** Feldman commitment D_i1 = b_i·G (public, for verification) */
  slopeCommitment: Uint8Array;
  /** Sub-shares g_i(j) for j = 1..numParties */
  subShares: bigint[];
}

/**
 * Generate a refresh polynomial g_i(x) = 0 + b_i·x for party i.
 *
 * The constant term is ZERO — this is the key property.
 * When all parties add their refresh sub-shares, the combined secret
 * doesn't change: Σ g_i(0) = 0.
 */
export function generateRefreshPolynomial(
  partyIndex: number,
  numParties: number
): RefreshPolynomial {
  const slope = randomScalar();
  const slopeCommitment = G.multiply(slope).toRawBytes(true);

  // Sub-shares: g_i(j) = 0 + b_i·j = b_i·j mod N
  const subShares: bigint[] = [];
  for (let j = 1; j <= numParties; j++) {
    subShares.push(mod(slope * BigInt(j), N));
  }

  return { partyIndex, slope, slopeCommitment, subShares };
}

/**
 * Verify a refresh sub-share using Feldman verification.
 *
 * For a zero-secret polynomial g_i(x) = 0 + b_i·x:
 *   g_i(j)·G should equal 0·G + j·D_i1 = j·D_i1
 *   (since the constant commitment is the identity point)
 *
 * Simplified: g_i(j)·G == j · D_i1
 */
export function verifyRefreshSubshare(
  subshare: bigint,
  slopeCommitment: Uint8Array,
  j: number
): boolean {
  // Left side: g_i(j) · G
  const left = G.multiply(subshare);

  // Right side: j · D_i1 (since constant commitment is identity/zero)
  const di1Point = secp256k1.ProjectivePoint.fromHex(slopeCommitment);
  const right = di1Point.multiply(BigInt(j));

  return left.equals(right);
}

/**
 * Apply refresh to a Shamir share.
 *
 * X_j' = X_j + Σ g_i(j) for all parties i
 *
 * The new share X_j' lies on a new polynomial F'(x) = s + (b + Σb_i)·x
 * where s = F(0) is UNCHANGED (same secret, same public key).
 */
export function applyRefresh(
  currentShare: ShamirShare,
  refreshPolynomials: RefreshPolynomial[]
): ShamirShare {
  let refreshDelta = 0n;
  for (const poly of refreshPolynomials) {
    // g_i(partyIndex) = b_i · partyIndex
    refreshDelta = mod(refreshDelta + poly.subShares[currentShare.partyIndex - 1], N);
  }

  return {
    partyIndex: currentShare.partyIndex,
    share: mod(currentShare.share + refreshDelta, N),
  };
}

/**
 * Run complete key refresh for all parties.
 *
 * Each party generates a zero-secret refresh polynomial, distributes
 * sub-shares, verifies them, and updates their share.
 *
 * @returns New shares that sum to the same secret, with different values.
 */
export function runKeyRefresh(
  currentShares: ShamirShare[],
  numParties: number
): { newShares: ShamirShare[]; refreshPolynomials: RefreshPolynomial[] } {
  // Step 1: Each party generates refresh polynomial
  const refreshPolynomials: RefreshPolynomial[] = [];
  for (let i = 1; i <= numParties; i++) {
    refreshPolynomials.push(generateRefreshPolynomial(i, numParties));
  }

  // Step 2: Verify all refresh sub-shares (Feldman verification)
  for (const poly of refreshPolynomials) {
    for (let j = 1; j <= numParties; j++) {
      const valid = verifyRefreshSubshare(
        poly.subShares[j - 1],
        poly.slopeCommitment,
        j
      );
      if (!valid) {
        throw new Error(
          `Refresh verification FAILED: Party ${poly.partyIndex}'s sub-share for Party ${j}`
        );
      }
    }
  }

  // Step 3: Each party updates their share
  const newShares: ShamirShare[] = [];
  for (const share of currentShares) {
    newShares.push(applyRefresh(share, refreshPolynomials));
  }

  return { newShares, refreshPolynomials };
}

// ==========================================================================
// KEY RECOVERY (Protection 8)
// ==========================================================================

/**
 * Re-sharing polynomial for key recovery.
 * Each surviving party generates h_i(x) = x̃_i + c_i·x
 * where x̃_i = λ_i · X_i (their Lagrange-adjusted share).
 */
export interface RecoveryPolynomial {
  partyIndex: number;
  /** Lagrange-adjusted share x̃_i (constant term) */
  adjustedShare: bigint;
  /** Random slope c_i */
  slope: bigint;
  /** Feldman commitments: [x̃_i·G, c_i·G] */
  commitments: [Uint8Array, Uint8Array];
  /** Sub-shares h_i(j) for j = 1..newNumParties */
  subShares: bigint[];
}

/**
 * Generate a recovery polynomial for party i.
 *
 * The surviving parties each generate a new polynomial through their
 * Lagrange-adjusted share:
 *   h_i(x) = x̃_i + c_i·x
 *
 * When combined: H(x) = Σ h_i(x) = (Σ x̃_i) + (Σ c_i)·x = s + c·x
 * This is a NEW degree-1 polynomial with the SAME secret s.
 */
export function generateRecoveryPolynomial(
  partyIndex: number,
  shamirShare: ShamirShare,
  survivingSubset: number[],
  newNumParties: number
): RecoveryPolynomial {
  // Compute Lagrange-adjusted share
  const lambda = computeLagrangeCoefficient(partyIndex, survivingSubset);
  const adjustedShare = mod(lambda * shamirShare.share, N);

  // Pick random slope
  const slope = randomScalar();

  // Feldman commitments
  const c0 = G.multiply(adjustedShare).toRawBytes(true);
  const c1 = G.multiply(slope).toRawBytes(true);

  // Sub-shares: h_i(j) = x̃_i + c_i·j for j = 1..newNumParties
  const subShares: bigint[] = [];
  for (let j = 1; j <= newNumParties; j++) {
    subShares.push(mod(adjustedShare + slope * BigInt(j), N));
  }

  return {
    partyIndex,
    adjustedShare,
    slope,
    commitments: [c0, c1],
    subShares,
  };
}

/**
 * Combine recovery sub-shares to produce new Shamir shares.
 *
 * New party j computes: X_j_new = Σ h_i(j) = H(j)
 * H(0) = s (the original secret) — same public key, same address.
 */
export function combineRecoveryShares(
  newPartyIndex: number,
  recoveryPolynomials: RecoveryPolynomial[]
): ShamirShare {
  let share = 0n;
  for (const poly of recoveryPolynomials) {
    share = mod(share + poly.subShares[newPartyIndex - 1], N);
  }
  return { partyIndex: newPartyIndex, share };
}

/**
 * Run complete key recovery: replace a lost party with a new one.
 *
 * Scenario: Party `lostPartyIndex` is permanently lost.
 * The remaining parties (which must be >= threshold) re-share to create
 * new shares for ALL parties including the replacement.
 *
 * @param currentShares - Shares of the SURVIVING parties only
 * @param survivingIndices - Indices of parties that still have shares
 * @param newNumParties - Total parties after recovery (usually same as before)
 * @returns New shares for ALL parties (on the new polynomial, same secret)
 */
export function runKeyRecovery(
  currentShares: ShamirShare[],
  survivingIndices: number[],
  newNumParties: number
): { newShares: ShamirShare[]; recoveryPolynomials: RecoveryPolynomial[] } {
  if (currentShares.length < 2) {
    throw new Error("Need at least 2 surviving parties for recovery (threshold = 2)");
  }

  // Each surviving party generates a recovery polynomial
  const recoveryPolynomials: RecoveryPolynomial[] = [];
  for (const share of currentShares) {
    recoveryPolynomials.push(
      generateRecoveryPolynomial(
        share.partyIndex,
        share,
        survivingIndices,
        newNumParties
      )
    );
  }

  // Verify recovery sub-shares (Feldman verification)
  for (const poly of recoveryPolynomials) {
    for (let j = 1; j <= newNumParties; j++) {
      const valid = verifyFeldmanSubshare(
        poly.subShares[j - 1],
        poly.commitments[0],
        poly.commitments[1],
        j
      );
      if (!valid) {
        throw new Error(
          `Recovery verification FAILED: Party ${poly.partyIndex}'s sub-share for new Party ${j}`
        );
      }
    }
  }

  // Generate new shares for all parties
  const newShares: ShamirShare[] = [];
  for (let j = 1; j <= newNumParties; j++) {
    newShares.push(combineRecoveryShares(j, recoveryPolynomials));
  }

  return { newShares, recoveryPolynomials };
}

// ==========================================================================
// RPC Encoding for Contract Actions
// ==========================================================================

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
 * Build RPC args for start_key_refresh (shortname 0x60).
 * Args: key_id(u32)
 */
export function buildStartKeyRefreshArgs(keyId: number): Uint8Array {
  return encodeU32(keyId);
}

/**
 * Build RPC args for submit_refresh_share (shortname 0x61).
 * Args: key_id(u32), party_index(u8), slope_commitment(Vec<u8>)
 */
export function buildSubmitRefreshShareArgs(
  keyId: number,
  partyIndex: number,
  slopeCommitment: Uint8Array
): Uint8Array {
  return new Uint8Array([...encodeU32(keyId), partyIndex, ...encodeVec(slopeCommitment)]);
}

/**
 * Build RPC args for apply_refresh (shortname 0x62).
 * Args: key_id(u32)
 */
export function buildApplyRefreshArgs(keyId: number): Uint8Array {
  return encodeU32(keyId);
}

/**
 * Build RPC args for start_key_recovery (shortname 0x64).
 * Args: key_id(u32), lost_party_index(u8)
 */
export function buildStartKeyRecoveryArgs(keyId: number, lostPartyIndex: number): Uint8Array {
  return new Uint8Array([...encodeU32(keyId), lostPartyIndex]);
}

/**
 * Build RPC args for submit_recovery_subshare (shortname 0x65).
 * Args: key_id(u32), party_index(u8), commitment_c0(Vec<u8>), commitment_c1(Vec<u8>)
 */
export function buildSubmitRecoverySubshareArgs(
  keyId: number,
  partyIndex: number,
  commitmentC0: Uint8Array,
  commitmentC1: Uint8Array
): Uint8Array {
  return new Uint8Array([
    ...encodeU32(keyId),
    partyIndex,
    ...encodeVec(commitmentC0),
    ...encodeVec(commitmentC1),
  ]);
}
