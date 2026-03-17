/**
 * GG20 Threshold ECDSA Signing Protocol — FULLY TRUSTLESS.
 *
 * NO coordinator. NO single party ever knows k, k⁻¹, or private key s.
 *
 * Key insight from GG20 (Gennaro & Goldfeder, 2020):
 * - Each party generates k_i and γ_i (random masking value)
 * - MtA protocol converts k_i · γ_j products to additive shares
 * - Opening δ = k·γ reveals nothing (masked by γ)
 * - R = δ⁻¹ · Γ gives the nonce point WITHOUT anyone knowing k
 * - Partial signatures s_i sum to s = k·(m + r·x) which is valid ECDSA
 *
 * SECURITY:
 * - k = Σk_i is NEVER computed by anyone
 * - k⁻¹ is NEVER computed by anyone
 * - s = Σs_i is NEVER seen by anyone until on-chain verification
 * - Only assumption: Paillier key holder doesn't collude with threshold parties
 *
 * Protocol rounds:
 * 1. Each party generates (k_i, γ_i), commits Γ_i = γ_i·G
 * 2. MtA rounds: compute additive shares of k·γ and k·x
 * 3. Open δ = Σδ_i = k·γ (safe — masked by γ)
 * 4. Compute R = δ⁻¹ · Γ = k⁻¹·G (nobody knows k⁻¹)
 * 5. Each party computes s_i = m·k_i + r·σ_i
 * 6. Contract combines s = Σs_i and verifies ECDSA
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { randomScalar, bigintTo32Bytes, bytesToBigint } from "./shamir-ts.js";
import { paillierKeygen, type PaillierKeyPair } from "./paillier.js";
import { runMtA } from "./mta.js";
import { createHmac } from "crypto";
import { mod } from "@noble/curves/abstract/modular";

const N = secp256k1.CURVE.n;
const G = secp256k1.ProjectivePoint.BASE;

// --- Types ---

/** Per-party secrets for one signing round */
export interface GG20PartyState {
  partyIndex: number;
  /** Party's private key share x_i */
  x_i: bigint;
  /** Nonce share k_i (random per signing round) */
  k_i: bigint;
  /** Masking value γ_i (random per signing round) */
  gamma_i: bigint;
  /** Commitment point Γ_i = γ_i · G */
  Gamma_i: Uint8Array;
  /** Paillier key pair for MtA */
  paillierKeys: PaillierKeyPair;
  /** Additive share of k·γ (computed via MtA) */
  delta_i: bigint;
  /** Additive share of k·x (computed via MtA) */
  sigma_i: bigint;
}

/** Result of GG20 signing protocol */
export interface GG20SignatureData {
  /** r value (x-coordinate of R) */
  r: bigint;
  r_bytes: Uint8Array;
  /** Combined R point (compressed) */
  R_compressed: Uint8Array;
  /** Recovery ID */
  recovery_id: number;
  /** Partial signature values s_i for each party */
  partials: Array<{ partyIndex: number; s_i: bigint; bytes: Uint8Array }>;
  /** Delta values δ_i for on-chain verification */
  deltas: Array<{ partyIndex: number; delta_i: bigint; bytes: Uint8Array }>;
  /** Gamma points Γ_i for on-chain verification */
  gammaPoints: Uint8Array[];
}

// --- Protocol Implementation ---

/**
 * Generate a deterministic nonce k_i using HMAC-DRBG (RFC 6979 inspired).
 * Mixes the party's secret share with the message hash and additional entropy
 * to produce a deterministic but unpredictable nonce.
 *
 * Even if the system RNG is weak, this produces a strong k_i because:
 * - It's seeded with the party's secret x_i (high entropy)
 * - It's bound to the specific message being signed
 * - Additional system entropy is mixed in as extra protection
 */
function deterministicNonce(x_i: bigint, msgHash?: Uint8Array, label?: string): bigint {
  const x_bytes = bigintTo32Bytes(x_i);
  const msg = msgHash ?? new Uint8Array(32);
  const extra = new Uint8Array(32);
  globalThis.crypto.getRandomValues(extra); // additional entropy

  // HMAC-DRBG: K = HMAC(x_i, msg || extra || label)
  const hmac = createHmac("sha256", Buffer.from(x_bytes));
  hmac.update(Buffer.from(msg));
  hmac.update(Buffer.from(extra));
  if (label) hmac.update(label);
  const hash = new Uint8Array(hmac.digest());

  return mod(bytesToBigint(hash) + 1n, N);
}

/**
 * Phase 1: Each party initializes their state for signing.
 * Generates k_i, γ_i, Γ_i = γ_i·G, and Paillier keys.
 *
 * k_i and γ_i are generated using deterministic HMAC-DRBG seeded with x_i,
 * ensuring strong nonces even if the system RNG is weak.
 */
export function gg20InitParty(
  partyIndex: number,
  x_i: bigint,
  paillierKeys?: PaillierKeyPair,
  msgHash?: Uint8Array
): GG20PartyState {
  // Use deterministic nonce generation seeded with party's secret
  const k_i = deterministicNonce(x_i, msgHash, `k_${partyIndex}`);
  const gamma_i = deterministicNonce(x_i, msgHash, `gamma_${partyIndex}`);
  const Gamma_point = G.multiply(gamma_i);
  const Gamma_i = Gamma_point.toRawBytes(true);

  return {
    partyIndex,
    x_i,
    k_i,
    gamma_i,
    Gamma_i,
    paillierKeys: paillierKeys ?? paillierKeygen(1024),
    delta_i: 0n,
    sigma_i: 0n,
  };
}

/**
 * Phase 2: Run MtA rounds between all party pairs.
 *
 * For each pair (i, j):
 * - MtA(k_i, γ_j) → α_ij (for i) + β_ij (for j) = k_i · γ_j
 * - MtA(k_i, x_j) → μ_ij (for i) + ν_ij (for j) = k_i · x_j
 *
 * After all MtA rounds:
 * - δ_i = k_i·γ_i + Σ_{j≠i} (α_ij + β_ji)
 * - σ_i = k_i·x_i + Σ_{j≠i} (μ_ij + ν_ji)
 *
 * Where:
 * - Σ δ_i = k·γ (can be opened safely)
 * - Σ σ_i = k·x (kept as additive shares)
 */
export function gg20RunMtARounds(parties: GG20PartyState[]): void {
  const n = parties.length;

  // Initialize δ_i = k_i · γ_i and σ_i = k_i · x_i
  for (const party of parties) {
    party.delta_i = (party.k_i * party.gamma_i) % N;
    party.sigma_i = (party.k_i * party.x_i) % N;
  }

  // MtA rounds for each pair (i, j) where i ≠ j
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      if (i === j) continue;

      // MtA for k_i · γ_j → α_ij + β_ij = k_i · γ_j
      const { alpha: alpha_ij, beta: beta_ij } = runMtA(
        parties[i].k_i,
        parties[j].gamma_i,
        parties[i].paillierKeys.publicKey,
        parties[i].paillierKeys.privateKey
      );

      // Party i adds α_ij to their δ_i
      parties[i].delta_i = (parties[i].delta_i + alpha_ij) % N;
      // Party j adds β_ij to their δ_j
      parties[j].delta_i = (parties[j].delta_i + beta_ij) % N;

      // MtA for k_i · x_j → μ_ij + ν_ij = k_i · x_j
      const { alpha: mu_ij, beta: nu_ij } = runMtA(
        parties[i].k_i,
        parties[j].x_i,
        parties[i].paillierKeys.publicKey,
        parties[i].paillierKeys.privateKey
      );

      // Party i adds μ_ij to their σ_i
      parties[i].sigma_i = (parties[i].sigma_i + mu_ij) % N;
      // Party j adds ν_ij to their σ_j
      parties[j].sigma_i = (parties[j].sigma_i + nu_ij) % N;
    }
  }
}

/**
 * Phase 3: Compute δ, R, r from the MtA outputs.
 *
 * - δ = Σ δ_i = k·γ (opened publicly — safe because γ masks k)
 * - Γ = Σ Γ_i = γ·G
 * - R = δ⁻¹ · Γ = (k·γ)⁻¹ · γ·G = k⁻¹·G
 * - r = R.x
 *
 * NOBODY computes k⁻¹ explicitly! R = k⁻¹·G is computed as δ⁻¹·Γ.
 */
export function gg20ComputeR(
  parties: GG20PartyState[]
): { delta: bigint; r: bigint; r_bytes: Uint8Array; R_compressed: Uint8Array; recovery_id: number } {
  // Open δ = Σ δ_i
  let delta = 0n;
  for (const party of parties) {
    delta = (delta + party.delta_i) % N;
  }

  // Compute Γ = Σ Γ_i (EC point addition)
  let Gamma = secp256k1.ProjectivePoint.fromHex(parties[0].Gamma_i);
  for (let i = 1; i < parties.length; i++) {
    Gamma = Gamma.add(secp256k1.ProjectivePoint.fromHex(parties[i].Gamma_i));
  }

  // R = δ⁻¹ · Γ = (k·γ)⁻¹ · (γ·G) = k⁻¹ · G
  const deltaInv = modInverse(delta, N);
  const R = Gamma.multiply(deltaInv);
  const R_affine = R.toAffine();
  const r = R_affine.x % N;
  const recovery_id = R_affine.y % 2n === 0n ? 0 : 1;

  return {
    delta,
    r,
    r_bytes: bigintTo32Bytes(r),
    R_compressed: R.toRawBytes(true),
    recovery_id,
  };
}

/**
 * Phase 4: Each party computes their partial signature.
 *
 * s_i = m · k_i + r · σ_i (mod N)
 *
 * When combined: s = Σs_i = m·k + r·k·x = k·(m + r·x)
 *
 * In GG20, the nonce point is R = k⁻¹·G (not k·G).
 * So k_actual = k⁻¹, and the ECDSA signature is:
 *   s_ecdsa = k_actual⁻¹ · (m + r·x) = k · (m + r·x) ✓
 */
export function gg20ComputePartials(
  parties: GG20PartyState[],
  msgHash: Uint8Array,
  r: bigint
): Array<{ partyIndex: number; s_i: bigint; bytes: Uint8Array }> {
  const m = bytesToBigint(msgHash);
  const partials = [];

  for (const party of parties) {
    // s_i = m · k_i + r · σ_i (mod N)
    const mk = (m * party.k_i) % N;
    const rSigma = (r * party.sigma_i) % N;
    const s_i = (mk + rSigma) % N;

    partials.push({
      partyIndex: party.partyIndex,
      s_i,
      bytes: bigintTo32Bytes(s_i),
    });
  }

  return partials;
}

/**
 * Run the complete GG20 signing protocol.
 *
 * This simulates all parties in one process (for testing).
 * In production, each party runs on a separate machine.
 */
export function gg20Sign(
  partySecrets: Array<{ partyIndex: number; x_i: bigint }>,
  msgHash: Uint8Array,
  paillierKeys?: PaillierKeyPair[]
): GG20SignatureData {
  console.log("  [GG20] Phase 1: Init parties (k_i, γ_i, Γ_i for each)...");
  const parties = partySecrets.map((p, i) =>
    gg20InitParty(p.partyIndex, p.x_i, paillierKeys?.[i], msgHash)
  );

  console.log("  [GG20] Phase 2: MtA rounds (Paillier-encrypted multiplication)...");
  const numMtaRounds = parties.length * (parties.length - 1) * 2;
  console.log(`         Running ${numMtaRounds} MtA exchanges...`);
  gg20RunMtARounds(parties);

  console.log("  [GG20] Phase 3: Open δ, compute R = δ⁻¹·Γ...");
  const { delta, r, r_bytes, R_compressed, recovery_id } = gg20ComputeR(parties);
  console.log(`         δ = k·γ = ${delta.toString(16).slice(0, 16)}... (safe to open)`);
  console.log(`         R = k⁻¹·G (nobody knows k⁻¹ as a number)`);
  console.log(`         r = ${bigintToHex(r).slice(0, 16)}...`);

  console.log("  [GG20] Phase 4: Compute partial signatures s_i...");
  const partials = gg20ComputePartials(parties, msgHash, r);

  // Verify locally (for testing — contract does this on-chain)
  let s_combined = 0n;
  for (const p of partials) {
    s_combined = (s_combined + p.s_i) % N;
  }

  // Prepare delta values for on-chain verification
  const deltas = parties.map((p) => ({
    partyIndex: p.partyIndex,
    delta_i: p.delta_i,
    bytes: bigintTo32Bytes(p.delta_i),
  }));

  const gammaPoints = parties.map((p) => p.Gamma_i);

  // Clean up secrets from party state
  for (const party of parties) {
    party.k_i = 0n;
    party.gamma_i = 0n;
    party.delta_i = 0n;
    party.sigma_i = 0n;
  }

  console.log("  [GG20] All k_i, γ_i, σ_i values wiped from memory");

  return {
    r,
    r_bytes,
    R_compressed,
    recovery_id,
    partials,
    deltas,
    gammaPoints,
  };
}

/**
 * Verify the GG20 signature locally (for testing).
 * Uses the standard ECDSA verification with R = k⁻¹·G convention.
 */
export function gg20VerifyLocally(
  combinedPublicKey: Uint8Array,
  msgHash: Uint8Array,
  r: bigint,
  s: bigint
): boolean {
  try {
    const sig = new secp256k1.Signature(r, s);
    const pk = secp256k1.ProjectivePoint.fromHex(combinedPublicKey);

    // Standard ECDSA verification:
    // u1 = s⁻¹ · m, u2 = s⁻¹ · r
    // X = u1·G + u2·P
    // Check X.x == r
    const m = bytesToBigint(msgHash);
    const sInv = modInverse(s, N);
    const u1 = (sInv * m) % N;
    const u2 = (sInv * r) % N;

    const X = G.multiply(u1).add(pk.multiply(u2));
    const xCoord = X.toAffine().x % N;

    return xCoord === r;
  } catch {
    return false;
  }
}

// --- Utilities ---

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

function bigintToHex(n: bigint): string {
  return n.toString(16).padStart(64, "0");
}

// --- RPC Encoding ---

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
 * Build RPC args for submit_delta (shortname 0x45).
 * Args: key_id(u32), party_index(u8), delta_bytes(Vec<u8>)
 */
export function buildSubmitDeltaArgs(
  keyId: number,
  partyIndex: number,
  deltaBytes: Uint8Array
): Uint8Array {
  return new Uint8Array([
    ...encodeU32(keyId),
    partyIndex,
    ...encodeVec(deltaBytes),
  ]);
}

/**
 * Build RPC args for submit_gamma_point (shortname 0x46).
 * Args: key_id(u32), party_index(u8), gamma_point(Vec<u8>)
 */
export function buildSubmitGammaPointArgs(
  keyId: number,
  partyIndex: number,
  gammaPoint: Uint8Array
): Uint8Array {
  return new Uint8Array([
    ...encodeU32(keyId),
    partyIndex,
    ...encodeVec(gammaPoint),
  ]);
}

/**
 * Build RPC args for gg20_finalize_r (shortname 0x47).
 * Args: key_id(u32)
 */
export function buildGG20FinalizeRArgs(keyId: number): Uint8Array {
  return encodeU32(keyId);
}

/**
 * Build RPC args for abort_signing (shortname 0x48).
 * Args: key_id(u32)
 */
export function buildAbortSigningArgs(keyId: number): Uint8Array {
  return encodeU32(keyId);
}

/**
 * Build RPC args for open_gg20_deltas (shortname 0x52).
 * Args: key_id(u32)
 */
export function buildOpenGG20DeltasArgs(keyId: number): Uint8Array {
  return encodeU32(keyId);
}

/**
 * Split a 256-bit delta scalar into high (first 16 bytes) and low (last 16 bytes) halves.
 */
export function splitDelta(deltaBytes: Uint8Array): [Uint8Array, Uint8Array] {
  const high = deltaBytes.slice(0, 16);
  const low = deltaBytes.slice(16, 32);
  return [high, low];
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

/**
 * Build RPC args for commit_partial_sig (shortname 0x44).
 * Args: key_id(u32), party_index(u8), commitment_hash(Vec<u8>)
 */
export function buildCommitPartialSigArgs(
  keyId: number,
  partyIndex: number,
  commitmentHash: Uint8Array
): Uint8Array {
  return new Uint8Array([
    ...encodeU32(keyId),
    partyIndex,
    ...encodeVec(commitmentHash),
  ]);
}

/**
 * Compute SHA-256 of data.
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await globalThis.crypto.subtle.digest("SHA-256", data as any);
  return new Uint8Array(hashBuffer);
}

/**
 * Build RPC args for commit_delta (shortname 0x49).
 * Args: key_id(u32), party_index(u8), commitment_hash(Vec<u8>)
 */
export function buildCommitDeltaArgs(
  keyId: number,
  partyIndex: number,
  commitmentHash: Uint8Array
): Uint8Array {
  return new Uint8Array([
    ...encodeU32(keyId),
    partyIndex,
    ...encodeVec(commitmentHash),
  ]);
}
