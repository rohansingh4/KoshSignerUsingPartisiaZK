/**
 * MtA (Multiplicative to Additive) Protocol using Paillier encryption.
 *
 * Problem: Party A has secret a, Party B has secret b.
 *          We want additive shares α, β such that α + β = a·b (mod q)
 *          WITHOUT revealing a to B or b to A.
 *
 * Protocol:
 * 1. Party A encrypts a: c_a = Enc_A(a)
 * 2. Party A sends c_a to Party B (along with their Paillier public key)
 * 3. Party B picks random β' ∈ Z_q
 * 4. Party B computes: c_result = c_a^b · Enc_A(-β') = Enc_A(a·b - β')
 * 5. Party B sends c_result back to Party A, keeps β = β'
 * 6. Party A decrypts: α = Dec(c_result) = a·b - β'
 *
 * Result: α + β = (a·b - β') + β' = a·b  ✓
 *
 * Neither party learned the other's secret.
 */

import {
  paillierEncrypt,
  paillierDecrypt,
  paillierScalarMul,
  paillierAdd,
  modInverse,
  type PaillierPublicKey,
  type PaillierPrivateKey,
} from "./paillier.js";
import { randomScalar } from "./shamir-ts.js";
import { secp256k1 } from "@noble/curves/secp256k1";

const N = secp256k1.CURVE.n; // secp256k1 group order

// --- Types ---

/** Session context that binds MtA messages to a specific signing round */
export interface MtASessionContext {
  /** Key ID being signed for */
  keyId: number;
  /** Signing task ID */
  taskId: number;
  /** Signing round number */
  round: number;
  /** Sender party index */
  sender: number;
  /** Receiver party index */
  receiver: number;
}

/** Message from Party A → Party B in MtA round 1 */
export interface MtAMessage1 {
  /** Paillier-encrypted value of a: Enc(a) */
  encryptedA: bigint;
  /** Party A's Paillier public key */
  paillierPk: PaillierPublicKey;
  /** Session binding (prevents replay across rounds) */
  session?: MtASessionContext;
}

/** Message from Party B → Party A in MtA round 2 */
export interface MtAMessage2 {
  /** Enc_A(a·b - β) — A will decrypt to get α */
  encryptedResult: bigint;
  /** Session binding (must match msg1 session) */
  session?: MtASessionContext;
}

/** Party A's output from MtA */
export interface MtAOutputA {
  /** α = a·b - β (mod q) — Party A's additive share */
  alpha: bigint;
}

/** Party B's output from MtA */
export interface MtAOutputB {
  /** β — Party B's additive share */
  beta: bigint;
}

// --- Protocol Steps ---

/**
 * MtA Round 1 — Party A's side.
 * Party A encrypts their secret value a with their Paillier key.
 *
 * @param a - Party A's secret value
 * @param paillierPk - Party A's Paillier public key
 * @returns Message to send to Party B
 */
export function mtaRound1_A(
  a: bigint,
  paillierPk: PaillierPublicKey,
  session?: MtASessionContext
): MtAMessage1 {
  // Reduce a into Paillier plaintext space
  const aMod = ((a % paillierPk.n) + paillierPk.n) % paillierPk.n;
  const encryptedA = paillierEncrypt(paillierPk, aMod);
  return { encryptedA, paillierPk, session };
}

/**
 * MtA Round 2 — Party B's side.
 * Party B uses homomorphic operations to compute Enc(a·b - β)
 * without learning a. Keeps β as their share.
 *
 * @param msg1 - Message received from Party A
 * @param b - Party B's secret value
 * @returns Message to send back to Party A, and Party B's share β
 */
export function mtaRound2_B(
  msg1: MtAMessage1,
  b: bigint,
  expectedSession?: MtASessionContext
): { msg2: MtAMessage2; outputB: MtAOutputB } {
  const { encryptedA, paillierPk, session } = msg1;

  // Validate session binding if expected (prevents replay attacks)
  if (expectedSession) {
    if (!session) throw new Error("MtA message missing session binding");
    if (session.keyId !== expectedSession.keyId ||
        session.taskId !== expectedSession.taskId ||
        session.round !== expectedSession.round ||
        session.sender !== expectedSession.sender ||
        session.receiver !== expectedSession.receiver) {
      throw new Error("MtA session mismatch — possible replay attack");
    }
  }

  // Pick random β ∈ [0, N)
  const beta = randomScalar();

  // Compute Enc(a·b) = Enc(a)^b mod n²
  const bMod = ((b % paillierPk.n) + paillierPk.n) % paillierPk.n;
  const encAB = paillierScalarMul(paillierPk, encryptedA, bMod);

  // Compute Enc(-β) = Enc(n - β mod n)
  const negBeta = (((-beta) % paillierPk.n) + paillierPk.n) % paillierPk.n;
  const encNegBeta = paillierEncrypt(paillierPk, negBeta);

  // Enc(a·b - β) = Enc(a·b) · Enc(-β) mod n²
  const encryptedResult = paillierAdd(paillierPk, encAB, encNegBeta);

  return {
    msg2: { encryptedResult, session },
    outputB: { beta: ((beta % N) + N) % N },
  };
}

/**
 * MtA Finalize — Party A's side.
 * Party A decrypts to get their share α = a·b - β.
 *
 * @param msg2 - Message received from Party B
 * @param paillierPk - Party A's Paillier public key
 * @param paillierSk - Party A's Paillier private key
 * @returns Party A's share α
 */
export function mtaFinalize_A(
  msg2: MtAMessage2,
  paillierPk: PaillierPublicKey,
  paillierSk: PaillierPrivateKey,
  expectedSession?: MtASessionContext
): MtAOutputA {
  // Validate session binding if expected
  if (expectedSession) {
    if (!msg2.session) throw new Error("MtA response missing session binding");
    if (msg2.session.keyId !== expectedSession.keyId ||
        msg2.session.taskId !== expectedSession.taskId ||
        msg2.session.round !== expectedSession.round) {
      throw new Error("MtA response session mismatch — possible replay attack");
    }
  }

  const decrypted = paillierDecrypt(paillierPk, paillierSk, msg2.encryptedResult);
  // Paillier decrypts in [0, n). Values > n/2 represent negative numbers.
  // Interpret as signed: if > n/2, subtract n to get the negative value.
  let signed = decrypted;
  if (signed > paillierPk.n / 2n) {
    signed = signed - paillierPk.n;
  }
  // Reduce to secp256k1 order
  const alpha = ((signed % N) + N) % N;
  return { alpha };
}

// --- High-level MtA ---

/**
 * Run complete MtA protocol between two parties (for testing/simulation).
 *
 * In production, each step runs on a separate machine:
 * - Machine A: mtaRound1_A → sends msg1 → receives msg2 → mtaFinalize_A
 * - Machine B: receives msg1 → mtaRound2_B → sends msg2
 *
 * @param a - Party A's secret
 * @param b - Party B's secret
 * @param paillierPk - Party A's Paillier public key
 * @param paillierSk - Party A's Paillier private key
 * @returns { alpha, beta } where (alpha + beta) ≡ a·b (mod N)
 */
export function runMtA(
  a: bigint,
  b: bigint,
  paillierPk: PaillierPublicKey,
  paillierSk: PaillierPrivateKey
): { alpha: bigint; beta: bigint } {
  // Round 1: Party A encrypts a
  const msg1 = mtaRound1_A(a, paillierPk);

  // Round 2: Party B computes homomorphically, picks β
  const { msg2, outputB } = mtaRound2_B(msg1, b);

  // Finalize: Party A decrypts α
  const outputA = mtaFinalize_A(msg2, paillierPk, paillierSk);

  return { alpha: outputA.alpha, beta: outputB.beta };
}

/**
 * Verify MtA result (for testing only — parties can't do this in production
 * because neither knows both a and b).
 */
export function verifyMtA(
  a: bigint,
  b: bigint,
  alpha: bigint,
  beta: bigint
): boolean {
  const product = ((a * b) % N + N) % N;
  const sum = ((alpha + beta) % N + N) % N;
  return product === sum;
}
