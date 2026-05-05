/**
 * PQC-Authenticated Action Wrapping
 *
 * Every party action in the signing protocol (submit_delta, submit_gamma,
 * submit_partial_sig, DKG commit/reveal) is wrapped with a Dilithium
 * (ML-DSA-65) signature. This provides:
 *
 * 1. Authentication — proves the action came from the party who holds that
 *    Dilithium private key, not an impersonator.
 * 2. Integrity — any tampering with the payload invalidates the signature.
 * 3. Replay protection — timestamp is included in the signed data.
 *    Actions older than MAX_AGE_MS are rejected.
 * 4. Quantum safety — Dilithium is immune to Shor's algorithm. Even after
 *    Q-Day, recorded protocol messages cannot be forged or attributed to
 *    a different party.
 *
 * This is a pure off-chain layer. The Partisia contract sees the original
 * payload bytes unchanged — no ABI modifications required.
 */

import { createHash } from "crypto";
import { dilithiumSign, dilithiumVerify } from "./pqc.js";
import { type PqcPartyIdentity, type PublicBundle } from "./pqc-identity.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A signing protocol action wrapped with a Dilithium signature.
 * The coordinator verifies this before relaying to Partisia.
 */
export interface AuthenticatedAction {
  /** The raw RPC payload bytes (unchanged — sent to Partisia as-is). */
  payload: Uint8Array;
  /** 1-based party index of the sender. */
  partyIndex: number;
  /** ML-DSA-65 signature over: payload || partyIndex(u8) || timestamp(u64 BE). */
  dilithiumSig: Uint8Array;
  /** Sender's Dilithium public key (for verification without a registry lookup). */
  dilithiumPubKey: Uint8Array;
  /** Unix timestamp in milliseconds — replay protection window. */
  timestamp: number;
}

/** Maximum age of an authenticated action before it is considered a replay. */
const MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes

// ---------------------------------------------------------------------------
// Signing data construction
// ---------------------------------------------------------------------------

/**
 * Build the exact bytes that are signed by Dilithium.
 *
 * Signed data layout:
 *   payload bytes  (variable)
 *   partyIndex     (1 byte)
 *   timestamp      (8 bytes, big-endian uint64)
 *
 * Including all three prevents:
 *   - Cross-action replay (payload differs)
 *   - Cross-party forgery (partyIndex differs)
 *   - Time-delayed replay (timestamp differs)
 */
function buildSignedData(
  payload: Uint8Array,
  partyIndex: number,
  timestamp: number
): Uint8Array {
  const tsBytes = new Uint8Array(8);
  const tsView = new DataView(tsBytes.buffer);
  // Write timestamp as 64-bit big-endian (safe for timestamps up to ~year 2554)
  const hi = Math.floor(timestamp / 0x100000000);
  const lo = timestamp >>> 0;
  tsView.setUint32(0, hi, false);
  tsView.setUint32(4, lo, false);

  const partyByte = new Uint8Array([partyIndex & 0xff]);
  const combined = new Uint8Array(payload.length + 1 + 8);
  combined.set(payload, 0);
  combined.set(partyByte, payload.length);
  combined.set(tsBytes, payload.length + 1);
  return combined;
}

// ---------------------------------------------------------------------------
// Core API
// ---------------------------------------------------------------------------

/**
 * Wrap an RPC payload with a Dilithium signature.
 *
 * Call this on the party's machine before sending the action to the
 * coordinator or directly to Partisia.
 */
export function authenticateAction(
  payload: Uint8Array,
  identity: PqcPartyIdentity,
  timestamp: number = Date.now()
): AuthenticatedAction {
  const signedData = buildSignedData(payload, identity.partyIndex, timestamp);
  const sig = dilithiumSign(signedData, identity.dilithium.privateKey);

  return {
    payload,
    partyIndex: identity.partyIndex,
    dilithiumSig: sig,
    dilithiumPubKey: identity.dilithium.publicKey,
    timestamp,
  };
}

/**
 * Verify an AuthenticatedAction.
 *
 * Returns true only if ALL of:
 * 1. The Dilithium signature is valid over the correct signed data.
 * 2. The Dilithium public key matches the known bundle for this partyIndex.
 * 3. The timestamp is within MAX_AGE_MS of now (replay protection).
 *
 * @param action    The action to verify.
 * @param bundles   Known public bundles for all parties (from pre-DKG exchange).
 * @param nowMs     Current time in ms (injectable for testing).
 */
export function verifyAction(
  action: AuthenticatedAction,
  bundles: PublicBundle[],
  nowMs: number = Date.now()
): boolean {
  // 1. Replay protection
  const age = nowMs - action.timestamp;
  if (age < 0 || age > MAX_AGE_MS) {
    return false;
  }

  // 2. Party must be in known bundles
  const bundle = bundles.find((b) => b.partyIndex === action.partyIndex);
  if (!bundle) {
    return false;
  }

  // 3. Public key in action must match known bundle (prevent key substitution)
  if (!uint8ArrayEqual(action.dilithiumPubKey, bundle.dilithiumPublicKey)) {
    return false;
  }

  // 4. Dilithium signature verification
  const signedData = buildSignedData(
    action.payload,
    action.partyIndex,
    action.timestamp
  );
  try {
    return dilithiumVerify(signedData, action.dilithiumSig, action.dilithiumPubKey);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Serialization (for network transport)
// ---------------------------------------------------------------------------

interface SerializedAction {
  payload: string;       // base64
  partyIndex: number;
  dilithiumSig: string;  // base64
  dilithiumPubKey: string; // base64
  timestamp: number;
}

export function serializeAction(action: AuthenticatedAction): string {
  const s: SerializedAction = {
    payload: Buffer.from(action.payload).toString("base64"),
    partyIndex: action.partyIndex,
    dilithiumSig: Buffer.from(action.dilithiumSig).toString("base64"),
    dilithiumPubKey: Buffer.from(action.dilithiumPubKey).toString("base64"),
    timestamp: action.timestamp,
  };
  return JSON.stringify(s);
}

export function deserializeAction(s: string): AuthenticatedAction {
  const obj: SerializedAction = JSON.parse(s);
  return {
    payload: new Uint8Array(Buffer.from(obj.payload, "base64")),
    partyIndex: obj.partyIndex,
    dilithiumSig: new Uint8Array(Buffer.from(obj.dilithiumSig, "base64")),
    dilithiumPubKey: new Uint8Array(Buffer.from(obj.dilithiumPubKey, "base64")),
    timestamp: obj.timestamp,
  };
}

// ---------------------------------------------------------------------------
// Convenience: hash an action for logging / audit trail
// ---------------------------------------------------------------------------

/**
 * SHA-256 digest of the authenticated action (payload + sig).
 * Useful for on-chain audit logs or coordinator deduplication.
 */
export function actionDigest(action: AuthenticatedAction): Uint8Array {
  const h = createHash("sha256");
  h.update(Buffer.from(action.payload));
  h.update(Buffer.from(action.dilithiumSig));
  const partyByte = new Uint8Array([action.partyIndex]);
  h.update(Buffer.from(partyByte));
  return new Uint8Array(h.digest());
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function uint8ArrayEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
