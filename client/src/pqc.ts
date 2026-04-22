/**
 * PQC auth + transport using ML-KEM (Kyber) and ML-DSA (Dilithium)
 * from @noble/post-quantum.
 *
 * This uses real post-quantum primitives in JS:
 * - ML-KEM-768 for shared secrets (Kyber)
 * - ML-DSA-65 for signatures (Dilithium)
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes as nodeRandom } from "crypto";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { randomBytes } from "@noble/post-quantum/utils.js";

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------

export interface KyberKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface DilithiumKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface PqcIdentity {
  kyber: KyberKeyPair;
  dilithium: DilithiumKeyPair;
}

export interface EncryptedPayload {
  kem: Uint8Array;      // KEM ciphertext (ephemeral public key)
  nonce: Uint8Array;    // AES-GCM nonce
  tag: Uint8Array;      // AES-GCM tag
  ciphertext: Uint8Array;
}

// ----------------------------------------------------------------------------
// Key Generation
// ----------------------------------------------------------------------------

export function generatePqcIdentity(): PqcIdentity {
  const kyber = generateKyberKeyPair();
  const dilithium = generateDilithiumKeyPair();
  return { kyber, dilithium };
}

export function generateKyberKeyPair(): KyberKeyPair {
  // ML-KEM seed is optional; use 64 random bytes for determinism if needed.
  const seed = randomBytes(64);
  const keys = ml_kem768.keygen(seed);
  return { publicKey: keys.publicKey, privateKey: keys.secretKey };
}

export function generateDilithiumKeyPair(): DilithiumKeyPair {
  // ML-DSA seed is optional; use 32 random bytes.
  const seed = randomBytes(32);
  const keys = ml_dsa65.keygen(seed);
  return { publicKey: keys.publicKey, privateKey: keys.secretKey };
}

// ----------------------------------------------------------------------------
// Kyber-like KEM (encap/decap)
// ----------------------------------------------------------------------------

export function kyberEncapsulate(recipientPublicKey: Uint8Array): { kem: Uint8Array; sharedSecret: Uint8Array } {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(recipientPublicKey);
  return { kem: cipherText, sharedSecret };
}

export function kyberDecapsulate(kem: Uint8Array, recipientPrivateKey: Uint8Array): Uint8Array {
  return ml_kem768.decapsulate(kem, recipientPrivateKey);
}

// ----------------------------------------------------------------------------
// Dilithium-like signatures (sign/verify)
// ----------------------------------------------------------------------------

export function dilithiumSign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ml_dsa65.sign(message, privateKey);
}

export function dilithiumVerify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  return ml_dsa65.verify(signature, message, publicKey);
}

// ----------------------------------------------------------------------------
// Symmetric encryption for transport (AES-256-GCM)
// ----------------------------------------------------------------------------

export function encryptWithSharedSecret(sharedSecret: Uint8Array, plaintext: Uint8Array): EncryptedPayload {
  const key = sha256(sharedSecret);
  const nonce = nodeRandom(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    kem: new Uint8Array(),
    nonce: new Uint8Array(nonce),
    tag: new Uint8Array(tag),
    ciphertext: new Uint8Array(ciphertext),
  };
}

export function decryptWithSharedSecret(sharedSecret: Uint8Array, payload: EncryptedPayload): Uint8Array {
  const key = sha256(sharedSecret);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(payload.nonce));
  decipher.setAuthTag(Buffer.from(payload.tag));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(payload.ciphertext)), decipher.final()]);
  return new Uint8Array(plaintext);
}

// ----------------------------------------------------------------------------
// Utils
// ----------------------------------------------------------------------------

export function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(Buffer.from(data)).digest();
}

export function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function base64ToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}
