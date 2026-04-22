/**
 * PQC Party Identity Management
 *
 * Each signing party maintains a persistent PQC identity consisting of:
 * - ML-KEM-768 (Kyber) keypair — for quantum-safe key encapsulation / share transport
 * - ML-DSA-65 (Dilithium) keypair — for quantum-safe action authentication
 *
 * The identity is saved to disk as JSON and loaded between sessions.
 * Private keys never leave the party's machine.
 *
 * Public bundles are shared with the coordinator and other parties
 * before DKG and before each signing session.
 */

import { readFileSync, writeFileSync, existsSync } from "fs";
import {
  generateKyberKeyPair,
  generateDilithiumKeyPair,
  type KyberKeyPair,
  type DilithiumKeyPair,
} from "./pqc.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PqcPartyIdentity {
  partyIndex: number;
  kyber: KyberKeyPair;
  dilithium: DilithiumKeyPair;
  createdAt: number; // unix ms
}

/**
 * Public bundle — safe to share with coordinator and other parties.
 * Contains NO private key material.
 */
export interface PublicBundle {
  partyIndex: number;
  kyberPublicKey: Uint8Array;     // 1184 bytes (ML-KEM-768)
  dilithiumPublicKey: Uint8Array; // 1952 bytes (ML-DSA-65)
}

// Serialized form (base64 strings for JSON storage)
interface SerializedIdentity {
  partyIndex: number;
  kyberPublicKey: string;
  kyberPrivateKey: string;
  dilithiumPublicKey: string;
  dilithiumPrivateKey: string;
  createdAt: number;
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

function serializeIdentity(id: PqcPartyIdentity): SerializedIdentity {
  return {
    partyIndex: id.partyIndex,
    kyberPublicKey: toBase64(id.kyber.publicKey),
    kyberPrivateKey: toBase64(id.kyber.privateKey),
    dilithiumPublicKey: toBase64(id.dilithium.publicKey),
    dilithiumPrivateKey: toBase64(id.dilithium.privateKey),
    createdAt: id.createdAt,
  };
}

function deserializeIdentity(s: SerializedIdentity): PqcPartyIdentity {
  return {
    partyIndex: s.partyIndex,
    kyber: {
      publicKey: fromBase64(s.kyberPublicKey),
      privateKey: fromBase64(s.kyberPrivateKey),
    },
    dilithium: {
      publicKey: fromBase64(s.dilithiumPublicKey),
      privateKey: fromBase64(s.dilithiumPrivateKey),
    },
    createdAt: s.createdAt,
  };
}

// ---------------------------------------------------------------------------
// PqcIdentityStore
// ---------------------------------------------------------------------------

export class PqcIdentityStore {
  /**
   * Generate a fresh PQC identity for a party.
   * Both Kyber and Dilithium keypairs are newly generated.
   */
  generate(partyIndex: number): PqcPartyIdentity {
    return {
      partyIndex,
      kyber: generateKyberKeyPair(),
      dilithium: generateDilithiumKeyPair(),
      createdAt: Date.now(),
    };
  }

  /**
   * Save identity to disk as JSON.
   * WARNING: file contains private keys — restrict permissions.
   */
  save(identity: PqcPartyIdentity, filePath: string): void {
    const serialized = serializeIdentity(identity);
    writeFileSync(filePath, JSON.stringify(serialized, null, 2), { mode: 0o600 });
    console.log(`[PQC] Identity for party ${identity.partyIndex} saved to ${filePath}`);
  }

  /**
   * Load identity from disk.
   * Throws if file does not exist.
   */
  load(filePath: string): PqcPartyIdentity {
    if (!existsSync(filePath)) {
      throw new Error(`PQC identity file not found: ${filePath}`);
    }
    const raw = readFileSync(filePath, "utf-8");
    const serialized: SerializedIdentity = JSON.parse(raw);
    return deserializeIdentity(serialized);
  }

  /**
   * Load if exists, otherwise generate and save.
   */
  loadOrGenerate(partyIndex: number, filePath: string): PqcPartyIdentity {
    if (existsSync(filePath)) {
      return this.load(filePath);
    }
    const identity = this.generate(partyIndex);
    this.save(identity, filePath);
    return identity;
  }

  /**
   * Extract the public bundle — safe to share with other parties.
   * Contains ONLY public keys.
   */
  getPublicBundle(identity: PqcPartyIdentity): PublicBundle {
    return {
      partyIndex: identity.partyIndex,
      kyberPublicKey: identity.kyber.publicKey,
      dilithiumPublicKey: identity.dilithium.publicKey,
    };
  }

  /**
   * Serialize a PublicBundle to a base64-JSON string for transmission.
   */
  serializeBundle(bundle: PublicBundle): string {
    return JSON.stringify({
      partyIndex: bundle.partyIndex,
      kyberPublicKey: toBase64(bundle.kyberPublicKey),
      dilithiumPublicKey: toBase64(bundle.dilithiumPublicKey),
    });
  }

  /**
   * Deserialize a PublicBundle from a base64-JSON string.
   */
  deserializeBundle(s: string): PublicBundle {
    const obj = JSON.parse(s);
    return {
      partyIndex: obj.partyIndex,
      kyberPublicKey: fromBase64(obj.kyberPublicKey),
      dilithiumPublicKey: fromBase64(obj.dilithiumPublicKey),
    };
  }

  /**
   * Default file path for a party's PQC identity.
   */
  static defaultPath(partyIndex: number): string {
    return `./pqc-identity-party${partyIndex}.json`;
  }
}

export const defaultIdentityStore = new PqcIdentityStore();
