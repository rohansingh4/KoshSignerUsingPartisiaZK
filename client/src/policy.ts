/**
 * Policy + RBAC — Mandatory Signer Rules per Transaction Type.
 *
 * Allows you to define rules like:
 *   "For any transaction tagged 'treasury', Party 2 MUST be in the signing set."
 *   "For any transaction tagged 'admin', both Party 1 AND Party 2 must sign."
 *
 * Enforcement is CLIENT-SIDE: the client checks the policy before submitting
 * gg20_start_signing. A party that tries to bypass this on their own machine
 * simply won't be able to complete the protocol (the other compliant parties
 * will refuse to participate if mandatory parties are absent).
 *
 * Usage:
 *   const store = new PolicyStore();
 *   store.add({ name: "treasury", txTag: "treasury", mandatoryParties: [2], minThreshold: 2 });
 *   store.add({ name: "admin",    txTag: "admin",    mandatoryParties: [1, 2], minThreshold: 2 });
 *
 *   // Before starting a signing session:
 *   const violation = store.check("treasury", [1, 3]);
 *   if (violation) throw new Error(violation);  // "Policy 'treasury': Party 2 is mandatory"
 *
 *   // Passes:
 *   store.check("treasury", [1, 2]);  // → null (no violation)
 *   store.check("treasury", [2, 3]);  // → null
 *   store.check("", [1, 3]);          // → null (no tag = no policy applies)
 */

import * as fs from "fs";

// ============================================================================
// Types
// ============================================================================

/** A policy rule binding a transaction tag to signing requirements. */
export interface Policy {
  /** Auto-assigned sequential ID. */
  id: number;
  /** Human-readable name (e.g. "treasury", "admin"). */
  name: string;
  /**
   * Transaction tag this policy applies to.
   * Matches the TX_TAG env var passed when queuing sign_message.
   * Empty string matches all transactions (use carefully).
   */
  txTag: string;
  /**
   * Party indices (1-based) that MUST appear in the signing subset.
   * If any of these are absent, the signing session is rejected.
   */
  mandatoryParties: number[];
  /**
   * Minimum number of parties required to sign (overrides global threshold).
   * 0 = use the global threshold setting.
   */
  minThreshold: number;
  /** When this policy was created (ISO timestamp). */
  createdAt: string;
}

/** Violation details returned when a policy is not satisfied. */
export interface PolicyViolation {
  policyId: number;
  policyName: string;
  txTag: string;
  missingParties: number[];
  message: string;
}

// ============================================================================
// PolicyStore
// ============================================================================

/**
 * In-memory policy store with optional file persistence.
 *
 * Policies survive process restart when a `filePath` is provided.
 * Without a filePath, policies are in-memory only (reset on restart).
 */
export class PolicyStore {
  private policies: Policy[] = [];
  private nextId = 1;
  private filePath?: string;

  constructor(filePath?: string) {
    this.filePath = filePath;
    if (filePath) this.load();
  }

  /** Add a new policy. Returns the assigned policy ID. */
  add(policy: Omit<Policy, "id" | "createdAt">): number {
    // Validate no duplicate txTag
    const existing = this.policies.find(p => p.txTag === policy.txTag);
    if (existing) {
      throw new Error(
        `Policy with txTag "${policy.txTag}" already exists (id=${existing.id}, name="${existing.name}"). Remove it first.`
      );
    }
    if (policy.mandatoryParties.length === 0) {
      throw new Error("mandatoryParties must not be empty — use a policy with at least one mandatory party.");
    }
    if (policy.mandatoryParties.some(p => p < 1 || p > 255)) {
      throw new Error("mandatoryParties must be 1-based party indices in range [1, 255].");
    }

    const id = this.nextId++;
    const full: Policy = { ...policy, id, createdAt: new Date().toISOString() };
    this.policies.push(full);
    if (this.filePath) this.save();
    return id;
  }

  /** Remove a policy by ID. Returns true if found and removed. */
  remove(id: number): boolean {
    const idx = this.policies.findIndex(p => p.id === id);
    if (idx < 0) return false;
    this.policies.splice(idx, 1);
    if (this.filePath) this.save();
    return true;
  }

  /** Remove all policies for a given txTag. */
  removeByTag(txTag: string): number {
    const before = this.policies.length;
    this.policies = this.policies.filter(p => p.txTag !== txTag);
    if (this.filePath && this.policies.length !== before) this.save();
    return before - this.policies.length;
  }

  /** List all policies. */
  list(): Policy[] {
    return [...this.policies];
  }

  /** Get a specific policy by ID. */
  get(id: number): Policy | undefined {
    return this.policies.find(p => p.id === id);
  }

  /** Find the policy that applies to a given transaction tag (first match). */
  findForTag(txTag: string): Policy | undefined {
    if (!txTag) return undefined;
    return this.policies.find(p => p.txTag === txTag);
  }

  /**
   * Check whether a proposed signing subset satisfies the policy for a txTag.
   *
   * @param txTag - The transaction tag (from TX_TAG env var or passed explicitly).
   * @param signingSubset - Array of party indices that will participate in signing.
   * @returns null if compliant, or a PolicyViolation describing what's missing.
   */
  check(txTag: string, signingSubset: number[]): PolicyViolation | null {
    const policy = this.findForTag(txTag);
    if (!policy) return null; // No policy for this tag — any subset is fine

    const missingParties = policy.mandatoryParties.filter(
      p => !signingSubset.includes(p)
    );

    if (missingParties.length === 0) {
      // Also check minThreshold
      if (policy.minThreshold > 0 && signingSubset.length < policy.minThreshold) {
        return {
          policyId: policy.id,
          policyName: policy.name,
          txTag,
          missingParties: [],
          message: `Policy "${policy.name}" (tag="${txTag}") requires at least ${policy.minThreshold} parties, but signing subset has only ${signingSubset.length}.`,
        };
      }
      return null;
    }

    return {
      policyId: policy.id,
      policyName: policy.name,
      txTag,
      missingParties,
      message:
        `Policy "${policy.name}" (tag="${txTag}"): ` +
        `Party ${missingParties.join(", Party ")} ${missingParties.length === 1 ? "is" : "are"} mandatory but not in signing subset {${signingSubset.join(",")}}.`,
    };
  }

  /**
   * Enforce policy compliance. Throws an error if the subset violates the policy.
   * Use this as a guard before starting a signing session.
   */
  enforce(txTag: string, signingSubset: number[]): void {
    const violation = this.check(txTag, signingSubset);
    if (violation) {
      throw new Error(`POLICY VIOLATION: ${violation.message}`);
    }
  }

  // ---- Persistence ----

  private save(): void {
    if (!this.filePath) return;
    const data = { nextId: this.nextId, policies: this.policies };
    fs.writeFileSync(this.filePath, JSON.stringify(data, null, 2), "utf-8");
  }

  private load(): void {
    if (!this.filePath || !fs.existsSync(this.filePath)) return;
    try {
      const raw = fs.readFileSync(this.filePath, "utf-8");
      const data = JSON.parse(raw) as { nextId: number; policies: Policy[] };
      this.policies = data.policies ?? [];
      this.nextId = data.nextId ?? (this.policies.length + 1);
    } catch {
      console.warn(`[PolicyStore] Could not load ${this.filePath} — starting fresh.`);
    }
  }
}

// ============================================================================
// Default store (singleton, loaded from POLICY_FILE env var if set)
// ============================================================================

/** Global default policy store — loaded from POLICY_FILE env var if set. */
export const defaultPolicies = new PolicyStore(process.env.POLICY_FILE);

// ============================================================================
// RPC Builders (for future on-chain policy enforcement)
// ============================================================================

function encodeU32(n: number): Uint8Array {
  return new Uint8Array([(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}

function encodeVec(data: Uint8Array): Uint8Array {
  return new Uint8Array([...encodeU32(data.length), ...data]);
}

function encodeString(s: string): Uint8Array {
  return encodeVec(new TextEncoder().encode(s));
}

function encodeAddress(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length !== 42) throw new Error(`Invalid address length: ${hex}`);
  const bytes = new Uint8Array(21);
  for (let i = 0; i < 21; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/**
 * Build RPC args for add_policy (shortname 0x70).
 * Owner-only — registers a new policy rule on-chain.
 *
 * Contract args: key_id(u32), name(Vec<u8>), tx_tag(Vec<u8>),
 *                mandatory_parties(Vec<u8>), min_threshold(u8)
 */
export function buildAddPolicyArgs(
  keyId: number,
  name: string,
  txTag: string,
  mandatoryParties: number[],
  minThreshold: number
): Uint8Array {
  const nameBytes = encodeString(name);
  const tagBytes = encodeString(txTag);
  const partiesBytes = new Uint8Array([...encodeU32(mandatoryParties.length), ...mandatoryParties]);
  return new Uint8Array([
    ...encodeU32(keyId),
    ...nameBytes,
    ...tagBytes,
    ...partiesBytes,
    minThreshold & 0xff,
  ]);
}

/**
 * Build RPC args for remove_policy (shortname 0x71).
 * Owner-only — removes a policy by ID.
 *
 * Contract args: key_id(u32), policy_id(u32)
 */
export function buildRemovePolicyArgs(keyId: number, policyId: number): Uint8Array {
  return new Uint8Array([...encodeU32(keyId), ...encodeU32(policyId)]);
}

/**
 * Build RPC args for register_party_address (shortname 0x72).
 * Owner-only — binds a party index to a wallet address on-chain.
 *
 * Contract args: key_id(u32), party_index(u8), address(Address[21 bytes])
 */
export function buildRegisterPartyAddressArgs(
  keyId: number,
  partyIndex: number,
  address: string
): Uint8Array {
  return new Uint8Array([
    ...encodeU32(keyId),
    partyIndex & 0xff,
    ...encodeAddress(address),
  ]);
}

/**
 * Build RPC args for sign_message_with_tag (shortname 0x03 — extended version).
 * Attaches a tx_tag so the contract can resolve the matching policy.
 *
 * Contract args: key_id(u32), message(Vec<u8>), tx_tag(Vec<u8>)
 *
 * NOTE: The current contract sign_message (0x03) takes (key_id, message) only.
 * This builder is forward-compatible — use it once the contract is upgraded.
 * Until then, use the standard buildSignArgs from gg20-signing.ts.
 */
export function buildSignMessageWithTagArgs(
  keyId: number,
  message: Uint8Array,
  txTag: string
): Uint8Array {
  return new Uint8Array([
    ...encodeU32(keyId),
    ...encodeVec(message),
    ...encodeString(txTag),
  ]);
}

// ============================================================================
// Display helpers
// ============================================================================

/** Pretty-print all policies to console. */
export function printPolicies(store: PolicyStore = defaultPolicies): void {
  const list = store.list();
  if (list.length === 0) {
    console.log("  No policies defined.");
    return;
  }
  console.log(`  ${list.length} policy/policies:`);
  for (const p of list) {
    console.log(
      `    [${p.id}] "${p.name}"  tag="${p.txTag}"  ` +
      `mandatory={${p.mandatoryParties.join(",")}}  ` +
      `minThreshold=${p.minThreshold || "global"}`
    );
  }
}
