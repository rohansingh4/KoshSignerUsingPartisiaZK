/**
 * PQC Integration Tests
 *
 * Tests all quantum-safe primitives and their integration with the Kosh signing protocol.
 *
 * Run: npx tsx src/test-pqc.ts
 */

import { secp256k1 } from "@noble/curves/secp256k1";

import {
  generateKyberKeyPair,
  generateDilithiumKeyPair,
  generatePqcIdentity,
  kyberEncapsulate,
  kyberDecapsulate,
  dilithiumSign,
  dilithiumVerify,
  encryptWithSharedSecret,
  decryptWithSharedSecret,
} from "./pqc.js";

import { PqcIdentityStore } from "./pqc-identity.js";

import {
  authenticateAction,
  verifyAction,
  serializeAction,
  deserializeAction,
  actionDigest,
} from "./pqc-auth.js";

import {
  encryptKInvForCoordinator,
  decryptKInv,
} from "./gg20-signing.js";

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void | Promise<void>): void {
  try {
    const result = fn();
    if (result instanceof Promise) {
      result
        .then(() => {
          console.log(`  [PASS] ${name}`);
          passed++;
        })
        .catch((err) => {
          console.log(`  [FAIL] ${name}: ${err.message}`);
          failed++;
        });
    } else {
      console.log(`  [PASS] ${name}`);
      passed++;
    }
  } catch (err: any) {
    console.log(`  [FAIL] ${name}: ${err.message}`);
    failed++;
  }
}

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function assertEqual(a: Uint8Array, b: Uint8Array, message: string): void {
  assert(a.length === b.length, `${message} — length mismatch: ${a.length} vs ${b.length}`);
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) throw new Error(`${message} — byte mismatch at index ${i}`);
  }
}

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  for (let i = 0; i < n; i++) buf[i] = Math.floor(Math.random() * 256);
  return buf;
}

// ---------------------------------------------------------------------------
// 1. ML-KEM-768 (Kyber) tests
// ---------------------------------------------------------------------------

console.log("\n=== ML-KEM-768 (Kyber) ===");

test("Kyber keygen produces correct key sizes", () => {
  const kp = generateKyberKeyPair();
  assert(kp.publicKey.length === 1184, `Public key should be 1184 bytes, got ${kp.publicKey.length}`);
  assert(kp.privateKey.length === 2400, `Private key should be 2400 bytes, got ${kp.privateKey.length}`);
});

test("Kyber encap → decap produces identical shared secret", () => {
  const { publicKey, privateKey } = generateKyberKeyPair();
  const { kem, sharedSecret: ss1 } = kyberEncapsulate(publicKey);
  const ss2 = kyberDecapsulate(kem, privateKey);
  assert(ss1.length === 32, "Shared secret should be 32 bytes");
  assertEqual(ss1, ss2, "Shared secrets must match");
});

test("Kyber encap with different keys produces different shared secrets", () => {
  const kp1 = generateKyberKeyPair();
  const kp2 = generateKyberKeyPair();
  const { sharedSecret: ss1 } = kyberEncapsulate(kp1.publicKey);
  const { sharedSecret: ss2 } = kyberEncapsulate(kp2.publicKey);
  let allSame = true;
  for (let i = 0; i < ss1.length; i++) {
    if (ss1[i] !== ss2[i]) { allSame = false; break; }
  }
  assert(!allSame, "Different keys must produce different shared secrets");
});

test("Kyber wrong private key → decap mismatch (does not reconstruct secret)", () => {
  const { publicKey } = generateKyberKeyPair();
  const { privateKey: wrongPriv } = generateKyberKeyPair();
  const { kem, sharedSecret: correctSS } = kyberEncapsulate(publicKey);
  // ML-KEM decap with wrong key returns a random-looking value (implicit rejection)
  const wrongSS = kyberDecapsulate(kem, wrongPriv);
  let allSame = true;
  for (let i = 0; i < correctSS.length; i++) {
    if (correctSS[i] !== wrongSS[i]) { allSame = false; break; }
  }
  assert(!allSame, "Wrong private key must not reproduce the correct shared secret");
});

// ---------------------------------------------------------------------------
// 2. ML-DSA-65 (Dilithium) tests
// ---------------------------------------------------------------------------

console.log("\n=== ML-DSA-65 (Dilithium) ===");

test("Dilithium keygen produces correct key sizes", () => {
  const kp = generateDilithiumKeyPair();
  assert(kp.publicKey.length === 1952, `Public key should be 1952 bytes, got ${kp.publicKey.length}`);
  assert(kp.privateKey.length === 4032, `Private key should be 4032 bytes, got ${kp.privateKey.length}`);
});

test("Dilithium sign → verify succeeds", () => {
  const { publicKey, privateKey } = generateDilithiumKeyPair();
  const message = new TextEncoder().encode("Kosh threshold signature approved");
  const sig = dilithiumSign(message, privateKey);
  const valid = dilithiumVerify(message, sig, publicKey);
  assert(valid, "Dilithium signature verification must succeed");
});

test("Dilithium verify with wrong public key → false", () => {
  const { privateKey } = generateDilithiumKeyPair();
  const { publicKey: wrongPub } = generateDilithiumKeyPair();
  const message = randomBytes(32);
  const sig = dilithiumSign(message, privateKey);
  const valid = dilithiumVerify(message, sig, wrongPub);
  assert(!valid, "Dilithium verification with wrong key must fail");
});

test("Dilithium verify with tampered message → false", () => {
  const { publicKey, privateKey } = generateDilithiumKeyPair();
  const message = randomBytes(32);
  const sig = dilithiumSign(message, privateKey);
  const tampered = new Uint8Array(message);
  tampered[0] ^= 0xff;
  const valid = dilithiumVerify(tampered, sig, publicKey);
  assert(!valid, "Dilithium verification with tampered message must fail");
});

test("Dilithium verify with tampered signature → false", () => {
  const { publicKey, privateKey } = generateDilithiumKeyPair();
  const message = randomBytes(32);
  const sig = dilithiumSign(message, privateKey);
  const tamperedSig = new Uint8Array(sig);
  tamperedSig[100] ^= 0x01;
  const valid = dilithiumVerify(message, tamperedSig, publicKey);
  assert(!valid, "Dilithium verification with tampered signature must fail");
});

// ---------------------------------------------------------------------------
// 3. AES-256-GCM over Kyber shared secret
// ---------------------------------------------------------------------------

console.log("\n=== AES-256-GCM over Kyber Shared Secret ===");

test("Encrypt + decrypt round-trip with Kyber shared secret", () => {
  const { publicKey, privateKey } = generateKyberKeyPair();
  const { kem, sharedSecret } = kyberEncapsulate(publicKey);
  const recoveredSS = kyberDecapsulate(kem, privateKey);

  const plaintext = new TextEncoder().encode("send 1000 ETH to treasury");
  const encrypted = encryptWithSharedSecret(sharedSecret, plaintext);
  const decrypted = decryptWithSharedSecret(recoveredSS, encrypted);

  const decryptedText = new TextDecoder().decode(decrypted);
  assert(decryptedText === "send 1000 ETH to treasury", `Round-trip failed: ${decryptedText}`);
});

test("Decryption with wrong shared secret fails (GCM auth tag)", () => {
  const { publicKey } = generateKyberKeyPair();
  const { sharedSecret: correctSS } = kyberEncapsulate(publicKey);
  const { sharedSecret: wrongSS } = kyberEncapsulate(publicKey); // different encap

  const plaintext = randomBytes(32);
  const encrypted = encryptWithSharedSecret(correctSS, plaintext);
  let threw = false;
  try {
    decryptWithSharedSecret(wrongSS, encrypted);
  } catch {
    threw = true;
  }
  assert(threw, "Decryption with wrong shared secret must throw (GCM auth tag mismatch)");
});

// ---------------------------------------------------------------------------
// 4. Hybrid: ECDSA + Dilithium on same message
// ---------------------------------------------------------------------------

console.log("\n=== Hybrid: ECDSA + Dilithium ===");

test("Same message signed by both ECDSA and Dilithium", () => {
  const ecdsaPriv = secp256k1.utils.randomPrivateKey();
  const ecdsaPub = secp256k1.getPublicKey(ecdsaPriv, true);

  const { publicKey: dilPub, privateKey: dilPriv } = generateDilithiumKeyPair();

  const messageHash = randomBytes(32);

  // ECDSA sign
  const ecdsaSig = secp256k1.sign(messageHash, ecdsaPriv);
  const ecdsaValid = secp256k1.verify(ecdsaSig.toCompactRawBytes(), messageHash, ecdsaPub);

  // Dilithium sign
  const dilSig = dilithiumSign(messageHash, dilPriv);
  const dilValid = dilithiumVerify(messageHash, dilSig, dilPub);

  assert(ecdsaValid, "ECDSA signature must verify");
  assert(dilValid, "Dilithium signature must verify");
});

// ---------------------------------------------------------------------------
// 5. Kyber k⁻¹ encrypted transport
// ---------------------------------------------------------------------------

console.log("\n=== Kyber-Encrypted k⁻¹ Transport ===");

test("k⁻¹ encrypt → decrypt produces same bytes", () => {
  const coordinator = generateKyberKeyPair();
  // Simulate a real k⁻¹: random non-zero secp256k1 scalar
  const kScalar = secp256k1.utils.randomPrivateKey();
  const kInv = BigInt("0x" + Buffer.from(kScalar).toString("hex"));
  const kInvMod = kInv % secp256k1.CURVE.n;
  const kInvBytes = new Uint8Array(32);
  let v = kInvMod;
  for (let i = 31; i >= 0; i--) { kInvBytes[i] = Number(v & 0xffn); v >>= 8n; }

  const encrypted = encryptKInvForCoordinator(kInvBytes, coordinator.publicKey);
  const decrypted = decryptKInv(encrypted, coordinator.privateKey);

  assertEqual(kInvBytes, decrypted, "Decrypted k⁻¹ must match original");
});

test("k⁻¹ encrypted with coordinator A cannot be decrypted by coordinator B", () => {
  const coordA = generateKyberKeyPair();
  const coordB = generateKyberKeyPair();
  const kInvBytes = secp256k1.utils.randomPrivateKey();

  const encrypted = encryptKInvForCoordinator(kInvBytes, coordA.publicKey);
  let threw = false;
  try {
    const result = decryptKInv(encrypted, coordB.privateKey);
    // If it doesn't throw, check the result is different
    let allSame = true;
    for (let i = 0; i < kInvBytes.length; i++) {
      if (kInvBytes[i] !== result[i]) { allSame = false; break; }
    }
    if (allSame) threw = false; // would be a problem
  } catch {
    threw = true;
  }
  assert(threw, "k⁻¹ encrypted for coordinator A must not decrypt with coordinator B key");
});

test("encryptKInvForCoordinator rejects non-32-byte input", () => {
  const coord = generateKyberKeyPair();
  let threw = false;
  try {
    encryptKInvForCoordinator(randomBytes(31), coord.publicKey);
  } catch {
    threw = true;
  }
  assert(threw, "Should throw for non-32-byte k⁻¹ input");
});

// ---------------------------------------------------------------------------
// 6. PqcIdentityStore
// ---------------------------------------------------------------------------

console.log("\n=== PqcIdentityStore ===");

test("generate produces unique identities", () => {
  const store = new PqcIdentityStore();
  const id1 = store.generate(1);
  const id2 = store.generate(1);
  let kyberSame = true;
  for (let i = 0; i < id1.kyber.publicKey.length; i++) {
    if (id1.kyber.publicKey[i] !== id2.kyber.publicKey[i]) { kyberSame = false; break; }
  }
  assert(!kyberSame, "Two generated identities must have different Kyber keys");
});

test("getPublicBundle contains no private key material", () => {
  const store = new PqcIdentityStore();
  const identity = store.generate(2);
  const bundle = store.getPublicBundle(identity);
  assert(bundle.partyIndex === 2, "Party index must be preserved");
  assert(bundle.kyberPublicKey.length === 1184, "Kyber public key size correct");
  assert(bundle.dilithiumPublicKey.length === 1952, "Dilithium public key size correct");
  assert(!("privateKey" in bundle), "Bundle must not have privateKey field");
  assert(!("kyber" in bundle) || !("privateKey" in (bundle as any).kyber), "Bundle must not expose private keys");
});

test("serializeBundle → deserializeBundle round-trip", () => {
  const store = new PqcIdentityStore();
  const identity = store.generate(3);
  const bundle = store.getPublicBundle(identity);
  const serialized = store.serializeBundle(bundle);
  const recovered = store.deserializeBundle(serialized);
  assert(recovered.partyIndex === bundle.partyIndex, "Party index preserved");
  assertEqual(recovered.kyberPublicKey, bundle.kyberPublicKey, "Kyber public key preserved");
  assertEqual(recovered.dilithiumPublicKey, bundle.dilithiumPublicKey, "Dilithium public key preserved");
});

// ---------------------------------------------------------------------------
// 7. PQC-Authenticated Actions (pqc-auth.ts)
// ---------------------------------------------------------------------------

console.log("\n=== PQC-Authenticated Actions ===");

test("authenticateAction + verifyAction round-trip", () => {
  const store = new PqcIdentityStore();
  const identity = store.generate(1);
  const bundle = store.getPublicBundle(identity);

  const payload = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
  const action = authenticateAction(payload, identity);
  const valid = verifyAction(action, [bundle]);
  assert(valid, "verifyAction must return true for valid authenticated action");
});

test("verifyAction with unknown party → false", () => {
  const store = new PqcIdentityStore();
  const identity = store.generate(1);
  // Bundles list has party 2 only, not party 1
  const otherBundle = store.getPublicBundle(store.generate(2));

  const payload = randomBytes(32);
  const action = authenticateAction(payload, identity);
  const valid = verifyAction(action, [otherBundle]);
  assert(!valid, "verifyAction must fail if party is not in known bundles");
});

test("verifyAction with wrong bundle (substituted public key) → false", () => {
  const store = new PqcIdentityStore();
  const identity = store.generate(1);
  const wrongIdentity = store.generate(1); // same party index, different keys
  const wrongBundle = store.getPublicBundle(wrongIdentity);

  const payload = randomBytes(32);
  const action = authenticateAction(payload, identity);
  const valid = verifyAction(action, [wrongBundle]);
  assert(!valid, "verifyAction must fail if public key does not match bundle");
});

test("verifyAction with tampered payload → false", () => {
  const store = new PqcIdentityStore();
  const identity = store.generate(1);
  const bundle = store.getPublicBundle(identity);

  const payload = randomBytes(32);
  const action = authenticateAction(payload, identity);

  // Tamper the payload
  const tampered = { ...action, payload: randomBytes(32) };
  const valid = verifyAction(tampered, [bundle]);
  assert(!valid, "verifyAction must fail if payload is tampered");
});

test("verifyAction with expired timestamp (replay) → false", () => {
  const store = new PqcIdentityStore();
  const identity = store.generate(1);
  const bundle = store.getPublicBundle(identity);

  const payload = randomBytes(32);
  const oldTimestamp = Date.now() - 10 * 60 * 1000; // 10 minutes ago
  const action = authenticateAction(payload, identity, oldTimestamp);
  const valid = verifyAction(action, [bundle]);
  assert(!valid, "verifyAction must reject actions older than MAX_AGE_MS");
});

test("verifyAction with future timestamp (clock skew attack) → false", () => {
  const store = new PqcIdentityStore();
  const identity = store.generate(1);
  const bundle = store.getPublicBundle(identity);

  const payload = randomBytes(32);
  const futureTimestamp = Date.now() + 10 * 60 * 1000; // 10 minutes in future
  const action = authenticateAction(payload, identity, futureTimestamp);
  const valid = verifyAction(action, [bundle]);
  assert(!valid, "verifyAction must reject actions with future timestamp");
});

test("serializeAction → deserializeAction → verifyAction round-trip", () => {
  const store = new PqcIdentityStore();
  const identity = store.generate(2);
  const bundle = store.getPublicBundle(identity);

  const payload = randomBytes(64);
  const action = authenticateAction(payload, identity);
  const serialized = serializeAction(action);
  const recovered = deserializeAction(serialized);
  const valid = verifyAction(recovered, [bundle]);
  assert(valid, "Serialized + deserialized action must still verify");
});

test("actionDigest produces deterministic 32-byte hash", () => {
  const store = new PqcIdentityStore();
  const identity = store.generate(1);

  const payload = randomBytes(32);
  const action = authenticateAction(payload, identity);
  const digest1 = actionDigest(action);
  const digest2 = actionDigest(action);
  assert(digest1.length === 32, "Digest must be 32 bytes");
  assertEqual(digest1, digest2, "Digest must be deterministic");
});

// ---------------------------------------------------------------------------
// 8. Full PQC identity lifecycle (generate → public bundle → sign → verify)
// ---------------------------------------------------------------------------

console.log("\n=== Full PQC Protocol Simulation ===");

test("3-party signing session with PQC auth on all actions", () => {
  const store = new PqcIdentityStore();

  // Each party generates their PQC identity
  const identities = [1, 2, 3].map((i) => store.generate(i));
  const bundles = identities.map((id) => store.getPublicBundle(id));

  // Simulate each party authenticating a submit_partial_sig action
  const results: boolean[] = [];
  for (const identity of identities) {
    const fakePartialSig = randomBytes(32);
    // In real code, this would be buildSubmitPartialSigArgs(...)
    const payload = new Uint8Array([...new Uint8Array([0x00, 0x00, 0x00, 0x00]), ...fakePartialSig]);
    const action = authenticateAction(payload, identity);
    const valid = verifyAction(action, bundles);
    results.push(valid);
  }

  assert(results.every((v) => v), "All 3 party actions must verify");
});

test("Coordinator encrypts response to each party using Kyber", () => {
  const store = new PqcIdentityStore();
  const identities = [1, 2, 3].map((i) => store.generate(i));

  // Coordinator sends each party their k_inv encrypted with party's Kyber key
  const kInvBytes = secp256k1.utils.randomPrivateKey();

  for (const identity of identities) {
    const encrypted = encryptKInvForCoordinator(kInvBytes, identity.kyber.publicKey);
    const decrypted = decryptKInv(encrypted, identity.kyber.privateKey);
    assertEqual(kInvBytes, decrypted, `k⁻¹ round-trip failed for party ${identity.partyIndex}`);
  }
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

// Wait a tick for any async tests to finish
await new Promise((r) => setTimeout(r, 100));

console.log(`\n${"─".repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
console.log(`${"─".repeat(50)}`);

if (failed > 0) {
  process.exit(1);
}
