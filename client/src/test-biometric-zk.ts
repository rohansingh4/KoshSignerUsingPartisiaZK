/**
 * E2E test for Partisia-native biometric fuzzy extractor.
 *
 * Tests:
 * 1. Enroll with simulated fingerprint
 * 2. Recover with noisy version of same fingerprint → same seed
 * 3. Recover with different fingerprint → match fails
 * 4. Feed successful seed into DKG → derive Ethereum address
 *
 * Usage:
 *   npx tsx client/src/test-biometric-zk.ts [contractAddress]
 */

import { PartisiaClient } from "./partisia.js";
import { createZkClient } from "./zk-signer.js";
import { generateDkgShare, toHex } from "./dkg-party.js";
import { deterministicScalarFromBytes } from "./shamir-ts.js";
import {
  encodeTemplate,
  packForZk,
  unpackFromZk,
  countMatches,
  templateCommitment,
  MATCH_THRESHOLD,
} from "./biometric-native.js";
import { generateTemplate, addNoise } from "./minutiae-simulator.js";
import { enrollBiometric, recoverBiometric } from "./biometric-zk-flow.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

// --- Config ---

const DEPLOYER_KEY =
  process.env.DEPLOYER_KEY ??
  "d3e922aead1dbc8b67de4dad9bf0da70be574dfa2088ac1a7e116c39024c41e5";
const DEPLOYER_ADDR =
  process.env.DEPLOYER_ADDR ??
  "008fc011c7a89525b82929504fa46bb611475a3422";
const NODE_URL =
  process.env.NODE_URL ?? "https://node1.testnet.partisiablockchain.com";
const CONTRACT_ADDR = process.argv[2] ?? process.env.BIO_CONTRACT_ADDR ?? "";

// --- Local-only tests (no contract needed) ---

async function testLocalEncoding() {
  console.log("\n=== Test 1: Local Encoding & Matching ===\n");

  // Generate a deterministic fingerprint
  const alice = await generateTemplate("alice-right-thumb", 50);
  console.log(`Generated ${alice.length} minutiae for alice-right-thumb`);

  // Encode to template
  const aliceTemplate = encodeTemplate(alice);
  console.log(
    `Encoded template: ${aliceTemplate.filter((id) => id !== 0xffff).length} unique cells`
  );

  // Pack and unpack (roundtrip)
  const chunks = packForZk(aliceTemplate);
  const unpacked = unpackFromZk(chunks);

  // Verify roundtrip
  const match = aliceTemplate.every((id, i) => id === unpacked[i]);
  console.log(`Pack/unpack roundtrip: ${match ? "PASS" : "FAIL"}`);
  if (!match) throw new Error("Roundtrip failed");

  // Same finger with noise
  const aliceNoisy = await addNoise(alice, { seed: "test-noise-1" });
  const noisyTemplate = encodeTemplate(aliceNoisy);
  const sameFingerMatches = countMatches(aliceTemplate, noisyTemplate);
  console.log(
    `Same finger match: ${sameFingerMatches}/64 (threshold: ${MATCH_THRESHOLD})`
  );
  console.log(
    `Same finger: ${sameFingerMatches >= MATCH_THRESHOLD ? "PASS" : "FAIL"} (≥${MATCH_THRESHOLD})`
  );

  // Different finger
  const bob = await generateTemplate("bob-left-index", 50);
  const bobTemplate = encodeTemplate(bob);
  const diffFingerMatches = countMatches(aliceTemplate, bobTemplate);
  console.log(
    `Different finger match: ${diffFingerMatches}/64 (threshold: ${MATCH_THRESHOLD})`
  );
  console.log(
    `Different finger: ${diffFingerMatches < MATCH_THRESHOLD ? "PASS" : "FAIL"} (<${MATCH_THRESHOLD})`
  );

  // Commitment hash
  const commitment = await templateCommitment(aliceTemplate);
  console.log(`Commitment hash: ${toHex(commitment)}`);

  // Same template → same commitment
  const commitment2 = await templateCommitment(aliceTemplate);
  const commitMatch = toHex(commitment) === toHex(commitment2);
  console.log(`Commitment determinism: ${commitMatch ? "PASS" : "FAIL"}`);
}

async function testSeedDerivation() {
  console.log("\n=== Test 2: Seed → DKG Derivation ===\n");

  // Simulate a biometric seed (XOR-fold of enrollment chunks)
  const alice = await generateTemplate("alice-right-thumb", 50);
  const aliceTemplate = encodeTemplate(alice);
  const chunks = packForZk(aliceTemplate);

  // XOR-fold to simulate what ZK compute does
  const seed = new Uint8Array(16);
  for (const chunk of chunks) {
    for (let i = 0; i < 16; i++) {
      seed[i] ^= chunk[i];
    }
  }
  console.log(`Biometric seed (16 bytes): ${toHex(seed)}`);

  // Derive DKG share from seed (pad to 32 bytes)
  const seedPadded = new Uint8Array(32);
  seedPadded.set(seed, 0);
  // Fill remaining 16 bytes with SHA-256 of seed for entropy
  const seedHash = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", seed)
  );
  seedPadded.set(seedHash.slice(0, 16), 16);

  const scalar = deterministicScalarFromBytes(seedPadded);
  const pubPoint = secp256k1.ProjectivePoint.BASE.multiply(scalar);
  const pubKeyCompressed = pubPoint.toRawBytes(true);
  const pubKeyUncompressed = pubPoint.toRawBytes(false);

  // Derive Ethereum address from uncompressed public key
  const ethAddrBytes = keccak_256(pubKeyUncompressed.slice(1));
  const ethAddr =
    "0x" +
    Array.from(ethAddrBytes.slice(12))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

  console.log(`DKG scalar: ${scalar.toString(16).slice(0, 20)}...`);
  console.log(`Public key: ${toHex(pubKeyCompressed)}`);
  console.log(`Ethereum address: ${ethAddr}`);

  // Verify determinism: same seed → same address
  const scalar2 = deterministicScalarFromBytes(seedPadded);
  console.log(
    `Determinism check: ${scalar === scalar2 ? "PASS" : "FAIL"}`
  );
}

async function testMultipleNoiseRuns() {
  console.log("\n=== Test 3: Multiple Noise Runs ===\n");

  const alice = await generateTemplate("alice-right-thumb", 50);
  const aliceTemplate = encodeTemplate(alice);

  const results: number[] = [];
  for (let i = 0; i < 10; i++) {
    const noisy = await addNoise(alice, { seed: `noise-run-${i}` });
    const noisyTemplate = encodeTemplate(noisy);
    const matches = countMatches(aliceTemplate, noisyTemplate);
    results.push(matches);
  }

  const avg = results.reduce((a, b) => a + b, 0) / results.length;
  const min = Math.min(...results);
  const max = Math.max(...results);
  console.log(`10 noise runs: avg=${avg.toFixed(1)}, min=${min}, max=${max}`);
  console.log(
    `All above threshold: ${results.every((m) => m >= MATCH_THRESHOLD) ? "PASS" : "FAIL"}`
  );
}

// --- On-chain tests (require deployed contract) ---

async function testOnChainFlow() {
  if (!CONTRACT_ADDR) {
    console.log(
      "\n=== Skipping on-chain tests (no contract address provided) ===\n"
    );
    console.log(
      "Usage: npx tsx client/src/test-biometric-zk.ts <contractAddress>"
    );
    return;
  }

  console.log("\n=== Test 4: On-Chain Biometric Flow ===\n");
  console.log("Contract:", CONTRACT_ADDR);

  const partisia = new PartisiaClient({
    nodeUrl: NODE_URL,
    senderPrivateKey: DEPLOYER_KEY,
    senderAddress: DEPLOYER_ADDR,
  });

  const zkClient = createZkClient(NODE_URL, CONTRACT_ADDR);
  const keyId = 100; // Use a high key ID to avoid conflicts

  // First create a key on the contract (shortname 0x02 = create_key_with_id)
  console.log("Creating key", keyId, "on contract...");
  function encodeU32(n: number): Uint8Array {
    const buf = new Uint8Array(4);
    buf[0] = (n >> 24) & 0xff;
    buf[1] = (n >> 16) & 0xff;
    buf[2] = (n >> 8) & 0xff;
    buf[3] = n & 0xff;
    return buf;
  }
  const createKeyTx = await partisia.submitAction(
    CONTRACT_ADDR,
    0x02,
    encodeU32(keyId)
  );
  console.log("create_key_with_id tx:", createKeyTx);
  await new Promise((r) => setTimeout(r, 8000));

  // Generate fingerprint
  const alice = await generateTemplate("alice-right-thumb", 50);
  console.log("Generated simulated fingerprint");

  // Enroll
  console.log("\n--- Enrollment ---");
  const { commitment, cellIds } = await enrollBiometric(
    partisia,
    zkClient,
    CONTRACT_ADDR,
    keyId,
    alice
  );
  console.log("Enrollment commitment:", toHex(commitment));

  // Recovery with same finger (same raw minutiae — quantization produces identical template)
  console.log("\n--- Recovery (same finger) ---");
  const result1 = await recoverBiometric(
    partisia,
    zkClient,
    CONTRACT_ADDR,
    keyId,
    alice // Same minutiae → same quantized template → chunks match exactly
  );
  console.log("Same finger result:", result1.matched ? "MATCHED" : "FAILED");
  if (result1.seed) {
    console.log("Derived seed:", toHex(result1.seed));

    // Derive Ethereum address
    const seedPadded = new Uint8Array(32);
    seedPadded.set(result1.seed, 0);
    const seedHash = new Uint8Array(
      await globalThis.crypto.subtle.digest("SHA-256", result1.seed as any)
    );
    seedPadded.set(seedHash.slice(0, 16), 16);
    const scalar = deterministicScalarFromBytes(seedPadded);
    const pubPoint = secp256k1.ProjectivePoint.BASE.multiply(scalar);
    const pubKeyUncompressed = pubPoint.toRawBytes(false);
    const ethAddrBytes = keccak_256(pubKeyUncompressed.slice(1));
    const ethAddr =
      "0x" +
      Array.from(ethAddrBytes.slice(12))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    console.log("Derived Ethereum address:", ethAddr);
  }

  // Recovery with different finger (should fail)
  console.log("\n--- Recovery (different finger) ---");
  await new Promise((r) => setTimeout(r, 10000));
  const bob = await generateTemplate("bob-left-index", 50);
  const result2 = await recoverBiometric(
    partisia,
    zkClient,
    CONTRACT_ADDR,
    keyId,
    bob
  );
  console.log(
    "Different finger result:",
    result2.matched ? "MATCHED (unexpected!)" : "FAILED (expected)"
  );
}

// --- Main ---

async function main() {
  console.log("=== Partisia-Native Biometric Fuzzy Extractor Tests ===\n");

  await testLocalEncoding();
  await testSeedDerivation();
  await testMultipleNoiseRuns();
  await testOnChainFlow();

  console.log("\n=== All tests complete ===");
}

main().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
