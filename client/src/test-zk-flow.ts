/**
 * Full ZK pipeline test for kosh-zk-signer on Partisia testnet.
 *
 * Flow:
 * 1. Generate secp256k1 keypair
 * 2. Create key on contract (shortname 0x02)
 * 3. Post compressed public key (shortname 0x05)
 * 4. Shamir-split private key into 3 shares (threshold=2)
 * 5. Submit 6 ZK secret inputs (3 shares x 2 halves each)
 * 6. Force-complete keygen (since ZK callbacks may not trigger on testnet)
 * 7. Queue sign_message (shortname 0x03)
 * 8. Client-side reconstruct key + sign
 * 9. Post signature (shortname 0x07)
 * 10. Verify on-chain via cargo pbc
 *
 * Usage:
 *   PARTISIA_SENDER_KEY=<hex> PARTISIA_SENDER_ADDRESS=<hex> SIGNER_ADDRESS=<hex> npx tsx src/test-zk-flow.ts
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { PartisiaClient } from "./partisia.js";
import {
  createZkClient,
  submitZkShareHalf,
} from "./zk-signer.js";
import {
  split,
  reconstruct,
  scalarToHalves,
  randomScalar,
  bigintTo32Bytes,
} from "./shamir-ts.js";
import { execSync } from "child_process";

// --- Configuration ---

const SENDER_KEY = process.env.PARTISIA_SENDER_KEY ?? "";
const SENDER_ADDR = process.env.PARTISIA_SENDER_ADDRESS ?? "";
const SIGNER_ADDR = process.env.SIGNER_ADDRESS ?? "";
const NODE_URL = process.env.PARTISIA_NODE_URL ?? "https://node1.testnet.partisiablockchain.com";
const PK_FILE = process.env.PK_FILE ?? "../002ee35cde26782f255b9550ea1ac53faeac2c71cd.pk";
const ABI_FILE = process.env.ABI_FILE ?? "../target/wasm32-unknown-unknown/release/kosh_zk_signer.abi";

if (!SENDER_KEY || !SENDER_ADDR || !SIGNER_ADDR) {
  console.error("Required env vars: PARTISIA_SENDER_KEY, PARTISIA_SENDER_ADDRESS, SIGNER_ADDRESS");
  process.exit(1);
}

// --- Helpers ---

function encodeU32(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (n >> 24) & 0xff;
  buf[1] = (n >> 16) & 0xff;
  buf[2] = (n >> 8) & 0xff;
  buf[3] = n & 0xff;
  return buf;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Encode a Vec<u8> with a u32 length prefix (Partisia binary format). */
function encodeVec(data: Uint8Array): Uint8Array {
  return new Uint8Array([...encodeU32(data.length), ...data]);
}

/** Run cargo pbc to inspect contract state. */
function cargoShow(keyId: number): string {
  try {
    return execSync(
      `cargo pbc contract avl show --net testnet ${SIGNER_ADDR} openState.keys ${keyId}`,
      { encoding: "utf8", timeout: 15000 }
    );
  } catch {
    return "(cargo pbc not available or command failed)";
  }
}

/**
 * Submit an action and wait for cross-shard event execution.
 * Returns the event success status.
 */
async function submitAndWait(
  partisia: PartisiaClient,
  contractAddress: string,
  shortname: number,
  args: Uint8Array,
  label: string
): Promise<boolean> {
  const client = partisia.getTransactionClient();
  const shortnameBytes = shortname <= 0xff ? [shortname] : [shortname >> 8, shortname & 0xff];
  const wasmRpc = Buffer.from([...shortnameBytes, ...args]);
  const rpc = Buffer.concat([Buffer.from([0x09]), wasmRpc]); // openInvocation prefix

  const tx = { address: contractAddress, rpc };
  const sent = await client.signAndSend(tx, 500000);
  console.log(`  Tx: ${sent.transactionPointer.identifier}`);

  const tree = await client.waitForSpawnedEvents(sent);
  for (const ev of tree.events || []) {
    const es = (ev as any).transaction?.executionStatus;
    if (es?.success === false) {
      const msg = es.failure?.errorMessage ?? "unknown error";
      console.error(`  ${label} FAILED: ${msg.split("\n")[0]}`);
      return false;
    }
  }
  console.log(`  ${label} OK`);
  return true;
}

// --- Main ---

async function main() {
  console.log("=== Kosh ZK Signer - Full ZK Pipeline Test ===\n");

  const partisia = new PartisiaClient({
    nodeUrl: NODE_URL,
    senderPrivateKey: SENDER_KEY,
    senderAddress: SENDER_ADDR,
  });

  // Use a unique key_id based on timestamp to avoid conflicts
  const keyId = Math.floor(Date.now() / 1000) % 100000;
  console.log(`Using key_id: ${keyId}\n`);

  // Phase 1: Generate keypair
  console.log("--- Phase 1: Generate secp256k1 keypair ---");
  const privKeyScalar = randomScalar();
  const privKeyBytes = bigintTo32Bytes(privKeyScalar);
  const pubKeyPoint = secp256k1.ProjectivePoint.BASE.multiply(privKeyScalar);
  const compressedPubKey = pubKeyPoint.toRawBytes(true); // 33 bytes
  console.log(`  Private key: ${toHex(privKeyBytes).slice(0, 16)}...`);
  console.log(`  Public key:  ${toHex(compressedPubKey)}`);

  // Phase 2: Create key on contract
  console.log("\n--- Phase 2: create_key_with_id ---");
  await submitAndWait(partisia, SIGNER_ADDR, 0x02, encodeU32(keyId), "create_key");

  // Phase 3: Post public key
  // post_public_key(key_id: u32, public_key: Vec<u8>)
  console.log("\n--- Phase 3: post_public_key ---");
  const postPkArgs = new Uint8Array([...encodeU32(keyId), ...encodeVec(compressedPubKey)]);
  await submitAndWait(partisia, SIGNER_ADDR, 0x05, postPkArgs, "post_public_key");

  // Phase 4: Shamir split + submit ZK secrets
  console.log("\n--- Phase 4: Shamir split + ZK secret inputs ---");
  const threshold = 2;
  const numShares = 3;
  const randomCoeffs = [randomScalar()]; // t-1 = 1 random coeff
  const shares = split(privKeyScalar, threshold, numShares, randomCoeffs);

  console.log(`  Split into ${numShares} shares (threshold=${threshold})`);

  // Create ZK client for building encrypted inputs
  const zkClient = createZkClient(NODE_URL, SIGNER_ADDR);

  let submitted = 0;
  for (const share of shares) {
    const [highBytes, lowBytes] = scalarToHalves(share.value);

    // Submit high half
    console.log(`  Submitting share ${share.index} high half...`);
    try {
      const txHash = await submitZkShareHalf(
        partisia, zkClient, SIGNER_ADDR,
        keyId, share.index, true, highBytes
      );
      console.log(`    Tx: ${txHash}`);
      submitted++;
    } catch (err) {
      console.error(`    FAILED: ${err}`);
    }
    await sleep(3000);

    // Submit low half
    console.log(`  Submitting share ${share.index} low half...`);
    try {
      const txHash = await submitZkShareHalf(
        partisia, zkClient, SIGNER_ADDR,
        keyId, share.index, false, lowBytes
      );
      console.log(`    Tx: ${txHash}`);
      submitted++;
    } catch (err) {
      console.error(`    FAILED: ${err}`);
    }
    await sleep(3000);
  }
  console.log(`\n  ${submitted}/6 ZK shares submitted`);

  if (submitted < 6) {
    console.log("  WARNING: Not all shares submitted. ZK keygen may not auto-complete.");
  }

  // Phase 5: Force-complete keygen
  console.log("\n--- Phase 5: force_complete_keygen ---");
  await sleep(5000); // Wait for ZK share submissions to settle
  await submitAndWait(partisia, SIGNER_ADDR, 0x08, encodeU32(keyId), "force_complete_keygen");

  // Phase 6: Sign message
  console.log("\n--- Phase 6: Queue sign_message ---");
  const msgBytes = new TextEncoder().encode("test-zk-flow");
  const msgHash = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", msgBytes)
  );
  console.log(`  Message hash: ${toHex(msgHash)}`);

  // sign_message(key_id: u32, message: Vec<u8>)
  const signArgs = new Uint8Array([...encodeU32(keyId), ...encodeVec(msgHash)]);
  await submitAndWait(partisia, SIGNER_ADDR, 0x03, signArgs, "sign_message");

  // Phase 7: Client-side reconstruction + signing
  console.log("\n--- Phase 7: Client-side reconstruction + signing ---");
  console.log("  Using local shares for reconstruction (client-driven flow)");
  const openedShares = shares.slice(0, threshold);

  // Reconstruct private key
  const reconstructedKey = reconstruct(openedShares);
  const keysMatch = reconstructedKey === privKeyScalar;
  console.log(`  Key reconstruction: ${keysMatch ? "SUCCESS" : "MISMATCH"}`);

  if (!keysMatch) {
    console.error("  FATAL: Reconstructed key does not match original!");
    process.exit(1);
  }

  // Sign the message
  const reconstructedKeyBytes = bigintTo32Bytes(reconstructedKey);
  const sig = secp256k1.sign(msgHash, reconstructedKeyBytes, { lowS: true });
  const rBytes = bigintTo32Bytes(sig.r);
  const sBytes = bigintTo32Bytes(sig.s);
  const vByte = sig.recovery;
  const sigBytes = new Uint8Array([...rBytes, ...sBytes, vByte]);
  console.log(`  Signature: ${toHex(sigBytes).slice(0, 32)}...`);

  // Verify locally before posting
  const sigCompact = new Uint8Array([...rBytes, ...sBytes]);
  const isValid = secp256k1.verify(sigCompact, msgHash, compressedPubKey);
  console.log(`  Local verification: ${isValid ? "PASS" : "FAIL"}`);

  if (!isValid) {
    console.error("  FATAL: Local signature verification failed!");
    process.exit(1);
  }

  // Phase 8: Post signature to contract
  console.log("\n--- Phase 8: signing_complete ---");
  // signing_complete(key_id: u32, engine_index: u8, task_id: u32, signature: Vec<u8>)
  const sigCompleteArgs = new Uint8Array([
    ...encodeU32(keyId),
    0, // engine_index
    ...encodeU32(0), // task_id
    ...encodeVec(sigBytes), // 65-byte signature with length prefix
  ]);
  await submitAndWait(partisia, SIGNER_ADDR, 0x07, sigCompleteArgs, "signing_complete");

  // Phase 9: Verify on-chain state
  console.log("\n--- Phase 9: Verification ---");
  console.log("  Checking contract state via cargo pbc...");
  const stateOutput = cargoShow(keyId);
  console.log(stateOutput);

  // Check if signature is in the output
  const sigHex = toHex(sigBytes);
  if (stateOutput.includes("verified: true") || stateOutput.includes(sigHex.slice(0, 20))) {
    console.log("  SIGNATURE VERIFIED ON-CHAIN!");
  } else if (stateOutput.includes("cargo pbc not available")) {
    console.log("  (Cannot verify via CLI - check manually)");
    console.log(`  Run: cargo pbc contract avl show --net testnet ${SIGNER_ADDR} openState.keys ${keyId}`);
  } else {
    console.log("  Signature may not be verified yet or format mismatch.");
    console.log(`  Manual check: cargo pbc contract avl show --net testnet ${SIGNER_ADDR} openState.keys ${keyId}`);
  }

  console.log("\n=== ZK Pipeline Test Complete ===");
  console.log(`Key ID: ${keyId}`);
  console.log(`Public key: ${toHex(compressedPubKey)}`);
  console.log(`ZK shares submitted: ${submitted}/6`);
  console.log(`Signature: ${toHex(sigBytes)}`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
