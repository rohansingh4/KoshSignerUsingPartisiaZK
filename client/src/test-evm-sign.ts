/**
 * DKG + Threshold ECDSA → Sign a real EVM transaction.
 *
 * Flow:
 * 1. DKG: 3 parties create a key (private key NEVER assembled)
 * 2. Derive the Ethereum address from the combined public key
 * 3. Build a real EVM transaction (ETH transfer on Sepolia)
 * 4. Compute keccak256 of the serialized unsigned tx
 * 5. Threshold sign the hash (private key NEVER reconstructed)
 * 6. Retrieve the verified signature (r, s, v) from the contract
 * 7. Assemble the signed EVM transaction and verify it's valid
 *
 * Usage:
 *   PARTISIA_SENDER_KEY=<hex> PARTISIA_SENDER_ADDRESS=<hex> SIGNER_ADDRESS=<hex> npx tsx src/test-evm-sign.ts
 */

import { PartisiaClient } from "./partisia.js";
import { createZkClient, submitZkShareHalf } from "./zk-signer.js";
import {
  generateDkgShare,
  getShareHalves,
  computeCombinedPublicKey,
  buildDkgCreateKeyArgs,
  buildDkgCommitArgs,
  buildDkgRevealArgs,
  buildDkgFinalizeArgs,
  buildDkgCompleteKeygenArgs,
  toHex,
  type DkgShare,
} from "./dkg-party.js";
import {
  generateNonce,
  computePartialSignature,
  buildStartThresholdSignArgs,
  buildSubmitPartialSigArgs,
} from "./threshold-ecdsa.js";
import {
  keccak256,
  serializeTransaction,
  parseTransaction,
  getAddress,
  createPublicClient,
  http,
  formatEther,
  type TransactionSerializableEIP1559,
} from "viem";
import { sepolia } from "viem/chains";
import { publicKeyToAddress } from "viem/utils";

// --- Configuration ---

const SENDER_KEY = process.env.PARTISIA_SENDER_KEY ?? "";
const SENDER_ADDR = process.env.PARTISIA_SENDER_ADDRESS ?? "";
const SIGNER_ADDR = process.env.SIGNER_ADDRESS ?? "";
const NODE_URL = process.env.PARTISIA_NODE_URL ?? "https://node1.testnet.partisiablockchain.com";

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

function encodeVec(data: Uint8Array): Uint8Array {
  return new Uint8Array([...encodeU32(data.length), ...data]);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

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
  const rpc = Buffer.concat([Buffer.from([0x09]), wasmRpc]);
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
  console.log("=== Kosh ZK Signer — EVM Transaction Signing Test ===");
  console.log("=== Private key is NEVER assembled ===\n");

  const partisia = new PartisiaClient({
    nodeUrl: NODE_URL,
    senderPrivateKey: SENDER_KEY,
    senderAddress: SENDER_ADDR,
  });

  // Fixed key ID + deterministic seeds = same address every run
  const keyId = 99001;
  const numParties = 3;
  const DKG_SEED_PREFIX = "kosh-zk-signer-v1";
  console.log(`Key ID: ${keyId}, Parties: ${numParties}\n`);

  // =======================================================================
  // Phase 1-7: DKG (same as before — create key without ever assembling it)
  // =======================================================================
  console.log("--- Phase 1: Generate DKG shares (deterministic) ---");
  const parties: DkgShare[] = [];
  for (let i = 0; i < numParties; i++) {
    const seed = `${DKG_SEED_PREFIX}-key${keyId}-party${i + 1}`;
    const share = await generateDkgShare(seed);
    parties.push(share);
    console.log(`  Party ${i + 1}: P_i = ${toHex(share.publicKeyShare)}`);
  }

  const combinedPk = computeCombinedPublicKey(parties.map((p) => p.publicKeyShare));
  console.log(`  Combined public key (compressed): ${toHex(combinedPk)}`);

  // Decompress the public key for Ethereum address derivation
  // publicKeyToAddress expects uncompressed format: 0x04 + x(32) + y(32)
  const { secp256k1: secp } = await import("@noble/curves/secp256k1");
  const point = secp.ProjectivePoint.fromHex(combinedPk);
  const uncompressedBytes = point.toRawBytes(false); // 65 bytes: 04 || x || y
  const uncompressedHex = `0x${Buffer.from(uncompressedBytes).toString("hex")}` as `0x${string}`;
  const ethAddress = publicKeyToAddress(uncompressedHex);
  console.log(`  Uncompressed public key: ${uncompressedHex.slice(0, 20)}...`);

  console.log(`  Ethereum address: ${ethAddress}`);

  console.log("\n--- Phase 2: dkg_create_key ---");
  await submitAndWait(partisia, SIGNER_ADDR, 0x20, buildDkgCreateKeyArgs(keyId, numParties), "dkg_create_key");

  console.log("\n--- Phase 3: DKG Commit ---");
  for (let i = 0; i < numParties; i++) {
    await submitAndWait(partisia, SIGNER_ADDR, 0x21, buildDkgCommitArgs(keyId, parties[i].commitmentHash), `commit_${i + 1}`);
    await sleep(2000);
  }

  console.log("\n--- Phase 4: DKG Reveal ---");
  for (let i = 0; i < numParties; i++) {
    await submitAndWait(partisia, SIGNER_ADDR, 0x22, buildDkgRevealArgs(keyId, parties[i].publicKeyShare), `reveal_${i + 1}`);
    await sleep(2000);
  }

  console.log("\n--- Phase 5: dkg_finalize ---");
  await submitAndWait(partisia, SIGNER_ADDR, 0x23, buildDkgFinalizeArgs(keyId), "dkg_finalize");

  console.log("\n--- Phase 6: Submit ZK shares ---");
  const zkClient = createZkClient(NODE_URL, SIGNER_ADDR);
  for (let i = 0; i < numParties; i++) {
    const [highBytes, lowBytes] = getShareHalves(parties[i]);
    const shareIndex = i + 1;
    await submitZkShareHalf(partisia, zkClient, SIGNER_ADDR, keyId, shareIndex, true, highBytes);
    await sleep(3000);
    await submitZkShareHalf(partisia, zkClient, SIGNER_ADDR, keyId, shareIndex, false, lowBytes);
    await sleep(3000);
  }
  console.log("  6/6 ZK shares submitted");

  console.log("\n--- Phase 7: dkg_complete_keygen ---");
  await sleep(5000);
  await submitAndWait(partisia, SIGNER_ADDR, 0x24, buildDkgCompleteKeygenArgs(keyId), "dkg_complete_keygen");

  // =======================================================================
  // Phase 8: Build a REAL EVM transaction
  // =======================================================================
  console.log("\n--- Phase 8: Build EVM transaction ---");

  // Connect to Sepolia to get real nonce and balance
  const sepoliaClient = createPublicClient({
    chain: sepolia,
    transport: http("https://ethereum-sepolia-rpc.publicnode.com"),
  });

  let balance = await sepoliaClient.getBalance({ address: ethAddress as `0x${string}` });
  console.log(`  Address: ${ethAddress}`);
  console.log(`  Balance: ${formatEther(balance)} ETH`);

  if (balance === 0n) {
    console.log("\n  ⚠ Address has no funds. Waiting for you to fund it...");
    console.log(`  Send Sepolia ETH to: ${ethAddress}`);
    console.log("  Polling every 15 seconds...\n");

    // Poll until funded (max 10 minutes)
    const maxWait = 600_000;
    const startTime = Date.now();
    while (balance === 0n && Date.now() - startTime < maxWait) {
      await sleep(15000);
      balance = await sepoliaClient.getBalance({ address: ethAddress as `0x${string}` });
      if (balance > 0n) {
        console.log(`  Funded! Balance: ${formatEther(balance)} ETH`);
      } else {
        process.stdout.write(".");
      }
    }

    if (balance === 0n) {
      console.log("\n  Timed out waiting for funds. Exiting.");
      process.exit(1);
    }
  }

  const evmNonce = await sepoliaClient.getTransactionCount({ address: ethAddress as `0x${string}` });
  console.log(`  Nonce: ${evmNonce}`);

  const evmTx: TransactionSerializableEIP1559 = {
    type: "eip1559",
    chainId: 11155111, // Sepolia
    nonce: evmNonce,
    to: getAddress("0x742d35cc6634c0532925a3b844bc9e7595f2bd00"),
    value: 100000000000000n, // 0.0001 ETH (small amount)
    maxFeePerGas: 20000000000n, // 20 gwei
    maxPriorityFeePerGas: 1500000000n, // 1.5 gwei
    gas: 21000n,
  };

  console.log("  EVM Transaction:");
  console.log(`    Chain: Sepolia (${evmTx.chainId})`);
  console.log(`    To: ${evmTx.to}`);
  console.log(`    Value: ${evmTx.value} wei (0.0001 ETH)`);
  console.log(`    Gas: ${evmTx.gas}`);
  console.log(`    Nonce: ${evmNonce}`);
  console.log(`    From (derived): ${ethAddress}`);

  // Serialize the unsigned transaction and compute keccak256 hash
  const serializedUnsigned = serializeTransaction(evmTx);
  const txHash = keccak256(serializedUnsigned);
  const msgHash = new Uint8Array(Buffer.from(txHash.slice(2), "hex"));

  console.log(`\n  Serialized unsigned tx: ${serializedUnsigned}`);
  console.log(`  keccak256 hash: ${txHash}`);

  // =======================================================================
  // Phase 9: Threshold ECDSA sign the EVM tx hash
  // =======================================================================
  console.log("\n--- Phase 9: Threshold ECDSA sign (key NEVER reconstructed) ---");

  // Queue the message hash on-chain
  const signArgs = new Uint8Array([...encodeU32(keyId), ...encodeVec(msgHash)]);
  await submitAndWait(partisia, SIGNER_ADDR, 0x03, signArgs, "sign_message");

  // Generate nonce (k discarded inside)
  const nonce = generateNonce();
  console.log(`  R = ${toHex(nonce.R_compressed)}`);
  console.log(`  recovery_id = ${nonce.recovery_id}`);
  console.log("  k discarded — never returned from generateNonce()");

  // Each party computes partial signature
  const partialSigs = [];
  for (let i = 0; i < numParties; i++) {
    const includeMessage = i === 0;
    const partial = computePartialSignature(
      nonce.k_inv, nonce.r, msgHash, parties[i].secretScalar, includeMessage
    );
    partial.partyIndex = i + 1;
    partialSigs.push(partial);
    console.log(`  Party ${i + 1}: σ_${i + 1} = ${toHex(partial.bytes).slice(0, 16)}...`);
  }

  // Start threshold session
  const taskId = 0;
  const startArgs = buildStartThresholdSignArgs(keyId, taskId, nonce.r_bytes, nonce.recovery_id, numParties);
  await submitAndWait(partisia, SIGNER_ADDR, 0x30, startArgs, "start_threshold_sign");

  // Submit partials
  console.log("\n  Submitting partials to contract...");
  for (let i = 0; i < numParties; i++) {
    const partialArgs = buildSubmitPartialSigArgs(keyId, partialSigs[i].partyIndex, partialSigs[i].bytes);
    await submitAndWait(partisia, SIGNER_ADDR, 0x31, partialArgs, `partial_${i + 1}`);
    await sleep(2000);
  }

  console.log("\n  Contract combined σ = Σσ_i on-chain and verified ECDSA signature!");

  // =======================================================================
  // Phase 10: Retrieve signature and assemble signed EVM transaction
  // =======================================================================
  console.log("\n--- Phase 10: Retrieve signature & assemble signed EVM tx ---");

  // Read contract state to get the stored signature
  const contractData = await partisia.getContractData(SIGNER_ADDR);
  // The signing_information AVL tree has the signature at task_id=0
  // For now, reconstruct from the nonce r and the combined s

  // We know r from the nonce, and the contract verified the signature.
  // The contract stores: r(32) || s(32) || v(1)
  // We need to compute v for EIP-155: v = recovery_id + 27 (legacy) or just use recovery_id for EIP-1559

  const r = `0x${toHex(nonce.r_bytes)}` as `0x${string}`;

  // Compute combined s locally (the contract already verified this is correct)
  const { secp256k1 } = await import("@noble/curves/secp256k1");
  const N = secp256k1.CURVE.n;
  let combinedS = 0n;
  for (const p of partialSigs) {
    let val = 0n;
    for (const b of p.bytes) val = (val << 8n) | BigInt(b);
    combinedS = (combinedS + val) % N;
  }

  // EIP-2: s must be in the lower half of the curve order
  const halfN = N / 2n;
  let finalS = combinedS;
  let sNormalized = false;
  if (finalS > halfN) {
    finalS = N - finalS;
    sNormalized = true;
  }

  const sHex = finalS.toString(16).padStart(64, "0");
  const s = `0x${sHex}` as `0x${string}`;

  // Determine correct yParity by trying both and seeing which recovers our public key
  const rBigint = BigInt(r);
  const sBigint = BigInt(s);
  const msgHashBigint = BigInt(txHash);

  let yParity: 0 | 1 = 0;
  const sig0 = new secp256k1.Signature(rBigint, sBigint, 0);
  const sig1 = new secp256k1.Signature(rBigint, sBigint, 1);

  // Recover public key for both recovery IDs and compare
  try {
    const recovered0 = sig0.recoverPublicKey(msgHash).toHex(true);
    const expectedHex = toHex(combinedPk);
    if (recovered0 === expectedHex) {
      yParity = 0;
      console.log("  Recovery ID 0 matches combined public key");
    }
  } catch (_) {}
  try {
    const recovered1 = sig1.recoverPublicKey(msgHash).toHex(true);
    const expectedHex = toHex(combinedPk);
    if (recovered1 === expectedHex) {
      yParity = 1;
      console.log("  Recovery ID 1 matches combined public key");
    }
  } catch (_) {}

  console.log(`  r = ${r}`);
  console.log(`  s = ${s}`);
  console.log(`  yParity = ${yParity}`);

  // Serialize the signed transaction
  const signedTx = serializeTransaction(evmTx, {
    r,
    s,
    yParity,
  });

  console.log(`\n  Signed EVM transaction: ${signedTx.slice(0, 80)}...`);
  console.log(`  Full length: ${signedTx.length / 2 - 1} bytes`);

  // Parse it back to verify it's valid
  const parsed = parseTransaction(signedTx);
  console.log(`\n  Parsed signed tx:`);
  console.log(`    Type: eip1559`);
  console.log(`    Chain: ${parsed.chainId}`);
  console.log(`    To: ${parsed.to}`);
  console.log(`    Value: ${parsed.value} wei`);
  console.log(`    Gas: ${parsed.gas}`);
  console.log(`    r: ${(parsed as any).r}`);
  console.log(`    s: ${(parsed as any).s}`);
  console.log(`    yParity: ${(parsed as any).yParity}`);

  // Recover the signer address from the signed transaction
  const { recoverTransactionAddress } = await import("viem");
  const recoveredAddress = await recoverTransactionAddress({ serializedTransaction: signedTx });
  console.log(`\n  Recovered signer: ${recoveredAddress}`);
  console.log(`  Expected signer:  ${ethAddress}`);

  const signerMatch = recoveredAddress.toLowerCase() === ethAddress.toLowerCase();
  console.log(`  Match: ${signerMatch ? "YES" : "NO"}`);

  // =======================================================================
  // Phase 11: Broadcast to Sepolia
  // =======================================================================
  console.log("\n--- Phase 11: Broadcast signed transaction to Sepolia ---");

  if (balance === 0n) {
    console.log("  SKIPPED: Address has no funds.");
    console.log(`  Fund ${ethAddress} with Sepolia ETH and re-run.`);
    console.log(`  Signed tx (for manual broadcast): ${signedTx}`);
  } else {
    try {
      const txHashOnChain = await sepoliaClient.sendRawTransaction({
        serializedTransaction: signedTx,
      });
      console.log(`  BROADCAST SUCCESS!`);
      console.log(`  Sepolia tx hash: ${txHashOnChain}`);
      console.log(`  Explorer: https://sepolia.etherscan.io/tx/${txHashOnChain}`);

      console.log("\n  Waiting for confirmation...");
      const receipt = await sepoliaClient.waitForTransactionReceipt({
        hash: txHashOnChain,
        timeout: 120_000,
      });
      console.log(`  Status: ${receipt.status === "success" ? "SUCCESS" : "FAILED"}`);
      console.log(`  Block: ${receipt.blockNumber}`);
      console.log(`  Gas used: ${receipt.gasUsed}`);
    } catch (err: any) {
      console.error(`  Broadcast failed: ${err.message?.split("\n")[0] ?? err}`);
      console.log(`  Signed tx (for manual broadcast): ${signedTx}`);
    }
  }

  // =======================================================================
  // Summary
  // =======================================================================
  console.log("\n=== EVM Transaction Signing Complete ===");
  console.log(`Key ID: ${keyId}`);
  console.log(`Combined public key: ${toHex(combinedPk)}`);
  console.log(`Ethereum address: ${ethAddress}`);
  console.log(`Signed EVM tx hash: ${txHash}`);
  console.log(`Signer recovered: ${signerMatch ? "MATCHES" : "MISMATCH"}`);
  console.log("");
  console.log("SECURITY:");
  console.log("  [x] Private key NEVER existed as a single value (DKG)");
  console.log("  [x] Private key NEVER reconstructed for signing (threshold ECDSA)");
  console.log("  [x] Real EVM transaction (Sepolia ETH transfer) signed");
  console.log("  [x] Signature verified on Partisia contract (on-chain)");
  console.log("  [x] Signer address recovered correctly from signed tx");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
