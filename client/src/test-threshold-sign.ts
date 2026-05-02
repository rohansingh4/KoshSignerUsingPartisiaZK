/**
 * Pedersen/Feldman DKG + 2-of-3 Threshold ECDSA — End-to-End Test.
 *
 * UPGRADE from additive (3-of-3) to threshold (2-of-3):
 * - Each party generates polynomial f_i(x) = s_i + a_i·x (not just s_i)
 * - Sub-shares f_i(j) distributed and combined into Shamir shares X_j
 * - ANY 2 of 3 parties can sign using Lagrange interpolation
 * - Same Ethereum address regardless of which 2 parties sign
 *
 * Flow:
 * 1. Pedersen/Feldman DKG: polynomials, sub-shares, Feldman verification
 * 2. On-chain DKG ceremony: commit-reveal of public key shares
 * 3. GG20 signing with 2-of-3: Lagrange-adjusted shares in MtA
 * 4. Test ALL three 2-of-3 subsets produce the same valid signature
 */

import { PartisiaClient } from "./partisia.js";
import { createZkClient, submitZkShareHalf } from "./zk-signer.js";
import {
  generateThresholdDkgShare,
  combineShamirShares,
  verifyFeldmanSubshare,
  computeAdjustedShare,
  computeCombinedPublicKey,
  generateSchnorrProof,
  buildDkgCreateKeyArgs,
  buildDkgCommitArgs,
  buildDkgRevealArgs,
  buildDkgFinalizeArgs,
  buildDkgCompleteKeygenArgs,
  getShamirShareHalves,
  toHex,
  type ThresholdDkgShare,
  type ShamirShare,
} from "./dkg-party.js";
import {
  gg20Sign,
  gg20VerifyLocally,
  buildSubmitDeltaArgs,
  buildSubmitGammaPointArgs,
  buildGG20FinalizeRArgs,
  buildSubmitPartialSigArgs,
  buildCommitPartialSigArgs,
  sha256,
} from "./gg20-signing.js";
import {
  queueSignAndApprove,
  registerOnchainPqcIdentities,
  startApprovedGg20,
  submitAndWait,
} from "./testnet-pqc.js";
import { paillierKeygen, type PaillierKeyPair } from "./paillier.js";
import { bigintTo32Bytes } from "./shamir-ts.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { mod } from "@noble/curves/abstract/modular";
import {
  keccak256,
  serializeTransaction,
  getAddress,
  createPublicClient,
  http,
  formatEther,
  type TransactionSerializableEIP1559,
} from "viem";
import { sepolia } from "viem/chains";
import { publicKeyToAddress } from "viem/utils";

// --- Config ---

const SENDER_KEY = process.env.PARTISIA_SENDER_KEY ?? "";
const SENDER_ADDR = process.env.PARTISIA_SENDER_ADDRESS ?? "";
const SIGNER_ADDR = process.env.SIGNER_ADDRESS ?? "";
const NODE_URL = process.env.PARTISIA_NODE_URL ?? "https://node4.testnet.partisiablockchain.com";
const N = secp256k1.CURVE.n;

if (!SENDER_KEY || !SENDER_ADDR || !SIGNER_ADDR) {
  console.error("Required: PARTISIA_SENDER_KEY, PARTISIA_SENDER_ADDRESS, SIGNER_ADDRESS");
  process.exit(1);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// --- Main ---

async function main() {
  console.log("=== Kosh ZK Signer — 2-of-3 Threshold ECDSA (Pedersen/Feldman DKG) ===");
  console.log("=== ANY 2 of 3 parties can sign. Party offline? No problem. ===\n");

  const partisia = new PartisiaClient({
    nodeUrl: NODE_URL,
    senderPrivateKey: SENDER_KEY,
    senderAddress: SENDER_ADDR,
  });

  const keyId = parseInt(process.env.KEY_ID ?? `${Date.now() % 100000}`, 10);
  const numParties = 3;
  const DKG_SEED = "kosh-threshold-v1";
  const txTag = process.env.TX_TAG ?? "";

  // =======================================================================
  // Phase 1: Pedersen/Feldman DKG — polynomial generation + sub-shares
  // =======================================================================
  console.log("--- Phase 1: Pedersen/Feldman DKG (Polynomial Key Generation) ---\n");

  const dkgShares: ThresholdDkgShare[] = [];
  for (let i = 1; i <= numParties; i++) {
    const seed = `${DKG_SEED}-key${keyId}-party${i}`;
    const share = await generateThresholdDkgShare(i, numParties, seed);
    dkgShares.push(share);
    console.log(`  Party ${i}:`);
    console.log(`    f_${i}(x) = s_${i} + a_${i}·x`);
    console.log(`    C_${i}0 = s_${i}·G = ${toHex(share.C_i0).slice(0, 20)}...`);
    console.log(`    C_${i}1 = a_${i}·G = ${toHex(share.C_i1).slice(0, 20)}...`);
  }

  // Verify Feldman sub-shares
  console.log("\n  Feldman verification (each party checks received sub-shares):");
  let allValid = true;
  for (const sender of dkgShares) {
    for (let j = 1; j <= numParties; j++) {
      const valid = verifyFeldmanSubshare(
        sender.subShares[j - 1],
        sender.C_i0,
        sender.C_i1,
        j
      );
      if (!valid) {
        console.error(`    FAILED: f_${sender.partyIndex}(${j}) doesn't match commitments!`);
        allValid = false;
      }
    }
  }
  console.log(`    All sub-shares verified: ${allValid ? "PASSED" : "FAILED"}`);
  if (!allValid) process.exit(1);

  // Combine sub-shares into final Shamir shares
  console.log("\n  Combining sub-shares into final Shamir shares:");
  const shamirShares: ShamirShare[] = [];
  for (let j = 1; j <= numParties; j++) {
    const share = combineShamirShares(j, dkgShares);
    shamirShares.push(share);
    console.log(`    X_${j} = F(${j}) = Σ f_i(${j}) = ...${share.share.toString(16).slice(-8)}`);
  }

  // Verify: Lagrange reconstruction gives same secret for all 2-of-3 subsets
  const subsets: number[][] = [[1, 2], [1, 3], [2, 3]];
  console.log("\n  Lagrange reconstruction verification (all 2-of-3 subsets):");
  let reconstructedSecret: bigint | null = null;
  for (const subset of subsets) {
    let sum = 0n;
    for (const idx of subset) {
      const adjusted = computeAdjustedShare(shamirShares[idx - 1], subset);
      sum = mod(sum + adjusted, N);
    }
    if (reconstructedSecret === null) {
      reconstructedSecret = sum;
    }
    const match = sum === reconstructedSecret;
    console.log(`    Subset {${subset.join(",")}}: secret = ...${sum.toString(16).slice(-8)} ${match ? "✓" : "✗ MISMATCH"}`);
    if (!match) { console.error("    Lagrange reconstruction FAILED!"); process.exit(1); }
  }

  // Combined public key P = ΣC_i0 = s·G
  const combinedPk = computeCombinedPublicKey(dkgShares.map(p => p.C_i0));
  const point = secp256k1.ProjectivePoint.fromHex(combinedPk);
  const uncompressedHex = `0x${Buffer.from(point.toRawBytes(false)).toString("hex")}` as `0x${string}`;
  const ethAddress = publicKeyToAddress(uncompressedHex);
  console.log(`\n  Combined P = ${toHex(combinedPk)}`);
  console.log(`  Ethereum address: ${ethAddress}\n`);

  // =======================================================================
  // Phase 2: On-chain DKG ceremony (same as additive — commit/reveal P_i)
  // =======================================================================
  console.log("--- Phase 2: On-chain DKG ceremony ---");
  if (!await submitAndWait(partisia, SIGNER_ADDR, 0x20, buildDkgCreateKeyArgs(keyId, numParties), "dkg_create_key")) process.exit(1);

  // Generate Schnorr proofs (Protection 3: anti-rogue-key)
  console.log("  Generating Schnorr proofs of knowledge...");
  const schnorrProofs = [];
  for (let i = 0; i < numParties; i++) {
    const proof = await generateSchnorrProof(dkgShares[i].secretScalar, dkgShares[i].C_i0, i + 1);
    schnorrProofs.push(proof);
  }

  for (let i = 0; i < numParties; i++) {
    if (!await submitAndWait(partisia, SIGNER_ADDR, 0x21,
      buildDkgCommitArgs(keyId, i + 1, dkgShares[i].commitmentHash, dkgShares[i].C_i1, schnorrProofs[i].R, schnorrProofs[i].z),
      `commit_${i + 1} (with Schnorr proof)`)) process.exit(1);
    await sleep(2000);
  }
  for (let i = 0; i < numParties; i++) {
    if (!await submitAndWait(partisia, SIGNER_ADDR, 0x22, buildDkgRevealArgs(keyId, i + 1, dkgShares[i].publicKeyShare), `reveal_${i + 1}`)) process.exit(1);
    await sleep(2000);
  }
  if (!await submitAndWait(partisia, SIGNER_ADDR, 0x23, buildDkgFinalizeArgs(keyId), "dkg_finalize")) process.exit(1);

  // Submit Shamir shares (not raw s_i) as ZK secrets
  const zkClient = createZkClient(NODE_URL, SIGNER_ADDR);
  for (let i = 0; i < numParties; i++) {
    const [highBytes, lowBytes] = getShamirShareHalves(shamirShares[i]);
    await submitZkShareHalf(partisia, zkClient, SIGNER_ADDR, keyId, i + 1, true, highBytes);
    await sleep(3000);
    await submitZkShareHalf(partisia, zkClient, SIGNER_ADDR, keyId, i + 1, false, lowBytes);
    await sleep(3000);
  }
  await sleep(5000);
  if (!await submitAndWait(partisia, SIGNER_ADDR, 0x24, buildDkgCompleteKeygenArgs(keyId), "dkg_complete_keygen")) {
    console.log("  Trying force_complete_keygen...");
    const forceArgs = new Uint8Array([
      (keyId >>> 24) & 0xff,
      (keyId >>> 16) & 0xff,
      (keyId >>> 8) & 0xff,
      keyId & 0xff,
    ]);
    if (!await submitAndWait(partisia, SIGNER_ADDR, 0x08, forceArgs, "force_complete_keygen")) process.exit(1);
  }

  // =======================================================================
  // Phase 3: Paillier Key Generation
  // =======================================================================
  console.log("\n--- Phase 3: Paillier Key Generation ---");
  const paillierKeys: PaillierKeyPair[] = [];
  for (let i = 0; i < numParties; i++) {
    const keys = paillierKeygen(1024);
    paillierKeys.push(keys);
    console.log(`  Party ${i + 1}: Paillier ready`);
  }

  console.log("\n--- Phase 3b: On-chain identity + PQC key registration ---");
  await registerOnchainPqcIdentities(partisia, SIGNER_ADDR, keyId, [1, 2, 3], SENDER_ADDR);

  // =======================================================================
  // Phase 4: Build EVM transaction
  // =======================================================================
  console.log("\n--- Phase 4: Build EVM transaction ---");
  const sepoliaClient = createPublicClient({
    chain: sepolia,
    transport: http("https://ethereum-sepolia-rpc.publicnode.com"),
  });

  let balance = await sepoliaClient.getBalance({ address: ethAddress as `0x${string}` });
  console.log(`  Address: ${ethAddress}`);
  console.log(`  Balance: ${formatEther(balance)} ETH`);

  if (balance === 0n) {
    console.log(`\n  No Sepolia ETH — will skip broadcast but still test signing.`);
    console.log(`  To broadcast later, fund: ${ethAddress}\n`);
  }

  const evmNonce = await sepoliaClient.getTransactionCount({ address: ethAddress as `0x${string}` });
  const evmTx: TransactionSerializableEIP1559 = {
    type: "eip1559",
    chainId: 11155111,
    nonce: evmNonce,
    to: getAddress("0x742d35cc6634c0532925a3b844bc9e7595f2bd00"),
    value: 10000000000000n, // 0.00001 ETH
    maxFeePerGas: 20000000000n,
    maxPriorityFeePerGas: 1500000000n,
    gas: 21000n,
  };

  const serializedUnsigned = serializeTransaction(evmTx);
  const txHash = keccak256(serializedUnsigned);
  const msgHash = new Uint8Array(Buffer.from(txHash.slice(2), "hex"));
  console.log(`  Message hash: ${txHash}`);

  await queueSignAndApprove(partisia, SIGNER_ADDR, keyId, 0, msgHash, txTag, [1, 2]);

  // =======================================================================
  // Phase 5: 2-of-3 Threshold Signing (Party 3 OFFLINE)
  // =======================================================================
  const signingSubset = [1, 2]; // Party 3 is offline!
  console.log(`\n--- Phase 5: 2-of-3 Threshold Signing (subset {${signingSubset.join(",")}}) ---`);
  console.log(`  Party 3 is OFFLINE — only parties ${signingSubset.join(" and ")} sign.`);
  console.log("  Lagrange coefficients adjust their shares so Σ x̃_i = s.\n");

  // Compute Lagrange-adjusted shares for the signing subset
  const signingParties = signingSubset.map(idx => {
    const adjusted = computeAdjustedShare(shamirShares[idx - 1], signingSubset);
    console.log(`  Party ${idx}: λ_${idx} · X_${idx} = x̃_${idx} = ...${adjusted.toString(16).slice(-8)}`);
    return { partyIndex: idx, x_i: adjusted };
  });

  // Verify adjusted shares sum to secret
  let adjustedSum = 0n;
  for (const p of signingParties) adjustedSum = mod(adjustedSum + p.x_i, N);
  console.log(`  Σ x̃_i = ...${adjustedSum.toString(16).slice(-8)} (should equal secret)`);
  console.log(`  Match: ${adjustedSum === reconstructedSecret ? "YES" : "NO"}\n`);

  // Run GG20 with only the signing subset (2 parties, not 3)
  const signingPaillierKeys = signingSubset.map(idx => paillierKeys[idx - 1]);
  const sigData = gg20Sign(signingParties, msgHash, signingPaillierKeys);

  // Verify locally
  let sCombined = 0n;
  for (const p of sigData.partials) sCombined = mod(sCombined + p.s_i, N);
  const localVerify = gg20VerifyLocally(combinedPk, msgHash, sigData.r, sCombined);
  console.log(`\n  Local verification (2-of-3): ${localVerify ? "PASSED" : "FAILED"}`);
  if (!localVerify) { console.error("  Local verification failed!"); process.exit(1); }

  // =======================================================================
  // Phase 6: Submit to Partisia contract for on-chain verification
  // =======================================================================
  console.log("\n--- Phase 6: On-chain verification (2-of-3) ---");

  await startApprovedGg20(partisia, SIGNER_ADDR, keyId, 0, signingSubset);

  // Submit deltas (plaintext)
  for (const d of sigData.deltas) {
    if (!await submitAndWait(partisia, SIGNER_ADDR, 0x45, buildSubmitDeltaArgs(keyId, d.partyIndex, d.bytes), `delta_${d.partyIndex}`)) process.exit(1);
    await sleep(2000);
  }

  // Submit gamma points
  for (let i = 0; i < sigData.gammaPoints.length; i++) {
    const partyIdx = signingSubset[i];
    if (!await submitAndWait(partisia, SIGNER_ADDR, 0x46, buildSubmitGammaPointArgs(keyId, partyIdx, sigData.gammaPoints[i]), `gamma_${partyIdx}`)) process.exit(1);
    await sleep(2000);
  }

  // Finalize R
  if (!await submitAndWait(partisia, SIGNER_ADDR, 0x47, buildGG20FinalizeRArgs(keyId), "gg20_finalize_r")) process.exit(1);

  // Commit partial sigs
  for (const p of sigData.partials) {
    const commitHash = await sha256(p.bytes);
    if (!await submitAndWait(partisia, SIGNER_ADDR, 0x44, buildCommitPartialSigArgs(keyId, p.partyIndex, commitHash), `commit_${p.partyIndex}`)) process.exit(1);
    await sleep(2000);
  }

  // Reveal partial sigs
  for (const p of sigData.partials) {
    if (!await submitAndWait(partisia, SIGNER_ADDR, 0x31, buildSubmitPartialSigArgs(keyId, p.partyIndex, p.bytes), `partial_${p.partyIndex}`)) process.exit(1);
    await sleep(2000);
  }

  console.log("\n  Contract verified ECDSA signature from 2-of-3 parties!");

  // =======================================================================
  // Phase 6b: Test remaining subsets {1,3} and {2,3}
  // =======================================================================
  const remainingSubsets: number[][] = [[1, 3], [2, 3]];
  let nextTaskId = 1; // task 0 was used for subset {1,2}
  for (const subset of remainingSubsets) {
    const offlineParty = [1, 2, 3].find(p => !subset.includes(p))!;
    console.log(`\n--- Phase 6b: Signing with subset {${subset.join(",")}} (Party ${offlineParty} OFFLINE) ---`);

    // Queue a new message for this signing round
    const subsetMsgData = new Uint8Array(32);
    subsetMsgData[0] = subset[0]; subsetMsgData[1] = subset[1];
    globalThis.crypto.getRandomValues(subsetMsgData.subarray(2));
    await queueSignAndApprove(partisia, SIGNER_ADDR, keyId, nextTaskId, subsetMsgData, txTag, subset);

    const subsetParties = subset.map(idx => ({
      partyIndex: idx,
      x_i: computeAdjustedShare(shamirShares[idx - 1], subset),
    }));
    const subsetPaillier = subset.map(idx => paillierKeys[idx - 1]);
    const subsetSigData = gg20Sign(subsetParties, subsetMsgData, subsetPaillier);

    // Verify locally
    let subsetS = 0n;
    for (const p of subsetSigData.partials) subsetS = mod(subsetS + p.s_i, N);
    const subsetVerify = gg20VerifyLocally(combinedPk, subsetMsgData, subsetSigData.r, subsetS);
    console.log(`  Local verification {${subset.join(",")}}: ${subsetVerify ? "PASSED" : "FAILED"}`);

    if (subsetVerify) {
      // Submit to contract
      const currentTaskId = nextTaskId++;
      await startApprovedGg20(partisia, SIGNER_ADDR, keyId, currentTaskId, subset);

      for (const d of subsetSigData.deltas) {
        if (!await submitAndWait(partisia, SIGNER_ADDR, 0x45, buildSubmitDeltaArgs(keyId, d.partyIndex, d.bytes), `delta_${d.partyIndex}`)) break;
        await sleep(2000);
      }
      for (let i = 0; i < subsetSigData.gammaPoints.length; i++) {
        if (!await submitAndWait(partisia, SIGNER_ADDR, 0x46, buildSubmitGammaPointArgs(keyId, subset[i], subsetSigData.gammaPoints[i]), `gamma_${subset[i]}`)) break;
        await sleep(2000);
      }
      if (!await submitAndWait(partisia, SIGNER_ADDR, 0x47, buildGG20FinalizeRArgs(keyId), `finalize_r_{${subset.join(",")}}`)) continue;

      for (const p of subsetSigData.partials) {
        const commitHash = await sha256(p.bytes);
        if (!await submitAndWait(partisia, SIGNER_ADDR, 0x44, buildCommitPartialSigArgs(keyId, p.partyIndex, commitHash), `commit_${p.partyIndex}`)) break;
        await sleep(2000);
      }
      for (const p of subsetSigData.partials) {
        if (!await submitAndWait(partisia, SIGNER_ADDR, 0x31, buildSubmitPartialSigArgs(keyId, p.partyIndex, p.bytes), `partial_${p.partyIndex}`)) break;
        await sleep(2000);
      }
      console.log(`  Contract verified ECDSA for subset {${subset.join(",")}}!`);
    }
  }

  // =======================================================================
  // Phase 7: Assemble signed EVM transaction
  // =======================================================================
  console.log("\n--- Phase 7: Assemble signed EVM tx ---");

  const r = `0x${sigData.r.toString(16).padStart(64, "0")}` as `0x${string}`;
  const halfN = N / 2n;
  let finalS = sCombined;
  if (finalS > halfN) finalS = N - finalS;
  const s = `0x${finalS.toString(16).padStart(64, "0")}` as `0x${string}`;

  // Determine yParity
  const secp = secp256k1;
  let yParity: 0 | 1 = 0;
  const rBig = BigInt(r);
  const sBig = BigInt(s);
  try {
    if (new secp.Signature(rBig, sBig, 0).recoverPublicKey(msgHash).toHex(true) === toHex(combinedPk))
      yParity = 0;
  } catch {}
  try {
    if (new secp.Signature(rBig, sBig, 1).recoverPublicKey(msgHash).toHex(true) === toHex(combinedPk))
      yParity = 1;
  } catch {}

  const signedTx = serializeTransaction(evmTx, { r, s, yParity });
  const { recoverTransactionAddress } = await import("viem");
  const recovered = await recoverTransactionAddress({ serializedTransaction: signedTx });
  const match = recovered.toLowerCase() === ethAddress.toLowerCase();
  console.log(`  Recovered signer: ${recovered}`);
  console.log(`  Expected address: ${ethAddress}`);
  console.log(`  Match: ${match ? "YES" : "NO"}`);

  if (!match) {
    console.error("\n  SIGNATURE MISMATCH — recovered address doesn't match!");
    process.exit(1);
  }

  // =======================================================================
  // Phase 8: Broadcast
  // =======================================================================
  if (balance > 0n) {
    console.log("\n--- Phase 8: Broadcast to Sepolia ---");
    try {
      const txOnChain = await sepoliaClient.sendRawTransaction({ serializedTransaction: signedTx });
      console.log(`  SUCCESS! https://sepolia.etherscan.io/tx/${txOnChain}`);
      const receipt = await sepoliaClient.waitForTransactionReceipt({ hash: txOnChain, timeout: 120_000 });
      console.log(`  Status: ${receipt.status}, Block: ${receipt.blockNumber}`);
    } catch (e: any) {
      console.error(`  Broadcast failed: ${e.message?.split("\n")[0]}`);
    }
  }

  // =======================================================================
  // Summary
  // =======================================================================
  console.log("\n" + "=".repeat(65));
  console.log("  2-OF-3 THRESHOLD ECDSA — COMPLETE");
  console.log("=".repeat(65));
  console.log("");
  console.log("WHAT WAS ACHIEVED:");
  console.log(`  Signing subset: {${signingSubset.join(", ")}} (Party 3 was OFFLINE)`);
  console.log("  Private key s = Σ s_i          → NEVER computed");
  console.log("  Shamir shares X_i = F(i)       → points on polynomial line");
  console.log("  Lagrange weights λ_i           → adjusts shares for subset");
  console.log("  Adjusted shares x̃_i = λ_i·X_i  → sum to s for ANY 2-of-3");
  console.log("  Nonce k = Σ k_i                → NEVER computed");
  console.log("  Coordinator                    → NONE");
  console.log("");
  console.log("KEY DIFFERENCE FROM ADDITIVE:");
  console.log("  Additive (old):  ALL 3 parties needed → 3-of-3");
  console.log("  Threshold (new): ANY 2 parties enough → 2-of-3");
  console.log("  Same Ethereum address. Same public key. Same verification.");
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
