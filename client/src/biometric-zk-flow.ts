/**
 * Biometric ZK flow — contract interaction for Partisia-native biometric enrollment & recovery.
 *
 * Enrollment: quantize minutiae → pack into 8×Sbi128 → submit as ZK secrets → commit hash on-chain.
 * Recovery: submit new scan as ZK secrets → trigger MPC match → get deterministic seed.
 *
 * Follows the same patterns as zk-signer.ts (submitZkShareHalf, serializeSbi128, etc).
 */

import { PartisiaClient } from "./partisia.js";
import { RealZkClient } from "@partisiablockchain/zk-client";
import { serializeSbi128 } from "./zk-signer.js";
import {
  encodeTemplate,
  packForZk,
  templateCommitment,
  type Minutia,
} from "./biometric-native.js";

// --- RPC encoding helpers ---

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

// --- Biometric enrollment ---

/**
 * Enroll a biometric template for a key.
 *
 * Steps:
 * 1. Encode minutiae → quantized cell IDs → pack into 8 chunks
 * 2. Compute SHA-256 commitment hash of the template
 * 3. Call bio_enroll_start (0x60) with commitment hash
 * 4. Submit 8 chunks as ZK secret inputs (0x62)
 *
 * @returns The commitment hash (can be used for verification later)
 */
export async function enrollBiometric(
  partisia: PartisiaClient,
  zkClient: RealZkClient,
  contractAddr: string,
  keyId: number,
  minutiae: Minutia[]
): Promise<{ commitment: Uint8Array; cellIds: number[] }> {
  // Step 1: Encode template
  const cellIds = encodeTemplate(minutiae);
  const chunks = packForZk(cellIds);

  // Step 2: Compute commitment
  const commitment = await templateCommitment(cellIds);

  // Step 3: Start enrollment on-chain
  console.log("[bio] Starting enrollment for key", keyId);
  const enrollArgs = new Uint8Array([
    ...encodeU32(keyId),
    ...encodeVec(commitment),
  ]);
  const enrollTx = await partisia.submitAction(contractAddr, 0x60, enrollArgs);
  console.log("[bio] bio_enroll_start tx:", enrollTx);

  // Wait for enrollment start to be processed
  await new Promise((r) => setTimeout(r, 5000));

  // Step 4: Submit 8 template chunks as ZK secrets
  for (let i = 0; i < 8; i++) {
    console.log(`[bio] Submitting enrollment chunk ${i}/8...`);
    await submitBiometricChunk(
      partisia,
      zkClient,
      contractAddr,
      keyId,
      i,
      chunks[i],
      0x62 // bio_submit_template shortname
    );
    // Small delay between submissions
    await new Promise((r) => setTimeout(r, 3000));
  }

  // Step 5: Poll until all 8 enrollment chunks are confirmed
  console.log("[bio] Waiting for enrollment confirmation...");
  await pollVariableCount(partisia, contractAddr, 8, "enrollment");
  console.log("[bio] Enrollment chunks confirmed on-chain (8/8)");

  // Step 6: Force-complete enrollment (callback may not set bio_enrolled reliably)
  console.log("[bio] Forcing enrollment completion...");
  const forceEnrollTx = await partisia.submitAction(
    contractAddr,
    0x61,
    encodeU32(keyId)
  );
  console.log("[bio] bio_force_enroll_complete tx:", forceEnrollTx);
  await new Promise((r) => setTimeout(r, 8000));
  return { commitment, cellIds };
}

// --- Biometric recovery ---

/**
 * Recover using a biometric scan.
 *
 * Steps:
 * 1. Encode minutiae → quantized cell IDs → pack into 8 chunks
 * 2. Call bio_recover_start (0x64)
 * 3. Submit 8 chunks as ZK secret inputs (0x65)
 * 4. Call bio_trigger_match (0x66) to start MPC computation
 * 5. Poll for match result (bio_derived_seed in contract state)
 *
 * @returns The derived seed (16 bytes) if match succeeded, null if failed
 */
export async function recoverBiometric(
  partisia: PartisiaClient,
  zkClient: RealZkClient,
  contractAddr: string,
  keyId: number,
  minutiae: Minutia[]
): Promise<{ seed: Uint8Array | null; matched: boolean }> {
  // Step 1: Encode template
  const cellIds = encodeTemplate(minutiae);
  const chunks = packForZk(cellIds);

  // Step 2: Start recovery on-chain
  console.log("[bio] Starting recovery for key", keyId);
  const recoverArgs = encodeU32(keyId);
  const recoverTx = await partisia.submitAction(
    contractAddr,
    0x64,
    recoverArgs
  );
  console.log("[bio] bio_recover_start tx:", recoverTx);

  // Wait for recover_start tx to be processed
  await new Promise((r) => setTimeout(r, 10000));

  // Step 3: Submit 8 recovery chunks as ZK secrets
  for (let i = 0; i < 8; i++) {
    console.log(`[bio] Submitting recovery chunk ${i}/8...`);
    await submitBiometricChunk(
      partisia,
      zkClient,
      contractAddr,
      keyId,
      i,
      chunks[i],
      0x65 // bio_submit_recovery shortname
    );
    await new Promise((r) => setTimeout(r, 3000));
  }

  // Step 4: Wait for all 16 vars (8 enrollment + 8 recovery) to be confirmed
  console.log("[bio] Waiting for recovery chunks confirmation...");
  await pollVariableCount(partisia, contractAddr, 16, "recovery");
  console.log("[bio] All 16 chunks confirmed (8 enrollment + 8 recovery)");

  // Step 5: Trigger match computation
  console.log("[bio] Triggering biometric match computation...");
  const triggerArgs = encodeU32(keyId);
  const triggerTx = await partisia.submitAction(
    contractAddr,
    0x66,
    triggerArgs
  );
  console.log("[bio] bio_trigger_match tx:", triggerTx);

  // Step 5: Wait for computation output variable to appear
  console.log("[bio] Waiting for computation...");
  await pollVariableCount(partisia, contractAddr, 17, "computation");
  console.log("[bio] Computation produced output variable");

  // Wait for output variable to be opened and result to be stored
  console.log("[bio] Waiting for result to be processed...");
  await new Promise((r) => setTimeout(r, 30000));

  // Step 6: Poll for the result in bio_last_result (top-level state)
  console.log("[bio] Polling for match result...");
  const result = await pollBiometricResult(partisia, contractAddr, keyId);

  if (result && result.length > 0) {
    const isNonZero = result.some((b) => b !== 0);
    if (isNonZero) {
      console.log("[bio] Match succeeded! Seed derived.");
      return { seed: result, matched: true };
    }
  }

  console.log("[bio] Match failed — different finger or too much noise.");
  return { seed: null, matched: false };
}

// --- Internal helpers ---

/**
 * Submit a single biometric chunk as a ZK secret input.
 * Uses the same ZK encryption flow as key share submission.
 */
async function submitBiometricChunk(
  partisia: PartisiaClient,
  zkClient: RealZkClient,
  contractAddress: string,
  keyId: number,
  chunkIndex: number,
  chunkData: Uint8Array,
  shortname: number
): Promise<string> {
  const secretBits = serializeSbi128(chunkData);

  // additionalRpc: [shortname, key_id(u32), chunk_index(u8)]
  const additionalRpc = Buffer.from([
    shortname,
    ...encodeU32(keyId),
    chunkIndex,
  ]);

  const senderAddress = partisia.getSenderAddress();

  const tx = await zkClient.buildOnChainInputTransaction(
    senderAddress,
    secretBits,
    additionalRpc
  );

  return partisia.submitTransaction(tx);
}

/**
 * Poll until enrollment is confirmed by checking nextVariableId >= expectedCount.
 * The ZK framework assigns sequential variable IDs, so nextVariableId tells us
 * how many secrets have been accepted.
 */
async function pollVariableCount(
  partisia: PartisiaClient,
  contractAddress: string,
  expectedCount: number,
  label: string
): Promise<void> {
  await partisia.pollUntil<boolean>(
    contractAddress,
    (state) => {
      const nextVarId = (state as any).nextVariableId as number | undefined;
      if (nextVarId !== undefined) {
        console.log(`[bio] ${label}: ${nextVarId - 1}/${expectedCount} vars confirmed`);
        if (nextVarId > expectedCount) return true;
      }
      return null;
    },
    { intervalMs: 5000, timeoutMs: 180_000 }
  );
}

/**
 * Poll contract state until biometric match result is available.
 *
 * Checks the ZK state for:
 * - calculationStatus changing from CALCULATING back to WAITING (computation done)
 * - A new variable being created (the output from computation)
 * - The output variable being opened (data available in AVL tree)
 *
 * Since the contract state is binary, we look at the AVL tree entry for key_id
 * and check if bio_derived_seed has been populated (non-zero bytes at the end).
 */
async function pollBiometricResult(
  partisia: PartisiaClient,
  contractAddress: string,
  keyId: number,
  options?: { intervalMs?: number; timeoutMs?: number }
): Promise<Uint8Array> {
  let lastCalcStatus = "";

  return partisia.pollUntil<Uint8Array>(
    contractAddress,
    (state) => {
      const calcStatus = (state as any).calculationStatus as string;
      if (calcStatus !== lastCalcStatus) {
        console.log(`[bio] calculationStatus: ${calcStatus}`);
        lastCalcStatus = calcStatus;
      }

      // Check bio_last_result in top-level openState.data
      // The top-level state is: owner(21) + engines_vec + threshold(2) + num_shares(1) +
      //   next_key_id(4) + keys(AVL ref) + bio_last_result(Vec<u8>)
      // bio_last_result is the LAST field — encoded as u32_LE length + bytes
      const openStateData = (state as any).openState?.openState?.data;
      if (!openStateData) return null;

      const stateBytes = Buffer.from(openStateData, "base64");
      // bio_last_result Vec<u8> is the last field.
      // Read the last part: look for a vec with our key_id + 16 bytes seed
      // Total expected: 4 (vec len) + 4 (key_id LE) + 16 (seed) = 24 bytes if present
      // Or 4 (vec len = 0) if empty
      if (stateBytes.length < 4) return null;

      // Read the last vec length (u32 LE) — scan backwards for it
      // The vec is at the very end of the state
      const lastU32Offset = stateBytes.length - 4;
      // Check if the last 4 bytes could be the end of seed data
      // We need to find where bio_last_result starts
      // The pattern: if result exists, the vec is 20 bytes (4 key_id + 16 seed)
      // So state ends with: [len=20 as u32LE][key_id LE 4 bytes][seed 16 bytes]
      // = [14 00 00 00][key_id][seed]
      // Total added: 24 bytes

      // Search for bio_last_result: a vec with length 20 (4 key_id + 16 seed)
      // Scan backwards from end to find it
      for (let off = stateBytes.length - 24; off >= 0; off--) {
        if (off + 24 > stateBytes.length) continue;
        const vecLen = stateBytes.readUInt32LE(off);
        if (vecLen === 20) {
          const resultKeyIdLE = stateBytes.readUInt32LE(off + 4);
          const resultKeyIdBE = stateBytes.readUInt32BE(off + 4);
          // Accept either endianness for key_id match
          if (resultKeyIdLE === keyId || resultKeyIdBE === keyId) {
            const seed = stateBytes.slice(off + 8, off + 24);
            const isNonZero = seed.some((b: number) => b !== 0);
            console.log(
              `[bio] Found result! seed=${Buffer.from(seed).toString("hex")} nonzero=${isNonZero}`
            );
            if (isNonZero) {
              return new Uint8Array(seed);
            }
            return new Uint8Array(0); // Match failed
          }
        }
      }

      // Check if bio_last_result is empty (last 4 bytes = 0)
      // This means no result yet
      return null;
    },
    {
      intervalMs: options?.intervalMs ?? 10000,
      timeoutMs: options?.timeoutMs ?? 600_000,
    }
  );
}
