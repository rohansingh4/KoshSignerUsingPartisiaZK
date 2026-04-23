/**
 * ZK Signer helpers for the kosh-zk-signer contract.
 *
 * Includes:
 * - ZK secret input submission (Shamir share halves)
 * - Engine key extraction from contract state
 * - Polling for keygen/signing completion
 */

import { PartisiaClient } from "./partisia.js";
import { RealZkClient, Client } from "@partisiablockchain/zk-client";
import { BitOutput, type CompactBitArray } from "@secata-public/bitmanipulation-ts";
import BN from "bn.js";

// -- State type definitions for parsing contract state --

interface ZkSignerKeyState {
  public_key: string | null;
  keygen_phase: { discriminant: number };
  signing_phase: { discriminant: number };
  signing_information: Record<
    string,
    {
      signature: string | null;
      verified: boolean;
    }
  >;
  gg20_delta_zk_count: number;
  gg20_delta_zk_expected: number;
}

interface ZkSignerState {
  keys: Record<string, ZkSignerKeyState>;
}

// -- ZK secret input helpers --

/** Encode a u32 as 4 big-endian bytes. */
function encodeU32BE(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (n >> 24) & 0xff;
  buf[1] = (n >> 16) & 0xff;
  buf[2] = (n >> 8) & 0xff;
  buf[3] = n & 0xff;
  return buf;
}

/**
 * Serialize a 128-bit value (16 bytes, big-endian) as an Sbi128 CompactBitArray.
 *
 * Sbi128 is a signed 128-bit integer on Partisia. The raw bytes represent the
 * two's complement value. We write the 16 bytes directly as bits (128 bits)
 * which preserves the exact bit pattern regardless of sign interpretation.
 */
export function serializeSbi128(halfBytes: Uint8Array): CompactBitArray {
  return BitOutput.serializeBits((out) => {
    out.writeBytes(Buffer.from(halfBytes), 0, 16);
  });
}

/**
 * Build the additionalRpc buffer for the submit_key_share ZK input.
 * Format: [shortname=0x10, key_id(u32), share_index(u8), is_high_half(bool as u8)]
 */
export function buildShareAdditionalRpc(
  keyId: number,
  shareIndex: number,
  isHighHalf: boolean
): Buffer {
  return Buffer.from([
    0x10,
    ...encodeU32BE(keyId),
    shareIndex,
    isHighHalf ? 1 : 0,
  ]);
}

/**
 * Create a RealZkClient for the given contract address.
 * Uses the Partisia SDK's Client to read contract state (engine keys, etc).
 */
export function createZkClient(
  nodeUrl: string,
  contractAddress: string
): RealZkClient {
  const blockchainClient = new Client(nodeUrl);
  return RealZkClient.create(contractAddress, blockchainClient);
}

/**
 * Submit a single Sbi128 ZK secret input (one share half) to the contract.
 *
 * Uses RealZkClient.buildOnChainInputTransaction() to encrypt the secret
 * for each ZK engine, then submits via PartisiaClient with proper signing.
 */
export async function submitZkShareHalf(
  partisia: PartisiaClient,
  zkClient: RealZkClient,
  contractAddress: string,
  keyId: number,
  shareIndex: number,
  isHighHalf: boolean,
  halfBytes: Uint8Array
): Promise<string> {
  const secretBits = serializeSbi128(halfBytes);
  const additionalRpc = buildShareAdditionalRpc(keyId, shareIndex, isHighHalf);
  const senderAddress = partisia.getSenderAddress();

  const tx = await zkClient.buildOnChainInputTransaction(
    senderAddress,
    secretBits,
    additionalRpc
  );

  return partisia.submitTransaction(tx);
}

// -- k⁻¹ ZK secret input helpers (for ZK partial sig path) --

/**
 * Build the additionalRpc buffer for submit_kinv_zk (0x53).
 * Format: [shortname=0x53, key_id(u32), party_index(u8), is_high_half(bool as u8)]
 *
 * Each party submits their k⁻¹ contribution in two halves:
 *   isHighHalf=true  → first 16 bytes of the 32-byte k⁻¹ scalar
 *   isHighHalf=false → last 16 bytes
 */
export function buildKInvAdditionalRpc(
  keyId: number,
  partyIndex: number,
  isHighHalf: boolean
): Buffer {
  return Buffer.from([
    0x53,
    ...encodeU32BE(keyId),
    partyIndex,
    isHighHalf ? 1 : 0,
  ]);
}

/**
 * Submit one 16-byte half of a party's k⁻¹ as a ZK secret input.
 *
 * Call twice per party — once with isHighHalf=true (bytes 0..16),
 * once with isHighHalf=false (bytes 16..32).
 */
export async function submitZkKInvHalf(
  partisia: PartisiaClient,
  zkClient: RealZkClient,
  contractAddress: string,
  keyId: number,
  partyIndex: number,
  isHighHalf: boolean,
  halfBytes: Uint8Array  // exactly 16 bytes
): Promise<string> {
  const secretBits = serializeSbi128(halfBytes);
  const additionalRpc = buildKInvAdditionalRpc(keyId, partyIndex, isHighHalf);
  const senderAddress = partisia.getSenderAddress();

  const tx = await zkClient.buildOnChainInputTransaction(
    senderAddress,
    secretBits,
    additionalRpc
  );

  return partisia.submitTransaction(tx);
}

// -- Delta ZK secret input helpers --

/**
 * Build the additionalRpc buffer for the submit_delta_zk ZK input.
 * Format: [shortname=0x51, key_id(u32), party_index(u8), is_high_half(bool as u8)]
 */
export function buildDeltaAdditionalRpc(
  keyId: number,
  partyIndex: number,
  isHighHalf: boolean
): Buffer {
  return Buffer.from([
    0x51,
    ...encodeU32BE(keyId),
    partyIndex,
    isHighHalf ? 1 : 0,
  ]);
}

/**
 * Submit a single Sbi128 ZK secret input (one delta half) to the contract.
 *
 * Uses RealZkClient.buildOnChainInputTransaction() to encrypt the secret
 * for each ZK engine, then submits via PartisiaClient with proper signing.
 */
export async function submitZkDelta(
  partisia: PartisiaClient,
  zkClient: RealZkClient,
  contractAddress: string,
  keyId: number,
  partyIndex: number,
  isHighHalf: boolean,
  halfBytes: Uint8Array
): Promise<string> {
  const secretBits = serializeSbi128(halfBytes);
  const additionalRpc = buildDeltaAdditionalRpc(keyId, partyIndex, isHighHalf);
  const senderAddress = partisia.getSenderAddress();

  const tx = await zkClient.buildOnChainInputTransaction(
    senderAddress,
    secretBits,
    additionalRpc
  );

  return partisia.submitTransaction(tx);
}

// -- Polling helpers --

/**
 * Poll until key generation is complete for a given key_id.
 * Returns the compressed public key hex string (33 bytes).
 */
export async function pollKeyGenComplete(
  partisia: PartisiaClient,
  signerAddress: string,
  keyId: number,
  options?: { intervalMs?: number; timeoutMs?: number }
): Promise<string> {
  return partisia.pollUntil<string>(
    signerAddress,
    (state) => {
      const signerState = state as unknown as ZkSignerState;
      const key = signerState?.keys?.[String(keyId)];
      // ZkKeyGenPhase::Complete has discriminant 2
      if (key?.public_key && key.keygen_phase?.discriminant === 2) {
        return key.public_key;
      }
      return null;
    },
    { intervalMs: options?.intervalMs ?? 5000, timeoutMs: options?.timeoutMs ?? 180_000 }
  );
}

/**
 * Poll until signing is complete for a given key_id and task_id.
 * Returns the 65-byte signature hex string (r || s || v).
 */
export async function pollSigningComplete(
  partisia: PartisiaClient,
  signerAddress: string,
  keyId: number,
  taskId: number,
  options?: { intervalMs?: number; timeoutMs?: number }
): Promise<string> {
  return partisia.pollUntil<string>(
    signerAddress,
    (state) => {
      const signerState = state as unknown as ZkSignerState;
      const key = signerState?.keys?.[String(keyId)];
      const sigInfo = key?.signing_information?.[String(taskId)];
      if (sigInfo?.signature && sigInfo.verified) {
        return sigInfo.signature;
      }
      return null;
    },
    { intervalMs: options?.intervalMs ?? 5000, timeoutMs: options?.timeoutMs ?? 300_000 }
  );
}

/**
 * Poll until all ZK delta secret inputs have been confirmed and registered
 * in the contract state (gg20_delta_zk_count >= gg20_delta_zk_expected).
 *
 * Must be called after all submitZkDelta calls and BEFORE open_gg20_deltas.
 * Without this, open_gg20_deltas will fail with "No delta ZK variables to open"
 * because the ZK nodes haven't finished processing the inputs yet.
 */
export async function pollUntilDeltaZkReady(
  partisia: PartisiaClient,
  signerAddress: string,
  keyId: number,
  expectedCount: number,
  options?: { intervalMs?: number; timeoutMs?: number }
): Promise<void> {
  await partisia.pollUntil<true>(
    signerAddress,
    (state) => {
      const signerState = state as unknown as ZkSignerState;
      const key = signerState?.keys?.[String(keyId)];
      if (
        key?.gg20_delta_zk_count !== undefined &&
        key.gg20_delta_zk_count >= expectedCount
      ) {
        return true;
      }
      return null;
    },
    { intervalMs: options?.intervalMs ?? 4000, timeoutMs: options?.timeoutMs ?? 120_000 }
  );
}
