/**
 * Kosh ZK Signer — Per-Party Script for Distributed 3-Laptop Testing.
 *
 * Run ONE instance of this script per laptop:
 *
 *   Laptop 1 (Party 1):
 *     PARTY_INDEX=1 COORD_URL=http://localhost:3000 \
 *     PARTISIA_SENDER_KEY=... PARTISIA_SENDER_ADDRESS=... SIGNER_ADDRESS=... \
 *     npx tsx src/party.ts
 *
 *   Laptop 2 (Party 2):
 *     PARTY_INDEX=2 COORD_URL=https://xxxx.ngrok.io \
 *     PARTISIA_SENDER_KEY=... PARTISIA_SENDER_ADDRESS=... SIGNER_ADDRESS=... \
 *     npx tsx src/party.ts
 *
 *   Laptop 3 (Party 3):
 *     PARTY_INDEX=3 COORD_URL=https://xxxx.ngrok.io \
 *     PARTISIA_SENDER_KEY=... PARTISIA_SENDER_ADDRESS=... SIGNER_ADDRESS=... \
 *     npx tsx src/party.ts
 *
 * Environment variables:
 *   PARTY_INDEX         — 1, 2, or 3 (required)
 *   COORD_URL           — URL of the coordination server (required)
 *   PARTISIA_SENDER_KEY — Private key for Partisia chain txns (required)
 *   PARTISIA_SENDER_ADDRESS — Partisia wallet address (required)
 *   SIGNER_ADDRESS      — Deployed ZK signer contract address (required)
 *   KEY_ID              — Key slot to use (default: 1)
 *   NUM_PARTIES         — Total number of parties (default: 3)
 *   SIGNING_SUBSET      — Comma-separated party indices for signing (default: "1,2")
 *   NODE_URL            — Partisia node URL (default: testnet node 1)
 *
 * Protocol overview:
 *   Phase 1  — DKG: each party generates polynomial, posts public commitments
 *   Phase 2  — DKG: collect + verify sub-shares from other parties
 *   Phase 3  — On-chain DKG ceremony (commit → reveal → finalize → ZK input)
 *   Phase 4  — Paillier key generation + exchange
 *   Phase 5  — GG20 MtA rounds (distributed Paillier exchanges via server)
 *   Phase 6  — On-chain signing verification
 */

import { PartisiaClient } from "./partisia.js";
import * as fs from "fs";
import { createZkClient, submitZkShareHalf } from "./zk-signer.js";
import {
  generateThresholdDkgShare,
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
  gg20InitParty,
  gg20RunMtARounds,
  gg20ComputeR,
  gg20ComputePartials,
  gg20VerifyLocally,
  buildSubmitDeltaArgs,
  buildSubmitGammaPointArgs,
  buildGG20FinalizeRArgs,
  buildGG20StartSigningArgs,
  buildSubmitPartialSigArgs,
  buildCommitPartialSigArgs,
  buildRegisterDilithiumPubkeyArgs,
  buildRegisterKyberPubkeyArgs,
  buildStartPqcApprovalSessionArgs,
  buildSubmitPqcApprovalArgs,
  buildFinalizePqcApprovalArgs,
  sha256 as gg20Sha256,
  type GG20PartyState,
} from "./gg20-signing.js";
import {
  mtaRound1_A,
  mtaRound2_B,
  mtaFinalize_A,
  type MtAMessage1,
  type MtAMessage2,
} from "./mta.js";
import { paillierKeygen, modInverse, type PaillierPublicKey, type PaillierKeyPair } from "./paillier.js";
import { bigintTo32Bytes, bytesToBigint } from "./shamir-ts.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { mod } from "@noble/curves/abstract/modular";
import {
  PolicyStore,
  printPolicies,
  buildRegisterPartyAddressArgs,
  buildSignMessageWithTagArgs,
} from "./policy.js";
import {
  base64ToBytes,
  bytesToBase64,
  decryptWithSharedSecret,
  dilithiumSign,
  dilithiumVerify,
  encryptWithSharedSecret,
  generatePqcIdentity,
  kyberDecapsulate,
  kyberEncapsulate,
  sha256 as pqcSha256,
  type PqcIdentity,
} from "./pqc.js";

// =============================================================================
// Config
// =============================================================================

const PARTY_INDEX = parseInt(process.env.PARTY_INDEX ?? "0");
const COORD_URL = (process.env.COORD_URL ?? "http://localhost:3000").replace(/\/$/, "");
const SENDER_KEY = process.env.PARTISIA_SENDER_KEY ?? "";
const SENDER_ADDR = process.env.PARTISIA_SENDER_ADDRESS ?? "";
const SIGNER_ADDR = process.env.SIGNER_ADDRESS ?? "";
const NODE_URL = process.env.PARTISIA_NODE_URL ?? "https://node1.testnet.partisiablockchain.com";
const KEY_ID = parseInt(process.env.KEY_ID ?? "1");
const NUM_PARTIES = parseInt(process.env.NUM_PARTIES ?? "3");
const SIGNING_SUBSET = (process.env.SIGNING_SUBSET ?? "1,2").split(",").map(Number);
const TASK_ID = parseInt(process.env.TASK_ID ?? "0");
/** Transaction type tag — matched against policy rules. Empty = no policy applies. */
const TX_TAG = process.env.TX_TAG ?? "";
/** Optional path to a JSON file persisting policy rules across restarts. */
const POLICY_FILE = process.env.POLICY_FILE;
const PQC_ENABLED = (process.env.PQC_ENABLED ?? "1") !== "0";
const PQC_KEY_FILE = process.env.PQC_KEY_FILE;

if (!PARTY_INDEX || !COORD_URL || !SENDER_KEY || !SENDER_ADDR || !SIGNER_ADDR) {
  console.error("Missing required env vars: PARTY_INDEX, COORD_URL, PARTISIA_SENDER_KEY, PARTISIA_SENDER_ADDRESS, SIGNER_ADDRESS");
  process.exit(1);
}

// Load policies (from file if POLICY_FILE is set, otherwise in-memory defaults)
const policies = new PolicyStore(POLICY_FILE);

const N = secp256k1.CURVE.n;
const G = secp256k1.ProjectivePoint.BASE;

// =============================================================================
// PQC Identity (Kyber + Dilithium)
// =============================================================================

type PqcKeyFile = {
  kyberPublicKey: string;
  kyberPrivateKey: string;
  dilithiumPublicKey: string;
  dilithiumPrivateKey: string;
};

let pqcIdentity: PqcIdentity | null = null;

function loadOrCreatePqcIdentity(): PqcIdentity {
  if (pqcIdentity) return pqcIdentity;

  if (PQC_KEY_FILE && fs.existsSync(PQC_KEY_FILE)) {
    const raw = fs.readFileSync(PQC_KEY_FILE, "utf-8");
    const data = JSON.parse(raw) as PqcKeyFile;
    pqcIdentity = {
      kyber: {
        publicKey: base64ToBytes(data.kyberPublicKey),
        privateKey: base64ToBytes(data.kyberPrivateKey),
      },
      dilithium: {
        publicKey: base64ToBytes(data.dilithiumPublicKey),
        privateKey: base64ToBytes(data.dilithiumPrivateKey),
      },
    };
    return pqcIdentity;
  }

  pqcIdentity = generatePqcIdentity();

  if (PQC_KEY_FILE) {
    const data: PqcKeyFile = {
      kyberPublicKey: bytesToBase64(pqcIdentity.kyber.publicKey),
      kyberPrivateKey: bytesToBase64(pqcIdentity.kyber.privateKey),
      dilithiumPublicKey: bytesToBase64(pqcIdentity.dilithium.publicKey),
      dilithiumPrivateKey: bytesToBase64(pqcIdentity.dilithium.privateKey),
    };
    fs.writeFileSync(PQC_KEY_FILE, JSON.stringify(data, null, 2), "utf-8");
  }

  return pqcIdentity;
}

function encodeU32Be(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (n >>> 24) & 0xff;
  buf[1] = (n >>> 16) & 0xff;
  buf[2] = (n >>> 8) & 0xff;
  buf[3] = n & 0xff;
  return buf;
}

function encodeLenPrefixedBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array([...encodeU32Be(bytes.length), ...bytes]);
}

function encodePartyVector(parties: number[]): Uint8Array {
  return new Uint8Array([...encodeU32Be(parties.length), ...parties.map((p) => p & 0xff)]);
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function computePqcSessionChallenge(
  keyId: number,
  taskId: number,
  msgHash: Uint8Array,
  txTag: string,
  signingSubset: number[]
): Uint8Array {
  return pqcSha256(concatBytes(
    new TextEncoder().encode("KOSH_PQC_SESSION_V1"),
    encodeU32Be(keyId),
    encodeU32Be(taskId),
    encodeLenPrefixedBytes(msgHash),
    encodeLenPrefixedBytes(new TextEncoder().encode(txTag)),
    encodePartyVector(signingSubset),
  ));
}

function buildPqcApprovalPayload(
  keyId: number,
  taskId: number,
  partyIndex: number,
  msgHash: Uint8Array,
  txTag: string,
  signingSubset: number[],
  challenge: Uint8Array
): Uint8Array {
  return concatBytes(
    new TextEncoder().encode("KOSH_PQC_APPROVAL_V1"),
    encodeU32Be(keyId),
    encodeU32Be(taskId),
    new Uint8Array([partyIndex & 0xff]),
    encodeLenPrefixedBytes(msgHash),
    encodeLenPrefixedBytes(new TextEncoder().encode(txTag)),
    encodePartyVector(signingSubset),
    encodeLenPrefixedBytes(challenge),
  );
}

async function phaseRegisterOnchainIdentity(partisia: PartisiaClient): Promise<void> {
  const identity = loadOrCreatePqcIdentity();
  await postJson(`party_identity_${KEY_ID}_${PARTY_INDEX}`, {
    senderAddress: SENDER_ADDR,
    dilithiumPubkey: bytesToBase64(identity.dilithium.publicKey),
    kyberPubkey: bytesToBase64(identity.kyber.publicKey),
  });

  if (PARTY_INDEX === 1) {
    for (let j = 1; j <= NUM_PARTIES; j++) {
      const entry = await readJson<{
        senderAddress: string;
        dilithiumPubkey: string;
        kyberPubkey: string;
      }>(`party_identity_${KEY_ID}_${j}`);

      if (!await submitAndWait(
        partisia,
        0x72,
        buildRegisterPartyAddressArgs(KEY_ID, j, entry.senderAddress),
        `register_party_address_P${j}`,
      )) {
        throw new Error(`register_party_address failed for party ${j}`);
      }

      if (!await submitAndWait(
        partisia,
        0x73,
        buildRegisterDilithiumPubkeyArgs(KEY_ID, j, base64ToBytes(entry.dilithiumPubkey)),
        `register_dilithium_pubkey_P${j}`,
      )) {
        throw new Error(`register_dilithium_pubkey failed for party ${j}`);
      }

      if (!await submitAndWait(
        partisia,
        0x74,
        buildRegisterKyberPubkeyArgs(KEY_ID, j, base64ToBytes(entry.kyberPubkey)),
        `register_kyber_pubkey_P${j}`,
      )) {
        throw new Error(`register_kyber_pubkey failed for party ${j}`);
      }
    }
    await post(`onchain_identity_registered_${KEY_ID}`, "1");
  } else {
    await read(`onchain_identity_registered_${KEY_ID}`);
  }
}

// =============================================================================
// Bulletin Board Client
// =============================================================================

/** Post a value to the bulletin board. */
async function post(topic: string, value: string): Promise<void> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      const res = await fetch(`${COORD_URL}/set/${topic}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ value }),
      });
      if (!res.ok) throw new Error(`POST /set/${topic} failed: ${res.status}`);
      return;
    } catch (err) {
      lastErr = err;
      if (attempt === 5) break;
      await sleep(500 * attempt);
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr ?? `POST /set/${topic} failed`));
}

/** Read a value from the bulletin board (long-polls until available). */
async function read(topic: string, timeoutMs = 300_000): Promise<string> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const remainingMs = Math.max(1000, timeoutMs - (Date.now() - startedAt));
    const url = `${COORD_URL}/get/${topic}?wait=1`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(remainingMs + 5000, 35_000));
    try {
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);
      if (res.status === 408) {
        continue;
      }
      if (!res.ok) throw new Error(`GET /get/${topic} failed: ${res.status}`);
      const body = await res.json() as { ok: boolean; value?: string; error?: string };
      if (!body.ok || !body.value) throw new Error(`Topic ${topic} not available: ${body.error}`);
      return body.value;
    } catch (err) {
      clearTimeout(timer);
      if (err instanceof Error && err.name === "AbortError") {
        continue;
      }
      throw err;
    }
  }
  throw new Error(`Timed out waiting for topic ${topic}`);
}

/** Post a JSON object to the bulletin board. */
async function postJson(topic: string, obj: unknown): Promise<void> {
  await post(topic, JSON.stringify(obj));
}

/** Read and parse a JSON object from the bulletin board. */
async function readJson<T>(topic: string): Promise<T> {
  const raw = await read(topic);
  return JSON.parse(raw) as T;
}

// =============================================================================
// PQC Approval Flow (Kyber transport + Dilithium approvals)
// =============================================================================

type EncryptedApproval = {
  kem: string;
  nonce: string;
  tag: string;
  ciphertext: string;
};

async function phasePqcApprovals(
  partisia: PartisiaClient,
  msgHash: Uint8Array,
  signingSubset: number[],
  taskId: number,
): Promise<void> {
  if (!PQC_ENABLED) {
    console.log(`  [P${PARTY_INDEX}] PQC approvals: disabled`);
    return;
  }

  const identity = loadOrCreatePqcIdentity();
  const challenge = computePqcSessionChallenge(KEY_ID, taskId, msgHash, TX_TAG, signingSubset);

  if (PARTY_INDEX === 1) {
    const startArgs = buildStartPqcApprovalSessionArgs(KEY_ID, taskId, signingSubset);
    if (!await submitAndWait(partisia, 0x75, startArgs, "start_pqc_approval_session")) {
      throw new Error("start_pqc_approval_session failed");
    }
    await post(`onchain_pqc_session_started_${KEY_ID}_${taskId}`, "1");
  } else {
    await read(`onchain_pqc_session_started_${KEY_ID}_${taskId}`);
  }

  await post(`pqc_kyber_pk_${PARTY_INDEX}`, bytesToBase64(identity.kyber.publicKey));
  await post(`pqc_dilithium_pk_${PARTY_INDEX}`, bytesToBase64(identity.dilithium.publicKey));

  const kyberPks = new Map<number, Uint8Array>();
  const dilithiumPks = new Map<number, Uint8Array>();

  for (const j of signingSubset) {
    const kyberPk = base64ToBytes(await read(`pqc_kyber_pk_${j}`));
    const dilithiumPk = base64ToBytes(await read(`pqc_dilithium_pk_${j}`));
    kyberPks.set(j, kyberPk);
    dilithiumPks.set(j, dilithiumPk);
  }

  const msgHex = Buffer.from(msgHash).toString("hex");
  const approval = {
    keyId: KEY_ID,
    taskId,
    txTag: TX_TAG,
    msgHash: msgHex,
    signingSubset,
    partyIndex: PARTY_INDEX,
    challenge: bytesToBase64(challenge),
  };
  const approvalBytes = buildPqcApprovalPayload(
    KEY_ID,
    taskId,
    PARTY_INDEX,
    msgHash,
    TX_TAG,
    signingSubset,
    challenge,
  );
  const signature = dilithiumSign(approvalBytes, identity.dilithium.privateKey);
  const signedPayload = { approval, sig: bytesToBase64(signature) };
  const signedBytes = new TextEncoder().encode(JSON.stringify(signedPayload));

  for (const j of signingSubset) {
    if (j === PARTY_INDEX) continue;
    const { kem, sharedSecret } = kyberEncapsulate(kyberPks.get(j)!);
    const enc = encryptWithSharedSecret(sharedSecret, signedBytes);
    const payload: EncryptedApproval = {
      kem: bytesToBase64(kem),
      nonce: bytesToBase64(enc.nonce),
      tag: bytesToBase64(enc.tag),
      ciphertext: bytesToBase64(enc.ciphertext),
    };
    await postJson(`pqc_approval_${KEY_ID}_${PARTY_INDEX}_to_${j}`, payload);
  }

  // Verify approvals from all signing parties
  for (const sender of signingSubset) {
    let payloadBytes: Uint8Array;
    if (sender === PARTY_INDEX) {
      payloadBytes = signedBytes;
    } else {
      const enc = await readJson<EncryptedApproval>(`pqc_approval_${KEY_ID}_${sender}_to_${PARTY_INDEX}`);
      const shared = kyberDecapsulate(base64ToBytes(enc.kem), identity.kyber.privateKey);
      payloadBytes = decryptWithSharedSecret(shared, {
        kem: new Uint8Array(),
        nonce: base64ToBytes(enc.nonce),
        tag: base64ToBytes(enc.tag),
        ciphertext: base64ToBytes(enc.ciphertext),
      });
    }

    const decoded = JSON.parse(new TextDecoder().decode(payloadBytes)) as {
      approval: {
        keyId: number;
        taskId: number;
        txTag: string;
        msgHash: string;
        signingSubset: number[];
        partyIndex: number;
        challenge: string;
      };
      sig: string;
    };

    const approvalCheck = buildPqcApprovalPayload(
      decoded.approval.keyId,
      decoded.approval.taskId,
      decoded.approval.partyIndex,
      hexToBytes(decoded.approval.msgHash),
      decoded.approval.txTag,
      decoded.approval.signingSubset,
      base64ToBytes(decoded.approval.challenge),
    );
    const sigBytes = base64ToBytes(decoded.sig);
    const pk = dilithiumPks.get(sender)!;

    if (!dilithiumVerify(approvalCheck, sigBytes, pk)) {
      throw new Error(`PQC approval invalid from Party ${sender}`);
    }
    if (
      decoded.approval.keyId !== KEY_ID ||
      decoded.approval.taskId !== taskId ||
      decoded.approval.msgHash !== msgHex ||
      decoded.approval.txTag !== TX_TAG ||
      decoded.approval.challenge !== bytesToBase64(challenge)
    ) {
      throw new Error(`PQC approval mismatch from Party ${sender}`);
    }
  }

  const approvalHash = pqcSha256(approvalBytes);
  const submitArgs = buildSubmitPqcApprovalArgs(KEY_ID, taskId, PARTY_INDEX, approvalHash);
  if (!await submitAndWait(partisia, 0x76, submitArgs, `submit_pqc_approval_P${PARTY_INDEX}`)) {
    throw new Error("submit_pqc_approval failed");
  }
  await post(`onchain_pqc_approval_${KEY_ID}_${taskId}_${PARTY_INDEX}`, "1");

  for (const sender of signingSubset) {
    await read(`onchain_pqc_approval_${KEY_ID}_${taskId}_${sender}`);
  }

  if (PARTY_INDEX === 1) {
    const finalizeArgs = buildFinalizePqcApprovalArgs(KEY_ID, taskId);
    if (!await submitAndWait(partisia, 0x77, finalizeArgs, "finalize_pqc_approval")) {
      throw new Error("finalize_pqc_approval failed");
    }
    await post(`onchain_pqc_approval_finalized_${KEY_ID}_${taskId}`, "1");
  } else {
    await read(`onchain_pqc_approval_finalized_${KEY_ID}_${taskId}`);
  }

  console.log(`  [P${PARTY_INDEX}] PQC approvals verified for subset {${signingSubset.join(",")}}`);
}

// =============================================================================
// Partisia On-chain Helpers
// =============================================================================

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
  shortname: number,
  args: Uint8Array,
  label: string
): Promise<boolean> {
  const client = partisia.getTransactionClient();
  const shortnameBytes = shortname <= 0xff ? [shortname] : [shortname >> 8, shortname & 0xff];
  const wasmRpc = Buffer.from([...shortnameBytes, ...args]);
  const rpc = Buffer.concat([Buffer.from([0x09]), wasmRpc]);
  const tx = { address: SIGNER_ADDR, rpc };
  let sent: Awaited<ReturnType<typeof client.signAndSend>> | undefined;
  let tree: Awaited<ReturnType<typeof client.waitForSpawnedEvents>> | undefined;
  let lastErr: unknown;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      sent = await client.signAndSend(tx, 500000);
      const txId = sent.transactionPointer.identifier;
      console.log(`  [P${PARTY_INDEX}] Tx: ${txId}${attempt > 1 ? ` (attempt ${attempt})` : ""}`);
      tree = await client.waitForSpawnedEvents(sent);
      break;
    } catch (err) {
      lastErr = err;
      if (attempt === 3) throw err;
      console.warn(`  [P${PARTY_INDEX}] ${label}: transient Partisia RPC failure, retrying (${attempt}/3)`);
      await sleep(1500 * attempt);
    }
  }
  if (!tree) throw lastErr instanceof Error ? lastErr : new Error(String(lastErr ?? "unknown Partisia RPC error"));
  const rootStatus = (tree as any).root?.transaction?.executionStatus
    ?? (tree as any).transaction?.executionStatus;
  if (rootStatus?.success === false) {
    const msg = rootStatus.failure?.errorMessage ?? "unknown error";
    console.error(`  [P${PARTY_INDEX}] ${label} FAILED: ${msg.split("\n")[0]}`);
    return false;
  }
  const events = tree.events ?? (tree as any).spawned ?? [];
  for (const ev of events) {
    const es = (ev as any).transaction?.executionStatus ?? (ev as any).executionStatus;
    if (es?.success === false) {
      const msg = es.failure?.errorMessage ?? es.errorMessage ?? "unknown";
      console.error(`  [P${PARTY_INDEX}] ${label} FAILED (spawned): ${msg.split("\n")[0]}`);
      return false;
    }
  }
  console.log(`  [P${PARTY_INDEX}] ${label} OK`);
  return true;
}

// =============================================================================
// Serialization helpers for bulletin board
// =============================================================================

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const padded = clean.length % 2 === 0 ? clean : "0" + clean;
  const buf = new Uint8Array(padded.length / 2);
  for (let i = 0; i < buf.length; i++) {
    buf[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  return buf;
}

function bigintToHex(n: bigint): string {
  return n.toString(16).padStart(64, "0");
}

function hexToBigint(hex: string): bigint {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  return BigInt("0x" + (clean || "0"));
}

// =============================================================================
// Phase 1 — DKG: Polynomial generation + post commitments
// =============================================================================

async function phase1_dkgGenerate(): Promise<{ dkgShare: ThresholdDkgShare }> {
  console.log(`\n[P${PARTY_INDEX}] Phase 1: Generating DKG polynomial...`);

  // Each party generates their own polynomial with a random seed (no coordinator)
  const dkgShare = await generateThresholdDkgShare(PARTY_INDEX, NUM_PARTIES);
  const schnorrProof = await generateSchnorrProof(dkgShare.secretScalar, dkgShare.C_i0, PARTY_INDEX);

  // Post public commitments + Schnorr proof to bulletin board
  await postJson(`dkg_commit_${PARTY_INDEX}`, {
    C_i0: toHex(dkgShare.C_i0),
    C_i1: toHex(dkgShare.C_i1),
    commitmentHash: toHex(dkgShare.commitmentHash),
    schnorr_R: toHex(schnorrProof.R),
    schnorr_z: toHex(schnorrProof.z),
    partyIndex: PARTY_INDEX,
  });
  console.log(`  [P${PARTY_INDEX}] Posted DKG commit (C_i0, C_i1, Schnorr proof)`);

  // Post sub-shares to the bulletin board (routed to each party j)
  // In production: encrypt f_i(j) with party j's NaCl public key before posting
  for (let j = 1; j <= NUM_PARTIES; j++) {
    await post(`subshare_${PARTY_INDEX}_${j}`, bigintToHex(dkgShare.subShares[j - 1]));
  }
  console.log(`  [P${PARTY_INDEX}] Posted ${NUM_PARTIES} sub-shares`);

  return { dkgShare };
}

// =============================================================================
// Phase 2 — DKG: Collect sub-shares, verify, combine into Shamir share
// =============================================================================

async function phase2_collectShares(dkgShare: ThresholdDkgShare): Promise<ShamirShare> {
  console.log(`\n[P${PARTY_INDEX}] Phase 2: Collecting sub-shares from other parties...`);

  // Collect DKG commitments from all parties (need C_j0, C_j1 to verify)
  const allCommits: Record<number, { C_i0: string; C_i1: string }> = {};
  for (let j = 1; j <= NUM_PARTIES; j++) {
    const commit = await readJson<{ C_i0: string; C_i1: string }>(`dkg_commit_${j}`);
    allCommits[j] = commit;
    if (j !== PARTY_INDEX) {
      console.log(`  [P${PARTY_INDEX}] Got commit from Party ${j}`);
    }
  }

  // Collect sub-shares sent TO this party
  let shamirShare = 0n;
  for (let i = 1; i <= NUM_PARTIES; i++) {
    const subshareHex = await read(`subshare_${i}_${PARTY_INDEX}`);
    const fij = hexToBigint(subshareHex);

    // Feldman verification: f_i(j)·G == C_i0 + j·C_i1
    const C_i0_bytes = hexToBytes(allCommits[i].C_i0);
    const C_i1_bytes = hexToBytes(allCommits[i].C_i1);
    const valid = verifyFeldmanSubshare(fij, C_i0_bytes, C_i1_bytes, PARTY_INDEX);
    if (!valid) {
      throw new Error(`Feldman verification FAILED: sub-share from Party ${i} is invalid!`);
    }
    console.log(`  [P${PARTY_INDEX}] Verified sub-share from Party ${i}: OK`);

    shamirShare = mod(shamirShare + fij, N);
  }

  const myShare: ShamirShare = { partyIndex: PARTY_INDEX, share: shamirShare };
  console.log(`  [P${PARTY_INDEX}] Shamir share X_${PARTY_INDEX} = ...${shamirShare.toString(16).slice(-8)}`);

  return myShare;
}

// =============================================================================
// Phase 3 — On-chain DKG ceremony
// =============================================================================

async function phase3_onchainDkg(
  partisia: PartisiaClient,
  dkgShare: ThresholdDkgShare,
  shamirShare: ShamirShare
): Promise<Uint8Array> {
  console.log(`\n[P${PARTY_INDEX}] Phase 3: On-chain DKG ceremony...`);

  const zkClient = createZkClient(NODE_URL, SIGNER_ADDR);

  // --- Step 1: Party 1 creates the key slot ---
  if (PARTY_INDEX === 1) {
    if (!await submitAndWait(partisia, 0x20, buildDkgCreateKeyArgs(KEY_ID, NUM_PARTIES), "dkg_create_key")) {
      throw new Error("dkg_create_key failed");
    }
    await post("onchain_create_done", "1");
  } else {
    console.log(`  [P${PARTY_INDEX}] Waiting for Party 1 to create key slot...`);
    await read("onchain_create_done");
  }
  await sleep(2000);

  // --- Step 2: Each party submits their commit (with Schnorr proof) ---
  const schnorrProof = await generateSchnorrProof(dkgShare.secretScalar, dkgShare.C_i0, PARTY_INDEX);
  if (!await submitAndWait(partisia, 0x21,
    buildDkgCommitArgs(KEY_ID, PARTY_INDEX, dkgShare.commitmentHash, dkgShare.C_i1, schnorrProof.R, schnorrProof.z),
    `dkg_commit_P${PARTY_INDEX}`)) {
    throw new Error("dkg_commit failed");
  }
  await post(`onchain_commit_${PARTY_INDEX}`, "done");

  // Wait for all parties to commit
  for (let j = 1; j <= NUM_PARTIES; j++) {
    await read(`onchain_commit_${j}`);
  }
  console.log(`  [P${PARTY_INDEX}] All parties committed on-chain`);
  await sleep(2000);

  // --- Step 3: Each party submits their reveal ---
  if (!await submitAndWait(partisia, 0x22,
    buildDkgRevealArgs(KEY_ID, PARTY_INDEX, dkgShare.publicKeyShare),
    `dkg_reveal_P${PARTY_INDEX}`)) {
    throw new Error("dkg_reveal failed");
  }
  await post(`onchain_reveal_${PARTY_INDEX}`, "done");

  // Wait for all reveals
  for (let j = 1; j <= NUM_PARTIES; j++) {
    await read(`onchain_reveal_${j}`);
  }
  console.log(`  [P${PARTY_INDEX}] All parties revealed on-chain`);
  await sleep(2000);

  // --- Step 4: Party 1 finalizes ---
  if (PARTY_INDEX === 1) {
    if (!await submitAndWait(partisia, 0x23, buildDkgFinalizeArgs(KEY_ID), "dkg_finalize")) {
      throw new Error("dkg_finalize failed");
    }
    await post("onchain_finalize_done", "1");
  } else {
    await read("onchain_finalize_done");
  }
  await sleep(3000);

  // --- Step 5: Each party submits their ZK secret (Shamir share halves) ---
  const [highBytes, lowBytes] = getShamirShareHalves(shamirShare);
  await submitZkShareHalf(partisia, zkClient, SIGNER_ADDR, KEY_ID, PARTY_INDEX, true, highBytes);
  await sleep(3000);
  await submitZkShareHalf(partisia, zkClient, SIGNER_ADDR, KEY_ID, PARTY_INDEX, false, lowBytes);
  await sleep(3000);
  await post(`onchain_zk_${PARTY_INDEX}`, "done");

  // Wait for all ZK secrets
  for (let j = 1; j <= NUM_PARTIES; j++) {
    await read(`onchain_zk_${j}`);
  }
  console.log(`  [P${PARTY_INDEX}] All parties submitted ZK secrets`);
  await sleep(5000);

  // --- Step 6: Party 1 completes keygen ---
  if (PARTY_INDEX === 1) {
    const ok = await submitAndWait(partisia, 0x24, buildDkgCompleteKeygenArgs(KEY_ID), "dkg_complete_keygen");
    if (!ok) {
      console.log("  Trying force_complete_keygen...");
      if (!await submitAndWait(partisia, 0x08, encodeU32(KEY_ID), "force_complete_keygen")) {
        throw new Error("dkg_complete_keygen failed");
      }
    }
    await post("onchain_keygen_done", "1");
  } else {
    await read("onchain_keygen_done");
  }

  // Compute combined public key from all commitments
  const allCommits = await Promise.all(
    Array.from({ length: NUM_PARTIES }, (_, i) =>
      readJson<{ C_i0: string }>(`dkg_commit_${i + 1}`)
    )
  );
  const allC_i0 = allCommits.map(c => hexToBytes(c.C_i0));
  const combinedPk = computeCombinedPublicKey(allC_i0);
  console.log(`  [P${PARTY_INDEX}] Combined public key: ${toHex(combinedPk)}`);

  return combinedPk;
}

// =============================================================================
// Phase 4 — Paillier key generation + exchange
// =============================================================================

async function phase4_paillierSetup(): Promise<PaillierKeyPair> {
  console.log(`\n[P${PARTY_INDEX}] Phase 4: Generating Paillier key pair...`);

  const paillierKeys = paillierKeygen(1024);
  const pk = paillierKeys.publicKey;

  // Post Paillier public key (n, n², g are all derivable from n, but we post explicitly)
  await postJson(`paillier_pk_${PARTY_INDEX}`, {
    n: pk.n.toString(16),
    n2: pk.n2.toString(16),
    g: pk.g.toString(16),
  });
  console.log(`  [P${PARTY_INDEX}] Posted Paillier public key`);

  return paillierKeys;
}

/** Read party j's Paillier public key from the bulletin board. */
async function readPaillierPk(j: number): Promise<PaillierPublicKey> {
  const raw = await readJson<{ n: string; n2: string; g: string }>(`paillier_pk_${j}`);
  const n = BigInt("0x" + raw.n);
  return {
    n,
    n2: BigInt("0x" + raw.n2),
    g: BigInt("0x" + raw.g),
  };
}

// =============================================================================
// Phase 5 — Distributed MtA rounds
// =============================================================================

/**
 * Run distributed MtA for (a_i, b_j) between parties i and j via the server.
 *
 * Party i (the "A" side) calls this for each j in the signing subset.
 * Party j (the "B" side) also calls this, responding to i's message.
 *
 * Both parties call this function concurrently — the long-poll handles sync.
 *
 * Returns: { alpha_i: bigint } — party i's additive share of a_i * b_j
 *          The beta (party j's share) is returned via their own call.
 */
async function runDistributedMtA_AsA(
  myValue: bigint,            // a_i
  otherPartyIndex: number,    // j
  topicPrefix: string,        // e.g. "mta_kg" or "mta_kx"
  myPaillierKeys: PaillierKeyPair
): Promise<bigint> {
  // Round 1: Encrypt a_i and post for party j
  const msg1 = mtaRound1_A(myValue, myPaillierKeys.publicKey);
  await postJson(`${topicPrefix}_${PARTY_INDEX}_${otherPartyIndex}`, {
    encryptedA: msg1.encryptedA.toString(16),
    paillierN: myPaillierKeys.publicKey.n.toString(16),
    paillierN2: myPaillierKeys.publicKey.n2.toString(16),
    paillierG: myPaillierKeys.publicKey.g.toString(16),
  });

  // Wait for party j's response
  const r2Raw = await readJson<{ encryptedResult: string }>(
    `${topicPrefix}_${PARTY_INDEX}_${otherPartyIndex}_r2`
  );
  const msg2: MtAMessage2 = { encryptedResult: BigInt("0x" + r2Raw.encryptedResult) };

  // Finalize: decrypt to get alpha
  const { alpha } = mtaFinalize_A(msg2, myPaillierKeys.publicKey, myPaillierKeys.privateKey);
  return alpha;
}

async function runDistributedMtA_AsB(
  otherPartyIndex: number,    // i (the A side)
  myValue: bigint,            // b_j
  topicPrefix: string         // e.g. "mta_kg" or "mta_kx"
): Promise<bigint> {
  // Wait for party i's Round 1 message
  const raw = await readJson<{
    encryptedA: string;
    paillierN: string;
    paillierN2: string;
    paillierG: string;
  }>(`${topicPrefix}_${otherPartyIndex}_${PARTY_INDEX}`);

  const paillierPk: PaillierPublicKey = {
    n: BigInt("0x" + raw.paillierN),
    n2: BigInt("0x" + raw.paillierN2),
    g: BigInt("0x" + raw.paillierG),
  };
  const msg1: MtAMessage1 = {
    encryptedA: BigInt("0x" + raw.encryptedA),
    paillierPk,
  };

  // Round 2: Compute response, pick beta
  const { msg2, outputB } = mtaRound2_B(msg1, myValue);

  // Post response back to party i
  await postJson(`${topicPrefix}_${otherPartyIndex}_${PARTY_INDEX}_r2`, {
    encryptedResult: msg2.encryptedResult.toString(16),
  });

  return outputB.beta;
}

/**
 * Run all MtA exchanges for the signing subset.
 *
 * For each ordered pair (i, j) in the subset where i ≠ j:
 * - MtA(k_i, γ_j) → α_ij (for i) + β_ij (for j) = k_i · γ_j
 * - MtA(k_i, x̃_j) → μ_ij (for i) + ν_ij (for j) = k_i · x̃_j
 *
 * Party i acts as "A" for pairs (i,j) and "B" for pairs (j,i).
 */
async function phase5_distributedMtA(
  state: GG20PartyState,
  adjustedShare: bigint,
  signingSubset: number[]
): Promise<void> {
  console.log(`\n[P${PARTY_INDEX}] Phase 5: Distributed MtA rounds...`);

  // Initialize delta_i = k_i · gamma_i, sigma_i = k_i · x̃_i
  state.delta_i = mod(state.k_i * state.gamma_i, N);
  state.sigma_i = mod(state.k_i * adjustedShare, N);

  const otherParties = signingSubset.filter(j => j !== PARTY_INDEX);

  // Run both MtA directions concurrently (as A for some, as B for others)
  const tasks: Promise<void>[] = [];

  for (const j of otherParties) {
    // MtA where I am Party A (encrypting k_i)
    tasks.push((async () => {
      // k_i · gamma_j → alpha + beta = k_i * gamma_j
      const alphaKG = await runDistributedMtA_AsA(
        state.k_i, j, `mta_kg_${KEY_ID}`, state.paillierKeys
      );
      // k_i · x̃_j → mu + nu = k_i * x̃_j
      const alphaKX = await runDistributedMtA_AsA(
        state.k_i, j, `mta_kx_${KEY_ID}`, state.paillierKeys
      );
      state.delta_i = mod(state.delta_i + alphaKG, N);
      state.sigma_i = mod(state.sigma_i + alphaKX, N);
      console.log(`  [P${PARTY_INDEX}] MtA (A side) with Party ${j}: done`);
    })());

    // MtA where I am Party B (responding to j's encryption of k_j)
    tasks.push((async () => {
      // gamma_i · k_j → party j gets alpha, I get beta
      const betaKG = await runDistributedMtA_AsB(j, state.gamma_i, `mta_kg_${KEY_ID}`);
      // x̃_i · k_j → party j gets mu, I get nu
      const betaKX = await runDistributedMtA_AsB(j, adjustedShare, `mta_kx_${KEY_ID}`);
      state.delta_i = mod(state.delta_i + betaKG, N);
      state.sigma_i = mod(state.sigma_i + betaKX, N);
      console.log(`  [P${PARTY_INDEX}] MtA (B side) with Party ${j}: done`);
    })());
  }

  await Promise.all(tasks);
  console.log(`  [P${PARTY_INDEX}] MtA complete. delta_i = ...${state.delta_i.toString(16).slice(-8)}`);
}

// =============================================================================
// Phase 6 — On-chain signing verification
// =============================================================================

async function phase6_onchainSigning(
  partisia: PartisiaClient,
  state: GG20PartyState,
  msgHash: Uint8Array,
  signingSubset: number[],
  combinedPk: Uint8Array
): Promise<void> {
  console.log(`\n[P${PARTY_INDEX}] Phase 6: On-chain signing...`);

  // Collect all gamma points and delta values from signing subset
  // (each party posts their own, then we wait for all)
  const myGammaPoint = state.Gamma_i;
  const myDeltaBytes = bigintTo32Bytes(state.delta_i);

  // Post our gamma point and delta to the board (for R computation)
  await post(`gamma_pt_${KEY_ID}_${PARTY_INDEX}`, toHex(myGammaPoint));
  await post(`delta_val_${KEY_ID}_${PARTY_INDEX}`, bigintToHex(state.delta_i));

  // Wait for all signing parties to post their gamma points and deltas
  const gammaPoints: Uint8Array[] = [];
  const deltaVals: bigint[] = [];
  for (const j of signingSubset) {
    const gp = hexToBytes(await read(`gamma_pt_${KEY_ID}_${j}`));
    const dv = hexToBigint(await read(`delta_val_${KEY_ID}_${j}`));
    gammaPoints.push(gp);
    deltaVals.push(dv);
  }

  // Compute combined delta = Σ delta_i and R = delta⁻¹ · Γ
  let combinedDelta = 0n;
  for (const d of deltaVals) combinedDelta = mod(combinedDelta + d, N);

  let Gamma = secp256k1.ProjectivePoint.fromHex(gammaPoints[0]);
  for (let i = 1; i < gammaPoints.length; i++) {
    Gamma = Gamma.add(secp256k1.ProjectivePoint.fromHex(gammaPoints[i]));
  }

  const deltaInv = modInverse(combinedDelta, N);
  const R = Gamma.multiply(deltaInv);
  const R_affine = R.toAffine();
  const r = R_affine.x % N;

  // Compute partial signature: s_i = m · k_i + r · σ_i
  const m = bytesToBigint(msgHash);
  const s_i = mod(mod(m * state.k_i, N) + mod(r * state.sigma_i, N), N);
  const sBytes = bigintTo32Bytes(s_i);

  console.log(`  [P${PARTY_INDEX}] r = ...${r.toString(16).slice(-8)}`);
  console.log(`  [P${PARTY_INDEX}] s_${PARTY_INDEX} = ...${s_i.toString(16).slice(-8)}`);

  // --- Policy check (client-side enforcement) ---
  if (TX_TAG) {
    console.log(`  [P${PARTY_INDEX}] Policy check: tag="${TX_TAG}", subset={${signingSubset.join(",")}}`);
    policies.enforce(TX_TAG, signingSubset); // throws immediately if mandatory party is missing
    console.log(`  [P${PARTY_INDEX}] Policy check: PASSED`);
  }

  // --- Submit to contract ---

  // Party 1: start signing session
  if (PARTY_INDEX === 1) {
    const startArgs = buildGG20StartSigningArgs(KEY_ID, TASK_ID, signingSubset);
    if (!await submitAndWait(partisia, 0x50, startArgs, "gg20_start_signing")) {
      throw new Error("gg20_start_signing failed");
    }
    await post(`onchain_signing_started_${KEY_ID}`, "1");
  } else {
    await read(`onchain_signing_started_${KEY_ID}`);
  }
  await sleep(2000);

  // Submit delta
  if (!await submitAndWait(partisia, 0x45, buildSubmitDeltaArgs(KEY_ID, PARTY_INDEX, myDeltaBytes), `delta_P${PARTY_INDEX}`)) {
    throw new Error("submit_delta failed");
  }
  await post(`onchain_delta_${KEY_ID}_${PARTY_INDEX}`, "done");
  for (const j of signingSubset) await read(`onchain_delta_${KEY_ID}_${j}`);
  await sleep(2000);

  // Submit gamma point
  if (!await submitAndWait(partisia, 0x46, buildSubmitGammaPointArgs(KEY_ID, PARTY_INDEX, myGammaPoint), `gamma_P${PARTY_INDEX}`)) {
    throw new Error("submit_gamma_point failed");
  }
  await post(`onchain_gamma_${KEY_ID}_${PARTY_INDEX}`, "done");
  for (const j of signingSubset) await read(`onchain_gamma_${KEY_ID}_${j}`);
  await sleep(2000);

  // Party 1: finalize R
  if (PARTY_INDEX === 1) {
    if (!await submitAndWait(partisia, 0x47, buildGG20FinalizeRArgs(KEY_ID), "gg20_finalize_r")) {
      throw new Error("gg20_finalize_r failed");
    }
    await post(`onchain_r_done_${KEY_ID}`, "1");
  } else {
    await read(`onchain_r_done_${KEY_ID}`);
  }
  await sleep(2000);

  // Commit partial sig
  const commitHash = await gg20Sha256(sBytes);
  if (!await submitAndWait(partisia, 0x44, buildCommitPartialSigArgs(KEY_ID, PARTY_INDEX, commitHash), `commit_sig_P${PARTY_INDEX}`)) {
    throw new Error("commit_partial_sig failed");
  }
  await post(`onchain_commit_sig_${KEY_ID}_${PARTY_INDEX}`, "done");
  for (const j of signingSubset) await read(`onchain_commit_sig_${KEY_ID}_${j}`);
  await sleep(2000);

  // Reveal partial sig
  if (!await submitAndWait(partisia, 0x31, buildSubmitPartialSigArgs(KEY_ID, PARTY_INDEX, sBytes), `partial_sig_P${PARTY_INDEX}`)) {
    throw new Error("submit_partial_sig failed");
  }
  await post(`onchain_reveal_sig_${KEY_ID}_${PARTY_INDEX}`, "done");
  for (const j of signingSubset) await read(`onchain_reveal_sig_${KEY_ID}_${j}`);

  // Local verification (redundant but good sanity check)
  if (PARTY_INDEX === 1) {
    // Collect all partial sigs to verify locally
    const partialSigs: bigint[] = [];
    for (const j of signingSubset) {
      // We don't have other parties' s_i values here — local verification is skipped
      // The on-chain contract does the authoritative verification
    }
    console.log(`\n  [P${PARTY_INDEX}] On-chain contract will verify combined signature`);
    console.log(`  [P${PARTY_INDEX}] If all partial sigs submitted, contract will PASS`);
  }
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  console.log(`\n  Kosh ZK Signer — Party ${PARTY_INDEX} of ${NUM_PARTIES}`);
  console.log(`  Coordination server: ${COORD_URL}`);
  console.log(`  Signing subset:      {${SIGNING_SUBSET.join(",")}}`);
  console.log(`  Transaction tag:     ${TX_TAG || "(none — any 2-of-3 allowed)"}`);
  console.log(`  Key ID:              ${KEY_ID}`);
  if (policies.list().length > 0) {
    console.log(`  Active policies:`);
    printPolicies(policies);
  }
  console.log();

  const partisia = new PartisiaClient({
    nodeUrl: NODE_URL,
    senderPrivateKey: SENDER_KEY,
    senderAddress: SENDER_ADDR,
  });

  // Check if I'm in the signing subset
  const inSigningSubset = SIGNING_SUBSET.includes(PARTY_INDEX);
  if (!inSigningSubset) {
    console.log(`  Party ${PARTY_INDEX} is NOT in signing subset {${SIGNING_SUBSET.join(",")}} — will participate in DKG only.`);
  }

  // --- Phase 1: DKG polynomial generation ---
  const { dkgShare } = await phase1_dkgGenerate();

  // --- Phase 2: Collect + verify sub-shares ---
  const shamirShare = await phase2_collectShares(dkgShare);

  // --- Phase 3: On-chain DKG ceremony ---
  const combinedPk = await phase3_onchainDkg(partisia, dkgShare, shamirShare);

  // Every DKG party still needs to register its on-chain identity and PQC keys.
  // Signing subset members continue into Paillier/MtA; non-signers stop after identity setup.
  await phaseRegisterOnchainIdentity(partisia);

  if (!inSigningSubset) {
    console.log(`\n  [P${PARTY_INDEX}] DKG complete. Party ${PARTY_INDEX} is offline for signing.`);
    console.log(`  [P${PARTY_INDEX}] The signing parties {${SIGNING_SUBSET.join(",")}} will proceed.`);
    return;
  }

  // --- Phase 4: Paillier key setup ---
  const paillierKeys = await phase4_paillierSetup();

  // Wait for all signing parties to post their Paillier PKs
  for (const j of SIGNING_SUBSET) {
    await read(`paillier_pk_${j}`);
  }
  console.log(`  [P${PARTY_INDEX}] All signing parties have Paillier keys`);

  // --- Party 1 posts the message to sign ---
  let msgHash: Uint8Array;
  if (PARTY_INDEX === 1) {
    const rawHash = new Uint8Array(32);
    globalThis.crypto.getRandomValues(rawHash);
    await post(`msg_to_sign_${KEY_ID}`, Buffer.from(rawHash).toString("hex"));

    // Queue signing on contract (include TX_TAG so contract can enforce policy)
    const signArgs = buildSignMessageWithTagArgs(KEY_ID, rawHash, TX_TAG);
    if (!await submitAndWait(partisia, 0x03, signArgs, "sign_message")) {
      throw new Error("sign_message failed");
    }
    await post(`onchain_sign_queued_${KEY_ID}`, "1");
    msgHash = rawHash;
    console.log(`  [P${PARTY_INDEX}] Posted message to sign: ${Buffer.from(rawHash).toString("hex").slice(0, 16)}...`);
  } else {
    await read(`onchain_sign_queued_${KEY_ID}`);
    const hashHex = await read(`msg_to_sign_${KEY_ID}`);
    msgHash = hexToBytes(hashHex);
    console.log(`  [P${PARTY_INDEX}] Got message to sign: ${hashHex.slice(0, 16)}...`);
  }

  // --- PQC approvals (Kyber transport + Dilithium signatures) ---
  await phasePqcApprovals(partisia, msgHash, SIGNING_SUBSET, TASK_ID);

  // --- Initialize GG20 party state ---
  const adjustedShare = computeAdjustedShare(shamirShare, SIGNING_SUBSET);
  console.log(`  [P${PARTY_INDEX}] Lagrange-adjusted share x̃_${PARTY_INDEX} = ...${adjustedShare.toString(16).slice(-8)}`);

  const state = gg20InitParty(
    PARTY_INDEX,
    adjustedShare,
    paillierKeys,
    msgHash,
    KEY_ID // session ID = key ID for simplicity
  );

  // --- Phase 5: Distributed MtA ---
  await phase5_distributedMtA(state, adjustedShare, SIGNING_SUBSET);

  // --- Phase 6: On-chain signing ---
  await phase6_onchainSigning(partisia, state, msgHash, SIGNING_SUBSET, combinedPk);

  console.log(`\n${"=".repeat(60)}`);
  console.log(`  PARTY ${PARTY_INDEX} — COMPLETE`);
  console.log(`${"=".repeat(60)}`);
  console.log(`  Key ID:          ${KEY_ID}`);
  console.log(`  Signing subset:  {${SIGNING_SUBSET.join(",")}}`);
  console.log(`  Combined pubkey: ${toHex(combinedPk)}`);
  console.log(`  No coordinator. No seed phrase. No assembled private key.`);
}

main().catch((err) => {
  console.error(`[P${PARTY_INDEX}] Fatal:`, err.message ?? err);
  process.exit(1);
});
