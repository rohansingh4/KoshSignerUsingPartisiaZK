import { PartisiaClient } from "./partisia.js";
import { buildRegisterPartyAddressArgs, buildSignMessageWithTagArgs } from "./policy.js";
import {
  buildFinalizePqcApprovalArgs,
  buildGG20StartSigningArgs,
  buildRegisterDilithiumPubkeyArgs,
  buildRegisterKyberPubkeyArgs,
  buildStartPqcApprovalSessionArgs,
  buildSubmitPqcApprovalArgs,
} from "./gg20-signing.js";
import { generatePqcIdentity, sha256 } from "./pqc.js";

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

export async function submitAndWait(
  partisia: PartisiaClient,
  contractAddress: string,
  shortname: number,
  args: Uint8Array,
  label: string,
): Promise<boolean> {
  const client = partisia.getTransactionClient();
  const shortnameBytes = shortname <= 0xff ? [shortname] : [shortname >> 8, shortname & 0xff];
  const wasmRpc = Buffer.from([...shortnameBytes, ...args]);
  const rpc = Buffer.concat([Buffer.from([0x09]), wasmRpc]);
  const tx = { address: contractAddress, rpc };
  let sent: Awaited<ReturnType<typeof client.signAndSend>> | undefined;
  let tree: Awaited<ReturnType<typeof client.waitForSpawnedEvents>> | undefined;
  let lastErr: unknown;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      sent = await client.signAndSend(tx, 500000);
      const txId = sent.transactionPointer.identifier;
      console.log(`  Tx: ${txId}${attempt > 1 ? ` (attempt ${attempt})` : ""}`);
      tree = await client.waitForSpawnedEvents(sent);
      break;
    } catch (err) {
      lastErr = err;
      if (attempt === 3) throw err;
      console.warn(`  ${label}: transient Partisia RPC failure, retrying (${attempt}/3)`);
      await new Promise((resolve) => setTimeout(resolve, 1500 * attempt));
    }
  }
  if (!tree) throw lastErr instanceof Error ? lastErr : new Error(String(lastErr ?? "unknown Partisia RPC error"));
  const rootStatus = (tree as any).root?.transaction?.executionStatus
    ?? (tree as any).transaction?.executionStatus;
  if (rootStatus?.success === false) {
    const msg = rootStatus.failure?.errorMessage ?? "unknown error";
    console.error(`  ${label} FAILED: ${msg.split("\n")[0]}`);
    return false;
  }
  const events = tree.events ?? (tree as any).spawned ?? [];
  for (const ev of events) {
    const es = (ev as any).transaction?.executionStatus ?? (ev as any).executionStatus;
    if (es?.success === false) {
      const msg = es.failure?.errorMessage ?? es.errorMessage ?? "unknown error";
      console.error(`  ${label} FAILED (spawned): ${msg.split("\n")[0]}`);
      return false;
    }
  }
  if ((tree as any).failed) {
    console.error(`  ${label} FAILED: transaction tree marked as failed`);
    return false;
  }
  console.log(`  ${label} OK`);
  return true;
}

function computePqcSessionChallenge(
  keyId: number,
  taskId: number,
  msgHash: Uint8Array,
  txTag: string,
  signingSubset: number[],
): Uint8Array {
  return sha256(concatBytes(
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
  challenge: Uint8Array,
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

export async function registerOnchainPqcIdentities(
  partisia: PartisiaClient,
  contractAddress: string,
  keyId: number,
  parties: number[],
  senderAddress: string,
): Promise<void> {
  const identities = parties.map(() => generatePqcIdentity());
  for (const partyIndex of parties) {
    if (!await submitAndWait(
      partisia,
      contractAddress,
      0x72,
      buildRegisterPartyAddressArgs(keyId, partyIndex, senderAddress),
      `register_party_address_P${partyIndex}`,
    )) process.exit(1);
    if (!await submitAndWait(
      partisia,
      contractAddress,
      0x73,
      buildRegisterDilithiumPubkeyArgs(keyId, partyIndex, identities[partyIndex - 1].dilithium.publicKey),
      `register_dilithium_pubkey_P${partyIndex}`,
    )) process.exit(1);
    if (!await submitAndWait(
      partisia,
      contractAddress,
      0x74,
      buildRegisterKyberPubkeyArgs(keyId, partyIndex, identities[partyIndex - 1].kyber.publicKey),
      `register_kyber_pubkey_P${partyIndex}`,
    )) process.exit(1);
  }
}

export async function queueSignAndApprove(
  partisia: PartisiaClient,
  contractAddress: string,
  keyId: number,
  taskId: number,
  msgHash: Uint8Array,
  txTag: string,
  signingSubset: number[],
): Promise<void> {
  if (!await submitAndWait(
    partisia,
    contractAddress,
    0x03,
    buildSignMessageWithTagArgs(keyId, msgHash, txTag),
    `sign_message_${taskId}`,
  )) process.exit(1);

  if (!await submitAndWait(
    partisia,
    contractAddress,
    0x75,
    buildStartPqcApprovalSessionArgs(keyId, taskId, signingSubset),
    `start_pqc_approval_session_${taskId}`,
  )) process.exit(1);

  const challenge = computePqcSessionChallenge(keyId, taskId, msgHash, txTag, signingSubset);
  for (const partyIndex of signingSubset) {
    const approvalHash = sha256(buildPqcApprovalPayload(
      keyId,
      taskId,
      partyIndex,
      msgHash,
      txTag,
      signingSubset,
      challenge,
    ));
    if (!await submitAndWait(
      partisia,
      contractAddress,
      0x76,
      buildSubmitPqcApprovalArgs(keyId, taskId, partyIndex, approvalHash),
      `submit_pqc_approval_P${partyIndex}_task_${taskId}`,
    )) process.exit(1);
  }

  if (!await submitAndWait(
    partisia,
    contractAddress,
    0x77,
    buildFinalizePqcApprovalArgs(keyId, taskId),
    `finalize_pqc_approval_${taskId}`,
  )) process.exit(1);
}

export async function startApprovedGg20(
  partisia: PartisiaClient,
  contractAddress: string,
  keyId: number,
  taskId: number,
  signingSubset: number[],
): Promise<void> {
  if (!await submitAndWait(
    partisia,
    contractAddress,
    0x50,
    buildGG20StartSigningArgs(keyId, taskId, signingSubset),
    `gg20_start_signing_${taskId}`,
  )) process.exit(1);
}
