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
import {
  submitAndWait,
  encodeU32Be,
  encodeLenPrefixedBytes,
  encodePartyVector,
  concatBytes,
} from "./chain-utils.js";

export { submitAndWait };

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
