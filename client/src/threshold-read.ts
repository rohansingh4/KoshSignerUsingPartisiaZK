import type { Hex } from "viem";
import { pubKeyToEvmAddress } from "./evm.js";
import { PartisiaClient } from "./partisia.js";

export interface ThresholdKeyStatus {
  keyId: number;
  exists: boolean;
  publicKeyHex: Hex | null;
  evmAddress: Hex | null;
  keygenPhaseDiscriminant: number | null;
  signingPhaseDiscriminant: number | null;
  verifiedTaskIds: number[];
}

type ContractKeyState = {
  public_key?: string | null;
  keygen_phase?: { discriminant?: number };
  signing_phase?: { discriminant?: number };
  signing_information?: Record<
    string,
    {
      verified?: boolean;
    }
  >;
};

export async function getThresholdKeyStatus(
  partisia: PartisiaClient,
  signerAddress: string,
  keyId: number
): Promise<ThresholdKeyStatus> {
  const state = await partisia.getContractData(signerAddress);
  const keys = (state as { openState?: { keys?: Record<string, ContractKeyState> } }).openState?.keys ?? {};
  const key = keys[String(keyId)];

  if (!key) {
    return {
      keyId,
      exists: false,
      publicKeyHex: null,
      evmAddress: null,
      keygenPhaseDiscriminant: null,
      signingPhaseDiscriminant: null,
      verifiedTaskIds: [],
    };
  }

  const publicKeyHex = (key.public_key ?? null) as Hex | null;
  const evmAddress = publicKeyHex ? pubKeyToEvmAddress(Buffer.from(publicKeyHex.slice(2), "hex")) : null;
  const verifiedTaskIds = Object.entries(key.signing_information ?? {})
    .filter(([, value]) => value?.verified)
    .map(([taskId]) => Number(taskId))
    .filter((taskId) => !Number.isNaN(taskId))
    .sort((a, b) => a - b);

  return {
    keyId,
    exists: true,
    publicKeyHex,
    evmAddress,
    keygenPhaseDiscriminant: key.keygen_phase?.discriminant ?? null,
    signingPhaseDiscriminant: key.signing_phase?.discriminant ?? null,
    verifiedTaskIds,
  };
}
