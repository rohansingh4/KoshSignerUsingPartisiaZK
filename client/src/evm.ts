import {
  createPublicClient,
  http,
  keccak256,
  serializeTransaction,
  type Hex,
  type TransactionSerializable,
  parseAbi,
  encodeFunctionData,
  toHex,
} from "viem";
import { sepolia } from "viem/chains";
import { secp256k1 } from "@noble/curves/secp256k1";

export const sepoliaClient = createPublicClient({
  chain: sepolia,
  transport: http(),
});

export const baseSepoliaClient = sepoliaClient;

export function pubKeyToEvmAddress(compressedPubKey: Uint8Array): Hex {
  const point = secp256k1.ProjectivePoint.fromHex(compressedPubKey);
  const uncompressed = point.toRawBytes(false);
  const pubKeyBytes = uncompressed.slice(1);
  const hash = keccak256(toHex(pubKeyBytes));
  return ("0x" + hash.slice(-40)) as Hex;
}

const erc20Abi = parseAbi([
  "function transfer(address to, uint256 amount) returns (bool)",
  "function balanceOf(address account) view returns (uint256)",
]);

export async function buildErc20Transfer(params: {
  from: Hex;
  tokenAddress: Hex;
  to: Hex;
  amount: bigint;
}): Promise<TransactionSerializable> {
  const { from, tokenAddress, to, amount } = params;

  const [nonce, gasPrice, chainId] = await Promise.all([
    sepoliaClient.getTransactionCount({ address: from }),
    sepoliaClient.estimateFeesPerGas(),
    sepoliaClient.getChainId(),
  ]);

  const data = encodeFunctionData({
    abi: erc20Abi,
    functionName: "transfer",
    args: [to, amount],
  });

  return {
    to: tokenAddress,
    data,
    chainId,
    nonce,
    maxFeePerGas: gasPrice.maxFeePerGas,
    maxPriorityFeePerGas: gasPrice.maxPriorityFeePerGas,
    gas: 65_000n,
    type: "eip1559",
  };
}

export async function buildEthTransfer(params: {
  from: Hex;
  to: Hex;
  value: bigint;
}): Promise<TransactionSerializable> {
  const { from, to, value } = params;

  const [nonce, gasPrice, chainId] = await Promise.all([
    sepoliaClient.getTransactionCount({ address: from }),
    sepoliaClient.estimateFeesPerGas(),
    sepoliaClient.getChainId(),
  ]);

  return {
    to,
    value,
    chainId,
    nonce,
    maxFeePerGas: gasPrice.maxFeePerGas,
    maxPriorityFeePerGas: gasPrice.maxPriorityFeePerGas,
    gas: 21_000n,
    type: "eip1559",
  };
}

export function getTransactionSigningHash(tx: TransactionSerializable): Hex {
  const serialized = serializeTransaction(tx);
  return keccak256(serialized);
}

export function signTransaction(
  tx: TransactionSerializable,
  r: Hex,
  s: Hex,
  recoveryId: number
): Hex {
  return serializeTransaction(tx, {
    r,
    s,
    yParity: recoveryId as 0 | 1,
  });
}

export async function submitSignedTransaction(
  signedTx: Hex
): Promise<Hex> {
  return sepoliaClient.sendRawTransaction({
    serializedTransaction: signedTx,
  });
}

export function parseSignatureBytes(
  sigBytes: Uint8Array,
  _signingHash: Hex,
  _expectedAddress: Hex
): { r: Hex; s: Hex; recoveryId: number } {
  if (sigBytes.length !== 64 && sigBytes.length !== 65) {
    throw new Error(`Expected 64 or 65 signature bytes, got ${sigBytes.length}`);
  }

  const r = toHex(sigBytes.slice(0, 32));
  const s = toHex(sigBytes.slice(32, 64));
  const recoveryId = sigBytes.length === 65 ? sigBytes[64] : 0;
  return { r, s, recoveryId };
}
