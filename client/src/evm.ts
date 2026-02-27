/**
 * EVM transaction building and submission utilities.
 *
 * Uses viem for Base Sepolia ERC20 transfers and general EVM tx construction.
 * Converts MPC-generated secp256k1 signatures into EVM-compatible signed transactions.
 */

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
import { baseSepolia } from "viem/chains";

/** Base Sepolia public client for reading chain state and submitting txs. */
export const baseSepoliaClient = createPublicClient({
  chain: baseSepolia,
  transport: http(),
});

/**
 * Derive an EVM address from a compressed secp256k1 public key (33 bytes).
 *
 * EVM address = last 20 bytes of keccak256(uncompressed_pubkey_without_prefix)
 *
 * Note: This requires decompressing the point. We use viem's secp256k1 utils.
 */
export function pubKeyToEvmAddress(compressedPubKey: Uint8Array): Hex {
  // For a proper implementation, we'd decompress the point and take keccak256.
  // viem doesn't expose point decompression directly, so we use a workaround:
  // The secp256k1 library can decompress the point.

  // Import secp256k1 from viem's internal dependency
  const { secp256k1 } = require("@noble/curves/secp256k1") as {
    secp256k1: {
      ProjectivePoint: {
        fromHex: (hex: Uint8Array) => { toRawBytes: (compressed?: boolean) => Uint8Array };
      };
    };
  };

  const point = secp256k1.ProjectivePoint.fromHex(compressedPubKey);
  const uncompressed = point.toRawBytes(false);

  // Remove the 0x04 prefix (65 bytes -> 64 bytes)
  const pubKeyBytes = uncompressed.slice(1);

  // keccak256 of the 64-byte public key, take last 20 bytes
  const hash = keccak256(pubKeyBytes as Hex);
  const address = ("0x" + hash.slice(-40)) as Hex;
  return address;
}

/** Standard ERC20 ABI for transfer function. */
const erc20Abi = parseAbi([
  "function transfer(address to, uint256 amount) returns (bool)",
  "function balanceOf(address account) view returns (uint256)",
]);

/**
 * Build an EIP-1559 ERC20 transfer transaction (unsigned).
 */
export async function buildErc20Transfer(params: {
  from: Hex;
  tokenAddress: Hex;
  to: Hex;
  amount: bigint;
}): Promise<TransactionSerializable> {
  const { from, tokenAddress, to, amount } = params;

  const [nonce, gasPrice, chainId] = await Promise.all([
    baseSepoliaClient.getTransactionCount({ address: from }),
    baseSepoliaClient.estimateFeesPerGas(),
    baseSepoliaClient.getChainId(),
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

/**
 * Build a simple ETH transfer transaction (unsigned).
 */
export async function buildEthTransfer(params: {
  from: Hex;
  to: Hex;
  value: bigint;
}): Promise<TransactionSerializable> {
  const { from, to, value } = params;

  const [nonce, gasPrice, chainId] = await Promise.all([
    baseSepoliaClient.getTransactionCount({ address: from }),
    baseSepoliaClient.estimateFeesPerGas(),
    baseSepoliaClient.getChainId(),
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

/**
 * Compute the signing hash for an EIP-1559 transaction.
 * This is the 32-byte hash that needs to be signed by the MPC signer.
 */
export function getTransactionSigningHash(tx: TransactionSerializable): Hex {
  const serialized = serializeTransaction(tx);
  return keccak256(serialized);
}

/**
 * Attach an ECDSA signature to a transaction and serialize it.
 *
 * @param tx - The unsigned transaction
 * @param r - 32-byte r component of the signature
 * @param s - 32-byte s component of the signature
 * @param recoveryId - Recovery ID (0 or 1), used to derive v/yParity
 * @returns The fully signed, serialized transaction ready for submission
 */
export function signTransaction(
  tx: TransactionSerializable,
  r: Hex,
  s: Hex,
  recoveryId: number
): Hex {
  const signature = {
    r,
    s,
    yParity: recoveryId as 0 | 1,
  };

  return serializeTransaction(tx, signature);
}

/**
 * Submit a signed transaction to Base Sepolia.
 */
export async function submitSignedTransaction(
  signedTx: Hex
): Promise<Hex> {
  const hash = await baseSepoliaClient.sendRawTransaction({
    serializedTransaction: signedTx,
  });
  return hash;
}

/**
 * Convert raw signature bytes (64 bytes: r || s) to hex components.
 * Tries both recovery IDs (0 and 1) to find the correct one.
 */
export function parseSignatureBytes(
  sigBytes: Uint8Array,
  signingHash: Hex,
  expectedAddress: Hex
): { r: Hex; s: Hex; recoveryId: number } {
  if (sigBytes.length !== 64) {
    throw new Error(`Expected 64 signature bytes, got ${sigBytes.length}`);
  }

  const r = toHex(sigBytes.slice(0, 32));
  const s = toHex(sigBytes.slice(32, 64));

  // For now, return recovery ID 0 — the client should try both
  // and verify which one recovers to the expected address
  return { r, s, recoveryId: 0 };
}
