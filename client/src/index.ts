/**
 * Kosh Keyless Account E2E Demo
 *
 * Demonstrates the full flow:
 * 1. Create an account on Partisia (triggers MPC key generation)
 * 2. Derive the EVM address from the MPC-generated public key
 * 3. Build an EVM transaction (ETH transfer on Base Sepolia)
 * 4. Request MPC signature via Partisia
 * 5. Assemble signed transaction and submit to Base Sepolia
 *
 * Prerequisites:
 * - Deployed kosh-vault, kosh-mpc-signer, kosh-account-registry on Partisia testnet
 * - Set environment variables (see below)
 */

import { keccak256, toBytes, toHex, type Hex } from "viem";
import { PartisiaClient } from "./partisia.js";
import {
  pubKeyToEvmAddress,
  buildEthTransfer,
  getTransactionSigningHash,
  signTransaction,
  submitSignedTransaction,
  parseSignatureBytes,
} from "./evm.js";

// --- Configuration ---

const config = {
  // Partisia testnet addresses (set after deployment)
  vaultAddress: process.env.VAULT_ADDRESS ?? "",
  signerAddress: process.env.SIGNER_ADDRESS ?? "",
  registryAddress: process.env.REGISTRY_ADDRESS ?? "",

  // Partisia sender credentials
  partisiaSenderKey: process.env.PARTISIA_SENDER_KEY ?? "",
  partisiaSenderAddress: process.env.PARTISIA_SENDER_ADDRESS ?? "",

  // EVM config
  evmRecipient: (process.env.EVM_RECIPIENT ?? "0x0000000000000000000000000000000000000001") as Hex,
  evmAmount: BigInt(process.env.EVM_AMOUNT ?? "1000000000000000"), // 0.001 ETH
};

// --- Helper: encode u32 as 4 big-endian bytes ---

function encodeU32(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (n >> 24) & 0xff;
  buf[1] = (n >> 16) & 0xff;
  buf[2] = (n >> 8) & 0xff;
  buf[3] = n & 0xff;
  return buf;
}

// --- Main E2E Flow ---

async function main() {
  console.log("=== Kosh Keyless Account E2E Demo ===\n");

  if (!config.vaultAddress) {
    console.log("Configuration:");
    console.log("  Set these environment variables before running:");
    console.log("    VAULT_ADDRESS       - Deployed vault contract address");
    console.log("    SIGNER_ADDRESS      - Deployed signer contract address");
    console.log("    REGISTRY_ADDRESS    - Deployed registry contract address");
    console.log("    PARTISIA_SENDER_KEY - Your Partisia private key (hex)");
    console.log("    PARTISIA_SENDER_ADDRESS - Your Partisia address");
    console.log("    EVM_RECIPIENT       - EVM address to send ETH to (optional)");
    console.log("    EVM_AMOUNT          - Amount in wei (optional, default 0.001 ETH)");
    process.exit(1);
  }

  const partisia = new PartisiaClient({
    senderPrivateKey: config.partisiaSenderKey,
    senderAddress: config.partisiaSenderAddress,
  });

  // Step 1: Create account on Partisia
  console.log("Step 1: Creating keyless account on Partisia...");
  const userIdHash = keccak256(toBytes("demo-user@kosh.finance"));
  console.log(`  User ID hash: ${userIdHash}`);

  // Submit create_account(user_id_hash) to vault
  // Shortname 0x01, arg = 32-byte hash
  const hashBytes = toBytes(userIdHash);
  const txHash = await partisia.submitAction(
    config.vaultAddress,
    0x01,
    hashBytes
  );
  console.log(`  Transaction submitted: ${txHash}`);

  // Step 2: Poll for key generation completion
  console.log("\nStep 2: Waiting for MPC key generation...");

  type SignerState = {
    keys: Record<
      string,
      {
        public_key: string | null;
        keygen_phase: { discriminant: number };
      }
    >;
  };

  const publicKeyHex = await partisia.pollUntil<string>(
    config.signerAddress,
    (state) => {
      const signerState = state as unknown as SignerState;
      const key = signerState?.keys?.["0"];
      if (key?.public_key && key.keygen_phase?.discriminant === 2) {
        return key.public_key;
      }
      return null;
    },
    { intervalMs: 5000, timeoutMs: 180_000 }
  );

  console.log(`  Public key: ${publicKeyHex}`);

  // Step 3: Derive EVM address
  console.log("\nStep 3: Deriving EVM address from MPC public key...");
  const pubKeyBytes = toBytes(publicKeyHex as Hex);
  const evmAddress = pubKeyToEvmAddress(pubKeyBytes);
  console.log(`  EVM address: ${evmAddress}`);
  console.log(
    `  Fund this address on Base Sepolia: https://www.alchemy.com/faucets/base-sepolia`
  );

  // Step 4: Build EVM transaction
  console.log("\nStep 4: Building EVM transaction...");
  const tx = await buildEthTransfer({
    from: evmAddress,
    to: config.evmRecipient,
    value: config.evmAmount,
  });
  console.log(`  To: ${config.evmRecipient}`);
  console.log(`  Value: ${config.evmAmount} wei`);

  const signingHash = getTransactionSigningHash(tx);
  console.log(`  Signing hash: ${signingHash}`);

  // Step 5: Request MPC signature via Partisia
  console.log("\nStep 5: Requesting MPC signature...");
  const sigHashBytes = toBytes(signingHash);

  // Submit request_signature(account_id=0, message=signingHash) to vault
  // Shortname 0x03, args = u32(account_id) + bytes(message_hash)
  const signArgs = new Uint8Array([
    ...encodeU32(0), // account_id = 0
    ...sigHashBytes, // 32-byte signing hash
  ]);
  const signTxHash = await partisia.submitAction(
    config.vaultAddress,
    0x03,
    signArgs
  );
  console.log(`  Signing request submitted: ${signTxHash}`);

  // Step 6: Poll for signature completion
  console.log("\nStep 6: Waiting for MPC signing...");

  type SigningInfo = {
    signing_information: Record<
      string,
      {
        signature: string | null;
        verified: boolean;
      }
    >;
  };

  const signatureHex = await partisia.pollUntil<string>(
    config.signerAddress,
    (state) => {
      const signerState = state as unknown as { keys: Record<string, SigningInfo> };
      const key = signerState?.keys?.["0"];
      const sigInfo = key?.signing_information?.["0"];
      if (sigInfo?.signature && sigInfo.verified) {
        return sigInfo.signature;
      }
      return null;
    },
    { intervalMs: 5000, timeoutMs: 300_000 }
  );

  console.log(`  Signature: ${signatureHex}`);

  // Step 7: Assemble and submit signed transaction
  console.log("\nStep 7: Assembling signed transaction...");
  const sigBytes = toBytes(signatureHex as Hex);
  const { r, s, recoveryId } = parseSignatureBytes(
    sigBytes,
    signingHash,
    evmAddress
  );

  const signedTx = signTransaction(tx, r, s, recoveryId);
  console.log(`  Signed tx: ${signedTx.slice(0, 66)}...`);

  console.log("\nStep 8: Submitting to Base Sepolia...");
  try {
    const evmTxHash = await submitSignedTransaction(signedTx);
    console.log(`  Transaction hash: ${evmTxHash}`);
    console.log(
      `  View on BaseScan: https://sepolia.basescan.org/tx/${evmTxHash}`
    );
  } catch (err) {
    console.error(`  Submission failed: ${err}`);
    console.log(
      "  This may be because the EVM address needs to be funded with Base Sepolia ETH."
    );
  }

  console.log("\n=== Demo Complete ===");
}

main().catch(console.error);
