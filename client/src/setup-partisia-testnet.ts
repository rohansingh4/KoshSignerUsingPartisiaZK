/**
 * One-shot Partisia testnet setup:
 * 1) Deploy account-registry
 * 2) Deploy vault
 * 3) Deploy zk-signer (owned by vault)
 * 4) Wire vault signer + transfer registry ownership to vault
 * 5) Create first account via vault
 *
 * Usage:
 *   npx tsx src/setup-partisia-testnet.ts
 *
 * Optional env:
 *   PARTISIA_NODE_URL
 *   PARTISIA_WEB_URL
 *   PARTISIA_PK_FILE
 *   PARTISIA_SENDER_KEY
 *   PARTISIA_SENDER_ADDRESS
 *   ACCOUNT_LABEL
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import {
  BlockchainTransactionClient,
  SenderAuthenticationKeyPair,
} from "@partisiablockchain/blockchain-api-transaction-client";
import { ChainControllerApi } from "@partisiablockchain/blockchain-api-transaction-client/target/main/generated/openapi/apis/ChainControllerApi.js";
import { Configuration } from "@partisiablockchain/blockchain-api-transaction-client/target/main/generated/openapi/runtime.js";
import { BlockchainClientForDeploymentImpl } from "@partisiablockchain/abi-client/target/main/deploymentclient/BlockchainClientForDeploymentImpl.js";
import { DeploymentBuilder } from "@partisiablockchain/abi-client/target/main/deploymentclient/DeploymentBuilder.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const NODE_URL = process.env.PARTISIA_NODE_URL ?? "https://node1.testnet.partisiablockchain.com";
const WEB_URL = process.env.PARTISIA_WEB_URL ?? "https://browser.testnet.partisiablockchain.com";

const DEFAULT_DEPLOYER_ADDRESS = "00c64bd3ad942e3efc3d4f3a6b7000ff88b595a180";
const DEPLOYER_PK_FILE =
  process.env.PARTISIA_PK_FILE ??
  resolve(__dirname, "../../00c64bd3ad942e3efc3d4f3a6b7000ff88b595a180.pk");
const DEPLOYER_KEY =
  process.env.PARTISIA_SENDER_KEY ?? readFileSync(DEPLOYER_PK_FILE, "utf8").trim();
const DEPLOYER_ADDRESS = process.env.PARTISIA_SENDER_ADDRESS ?? DEFAULT_DEPLOYER_ADDRESS;

const ENGINE_ADDRESSES = [
  "00eb99a86577a18fd24b8cdda5d5b57134ca187ce4",
  "00c64bd3ad942e3efc3d4f3a6b7000ff88b595a180",
  "009b3b44fc72180aed07002aaa66073f8d4b6afe62",
];

const THRESHOLD = 2;
const NUM_SHARES = 3;

const accountLabel = process.env.ACCOUNT_LABEL ?? `kosh-${Date.now()}`;

const REGISTRY_PBC = resolve(
  __dirname,
  "../../target/wasm32-unknown-unknown/release/kosh_account_registry.pbc"
);
const VAULT_PBC = resolve(
  __dirname,
  "../../target/wasm32-unknown-unknown/release/kosh_vault.pbc"
);
const SIGNER_PBC = resolve(
  __dirname,
  "../../target/wasm32-unknown-unknown/release/kosh_zk_signer.pbc"
);

function encodeShortname(shortname: number): Uint8Array {
  if (shortname <= 0xff) return new Uint8Array([shortname]);
  return new Uint8Array([shortname >> 8, shortname & 0xff]);
}

function encodeU16(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

function encodeU32(n: number): Uint8Array {
  return new Uint8Array([(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}

function encodeAddress(hexAddress: string): Uint8Array {
  if (!/^[0-9a-fA-F]{42}$/.test(hexAddress)) {
    throw new Error(`Invalid Partisia address: ${hexAddress}`);
  }
  return Buffer.from(hexAddress, "hex");
}

function encodeInitPrefix(): Uint8Array {
  return new Uint8Array([0xff, 0xff, 0xff, 0xff, 0x0f]);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const hash = await globalThis.crypto.subtle.digest("SHA-256", bytes as any);
  return new Uint8Array(hash);
}

function firstFailure(node: any): string | null {
  const status = node?.transaction?.executionStatus ?? node?.executionStatus;
  if (status?.success === false) {
    return status.failure?.errorMessage ?? "Unknown transaction failure";
  }
  const children = node?.events ?? [];
  for (const child of children) {
    const err = firstFailure(child);
    if (err) return err;
  }
  return null;
}

async function deployContract(
  deployClient: BlockchainClientForDeploymentImpl,
  pbcPath: string,
  initRpc: Uint8Array,
  gasCost: number
): Promise<string> {
  const pbcBytes = readFileSync(pbcPath);
  const builder = new DeploymentBuilder(deployClient);
  builder.pbcFile(pbcBytes);
  builder.initRpc(Buffer.from(initRpc));
  builder.gasCost(gasCost);
  const result = await builder.deploy();
  return result.contractAddress;
}

async function sendAction(
  txClient: BlockchainTransactionClient,
  contractAddress: string,
  shortname: number,
  args: Uint8Array,
  gasCost = 500_000
): Promise<string> {
  const rpc = Buffer.from([...encodeShortname(shortname), ...args]);
  const tx = { address: contractAddress, rpc };
  const sent = await txClient.signAndSend(tx, gasCost);
  const tree = await txClient.waitForSpawnedEvents(sent);
  const failure = firstFailure(tree);
  if (failure) {
    throw new Error(`Action 0x${shortname.toString(16)} failed: ${failure.split("\n")[0]}`);
  }
  return sent.transactionPointer.identifier;
}

function buildRegistryInitRpc(owner: string): Uint8Array {
  return new Uint8Array([...encodeInitPrefix(), ...encodeAddress(owner)]);
}

function buildVaultInitRpc(registryAddress: string, signerAddress: string): Uint8Array {
  return new Uint8Array([
    ...encodeInitPrefix(),
    ...encodeAddress(registryAddress),
    ...encodeAddress(signerAddress),
  ]);
}

function buildSignerInitRpc(owner: string): Uint8Array {
  const parts: number[] = [];
  parts.push(...encodeInitPrefix());
  parts.push(...encodeAddress(owner));
  parts.push(...encodeU32(ENGINE_ADDRESSES.length));
  for (const addr of ENGINE_ADDRESSES) {
    parts.push(...encodeAddress(addr));
  }
  parts.push(...encodeU16(THRESHOLD));
  parts.push(NUM_SHARES);
  return new Uint8Array(parts);
}

async function main() {
  console.log("=== Partisia Testnet Setup (Kosh) ===\n");
  console.log(`Reader: ${NODE_URL}`);
  console.log(`Browser: ${WEB_URL}`);
  console.log(`Deployer: ${DEPLOYER_ADDRESS}`);
  console.log(`Account label: ${accountLabel}\n`);

  const auth = SenderAuthenticationKeyPair.fromString(DEPLOYER_KEY);
  const txClient = BlockchainTransactionClient.create(NODE_URL, auth);
  const chainController = new ChainControllerApi(new Configuration({ basePath: NODE_URL }));
  const deployClient = new BlockchainClientForDeploymentImpl(txClient, chainController);

  console.log("1) Deploying kosh-account-registry...");
  const registryAddress = await deployContract(
    deployClient,
    REGISTRY_PBC,
    buildRegistryInitRpc(DEPLOYER_ADDRESS),
    8_000_000
  );
  console.log(`   Registry: ${registryAddress}`);

  console.log("2) Deploying kosh-vault...");
  const vaultAddress = await deployContract(
    deployClient,
    VAULT_PBC,
    buildVaultInitRpc(registryAddress, DEPLOYER_ADDRESS),
    8_000_000
  );
  console.log(`   Vault: ${vaultAddress}`);

  console.log("3) Deploying kosh-zk-signer (owner = vault)...");
  const signerAddress = await deployContract(
    deployClient,
    SIGNER_PBC,
    buildSignerInitRpc(vaultAddress),
    20_000_000
  );
  console.log(`   Signer: ${signerAddress}`);

  console.log("4) Wiring contracts...");
  await sendAction(
    txClient,
    vaultAddress,
    0x07, // register_signer(Address)
    encodeAddress(signerAddress),
    2_000_000
  );
  await sendAction(
    txClient,
    vaultAddress,
    0x08, // set_default_signer(Address)
    encodeAddress(signerAddress),
    2_000_000
  );
  await sendAction(
    txClient,
    registryAddress,
    0x06, // transfer_ownership(Address)
    encodeAddress(vaultAddress),
    2_000_000
  );
  console.log("   Wiring complete.");

  console.log("5) Creating first vault account...");
  const userHash = await sha256(new TextEncoder().encode(accountLabel));
  const createTx = await sendAction(
    txClient,
    vaultAddress,
    0x01, // create_account(Hash)
    userHash,
    3_000_000
  );
  console.log(`   create_account tx: ${createTx}`);

  console.log("\n=== Setup Complete ===");
  console.log(`REGISTRY_ADDRESS=${registryAddress}`);
  console.log(`VAULT_ADDRESS=${vaultAddress}`);
  console.log(`SIGNER_ADDRESS=${signerAddress}`);
  console.log(`ACCOUNT_HASH=${toHex(userHash)}`);
  console.log("NOTE: Newly created account is Pending until keygen/share submission is completed.");
}

main().catch((err) => {
  console.error("Setup failed:", err?.message ?? err);
  process.exit(1);
});
