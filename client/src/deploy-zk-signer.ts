/**
 * Deploy the kosh-zk-signer contract to Partisia testnet.
 *
 * Usage:
 *   PARTISIA_SENDER_KEY=<hex> PARTISIA_SENDER_ADDRESS=<hex> npx tsx src/deploy-zk-signer.ts
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

const SENDER_KEY = process.env.PARTISIA_SENDER_KEY ?? "";
const SENDER_ADDR = process.env.PARTISIA_SENDER_ADDRESS ?? "";
const NODE_URL = process.env.PARTISIA_NODE_URL ?? "https://node1.testnet.partisiablockchain.com";

const ENGINE_ADDRESSES = [
  "00eb99a86577a18fd24b8cdda5d5b57134ca187ce4",
  "00c64bd3ad942e3efc3d4f3a6b7000ff88b595a180",
  "009b3b44fc72180aed07002aaa66073f8d4b6afe62",
];
const THRESHOLD = 2;
const NUM_SHARES = 3;

if (!SENDER_KEY || !SENDER_ADDR) {
  console.error("Required env vars: PARTISIA_SENDER_KEY, PARTISIA_SENDER_ADDRESS");
  process.exit(1);
}

function encodeAddress(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}

function encodeU16BE(n: number): Buffer {
  const buf = Buffer.alloc(2);
  buf.writeUInt16BE(n);
  return buf;
}

function encodeU8(n: number): Buffer {
  return Buffer.from([n]);
}

function encodeU32BE(n: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(n);
  return buf;
}

function buildInitRpc(): Buffer {
  const parts: Buffer[] = [];
  // Init shortname: 0xffffffff0f (5 bytes, from ABI)
  parts.push(Buffer.from([0xff, 0xff, 0xff, 0xff, 0x0f]));
  // owner: Address (21 bytes)
  parts.push(encodeAddress(SENDER_ADDR));
  // engines: Vec<EngineConfig> — length prefix + each EngineConfig { address }
  parts.push(encodeU32BE(ENGINE_ADDRESSES.length));
  for (const addr of ENGINE_ADDRESSES) {
    parts.push(encodeAddress(addr));
  }
  // threshold: u16
  parts.push(encodeU16BE(THRESHOLD));
  // num_shares: u8
  parts.push(encodeU8(NUM_SHARES));
  return Buffer.concat(parts);
}

async function main() {
  console.log("=== Deploy kosh-zk-signer to testnet ===\n");

  const pbcPath = resolve(__dirname, "../../target/wasm32-unknown-unknown/release/kosh_zk_signer.pbc");
  const pbcBytes = readFileSync(pbcPath);
  console.log(`PBC file: ${pbcPath} (${pbcBytes.length} bytes)`);

  const auth = SenderAuthenticationKeyPair.fromString(SENDER_KEY);
  const txClient = BlockchainTransactionClient.create(NODE_URL, auth);

  const chainConfig = new Configuration({ basePath: NODE_URL });
  const chainController = new ChainControllerApi(chainConfig);

  const deployClient = new BlockchainClientForDeploymentImpl(txClient, chainController);

  const initRpc = buildInitRpc();
  console.log(`Init RPC: ${initRpc.toString("hex")} (${initRpc.length} bytes)`);

  const builder = new DeploymentBuilder(deployClient);
  builder.pbcFile(pbcBytes);
  builder.initRpc(initRpc);
  builder.gasCost(50_000_000);

  console.log("\nDeploying...");
  const result = await builder.deploy();

  console.log(`\nContract deployed!`);
  console.log(`Address: ${result.contractAddress}`);
  console.log(`\nSet SIGNER_ADDRESS=${result.contractAddress} for testing.`);
}

main().catch((err) => {
  console.error("Deploy failed:", err);
  if (err.cause) console.error("Cause:", err.cause);
  if (err.response) {
    err.response.text?.().then?.((t: string) => console.error("Response:", t));
  }
  process.exit(1);
});
