/**
 * Partisia Blockchain REST API client.
 *
 * Provides read/write access to deployed contracts:
 * - Read contract state (JSON)
 * - Submit signed transactions (action calls)
 * - Submit ZK secret input transactions (via SDK)
 * - Poll for state changes
 */

import {
  BlockchainTransactionClient,
  SenderAuthenticationKeyPair,
} from "@partisiablockchain/blockchain-api-transaction-client";
import type { Transaction as PbcTransaction } from "@partisiablockchain/blockchain-api-transaction-client";

const DEFAULT_NODE = "https://node1.testnet.partisiablockchain.com";

export interface PartisiaConfig {
  nodeUrl?: string;
  /** Sender's private key hex (for signing transactions) */
  senderPrivateKey: string;
  /** Sender's address on Partisia */
  senderAddress: string;
}

export class PartisiaClient {
  private nodeUrl: string;
  private senderPrivateKey: string;
  private senderAddress: string;
  private _txClient?: BlockchainTransactionClient;

  constructor(config: PartisiaConfig) {
    this.nodeUrl = config.nodeUrl ?? DEFAULT_NODE;
    this.senderPrivateKey = config.senderPrivateKey;
    this.senderAddress = config.senderAddress;
  }

  /** Get or create a BlockchainTransactionClient for proper signing. */
  getTransactionClient(): BlockchainTransactionClient {
    if (!this._txClient) {
      const auth = SenderAuthenticationKeyPair.fromString(this.senderPrivateKey);
      this._txClient = BlockchainTransactionClient.create(this.nodeUrl, auth);
    }
    return this._txClient;
  }

  resetTransactionClient(): void {
    this._txClient = undefined;
  }

  /** Get the sender address. */
  getSenderAddress(): string {
    return this.senderAddress;
  }

  /** Get the node URL. */
  getNodeUrl(): string {
    return this.nodeUrl;
  }

  /**
   * Submit a pre-built PBC Transaction (e.g. from ZkRpcBuilder) with proper crypto signing.
   * Returns the transaction hash.
   */
  async submitTransaction(tx: PbcTransaction, gasCost = 1_000_000): Promise<string> {
    let lastErr: unknown;
    for (let attempt = 1; attempt <= 5; attempt++) {
      try {
        if (attempt > 1) this.resetTransactionClient();
        const client = this.getTransactionClient();
        const signed = await client.sign(tx, gasCost);
        const sent = await client.send(signed);
        return sent.transactionPointer.identifier;
      } catch (err) {
        lastErr = err;
        if (attempt === 5) break;
        await new Promise((resolve) => setTimeout(resolve, 3000 * attempt));
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr ?? "submitTransaction failed"));
  }

  /**
   * Submit a pre-built RPC Buffer to a contract with proper crypto signing.
   * For ZK secret inputs, the rpc Buffer comes from ZkRpcBuilder.zkInputOnChain().
   */
  async submitRawRpc(contractAddress: string, rpc: Buffer, gasCost = 1_000_000): Promise<string> {
    const tx: PbcTransaction = { address: contractAddress, rpc };
    return this.submitTransaction(tx, gasCost);
  }

  /** Read the full contract data (serializedContract) as JSON. */
  async getContractData(contractAddress: string): Promise<Record<string, unknown>> {
    const url = `${this.nodeUrl}/shards/Shard0/blockchain/contracts/${contractAddress}?requireContractState=true`;
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`Failed to read state: ${resp.status}`);
    const data = await resp.json();
    return data.serializedContract ?? data;
  }

  /**
   * Read an AVL tree entry from contract state (base64 binary).
   * Returns the raw base64 data string for the given tree index and key.
   */
  async getAvlTreeEntry(
    contractAddress: string,
    treeIndex: number,
    keyBase64: string
  ): Promise<string | null> {
    const data = await this.getContractData(contractAddress);
    const openState = data.openState as { avlTrees?: Array<{ key: number; value: { avlTree: Array<{ key: { data: { data: string } }; value: { data: string } }> } }> } | undefined;
    if (!openState?.avlTrees) return null;
    const tree = openState.avlTrees.find((t) => t.key === treeIndex);
    if (!tree) return null;
    const entry = tree.value.avlTree.find((e) => e.key.data.data === keyBase64);
    return entry?.value?.data ?? null;
  }

  /**
   * Wait for a transaction to be executed.
   * Uses the SDK's BlockchainTransactionClient under the hood.
   */
  async waitForExecution(txHash: string, shardId = "Shard0"): Promise<unknown> {
    const client = this.getTransactionClient();
    return client.waitForInclusionInBlock({
      signedTransaction: null as any,
      transactionPointer: { identifier: txHash, destinationShardId: shardId },
    });
  }

  /**
   * Submit an action (transaction) to a contract.
   *
   * For ZK (REAL) contracts, wraps the WASM action RPC with the binder's
   * openInvocation prefix (0x09). Set isZk=true for ZK contracts.
   *
   * Uses the Partisia SDK's BlockchainTransactionClient for proper crypto signing.
   */
  async submitAction(
    contractAddress: string,
    shortname: number,
    args: Uint8Array,
    gasCost = 1_000_000,
    isZk = true
  ): Promise<string> {
    const shortnameBytes = shortname <= 0xff ? [shortname] : [shortname >> 8, shortname & 0xff];
    const wasmRpc = Buffer.from([...shortnameBytes, ...args]);

    // ZK contracts need the binder's openInvocation (0x09) prefix
    const rpc = isZk ? Buffer.concat([Buffer.from([0x09]), wasmRpc]) : wasmRpc;

    const tx: PbcTransaction = {
      address: contractAddress,
      rpc,
    };
    return this.submitTransaction(tx, gasCost);
  }

  /**
   * Poll a contract state until a condition is met.
   * Returns the value extracted by the selector function.
   */
  async pollUntil<T>(
    contractAddress: string,
    selector: (state: Record<string, unknown>) => T | null,
    options?: { intervalMs?: number; timeoutMs?: number }
  ): Promise<T> {
    const interval = options?.intervalMs ?? 3000;
    const timeout = options?.timeoutMs ?? 120_000;
    const start = Date.now();

    while (Date.now() - start < timeout) {
      try {
        const state =
          await this.getContractData(contractAddress);
        const result = selector(state);
        if (result !== null && result !== undefined) return result;
      } catch {
        // State might not be available yet
      }
      await new Promise((r) => setTimeout(r, interval));
    }

    throw new Error(`Polling timed out after ${timeout}ms`);
  }
}
