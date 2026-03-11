/**
 * Partisia Blockchain REST API client.
 *
 * Provides read/write access to deployed contracts:
 * - Read contract state (JSON)
 * - Submit signed transactions (action calls)
 * - Poll for state changes
 */

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

  constructor(config: PartisiaConfig) {
    this.nodeUrl = config.nodeUrl ?? DEFAULT_NODE;
    this.senderPrivateKey = config.senderPrivateKey;
    this.senderAddress = config.senderAddress;
  }

  /** Read the full state of a contract as JSON. */
  async getContractState<T = unknown>(contractAddress: string): Promise<T> {
    const url = `${this.nodeUrl}/shards/Shard0/blockchain/contracts/${contractAddress}?requireContractState=true`;
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`Failed to read state: ${resp.status}`);
    const data = await resp.json();
    return data.serializedContract?.state as T;
  }

  /** Read a specific field path from contract state. */
  async getStateField<T = unknown>(
    contractAddress: string,
    fieldPath: string
  ): Promise<T> {
    const state = await this.getContractState<Record<string, unknown>>(
      contractAddress
    );
    const parts = fieldPath.split(".");
    let current: unknown = state;
    for (const part of parts) {
      if (current == null || typeof current !== "object") {
        throw new Error(`Field path ${fieldPath} not found`);
      }
      current = (current as Record<string, unknown>)[part];
    }
    return current as T;
  }

  /**
   * Submit an action (transaction) to a contract.
   *
   * The RPC payload is the serialized action per Partisia's binary format:
   * - shortname (variable bytes) + serialized arguments
   *
   * For this prototype, we use the REST API's putTransaction endpoint.
   */
  async submitAction(
    contractAddress: string,
    shortname: number,
    args: Uint8Array
  ): Promise<string> {
    // Build the RPC payload: shortname as bytes + args
    const shortnameBytes = shortname <= 0xff ? [shortname] : [shortname >> 8, shortname & 0xff];
    const payload = new Uint8Array([...shortnameBytes, ...args]);

    const url = `${this.nodeUrl}/shards/Shard0/blockchain/transaction/putTransaction`;
    const body = {
      payload: Buffer.from(payload).toString("base64"),
      address: contractAddress,
      senderAddress: this.senderAddress,
      nonce: Date.now(),
      validTo: Date.now() + 60_000,
      gasCost: 1_000_000,
    };

    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Transaction failed: ${resp.status} ${text}`);
    }

    const result = await resp.json();
    return result.putSuccessful?.transactionHash ?? "unknown";
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
          await this.getContractState<Record<string, unknown>>(
            contractAddress
          );
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
