import { PartisiaClient } from "./partisia.js";

export function encodeU32Be(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (n >>> 24) & 0xff;
  buf[1] = (n >>> 16) & 0xff;
  buf[2] = (n >>> 8) & 0xff;
  buf[3] = n & 0xff;
  return buf;
}

export function encodeLenPrefixedBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array([...encodeU32Be(bytes.length), ...bytes]);
}

export function encodePartyVector(parties: number[]): Uint8Array {
  return new Uint8Array([...encodeU32Be(parties.length), ...parties.map((p) => p & 0xff)]);
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/**
 * Submit a WASM action transaction and wait for it to fully settle on-chain.
 * Retries up to 3 times on transient RPC failures. Returns true on success,
 * false on contract-level failure (prints the error message).
 *
 * @param logPrefix  Optional prefix for log lines, e.g. "[P1] "
 */
export async function submitAndWait(
  partisia: PartisiaClient,
  contractAddress: string,
  shortname: number,
  args: Uint8Array,
  label: string,
  logPrefix = "",
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
      console.log(`  ${logPrefix}Tx: ${txId}${attempt > 1 ? ` (attempt ${attempt})` : ""}`);
      tree = await client.waitForSpawnedEvents(sent);
      break;
    } catch (err) {
      lastErr = err;
      if (attempt === 3) throw err;
      console.warn(`  ${logPrefix}${label}: transient Partisia RPC failure, retrying (${attempt}/3)`);
      await new Promise((resolve) => setTimeout(resolve, 1500 * attempt));
    }
  }
  if (!tree) throw lastErr instanceof Error ? lastErr : new Error(String(lastErr ?? "unknown Partisia RPC error"));
  const rootStatus = (tree as any).root?.transaction?.executionStatus
    ?? (tree as any).transaction?.executionStatus;
  if (rootStatus?.success === false) {
    const msg = rootStatus.failure?.errorMessage ?? "unknown error";
    console.error(`  ${logPrefix}${label} FAILED: ${msg.split("\n")[0]}`);
    return false;
  }
  const events = tree.events ?? (tree as any).spawned ?? [];
  for (const ev of events) {
    const es = (ev as any).transaction?.executionStatus ?? (ev as any).executionStatus;
    if (es?.success === false) {
      const msg = es.failure?.errorMessage ?? es.errorMessage ?? "unknown error";
      console.error(`  ${logPrefix}${label} FAILED (spawned): ${msg.split("\n")[0]}`);
      return false;
    }
  }
  if ((tree as any).failed) {
    console.error(`  ${logPrefix}${label} FAILED: transaction tree marked as failed`);
    return false;
  }
  console.log(`  ${logPrefix}${label} OK`);
  return true;
}
