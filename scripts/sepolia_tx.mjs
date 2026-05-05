#!/usr/bin/env node
import { createPublicClient, http, keccak256, serializeTransaction, toHex } from '../frontend/KoshSignerUsingPartisiaZK/client/node_modules/viem/_esm/index.js';
import { sepolia } from '../frontend/KoshSignerUsingPartisiaZK/client/node_modules/viem/_esm/chains/index.js';

const rpcUrl = process.env.SEPOLIA_RPC_URL || undefined;
const client = createPublicClient({ chain: sepolia, transport: http(rpcUrl) });

function bigintReplacer(_key, value) {
  return typeof value === 'bigint' ? value.toString() : value;
}

function reviveTx(obj) {
  return {
    ...obj,
    chainId: Number(obj.chainId),
    nonce: Number(obj.nonce),
    gas: BigInt(obj.gas),
    maxFeePerGas: BigInt(obj.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(obj.maxPriorityFeePerGas),
    value: obj.value != null ? BigInt(obj.value) : undefined,
    type: obj.type,
    to: obj.to,
    data: obj.data,
  };
}

function parseSignatureBytes(sigHex) {
  const normalized = sigHex.startsWith('0x') ? sigHex.slice(2) : sigHex;
  const buf = Buffer.from(normalized, 'hex');
  if (buf.length !== 65) throw new Error(`Expected 65 signature bytes, got ${buf.length}`);
  return {
    r: toHex(buf.subarray(0, 32)),
    s: toHex(buf.subarray(32, 64)),
    recoveryId: buf[64],
  };
}

async function build(from, to, valueWei) {
  const [nonce, fees, chainId, balance] = await Promise.all([
    client.getTransactionCount({ address: from }),
    client.estimateFeesPerGas(),
    client.getChainId(),
    client.getBalance({ address: from }),
  ]);
  const requestedValue = BigInt(valueWei);
  const gas = 21_000n;
  const gasCost = gas * fees.maxFeePerGas;
  if (balance <= gasCost) {
    throw new Error(`sender ${from} does not have enough Sepolia ETH for gas; balance=${balance} gas_cost=${gasCost}`);
  }
  const spendableValue = balance - gasCost;
  const adjustedValue = requestedValue > spendableValue ? spendableValue : requestedValue;
  const tx = {
    to,
    value: adjustedValue,
    chainId,
    nonce,
    maxFeePerGas: fees.maxFeePerGas,
    maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
    gas,
    type: 'eip1559',
  };
  const signingHash = keccak256(serializeTransaction(tx));
  process.stdout.write(
    JSON.stringify(
      {
        unsigned_tx: tx,
        signing_hash: signingHash,
        sender_balance: balance,
        requested_value: requestedValue,
        adjusted_value: adjustedValue,
        was_value_adjusted: adjustedValue !== requestedValue,
        gas_cost: gasCost,
      },
      bigintReplacer,
    ),
  );
}

async function signAndSubmit(unsignedTxPath, signatureHex) {
  const fs = await import('node:fs');
  const raw = JSON.parse(fs.readFileSync(unsignedTxPath, 'utf8'));
  const tx = reviveTx(raw);
  const { r, s, recoveryId } = parseSignatureBytes(signatureHex);
  const signedTx = serializeTransaction(tx, { r, s, yParity: recoveryId });
  const txHash = await client.sendRawTransaction({ serializedTransaction: signedTx });
  process.stdout.write(JSON.stringify({ signed_tx_hex: signedTx, tx_hash: txHash }));
}

const [cmd, ...args] = process.argv.slice(2);
if (cmd === 'build') {
  const [from, to, valueWei] = args;
  if (!from || !to || !valueWei) throw new Error('usage: sepolia_tx.mjs build <from> <to> <value_wei>');
  await build(from, to, valueWei);
} else if (cmd === 'sign-submit') {
  const [unsignedTxPath, signatureHex] = args;
  if (!unsignedTxPath || !signatureHex) throw new Error('usage: sepolia_tx.mjs sign-submit <unsigned_tx_json_path> <signature_hex>');
  await signAndSubmit(unsignedTxPath, signatureHex);
} else {
  throw new Error('usage: sepolia_tx.mjs <build|sign-submit> ...');
}
