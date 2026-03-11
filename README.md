# Kosh Keyless Accounts — Partisia Testnet Deployment Guide

## Overview

Kosh creates **keyless EVM accounts** using Partisia Blockchain's execution engines for MPC key management. A user creates an account on Partisia, gets an MPC-generated secp256k1 key pair, derives an EVM address from it, and signs EVM transactions (e.g. on Base Sepolia) without ever holding a private key.

### Architecture

```
User / Client App
    |
    v
kosh-vault (Partisia on-chain coordinator)
    |                    |
    v                    v
kosh-account-registry    kosh-mpc-signer
(userIdHash -> pubkey)   (key generation + ECDSA signing)
                              |
                         Execution Engines (3x, off-chain)
                         (generate keys, compute signatures)
```

### Three Contracts

| Contract | Purpose | WASM Ready |
|---|---|---|
| `kosh-account-registry` | Maps user identities to public keys, tracks account lifecycle | Yes |
| `kosh-vault` | Entry point, coordinates between registry and signer | Yes |
| `kosh-mpc-signer` | Key generation + ECDSA signing via execution engines | Yes |

---

## WASM32 Compilation (Resolved)

The `kosh-mpc-signer` contract originally depended on `cggmp21`, which pulled in:

```
cggmp21 -> paillier-zk -> fast-paillier -> rug -> gmp-mpfr-sys (C library)
```

`gmp-mpfr-sys` cannot compile to `wasm32-unknown-unknown`, blocking `cargo pbc build`.

**Fix applied:** Removed `cggmp21` and all its transitive dependencies (`round-based`, `rand`, `rand_chacha`, `rand_core`, `serde`, `serde_json`). Replaced with direct `k256` (pure Rust) ECDSA signing:

- **Keygen:** Engine 0 generates a random secp256k1 key pair via `k256::ecdsa::SigningKey`, distributes the full secret key to all engines (testnet only).
- **Signing:** Engine 0 loads the secret key and calls `sign_prehash_recoverable()` to produce a 65-byte EVM-compatible signature (r || s || v).

This is centralized (engine 0 does everything) but produces **valid ECDSA signatures** that EVM chains accept. The on-chain round-message infrastructure is retained for a future upgrade to real threshold ECDSA with WASM-compatible dependencies.

---

## Deployment Instructions

### Prerequisites

- Partisia Blockchain CLI (`cargo pbc`) installed
- Partisia testnet account with gas (get from [Partisia faucet](https://browser.testnet.partisiablockchain.com/faucet))
- Rust toolchain with `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`

### Step 1: Build Contracts

The WASM blocker has been fixed (cggmp21 replaced with k256). Build all contracts:

```bash
cargo pbc build --release
```

This should produce `.wasm` + `.abi` files for all 3 contracts in `target/`.

### Step 2: Deploy Contracts (in order)

Deployment order matters because contracts reference each other:

```bash
# 1. Deploy kosh-account-registry
#    Init args: owner = <your_address> (will be updated to vault address later)
cargo pbc transaction deploy \
  --gas 5000000 \
  --privatekey <YOUR_PRIVATE_KEY> \
  target/wasm32-unknown-unknown/release/kosh_account_registry.wasm \
  target/wasm32-unknown-unknown/release/kosh_account_registry.abi \
  --init-arg "<YOUR_ADDRESS>"

# Note the deployed REGISTRY_ADDRESS

# 2. Deploy kosh-mpc-signer
#    Init args: owner = <your_address> (updated to vault later),
#               engines = [EngineConfig{address}; 3],
#               threshold = 2
cargo pbc transaction deploy \
  --gas 5000000 \
  --privatekey <YOUR_PRIVATE_KEY> \
  target/wasm32-unknown-unknown/release/kosh_mpc_signer.wasm \
  target/wasm32-unknown-unknown/release/kosh_mpc_signer.abi \
  --init-arg "<YOUR_ADDRESS>" \
  --init-arg "[{\"address\":\"<ENGINE_0_ADDR>\"},{\"address\":\"<ENGINE_1_ADDR>\"},{\"address\":\"<ENGINE_2_ADDR>\"}]" \
  --init-arg "2"

# Note the deployed SIGNER_ADDRESS

# 3. Deploy kosh-vault
#    Init args: registry_address, signer_address
cargo pbc transaction deploy \
  --gas 5000000 \
  --privatekey <YOUR_PRIVATE_KEY> \
  target/wasm32-unknown-unknown/release/kosh_vault.wasm \
  target/wasm32-unknown-unknown/release/kosh_vault.abi \
  --init-arg "<REGISTRY_ADDRESS>" \
  --init-arg "<SIGNER_ADDRESS>"

# Note the deployed VAULT_ADDRESS
```

> **Note:** The exact `cargo pbc` CLI syntax may differ. Check Partisia docs for current deployment commands. You may need to use the browser-based deployment tool or REST API instead.

### Step 3: Transfer Ownership

After deploying, transfer ownership of registry and signer to the vault:

```bash
# Transfer registry ownership to vault
# Registry action 0x06: transfer_ownership(new_owner: Address)
cargo pbc transaction action <REGISTRY_ADDRESS> transfer_ownership \
  --gas 100000 --privatekey <YOUR_PRIVATE_KEY> \
  --arg "<VAULT_ADDRESS>"

# Transfer signer ownership to vault
# (If you have a transfer_ownership action, otherwise set owner at deploy time)
```

### Step 4: Create an Account

```bash
# Vault action 0x01: create_account(user_id_hash: Hash)
# user_id_hash = SHA256("test-user@kosh.finance") = 32 bytes

cargo pbc transaction action <VAULT_ADDRESS> create_account \
  --gas 1000000 --privatekey <YOUR_PRIVATE_KEY> \
  --arg "<32_BYTE_USER_ID_HASH_HEX>"
```

This triggers:
1. Vault calls signer `create_key_with_id(key_id=0)`
2. Vault calls registry `register_account(user_id_hash, signer_address, key_id=0)`
3. Signer state: key 0 enters `WaitingForDealer` phase
4. Off-chain: engine 0 generates key, calls `distribute_key_shares`
5. All engines confirm, key gen completes
6. Signer calls vault `on_key_generated(key_id=0, public_key)`
7. Vault calls registry `activate_account(account_id=0, public_key)`

### Step 5: Verify Key Generation

Poll the signer contract state:

```bash
# Read signer state via REST API
curl "https://node1.testnet.partisiablockchain.com/shards/Shard0/blockchain/contracts/<SIGNER_ADDRESS>?requireContractState=true"
```

Look for:
```json
{
  "keys": {
    "0": {
      "public_key": "02abc123...",       // 33-byte compressed secp256k1
      "keygen_phase": { "discriminant": 2 }  // 2 = Complete
    }
  }
}
```

### Step 6: Derive the EVM Address

From the 33-byte compressed public key:

```
1. Decompress to 65-byte uncompressed point (04 || x || y)
2. Take the 64-byte payload (drop the 04 prefix)
3. keccak256(payload)
4. Take last 20 bytes = EVM address
```

```typescript
// Using viem/ethers:
import { keccak256 } from "viem";
import { secp256k1 } from "@noble/curves/secp256k1";

const compressed = Buffer.from("02abc123...", "hex");
const point = secp256k1.ProjectivePoint.fromHex(compressed);
const uncompressed = point.toRawBytes(false); // 65 bytes
const pubKeyBody = uncompressed.slice(1);     // 64 bytes
const hash = keccak256(pubKeyBody);
const evmAddress = "0x" + hash.slice(-40);
```

### Step 7: Fund the EVM Address

Send Base Sepolia ETH to the derived EVM address using:
- [Alchemy faucet](https://www.alchemy.com/faucets/base-sepolia)
- [Coinbase faucet](https://www.coinbase.com/faucets/base-ethereum-sepolia-faucet)

### Step 8: Build a Raw EVM Transaction

Build an unsigned EIP-1559 transaction:

```typescript
import { serializeTransaction, keccak256 } from "viem";

const tx = {
  to: "0xRecipientAddress...",
  value: 1000000000000000n,   // 0.001 ETH
  chainId: 84532,             // Base Sepolia
  nonce: 0,                   // from eth_getTransactionCount
  maxFeePerGas: 1000000000n,  // 1 gwei
  maxPriorityFeePerGas: 1000000n,
  gas: 21000n,
  type: "eip1559" as const,
};

// This is the 32-byte hash the MPC signer needs to sign
const serialized = serializeTransaction(tx);
const signingHash = keccak256(serialized);
// signingHash = "0xabc123..." (32 bytes)
```

### Step 9: Request MPC Signature

```bash
# Vault action 0x03: request_signature(account_id: u32, message: Vec<u8>)
# message = the 32-byte signing hash from step 8

cargo pbc transaction action <VAULT_ADDRESS> request_signature \
  --gas 1000000 --privatekey <YOUR_PRIVATE_KEY> \
  --arg "0" \
  --arg "<32_BYTE_SIGNING_HASH_HEX>"
```

This triggers:
1. Vault calls signer `sign_message(key_id=0, message_hash)`
2. Off-chain: engines run signing protocol
3. Engine posts `signing_complete(key_id=0, engine_index, task_id=0, signature)`

### Step 10: Read the Signature

Poll the signer contract state:

```bash
curl "https://node1.testnet.partisiablockchain.com/shards/Shard0/blockchain/contracts/<SIGNER_ADDRESS>?requireContractState=true"
```

Look for:
```json
{
  "keys": {
    "0": {
      "signing_information": {
        "0": {
          "signature": "0xr_32_bytes_s_32_bytes_v_1_byte",
          "verified": true
        }
      }
    }
  }
}
```

The signature is 65 bytes: `r (32) || s (32) || v (1)`.

### Step 11: Submit Signed Transaction to Base Sepolia

```typescript
import { serializeTransaction } from "viem";
import { createPublicClient, http } from "viem";
import { baseSepolia } from "viem/chains";

const client = createPublicClient({ chain: baseSepolia, transport: http() });

// Parse signature from contract state
const sigBytes = Buffer.from(signatureHex, "hex");
const r = "0x" + sigBytes.slice(0, 32).toString("hex");
const s = "0x" + sigBytes.slice(32, 64).toString("hex");
const v = sigBytes[64]; // 0 or 1

const signedTx = serializeTransaction(tx, {
  r: r as `0x${string}`,
  s: s as `0x${string}`,
  yParity: v as 0 | 1,
});

const txHash = await client.sendRawTransaction({
  serializedTransaction: signedTx,
});

console.log("Base Sepolia TX:", `https://sepolia.basescan.org/tx/${txHash}`);
```

---

## Contract Action Reference

### kosh-vault

| Shortname | Action | Args | Description |
|---|---|---|---|
| `0x01` | `create_account` | `user_id_hash: Hash` | Create keyless account, triggers keygen |
| `0x02` | `on_key_generated` | `key_id: u32, public_key: Vec<u8>` | Callback from signer (auto) |
| `0x03` | `request_signature` | `account_id: u32, message: Vec<u8>` | Request MPC signature for 32-byte hash |
| `0x04` | `transfer_account_ownership` | `account_id: u32, new_owner: Address` | Transfer account |
| `0x05` | `deactivate_account` | `account_id: u32` | Deactivate account |
| `0x06` | `transfer_vault_ownership` | `new_owner: Address` | Transfer admin |

### kosh-mpc-signer

| Shortname | Action | Caller | Description |
|---|---|---|---|
| `0x01` | `create_key` | Vault | Create key (auto-assign ID) |
| `0x02` | `create_key_with_id` | Vault | Create key with specific ID |
| `0x03` | `sign_message` | Vault | Queue 32-byte hash for signing |
| `0x04` | `distribute_key_shares` | Engine 0 | Post key shares + public key |
| `0x05` | `confirm_key_share` | Engines | Confirm share loaded |
| `0x06` | `signing_round_message` | Engines | Post signing protocol messages |
| `0x07` | `signing_complete` | Engines | Post final ECDSA signature |

### kosh-account-registry

| Shortname | Action | Description |
|---|---|---|
| `0x01` | `register_account` | Create Pending account entry |
| `0x02` | `activate_account` | Set public key, mark Active |
| `0x03` | `begin_key_rotation` | Start key rotation |
| `0x04` | `complete_key_rotation` | Finish rotation with new key |
| `0x05` | `deactivate_account` | Deactivate permanently |
| `0x06` | `transfer_ownership` | Transfer registry owner |

---

## State Reading (REST API)

```bash
# Read any contract's state:
GET https://node1.testnet.partisiablockchain.com/shards/Shard0/blockchain/contracts/{ADDRESS}?requireContractState=true

# The response contains serializedContract.state with all public fields.
```

---

## File Structure

```
contracts/
  kosh-vault/src/
    lib.rs               # Coordinator contract (284 lines)
    access_control.rs    # Auth helpers
  kosh-account-registry/src/
    lib.rs               # Identity registry (302 lines)
  kosh-mpc-signer/src/
    lib.rs               # On-chain actions (365 lines)
    signing_orchestration.rs  # State types (KeyGenPhase, SigningPhase, etc.)
    off_chain.rs         # Engine logic (k256 direct signing, WASM-compatible)
    task_queue.rs        # Generic task queue (reusable, no changes needed)
  Cargo.toml             # Workspace (SDK v.16.126.0)

client/                  # TypeScript E2E demo (optional, for reference)
  src/
    index.ts             # Full flow demo
    partisia.ts          # Partisia REST client
    evm.ts               # EVM tx building (viem)
```

---

## Implementation Priority

1. ~~**[BLOCKER] Rewrite `off_chain.rs`** — Remove cggmp21, implement keygen + signing with k256 only~~ **DONE**
2. ~~**[BLOCKER] Update `Cargo.toml`** — Remove cggmp21/round-based/serde deps~~ **DONE**
3. **Verify `cargo pbc build --release`** — All 3 contracts must produce .wasm + .abi
4. **Deploy to testnet** — Registry -> Signer -> Vault (in order)
5. **Test create_account** — Verify keygen completes, public key appears in state
6. **Test signing** — Submit a 32-byte hash, verify valid ECDSA signature in state
7. **E2E** — Build EVM tx, sign via Partisia, submit to Base Sepolia

---

## Partisia SDK Version

All contracts use Partisia SDK **v.16.126.0** from:
```
https://gitlab.com/partisiablockchain/language/contract-sdk.git?tag=v.16.126.0
```

---

## Security Notes (Testnet Only)

- Key shares are posted on-chain **in the clear** — anyone can read the private key
- Keygen uses a **centralized** approach (engine 0 generates everything)
- Signing is centralized to engine 0 (not threshold)
- These are acceptable for testnet demonstration only
- Production requires: full CGGMP21 DKG, encrypted share distribution, threshold signing
