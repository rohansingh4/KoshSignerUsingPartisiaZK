# Kosh ZK Signer

A decentralized key management system built on Partisia Blockchain.
It lets you create and manage a private key where **no single person or machine ever holds the full key** — the key is split into pieces and stored securely across ZK nodes on the blockchain.

---

## The Problem It Solves

Normal private keys sit in one file on one machine. If that file is stolen — everything is gone.

Kosh ZK Signer fixes this by:
- Splitting the private key into 3 pieces using math (Shamir's Secret Sharing)
- Storing those pieces encrypted on Partisia's ZK nodes (no single node sees the full key)
- Reconstructing the key only when needed for signing — in your RAM, for a split second

---

## How It Works — Simple Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         YOUR COMPUTER                               │
│                                                                     │
│   1. Generate private key + public key  (stays in RAM only)         │
│                         │                                           │
│   2. Split private key into 3 shares using Shamir math              │
│      Share 1 ──┐                                                    │
│      Share 2 ──┼── each share cut into HIGH + LOW half              │
│      Share 3 ──┘   = 6 pieces total                                 │
│                         │                                           │
└─────────────────────────┼───────────────────────────────────────────┘
                          │ encrypted for each ZK node
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    PARTISIA BLOCKCHAIN                               │
│                                                                     │
│   3. Contract stores the public key                                 │
│                                                                     │
│   4. ZK Nodes store the 6 encrypted pieces                          │
│      ZK Node 1 ── piece 1 (nobody else can read it)                 │
│      ZK Node 2 ── piece 2 (nobody else can read it)                 │
│      ZK Node 3 ── piece 3 (nobody else can read it)                 │
│      ZK Node 4 ── piece 4 (nobody else can read it)                 │
│                                                                     │
│   Key is now safely stored. Original key deleted from RAM.          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## How Signing Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SIGNING FLOW                                │
└─────────────────────────────────────────────────────────────────────┘

  You want to sign a message (e.g. an Ethereum transaction)

  Step 1 ── Tell the contract "I want to sign this message"
            Contract stores the message hash, creates a task

  Step 2 ── Take any 2 of your 3 local shares
            Run reverse Shamir math (Lagrange interpolation)
            Private key is rebuilt in your RAM

  Step 3 ── Sign the message using ECDSA
            Get 65-byte signature (r + s + recovery)
            Delete private key from RAM

  Step 4 ── Send signature to contract
            Contract checks: does this signature match the stored public key?
            If YES → stores signature, marks verified = true ✓
            If NO  → rejects the transaction ✗

  Result ── Signature is permanently stored on-chain, verified by the contract
```

---

## Why This Is Secure

```
┌──────────────────────────────────────────────────────────┐
│              WHAT AN ATTACKER WOULD NEED                 │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  To steal the key:                                       │
│    Must compromise 2 of 3 ZK nodes simultaneously  AND  │
│    Must hack your computer at exact moment of signing    │
│                                                          │
│  Stealing 1 ZK node  →  useless (only 1 of 3 pieces)   │
│  Stealing your files →  useless (key not stored there)  │
│  Reading the blockchain → useless (pieces are encrypted) │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
KoshSignerUsingPartisiaZK/
│
├── contracts/
│   ├── kosh-zk-signer/          ← Main ZK Signer contract (Rust)
│   │   └── src/
│   │       ├── lib.rs            ← All contract functions
│   │       ├── signing_state.rs  ← Data types and state machine
│   │       ├── shamir.rs         ← Split/reconstruct math
│   │       ├── off_chain.rs      ← Auto-trigger handlers
│   │       └── zk_compute.rs     ← Required ZK build stub
│   │
│   ├── kosh-vault/              ← Vault coordinator contract
│   └── kosh-account-registry/   ← Account identity registry
│
└── client/
    └── src/
        ├── shamir-ts.ts          ← Shamir math in TypeScript
        ├── zk-signer.ts          ← Encrypt and send secrets to ZK nodes
        ├── partisia.ts           ← Send transactions to Partisia
        └── test-zk-flow.ts       ← Full end-to-end test script
```

---

## What Each Contract File Does

| File | Purpose |
|------|---------|
| `lib.rs` | The smart contract — create key, accept shares, verify signature |
| `signing_state.rs` | All data stored on-chain (phases, share IDs, signatures) |
| `shamir.rs` | Math to split a key into shares and rebuild from shares |
| `off_chain.rs` | Auto-handlers for keygen/signing (not active on testnet) |
| `zk_compute.rs` | Empty stub required by the ZK build toolchain |

## What Each Client File Does

| File | Purpose |
|------|---------|
| `shamir-ts.ts` | Split private key into shares / rebuild from shares |
| `zk-signer.ts` | Encrypt share halves and send them to ZK nodes |
| `partisia.ts` | Sign and send all transactions to Partisia blockchain |
| `test-zk-flow.ts` | Runs the complete 10-step test end-to-end |

---

## Contract Functions (Shortnames)

| Shortname | Function | What it does |
|-----------|----------|-------------|
| `0x02` | `create_key_with_id` | Reserve a key slot on the contract |
| `0x03` | `sign_message` | Queue a message hash for signing |
| `0x05` | `post_public_key` | Store the public key on-chain |
| `0x07` | `signing_complete` | Submit and verify an ECDSA signature |
| `0x08` | `force_complete_keygen` | Mark keygen done (testnet only) |
| `0x10` | `submit_key_share` | Send an encrypted share half to ZK nodes |
| `0x11` | `request_reconstruction` | Ask ZK nodes to open share variables |

---

## Key Phases

### Key Generation Phase
```
WaitingForDealer  →  SubmittingShares  →  Complete
     (start)           (shares coming in)    (ready to sign)
```

### Signing Phase
```
Idle  →  ReconstructingKey  →  Signing  →  Complete  →  Idle
         (shares opening)      (waiting     (sig stored)  (ready again)
                               for sig)
```

---

## Running the Test

### Prerequisites

```bash
# Partisia CLI
cargo install cargo-partisia-contract

# Node.js dependencies
cd client && npm install
```

### Environment Variables

```bash
export PARTISIA_SENDER_KEY=<your_wallet_private_key_hex>
export PARTISIA_SENDER_ADDRESS=<your_wallet_address>
export SIGNER_ADDRESS=<deployed_zk_signer_contract_address>
```

### Run

```bash
cd client
npm run test:zk
```

### What You Will See

```
=== Kosh ZK Signer - Full ZK Pipeline Test ===

Phase 1:  Generate keypair              ✓
Phase 2:  create_key (on-chain)         ✓   Tx: abc123...
Phase 3:  post_public_key (on-chain)    ✓   Tx: def456...
Phase 4:  6/6 ZK shares submitted       ✓   6 transactions
Phase 5:  force_complete_keygen         ✓   Tx: ghi789...
Phase 6:  sign_message (on-chain)       ✓   Tx: jkl012...
Phase 7:  Key reconstructed locally     ✓
          Local signature verified      ✓
Phase 8:  signing_complete (on-chain)   ✓   Tx: mno345...
Phase 9:  On-chain state confirmed      ✓   verified: true
```

---

## Deploying the ZK Signer Contract

### Build

```bash
cd contracts/kosh-zk-signer
cargo pbc build --release
# Produces: target/wasm32-unknown-unknown/release/kosh_zk_signer.pbc
```

### Deploy

```bash
cargo pbc transaction deploy \
  --net testnet \
  --pk YOUR_KEY_FILE.pk \
  --gas 5000000 \
  target/wasm32-unknown-unknown/release/kosh_zk_signer.pbc \
  OWNER_ADDRESS \
  '[' '{' ENGINE1_ADDR '}' '{' ENGINE2_ADDR '}' '{' ENGINE3_ADDR '}' ']' \
  2 \
  3
# Args: owner_address, engines[3], threshold=2, num_shares=3
```

### Check Contract State

```bash
cargo pbc contract avl show --net testnet <CONTRACT_ADDRESS> openState.keys <KEY_ID>
```

---

## Testnet Deployment

| Item | Value |
|------|-------|
| Network | Partisia Testnet |
| Contract | `0317d170bb3cd654c5375fe18cd949c006e3ded334` |
| SDK Version | `v.16.126.0` |
| Threshold | 2-of-3 Shamir |
| ZK Inputs per key | 6 (3 shares × 2 halves) |

### Verified Test Run (2026-03-09)

```
Key ID:       45825
Public key:   02a57ccaa6e930862bd670d46e13c6cea1f61b184410ccd5780f40e8d1794fcd4a
Shares:       6/6 submitted to ZK nodes
Signature:    a284edc1b79b84ab...ad501 (65 bytes)
Verified:     TRUE ✓ (confirmed on-chain)
```

---

## Important Notes for Testnet

- `force_complete_keygen` (0x08) is needed on testnet because ZK node callbacks do not fire automatically
- On mainnet, keygen would complete automatically after all 6 shares are received
- The private key is generated client-side and never stored anywhere permanently
- ZK node addresses are assigned at deploy time by Partisia infrastructure — not the engine addresses you specify

---

## Technology Used

| Technology | What it does here |
|-----------|------------------|
| Shamir's Secret Sharing | Splits private key into 3 shares, any 2 can rebuild it |
| secp256k1 ECDSA | Ethereum-compatible key generation and signing |
| ECDH + AES-128 | Encrypts each share for ZK nodes before sending |
| Partisia ZK Nodes | Store encrypted share halves permanently and privately |
| Lagrange Interpolation | Rebuilds the private key from 2 shares |
| On-chain Verification | Contract verifies every signature using stored public key |
