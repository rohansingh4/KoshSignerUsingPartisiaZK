# Kosh ZK Signer — Threshold ECDSA Wallet on Partisia

A distributed signing system where a secp256k1 private key **never exists as a whole** — not during creation, not during signing. Three parties each hold a random piece. They produce valid Ethereum ECDSA signatures without any single party knowing the full private key.

---

## Table of Contents

1. [What This Does](#1-what-this-does)
2. [Architecture](#2-architecture)
3. [Smart Contracts](#3-smart-contracts)
4. [TypeScript Client Files](#4-typescript-client-files)
5. [Complete Flow — Phase by Phase](#5-complete-flow--phase-by-phase)
   - [Phase 0: Deploy](#phase-0-deploy)
   - [Phase 1: DKG — Key Born Split](#phase-1-dkg--key-born-split-12-transactions)
   - [Phase 2: PQC Registration](#phase-2-pqc-registration-optional-9-transactions)
   - [Phase 3: GG20 Signing](#phase-3-gg20-signing-12-transactions)
6. [Contract Actions Reference](#6-contract-actions-reference)
7. [Environment Setup](#7-environment-setup)
8. [Running Tests](#8-running-tests)
9. [Live Contract Addresses](#9-live-contract-addresses)
10. [Security Properties](#10-security-properties)
11. [What Needs to Be Fixed Before Production](#11-what-needs-to-be-fixed-before-production)

---

## 1. What This Does

A backend developer calls this system to:

1. **Create a distributed Ethereum wallet** — no single server holds the private key
2. **Sign Ethereum transactions** — 3 parties collaborate on Partisia blockchain, producing a valid `(r, σ)` ECDSA signature
3. **Optionally gate signing behind PQC approval** — ML-DSA-65 (Dilithium) + ML-KEM-768 (Kyber) post-quantum cryptography

The private key `s = s₁ + s₂ + s₃` is a mathematical ghost — it can be proven to exist (the public key `P = P₁+P₂+P₃` is on-chain), but it was never computed anywhere.

**Result**: A standard Ethereum signature `(r, σ)` that any EVM chain accepts.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          PARTISIA BLOCKCHAIN                         │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │              kosh-zk-signer Contract                            │ │
│  │                                                                 │ │
│  │  State:                                                         │ │
│  │  - keys[]     → public key + phase (DKG/Signing)                │ │
│  │  - tasks[]    → signing sessions + partial sigs                 │ │
│  │  - pqc_state  → Dilithium/Kyber pubkeys, approval sessions      │ │
│  │                                                                 │ │
│  │  ZK Variables:                                                  │ │
│  │  - key_share_high_i  → upper 128 bits of sᵢ (encrypted)         │ │
│  │  - key_share_low_i   → lower 128 bits of sᵢ (encrypted)         │ │
│  └──────────────────────────┬──────────────────────────────────────┘ │
│                             │                                        │
│        ┌────────────────────┼────────────────────┐                   │
│        ▼                    ▼                    ▼                   │
│   ZK Node 1           ZK Node 2           ZK Node 3                  │
│   (holds encrypted    (holds encrypted    (holds encrypted           │
│    share fragment)     share fragment)     share fragment)           │
└─────────────────────────────────────────────────────────────────────┘
               ▲                    ▲                    ▲
               │                    │                    │
               │  Partisia RPC (signAndSend)             │
               │                                         │
┌──────────────┴──────────────────────────────┐          │
│              TypeScript Client              │          │
│                                             │          │
│  party.ts (Party 1 logic)                   │          │
│  dkg-party.ts (DKG shared logic)            │          │
│  gg20-signing.ts (GG20 protocol)            │          │
│  paillier.ts + mta.ts (crypto)              │          │
│  chain-utils.ts (tx submission + retry)     │          │
│  testnet-pqc.ts (PQC flow)                  │──────────┘
│  test-gg20-sign.ts (full test)              │
└─────────────────────────────────────────────┘
               │
               ▼
   Partisia Testnet / Mainnet
   (transactions broadcast here)
```

**Data flow summary**:
- Parties run TypeScript locally, broadcast transactions to Partisia
- Each party's secret share `sᵢ` is encrypted and stored on Partisia ZK nodes
- The contract combines public data on-chain (EC point addition, partial sig aggregation)
- Final `(r, σ)` signature is stored on the Partisia contract, ready to broadcast to Ethereum

---

## 3. Smart Contracts

| Contract | Language | Purpose |
|----------|----------|---------|
| `kosh-zk-signer` | Rust (WASM) | Main contract — DKG, GG20 signing, PQC approval, state |
| `kosh-vault` | Rust (WASM) | Optional vault — holds assets, requires signer approval |
| `kosh-account-registry` | Rust (WASM) | Registry mapping addresses → signer contracts |

The active contract for development is `kosh-zk-signer`. The others are scaffolding.

**Key contract files** (`contracts/kosh-zk-signer/src/`):

| File | What It Does |
|------|-------------|
| `lib.rs` | Entry point — all action handlers (DKG, GG20, Shamir, PQC) |
| `signing_state.rs` | State types: `KeyEntry`, `SigningTask`, `Phase` enums |
| `dkg.rs` | DKG logic: commit/reveal/verify, EC point addition (k256 crate) |
| `shamir.rs` | Legacy Shamir split/reconstruct (still available, not recommended) |
| `off_chain.rs` | ZK node callbacks — fires when encrypted share is confirmed |
| `zk_compute.rs` | ZK compiler stub (Partisia ZK framework integration) |

---

## 4. TypeScript Client Files

**`client/src/`**

| File | Purpose |
|------|---------|
| `chain-utils.ts` | Shared utilities: `submitAndWait()` (3-retry tx submission), `encodeU32Be`, `encodeLenPrefixedBytes`, `encodePartyVector`, `concatBytes` |
| `partisia.ts` | `PartisiaClient` wrapper — loads account, builds `TransactionClient` |
| `dkg-party.ts` | DKG ceremony: generate keypair, `buildDkgCommitArgs`, `buildDkgRevealArgs`, `buildDkgFinalizeArgs` |
| `gg20-signing.ts` | GG20 protocol: `gg20Sign()` (full multi-party signing), `buildSubmitDeltaArgs`, `buildSubmitGammaPointArgs`, `buildSubmitPartialSigArgs`, `buildGG20StartSigningArgs` |
| `paillier.ts` | Paillier homomorphic encryption (1024-bit safe primes) — used by MtA |
| `mta.ts` | Multiplicative-to-Additive protocol — converts `kᵢ × sⱼ` cross-terms to additive shares using Paillier |
| `party.ts` | Single-party runner — loads identity from env, runs DKG/signing as one party |
| `zk-signer.ts` | ZK share submission: `submitZkShareHalf()` — encrypts `sᵢ` for each ZK node's public key |
| `pqc.ts` | PQC crypto: `generatePqcIdentity()` — generates Dilithium + Kyber keypairs via WASM |
| `pqc-identity.ts` | PQC identity loading/saving (`pqc-identity-party*.json`) |
| `pqc-auth.ts` | PQC authentication helpers |
| `policy.ts` | `buildRegisterPartyAddressArgs`, `buildSignMessageWithTagArgs` — contract call builders |
| `testnet-pqc.ts` | End-to-end PQC flow: `registerOnchainPqcIdentities`, `queueSignAndApprove`, `startApprovedGg20` |
| `deploy-zk-signer.ts` | Contract deployment via `DeploymentBuilder` (CLI can't parse complex init args) |
| `shamir-ts.ts` | Shamir math (Lagrange interpolation, polynomial evaluation) |
| `coord-server.ts` | Coordinator HTTP server for multi-machine party coordination |
| `key-refresh.ts` | Key refresh protocol stub |
| `test-gg20-sign.ts` | **Full integration test** — DKG + GG20 on Partisia testnet |
| `test-policy.ts` | Policy tests — 20 assertions |
| `test-pqc.ts` | PQC tests — 28 assertions |
| `test-gg20-local.ts` | Local GG20 math test (no chain calls) |
| `test-threshold-sign.ts` | Threshold signing test |

---

## 5. Complete Flow — Phase by Phase

### Phase 0: Deploy

Deploy the contract once. After deployment you get a `CONTRACT_ADDRESS`.

```bash
cd client
npx tsx src/deploy-zk-signer.ts
# Outputs: CONTRACT_ADDRESS=03xxxxxxxx...
```

The deploy script uses `DeploymentBuilder` + `BlockchainClientForDeploymentImpl` because the Partisia CLI cannot parse the `Vec<EngineConfig>` init argument.

---

### Phase 1: DKG — Key Born Split (12 transactions)

**Goal**: Create a secp256k1 keypair where `s = s₁+s₂+s₃` is never computed.

```
Party 1          Party 2          Party 3          Contract
───────          ───────          ───────          ────────
pick s₁          pick s₂          pick s₃
P₁ = s₁·G        P₂ = s₂·G        P₃ = s₃·G

                                              0x20 dkg_create_key(key_id, n_parties)
                                              Contract: phase → Committing

commit SHA256(P₁) ──────────────────────────► 0x21 dkg_commit(key_id, 1, SHA256(P₁))
commit SHA256(P₂) ──────────────────────────► 0x21 dkg_commit(key_id, 2, SHA256(P₂))
commit SHA256(P₃) ──────────────────────────► 0x21 dkg_commit(key_id, 3, SHA256(P₃))
                                              Contract: phase → Revealing (all committed)

reveal P₁ ──────────────────────────────────► 0x22 dkg_reveal(key_id, 1, P₁)
reveal P₂ ──────────────────────────────────► 0x22 dkg_reveal(key_id, 2, P₂)
reveal P₃ ──────────────────────────────────► 0x22 dkg_reveal(key_id, 3, P₃)
                                              Contract: verifies SHA256(Pᵢ) == Cᵢ for all i

                                              0x23 dkg_finalize(key_id)
                                              Contract: P = P₁+P₂+P₃ (EC point addition)
                                                        phase → WaitingForShares

submit s₁ halves (ZK encrypted) ────────────► 0x10 submit_key_share(key_id, 1, half) × 2
submit s₂ halves (ZK encrypted) ────────────► 0x10 submit_key_share(key_id, 2, half) × 2
submit s₃ halves (ZK encrypted) ────────────► 0x10 submit_key_share(key_id, 3, half) × 2
                                              ZK nodes store encrypted fragments

                                              0x24 dkg_complete_keygen(key_id)
                                              Contract: phase → Complete
```

**Why the commit-reveal?** Without it, Party 3 could wait to see `P₁` and `P₂`, then pick `s₃` to control the final public key (rogue key attack). The commit locks in the choice.

**Why ZK halves?** Each `sᵢ` is 256 bits, split into two 128-bit halves. Each half is encrypted separately for each ZK node — no single ZK node can reassemble a full share.

**Result**: `P` (combined public key) is stored on-chain. Ethereum address = `keccak256(P.x || P.y)[12:]`.

---

### Phase 2: PQC Registration (optional, 9 transactions)

**Goal**: Register Dilithium + Kyber post-quantum keys per party, so signing requires PQC approval.

```
For each party:
  generate Dilithium keypair (ML-DSA-65) + Kyber keypair (ML-KEM-768)

  0x72 register_party_address(key_id, party_index, address)
  0x73 register_dilithium_pubkey(key_id, party_index, dilithium_pubkey)
  0x74 register_kyber_pubkey(key_id, party_index, kyber_pubkey)
```

**PQC approval flow** (required before GG20 if PQC is registered):

```
0x03 sign_message(key_id, msg_hash, tx_tag)       ← queue the message
0x75 start_pqc_approval_session(key_id, task_id, signing_subset)
                                                   ← open approval window
For each party in signing_subset:
  compute approvalHash = SHA256(KOSH_PQC_APPROVAL_V1 || ... || challenge)
  0x76 submit_pqc_approval(key_id, task_id, party_index, approvalHash)

0x77 finalize_pqc_approval(key_id, task_id)       ← check all approved

Then → continue to Phase 3 (GG20)
```

---

### Phase 3: GG20 Signing (12 transactions)

**Goal**: Produce a valid ECDSA `(r, σ)` without any party knowing `k` or `s`.

**Off-chain pre-computation** (no chain calls):

```
Each party i independently:
  pick random kᵢ (HMAC-DRBG seeded with sᵢ)
  pick random γᵢ (masking value)
  compute Γᵢ = γᵢ·G   (gamma point)

Paillier MtA rounds (12 exchanges total, all pairs):
  For each pair (i,j):
    mtaRound — compute additive share of kᵢ·γⱼ  →  αᵢⱼ + βᵢⱼ
    mtaRound — compute additive share of kᵢ·sⱼ  →  μᵢⱼ + νᵢⱼ

Each party computes:
  δᵢ = kᵢ·γᵢ + Σ(cross-term shares from MtA)   ← share of k·γ
  σᵢ = kᵢ·sᵢ + Σ(cross-term shares from MtA)   ← share of k·s (NEVER revealed)
```

**On-chain transactions**:

```
Party 1          Party 2          Party 3          Contract
───────          ───────          ───────          ────────
                                              0x50 gg20_start_signing(key_id, task_id, subset)
                                              Contract: phase → ThresholdSigning

submit δ₁ ───────────────────────────────────► 0x45 submit_delta(key_id, 1, δ₁)
submit δ₂ ───────────────────────────────────► 0x45 submit_delta(key_id, 2, δ₂)
submit δ₃ ───────────────────────────────────► 0x45 submit_delta(key_id, 3, δ₃)

submit Γ₁ ───────────────────────────────────► 0x46 submit_gamma_point(key_id, 1, Γ₁)
submit Γ₂ ───────────────────────────────────► 0x46 submit_gamma_point(key_id, 2, Γ₂)
submit Γ₃ ───────────────────────────────────► 0x46 submit_gamma_point(key_id, 3, Γ₃)

                                              0x47 gg20_finalize_r(key_id, task_id)
                                              Contract computes:
                                                δ = δ₁+δ₂+δ₃       (= k·γ)
                                                Γ = Γ₁+Γ₂+Γ₃       (= γ·G)
                                                R = δ⁻¹·Γ           (= k⁻¹·G)
                                                r = R.x mod n       (part of sig)

compute σ₁ (using k⁻¹, r, s₁, z) ──────────► 0x30 commit_partial_sig(key_id, 1, SHA256(σ₁))
compute σ₂ (using k⁻¹, r, s₂, z) ──────────► 0x30 commit_partial_sig(key_id, 2, SHA256(σ₂))
compute σ₃ (using k⁻¹, r, s₃, z) ──────────► 0x30 commit_partial_sig(key_id, 3, SHA256(σ₃))

reveal σ₁ ───────────────────────────────────► 0x31 submit_partial_sig(key_id, 1, σ₁)
reveal σ₂ ───────────────────────────────────► 0x31 submit_partial_sig(key_id, 2, σ₂)
reveal σ₃ ───────────────────────────────────► 0x31 submit_partial_sig(key_id, 3, σ₃)

                                              0x32 finalize_gg20_sig(key_id, task_id)
                                              Contract combines:
                                                σ = σ₁+σ₂+σ₃ mod n
                                                if σ > n/2: σ = n-σ  (EIP-2 low-s)
                                                verify ECDSA(P, z, r, σ) ✓
                                                store signature on-chain ✓
```

**The key trick** — why `R = δ⁻¹·Γ = k⁻¹·G`:

```
δ = k·γ        (nobody knows k or γ, but MtA gave additive shares of k·γ)
Γ = γ·G        (sum of public gamma points)

R = δ⁻¹·Γ = (k·γ)⁻¹·(γ·G) = k⁻¹·γ⁻¹·γ·G = k⁻¹·G

γ cancels out. Nobody computed k or k⁻¹.
```

---

## 6. Contract Actions Reference

### DKG Actions

| Shortname | Name | Parameters | Effect |
|-----------|------|------------|--------|
| `0x20` | `dkg_create_key` | `key_id: u32, num_parties: u8` | Create empty key slot, phase → Committing |
| `0x21` | `dkg_commit` | `key_id: u32, party_index: u8, commitment: Vec<u8>` | Store `SHA-256(Pᵢ)` |
| `0x22` | `dkg_reveal` | `key_id: u32, party_index: u8, pubkey: Vec<u8>` | Reveal `Pᵢ`, verify hash matches |
| `0x23` | `dkg_finalize` | `key_id: u32` | Compute `P = P₁+P₂+P₃`, phase → WaitingForShares |
| `0x10` | `submit_key_share` | `key_id: u32, party_index: u8` + ZK input | Encrypt `sᵢ` half to ZK nodes |
| `0x24` | `dkg_complete_keygen` | `key_id: u32` | Mark key Complete |

### GG20 Signing Actions

| Shortname | Name | Parameters | Effect |
|-----------|------|------------|--------|
| `0x50` | `gg20_start_signing` | `key_id: u32, task_id: u32, subset: Vec<u8>` | Open signing session |
| `0x45` | `submit_delta` | `key_id: u32, party_index: u8, delta: Vec<u8>` | Submit `δᵢ` (share of `k·γ`) |
| `0x46` | `submit_gamma_point` | `key_id: u32, party_index: u8, point: Vec<u8>` | Submit `Γᵢ = γᵢ·G` |
| `0x47` | `gg20_finalize_r` | `key_id: u32, task_id: u32` | Compute `R = δ⁻¹·Γ`, extract `r` |
| `0x30` | `commit_partial_sig` | `key_id: u32, party_index: u8, hash: Vec<u8>` | Commit `SHA-256(σᵢ)` |
| `0x31` | `submit_partial_sig` | `key_id: u32, party_index: u8, sig: Vec<u8>` | Reveal `σᵢ`, verify hash |
| `0x32` | `finalize_gg20_sig` | `key_id: u32, task_id: u32` | Combine `σ = Σσᵢ`, low-s, ECDSA verify |
| `0x48` | `abort_signing` | `key_id: u32, task_id: u32` | Cancel session |

### PQC Actions

| Shortname | Name | Parameters | Effect |
|-----------|------|------------|--------|
| `0x72` | `register_party_address` | `key_id: u32, party_index: u8, address: str` | Link party index to Partisia address |
| `0x73` | `register_dilithium_pubkey` | `key_id: u32, party_index: u8, pubkey: Vec<u8>` | Store ML-DSA-65 public key |
| `0x74` | `register_kyber_pubkey` | `key_id: u32, party_index: u8, pubkey: Vec<u8>` | Store ML-KEM-768 public key |
| `0x75` | `start_pqc_approval_session` | `key_id: u32, task_id: u32, subset: Vec<u8>` | Open PQC approval window |
| `0x76` | `submit_pqc_approval` | `key_id: u32, task_id: u32, party_index: u8, hash: Vec<u8>` | Submit approval hash |
| `0x77` | `finalize_pqc_approval` | `key_id: u32, task_id: u32` | Verify all approvals, ungate signing |

### Policy / Legacy Actions

| Shortname | Name | Effect |
|-----------|------|--------|
| `0x03` | `sign_message` | Queue a message hash for signing (Shamir or PQC flow) |
| `0x07` | `signing_complete` | Submit pre-computed signature (Shamir legacy) |
| `0x02` | `create_key_with_id` | Create key with Shamir setup |
| `0x05` | `post_public_key` | Store public key directly |

---

## 7. Environment Setup

### Prerequisites

```bash
# Rust toolchain + Partisia contract compiler
rustup target add wasm32-unknown-unknown
cargo install cargo-partisia-contract

# Node.js 18+
cd client
npm install
```

### Environment Variables

Create `client/.env` or export:

```bash
# Partisia account that pays for transactions
PARTISIA_SENDER_KEY=<64-char hex private key>
PARTISIA_SENDER_ADDRESS=<partisia_account_address>

# Deployed contract address
SIGNER_ADDRESS=03xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Optional: Ethereum RPC for final tx broadcast
ETH_RPC_URL=https://sepolia.infura.io/v3/<key>
```

### Build Contract

```bash
cd contracts/kosh-zk-signer
cargo pbc build --release
# Output: target/wasm32-unknown-unknown/release/kosh_zk_signer.pbc
```

---

## 8. Running Tests

### Full DKG + GG20 Integration Test (testnet)

```bash
cd client
npx tsx src/test-gg20-sign.ts
```

Runs 12 DKG transactions + 12 signing transactions on Partisia testnet. Takes ~3–5 minutes.

**Expected output**:
```
=== DKG + GG20 Threshold ECDSA Test ===

DKG Phase:
  dkg_create_key OK
  dkg_commit_P1 OK     Tx: e0a3a36f...
  dkg_commit_P2 OK     Tx: 0e1dc99e...
  dkg_commit_P3 OK     Tx: cdfc2b39...
  dkg_reveal_P1 OK     Tx: 70e5f2d5...
  dkg_reveal_P2 OK     Tx: b0fce68c...
  dkg_reveal_P3 OK     Tx: 4c02e8b0...
  dkg_finalize OK       P = P₁+P₂+P₃ computed
  submit_key_share_P1_high OK
  submit_key_share_P1_low OK
  ...
  dkg_complete_keygen OK

GG20 Signing Phase:
  gg20_start_signing OK
  submit_delta_1 OK
  submit_delta_2 OK
  submit_delta_3 OK
  submit_gamma_point_1 OK
  submit_gamma_point_2 OK
  submit_gamma_point_3 OK
  gg20_finalize_r OK   r extracted
  commit_partial_sig_P1 OK
  commit_partial_sig_P2 OK
  commit_partial_sig_P3 OK
  submit_partial_sig_P1 OK
  submit_partial_sig_P2 OK
  submit_partial_sig_P3 OK
  finalize_gg20_sig OK  ✓ ECDSA signature verified on-chain
```

### Policy Tests

```bash
cd client
npx tsx src/test-policy.ts
# Expected: 20/20 PASS
```

### PQC Tests

```bash
cd client
npx tsx src/test-pqc.ts
# Expected: 28/28 PASS
```

### Local GG20 Math Test (no chain)

```bash
cd client
npx tsx src/test-gg20-local.ts
```

### TypeScript Type Check

```bash
cd client
npx tsc --noEmit
# Expected: zero errors
```

---

## 9. Live Contract Addresses

| Contract | Address | Last Active |
|----------|---------|------------|
| kosh-zk-signer (current) | `031fb3ede8b7274ffb94ef250ba3747e49b2706d12` | Apr 22, 2026 |
| kosh-zk-signer (previous) | `03a1e8aba3ba45c1e42d01f688768436cb2b572de0` | Apr 18, 2026 |

**Partisia Explorer**: `https://browser.testnet.partisiablockchain.com/contracts/<ADDRESS>`

**Deployer account**: `002ee35cde26782f255b9550ea1ac53faeac2c71cd`

**Proven Ethereum signing** (signature produced by GG20 without ever having the private key):

| Item | Value |
|------|-------|
| Sepolia Tx | `0x09ec739d1e7cf9a91019c393abc9eee91042eedf20b4ec9f70630f7b93b98d41` |
| Block | 10432151 |
| From | `0x46fe38ef06876C3d76E03D1e5991eD28FF2714ad` |
| Proof | Transaction was accepted by Ethereum Sepolia — the private key never existed |

---

## 10. Security Properties

| Property | Status | How |
|----------|--------|-----|
| Private key never assembled | ✓ | DKG additive shares — `s = s₁+s₂+s₃` never computed |
| Nonce never assembled | ✓ | GG20 — `k = k₁+k₂+k₃` never computed, `k⁻¹` never exists as a number |
| Rogue key attack prevented | ✓ | DKG commit-reveal: parties lock in `Pᵢ` before seeing others |
| Delta manipulation prevented | ✓ | `δᵢ` submitted plaintext (per GG20 protocol — safe to reveal because `γ` masks `k`) |
| Partial sig manipulation prevented | ✓ | Commit-reveal for `σᵢ`: hash committed first, then revealed |
| ZK share security | ✓ | Each `sᵢ` split into two 128-bit halves, each half encrypted per ZK node |
| EIP-2 / BIP-62 compliance | ✓ | Low-s normalization applied by contract before storing signature |
| Post-quantum gating (optional) | ✓ | ML-DSA-65 + ML-KEM-768 approval required before GG20 starts |

### Current Limitations (Pre-Production)

1. **No ZK range proofs in MtA** — A malicious party can submit crafted out-of-range Paillier values over multiple sessions to extract another party's `kᵢ`. Fix: add Πenc + Πaff-g proofs per GG20 paper, or replace with CGGMP21.

2. **No Γᵢ commitment** — Gamma points are submitted directly; delta has commit-reveal but gamma does not. Last-to-submit party could bias `R`. Fix: add commit-reveal for `Γᵢ`.

3. **All parties on one machine** — `gg20Sign()` runs all 3 parties in one process. Fix: separate processes per machine, communicate via authenticated network channels.

4. **3-of-3, not threshold** — If any party goes offline permanently, the wallet is locked. Fix: replace additive DKG with Feldman VSS for 2-of-3 threshold.

5. **1024-bit Paillier** — Borderline by 2024 standards. Fix: change to 2048-bit.

6. **Safe prime fallback** — `generateSafePrime()` silently falls back to a non-safe prime if generation is slow. Fix: remove fallback, fail loudly.

---

## 11. What Needs to Be Fixed Before Production

Ranked by severity:

| # | Issue | Severity | Fix |
|---|-------|----------|-----|
| 1 | No ZK range proofs in MtA | **Critical** | Add Πenc + Πaff-g per GG20 paper, or use CGGMP21 |
| 2 | All parties on one machine | **Critical** | Separate processes per machine + network layer |
| 3 | No Γᵢ commitment | **Medium** | Add commit-reveal for gamma points |
| 4 | 3-of-3, not 2-of-3 | **Medium** | Feldman VSS DKG (see `client/threshold.md`) |
| 5 | 1024-bit Paillier | Low | Change `paillierKeygen(1024)` to `(2048)` |
| 6 | Safe prime fallback | Low | Remove fallback, throw error |
| 7 | No identifiable abort | Low | Add per-submission ZK proofs |

**Recommended path to production**: Replace `paillier.ts` + `mta.ts` + `gg20-signing.ts` with [CGGMP21](https://github.com/LFDT-Lockness/cggmp21) (Rust) or [tss-lib](https://github.com/bnb-chain/tss-lib) (Go). Keep the Partisia contract layer — DKG commit/reveal, on-chain R computation, and partial sig combination are correct.
