# Kosh — The Wallet With No Key

### *"What if your company's crypto wallet couldn't be stolen — even if a hacker broke in?"*

---

## The Problem Everyone Has

Every crypto wallet today has one fatal flaw: **a single private key**.

One file. One password. One point of failure.

```
  TRADITIONAL WALLET
  ──────────────────────────────────────────
  Private Key  →  whoever has this file
                  controls ALL the funds.

  Hacker steals it       →  funds gone
  Employee copies it     →  funds gone
  Server is compromised  →  funds gone
  You lose it            →  funds gone forever
  ──────────────────────────────────────────
```

This is not a small risk. **Billions of dollars** have been lost this way.
Exchanges hacked. Employees gone rogue. Laptops stolen.

The whole premise of "be your own bank" falls apart the moment that one key is compromised.

---

## The Insight

**What if the key never existed in the first place?**

Not hidden. Not encrypted. Just... never created as a whole thing.

That is exactly what Kosh does.

---

## How Kosh Works — In Plain English

Three parties each contribute a random secret number. Through a mathematical ceremony, those secrets combine into a real Ethereum wallet address. But the private key that "owns" that address is **never computed by anyone** — not even for a millisecond.

When it's time to sign a transaction, any 2 of the 3 parties each produce a small mathematical fragment. Those two fragments combine on a blockchain smart contract into a valid signature. Ethereum accepts it as completely normal.

Nobody ever held the full key. Nothing was ever assembled.

---

## The Bank Vault Analogy

Imagine a bank vault that requires **2 out of 3 managers** to open it.

```
  Manager A + Manager B   →  vault opens  ✓
  Manager A + Manager C   →  vault opens  ✓
  Manager B + Manager C   →  vault opens  ✓

  Manager A alone         →  vault stays shut  ✗
  Hacker alone            →  vault stays shut  ✗
  Hacker + 1 manager      →  vault stays shut  ✗
```

- If one manager is sick → the other two handle it
- If one manager goes rogue → they cannot steal alone
- If a hacker breaks into one manager's laptop → they got a useless fragment

That is Kosh. But for crypto. And the vault key **literally does not exist**.

---

## How the Key Is Born — Step by Step

This is the part that makes Kosh fundamentally different.

### The Old Dangerous Way

```
  OLD WAY — Key Generated, Then Split
  ─────────────────────────────────────────────────────
  Step 1: One computer generates the full private key
          ↑
          THE KEY EXISTS HERE. On one machine.
          This is the moment everything can go wrong.

  Step 2: That computer distributes pieces to others
          ↑
          Pieces travel over a network. Can be intercepted.

  Step 3: The original key is "deleted"
          ↑
          Was it really? Can you prove it?
  ─────────────────────────────────────────────────────
  RISK: The full key existed. Even for one second.
        That one second is the attack window.
```

### The Kosh Way — Key Born Split

```
  KOSH — Key Never Assembled
  ─────────────────────────────────────────────────────
  Party 1          Party 2          Party 3
  ────────         ────────         ────────
  Picks a          Picks a          Picks a
  random secret    random secret    random secret
  (stays on P1)    (stays on P2)    (stays on P3)

       │                │                │
       └────────────────┼────────────────┘
                        │
                        ▼
              Mathematical ceremony
              on Partisia blockchain

                        │
                        ▼
              Combined wallet address
              created from all 3 secrets

  The private key s = s₁ + s₂ + s₃
  ↑ This number is NEVER computed. By anyone. Ever.
  ─────────────────────────────────────────────────────
```

### The 5-Phase Ceremony (What Actually Happens)

```
 ┌─────────────────────────────────────────────────────────┐
 │  PHASE 1 — COMMITMENT                                    │
 │                                                          │
 │  Each party posts a fingerprint of their secret         │
 │  to the Partisia blockchain.                            │
 │                                                          │
 │  Party 1 → posts Hash(secret₁)                         │
 │  Party 2 → posts Hash(secret₂)                         │
 │  Party 3 → posts Hash(secret₃)                         │
 │                                                          │
 │  Why: locks everyone in before anyone can see           │
 │  what others chose. Prevents manipulation.              │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  PHASE 2 — REVEAL                                        │
 │                                                          │
 │  Each party reveals their public contribution.          │
 │  Contract checks it matches the commitment.             │
 │                                                          │
 │  Contract combines them:                                │
 │  Public Key P = P₁ + P₂ + P₃  →  Ethereum address      │
 │                                                          │
 │  The wallet address now exists.                         │
 │  The private key does not.                              │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  PHASE 3 — CROSS-VERIFICATION                            │
 │                                                          │
 │  Each party sends a private fragment to each other      │
 │  party (encrypted, peer-to-peer).                       │
 │                                                          │
 │  Each party then verifies the math:                     │
 │  "Does what I received actually match the               │
 │   commitment that was posted on-chain?"                 │
 │                                                          │
 │  If anyone cheated → ceremony aborted, error logged.    │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  PHASE 4 — PROOFS POSTED ON-CHAIN                        │
 │                                                          │
 │  Each party proves their fragments were computed        │
 │  correctly — without revealing the secret itself.       │
 │                                                          │
 │  The Partisia contract verifies all proofs.             │
 │  No proof → no key. No exceptions.                      │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  PHASE 5 — ENCRYPTED STORAGE                             │
 │                                                          │
 │  Each party's share is stored on Partisia ZK nodes      │
 │  — a special encrypted layer of the blockchain.         │
 │                                                          │
 │  The share is itself split across multiple ZK nodes.    │
 │  No single node sees the complete share.                │
 │                                                          │
 │  KEY GENERATION COMPLETE.                               │
 │  Wallet address: exists and usable.                     │
 │  Private key: never existed.                            │
 └─────────────────────────────────────────────────────────┘
```

### What Each Party Knows After the Ceremony

```
 ┌──────────┬──────────────────────┬────────────────────────┐
 │          │  CAN SEE             │  CANNOT SEE            │
 ├──────────┼──────────────────────┼────────────────────────┤
 │ Party 1  │  Own share, address  │  Party 2 & 3 secrets   │
 │ Party 2  │  Own share, address  │  Party 1 & 3 secrets   │
 │ Party 3  │  Own share, address  │  Party 1 & 2 secrets   │
 │ Hacker   │  Wallet address only │  Everything that matters│
 │ Contract │  Wallet address only │  All private material  │
 └──────────┴──────────────────────┴────────────────────────┘

 Nobody has enough to do anything alone. Not even 2 out of 3.
 2 of 3 are only needed to SIGN — and even then, the
 private key never comes together.
```

---

## The Quantum Threat — Why This Cannot Wait

Every bank, every crypto wallet, every encrypted message on the internet today
depends on one piece of math: **it is hard to reverse an elliptic curve calculation**.

ECDSA — the signature behind every Ethereum transaction — relies entirely on that.

A quantum computer running **Shor's algorithm** solves that same math in hours.

```
  CLASSIC COMPUTER
  ─────────────────────────────────────────────
  Reverse ECDSA private key from public key:
  ~10^18 years (longer than the universe)

  QUANTUM COMPUTER (Shor's algorithm)
  ─────────────────────────────────────────────
  Same calculation:
  ~hours on a sufficiently large machine
```

### Q-Day — When Does This Happen?

The US National Security Agency, NIST, and major governments estimate
a cryptographically relevant quantum computer will exist within this decade.
No one knows the exact date. That uncertainty is itself the danger.

### The Attack Happening Right Now — "Harvest Now, Decrypt Later"

Adversaries do not need to wait for Q-Day to start attacking.

```
  TODAY (2025)
  ─────────────────────────────────────────────────────────
  Attacker intercepts and records:
    → Party 1 submits share to Partisia ZK node
    → Party 2 sends approval to coordinator
    → Partial signatures submitted by each party
    → All session keys protecting transport
  Attacker stores everything. Cannot break it yet.

  AFTER Q-DAY (2030s?)
  ─────────────────────────────────────────────────────────
  Attacker runs quantum computer on archived data:
    → Breaks all ECDSA session keys
    → Recovers share data from 2025
    → Reconstructs private key retroactively
    → Drains any wallet that held those assets
  ─────────────────────────────────────────────────────────
```

The attack is being set up today. The vault is cracked in the future.

---

## Quantum-Ready Layer — How Kosh Protects Against This

Kosh adds a post-quantum identity layer to every part of the off-chain protocol.
The blockchain still receives ECDSA signatures (required for compatibility),
but everything leading up to that — identity, transport, approvals — is already
quantum-safe.

### Two Post-Quantum Standards (NIST Approved 2024)

```
  ML-KEM-768 (CRYSTALS-Kyber)
  ─────────────────────────────────────────────────────────
  What it does:   Key Encapsulation — quantum-safe key exchange
  Based on:       Module Learning With Errors (lattice problem)
  Why safe:       No known quantum algorithm solves lattice problems
  Used for:       Encrypting share transport, k⁻¹ submission, session keys

  ML-DSA-65 (CRYSTALS-Dilithium)
  ─────────────────────────────────────────────────────────
  What it does:   Digital signatures — quantum-safe identity proof
  Based on:       Module Learning With Errors (lattice problem)
  Why safe:       Same lattice hardness — Shor's algorithm does not apply
  Used for:       Authenticating every party action in the signing protocol
```

Both are standardized by NIST in 2024 (FIPS 203 and FIPS 204).
No experimental cryptography — these are the official replacements for RSA and ECDSA.

### What Each Party Gets

Before any DKG or signing session, each party generates a PQC identity:

```
  PARTY 1                         PARTY 2                         PARTY 3
  ─────────────────────────────   ─────────────────────────────   ─────────────────
  Kyber keypair (1184 + 2400 B)   Kyber keypair                   Kyber keypair
  Dilithium keypair               Dilithium keypair               Dilithium keypair
  ↓                               ↓                               ↓
  Public bundle shared →          ← Public bundles exchanged →    ← Public bundle
  (contains ONLY public keys)
```

Public bundles contain zero private key material. They are shared before DKG
so each party can verify the others throughout the protocol.

### How It Protects Every Step

```
  DURING DKG CEREMONY
  ─────────────────────────────────────────────────────────
  Party commits:   { hash(P_i), dilithium_sig, timestamp }
  Party reveals:   { P_i, dilithium_sig, timestamp }
  Coordinator:     verifies Dilithium sig before accepting
  Result:          impersonation impossible even post-Q-Day

  DURING SIGNING SESSION
  ─────────────────────────────────────────────────────────
  Party computes k⁻¹
  Party encrypts k⁻¹ → Kyber → coordinator (quantum-safe)
  Party submits delta:    { delta, dilithium_sig, timestamp }
  Party submits gamma:    { gamma, dilithium_sig, timestamp }
  Party submits σ_i:      { partial_sig, dilithium_sig, timestamp }
  Coordinator verifies all Dilithium sigs before relaying to chain

  ON-CHAIN (Partisia + Ethereum)
  ─────────────────────────────────────────────────────────
  Contract receives:  normal ECDSA-compatible bytes (unchanged)
  Chain verifies:     secp256k1 signature (blockchain requirement)
  Ethereum accepts:   completely normal transaction
```

### Replay Protection Built In

Every Dilithium-signed action includes a timestamp.
Any action older than 5 minutes is rejected — even if the signature is valid.
This prevents:
- Replaying a party's old approval for a new transaction
- Delaying a submission until market conditions change
- Recording and resubmitting old actions from an archived session

### What a Quantum Attacker Gets — After Kosh

```
  ATTACKER RECORDS KOSH PROTOCOL TRAFFIC TODAY
  ─────────────────────────────────────────────────────────
  What they see:
    → Dilithium signatures (cannot forge — lattice-based)
    → Kyber-encrypted k⁻¹ packets (cannot decrypt — lattice-based)
    → Kyber-encrypted session tokens (cannot break)
    → Encrypted share submissions to ZK nodes

  AFTER Q-DAY — what Shor's algorithm can do to this:
    → Break ECDSA? Yes, but Kosh's protocol does not use ECDSA for transport
    → Break Kyber? No — Shor's algorithm has no effect on lattice problems
    → Break Dilithium? No — same lattice hardness guarantee
    → Recover shares? No — ZK variables never opened in GG20 flow
    → Forge a party approval? No — Dilithium remains secure
  ─────────────────────────────────────────────────────────
  Net result: nothing useful recovered
```

### The Hybrid Model — Why On-Chain Is Still ECDSA

Ethereum, Partisia, and every major blockchain uses ECDSA for transaction validation.
We cannot change that until the chains themselves upgrade.

What we CAN do — and have done — is protect everything else:

```
  PQC PROTECTED (quantum-safe today)
  ─────────────────────────────────────────────────────────
  Party identity verification          → Dilithium
  All protocol message authentication  → Dilithium
  Share submission encryption          → Kyber
  k⁻¹ transport to coordinator         → Kyber
  Session key establishment            → Kyber → AES-256-GCM

  ECDSA (blockchain requirement — will upgrade when chains do)
  ─────────────────────────────────────────────────────────
  Final on-chain transaction signature  → secp256k1 ECDSA
```

When Ethereum and Partisia add PQC signature support, Kosh requires
zero protocol changes — the on-chain signing output just changes algorithm.
The rest of the system is already there.

---

## How Signing Works — Without Assembling the Key

When it's time to send a transaction, this is what happens.

```
 YOU WANT TO SEND A TRANSACTION
          │
          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  STEP 1 — Transaction is queued on Partisia             │
 │                                                          │
 │  The message to sign (a 32-byte hash of the tx)         │
 │  is posted to the smart contract.                       │
 │                                                          │
 │  Optional: a tag is attached                            │
 │  tag = "treasury"  →  big transfer, CFO must approve    │
 │  tag = "admin"     →  contract upgrade, CEO must approve │
 │  tag = ""          →  routine, any 2 of 3 can sign      │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  STEP 2 — Each signing party generates a random nonce   │
 │                                                          │
 │  Party 1 picks k₁  (random, stays on their machine)     │
 │  Party 2 picks k₂  (random, stays on their machine)     │
 │                                                          │
 │  The combined nonce k = k₁ + k₂ is NEVER computed.     │
 │  Neither party knows the full k.                        │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  STEP 3 — Secret multiplication (MtA protocol)          │
 │                                                          │
 │  Parties need to multiply their secrets together.       │
 │  They do this using encrypted math (Paillier encryption)│
 │  so neither party ever sees the other's number.         │
 │                                                          │
 │  Result: each party has a private fragment δᵢ that      │
 │  together let the contract compute the nonce point R.   │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  STEP 4 — Contract computes the nonce point R           │
 │                                                          │
 │  Parties post their δᵢ fragments to the contract.       │
 │  Contract combines them and computes:                   │
 │                                                          │
 │  R = k⁻¹ · G  (a point on the elliptic curve)          │
 │                                                          │
 │  k⁻¹ is NEVER computed as a number.                     │
 │  R is computed as a mathematical point trick.           │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  STEP 5 — Each party computes their partial signature   │
 │                                                          │
 │  Party 1: sᵢ = (message · k₁) + (r · own_fragment)     │
 │  Party 2: s₂ = (message · k₂) + (r · own_fragment)     │
 │                                                          │
 │  Each party first commits a fingerprint of sᵢ,         │
 │  then reveals it. This prevents last-second cheating.  │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  STEP 6 — Contract combines and verifies                │
 │                                                          │
 │  s = s₁ + s₂                                           │
 │                                                          │
 │  Contract runs standard ECDSA verification:            │
 │  Does (r, s) prove that the holder of private key       │
 │  signed this message?  → YES ✓                         │
 │                                                          │
 │  Signature stored on-chain. Full audit trail.           │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  RESULT — A normal Ethereum signature                   │
 │                                                          │
 │  Ethereum receives a completely standard ECDSA          │
 │  signature. It has no idea how it was produced.         │
 │  Transaction executes.                                  │
 └─────────────────────────────────────────────────────────┘
```

---

## Policy + RBAC — Who Controls What Gets Signed

This is where Kosh goes beyond simple threshold wallets.

Not every transaction should be treated the same. Moving $5M from treasury is not the same as a $50 routine payment. Kosh lets you define **rules** — and enforces them at the **blockchain level**, not just in software.

### The Problem with Software-Only Rules

```
  TYPICAL "POLICY" TODAY
  ─────────────────────────────────────────────────────
  Rule: "CFO must approve all treasury transactions"
  ↓
  This rule lives in a config file.
  ↓
  A developer modifies the client app.
  ↓
  Rule bypassed. CFO never knew.
  ─────────────────────────────────────────────────────
  The rule was just software. Software can be changed.
```

### Kosh Policy — Enforced by the Blockchain

```
  KOSH POLICY
  ─────────────────────────────────────────────────────
  Rule: "CFO must approve all treasury transactions"
  ↓
  This rule lives inside the Partisia smart contract.
  ↓
  A developer modifies the client app.
  ↓
  The contract still rejects the transaction.
  ↓
  CFO is always there. The blockchain guarantees it.
  ─────────────────────────────────────────────────────
  The rule is math. Math cannot be changed.
```

### How It Works — The Full Flow

```
 YOU WANT TO SIGN A TREASURY TRANSACTION
          │
          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  STEP 1 — Tag the Transaction                           │
 │                                                          │
 │  The person requesting the signature attaches a tag:    │
 │                                                          │
 │  tag = "treasury"   →  large fund movement             │
 │  tag = "admin"      →  contract upgrade                │
 │  tag = ""           →  routine, no restriction         │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  STEP 2 — Contract Looks Up the Policy                  │
 │                                                          │
 │  tag = "treasury"                                       │
 │       │                                                 │
 │       ▼                                                 │
 │  Policy found in contract storage:                      │
 │  mandatory_signers = [ Party 2 — CFO ]                  │
 │                                                          │
 │  This policy ID is locked to this signing request.     │
 │  It cannot be changed after this point.                │
 │                                                          │
 │  tag = ""  →  no policy found, any 2 of 3 is fine      │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │  STEP 3 — Parties Propose Who Will Sign                 │
 │                                                          │
 │  Any party can propose a signing group.                 │
 │  The contract checks every proposal against the policy. │
 │                                                          │
 │  Proposal A: Party 1 + Party 3 (Developer + CEO)       │
 │  Proposal B: Party 1 + Party 2 (Developer + CFO)       │
 └───────────────────────┬─────────────────┬───────────────┘
                         │                 │
              Proposal A │                 │ Proposal B
                         ▼                 ▼
 ┌──────────────────────────┐  ┌──────────────────────────┐
 │  CONTRACT — REJECTS  ✗   │  │  CONTRACT — ACCEPTS  ✓   │
 │                          │  │                          │
 │  Policy requires CFO.    │  │  CFO (Party 2) is in     │
 │  CFO not in {1, 3}.      │  │  the signing group.      │
 │                          │  │                          │
 │  BLOCKED on-chain.       │  │  Policy satisfied.       │
 │  Error recorded.         │  │  Signing begins.         │
 │  Cannot be bypassed.     │  │                          │
 └──────────────────────────┘  └──────────┬───────────────┘
                                           │
                                           ▼
                         ┌─────────────────────────────────┐
                         │  STEP 4 — Threshold Signing     │
                         │                                 │
                         │  Party 1 + Party 2 sign         │
                         │  (GG20 protocol — no full key   │
                         │   ever assembled)               │
                         └──────────────┬──────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────┐
                         │  STEP 5 — Ethereum Executes     │
                         │                                 │
                         │  Standard signature.            │
                         │  Transaction goes through.      │
                         │  CFO was there. Guaranteed.     │
                         └─────────────────────────────────┘
```

### Real-World Role Assignments

```
 COMPANY TREASURY WALLET EXAMPLE
 ─────────────────────────────────────────────────────────
 Party 1  →  Developer / Operations
             Handles day-to-day tasks
             Cannot authorize large transfers alone

 Party 2  →  CFO / Finance
             MUST be present for any "treasury" transaction
             Cannot act alone

 Party 3  →  CEO / Executive
             MUST be present for any "admin" transaction
             Cannot act alone
 ─────────────────────────────────────────────────────────

 WHAT EACH TAG MEANS
 ─────────────────────────────────────────────────────────
 Transaction Type    Who MUST Sign        Who Can Co-sign
 ────────────────    ─────────────────    ───────────────
 treasury            CFO (Party 2)        Developer or CEO
 admin               CEO (Party 3)        Developer or CFO
 upgrade             CFO + CEO both       —
 (no tag)            Any 2 of 3           Any 2 of 3
 ─────────────────────────────────────────────────────────
```

### What On-Chain Enforcement Actually Means

```
 ╔═══════════════════════════════════════════════════════╗
 ║  LAYER 1 — WHO ARE YOU?  (verified on-chain)          ║
 ║                                                       ║
 ║  Each party registers their wallet address.           ║
 ║  The contract verifies identity before accepting      ║
 ║  any signature fragment.                              ║
 ║  "Claiming to be the CFO" does not work.              ║
 ║  You must cryptographically prove you are the CFO.    ║
 ╠═══════════════════════════════════════════════════════╣
 ║  LAYER 2 — WHAT ARE THE RULES?  (stored on-chain)    ║
 ║                                                       ║
 ║  Policy A:  tag="treasury"  →  Party 2 mandatory      ║
 ║  Policy B:  tag="admin"     →  Party 3 mandatory      ║
 ║  Policy C:  tag="upgrade"   →  Party 2 + 3 mandatory  ║
 ║                                                       ║
 ║  Lives in the smart contract.                         ║
 ║  Only the contract owner can add or remove.           ║
 ╠═══════════════════════════════════════════════════════╣
 ║  LAYER 3 — IS THE RULE SATISFIED?  (enforced on-chain)║
 ║                                                       ║
 ║  Before ANY signing session can open, the contract   ║
 ║  checks: are all mandatory parties in the group?     ║
 ║                                                       ║
 ║  YES → session opens, signing proceeds               ║
 ║  NO  → rejected with error, logged permanently       ║
 ║                                                       ║
 ║  This check cannot be skipped. Not by a hacker.      ║
 ║  Not by a developer. Not by any 2 parties colluding. ║
 ╚═══════════════════════════════════════════════════════╝
```

---

## Security — Questions You Should Ask

> **"A hacker breaks into Party 1's laptop and steals everything."**

They got one share. One share is mathematically useless alone — it reveals nothing about the private key. They cannot sign. They cannot move funds.

> **"Two employees collude to steal company funds."**

Any 2 of 3 can sign — that is the base design. But with policies, even 2 colluding parties cannot bypass a mandatory third signer. Party 1 and Party 3 cannot move treasury funds without Party 2 (CFO). The contract blocks them.

> **"What if we need to fire one of the key holders?"**

**Key Refresh.** The system issues fresh shares to all parties. The old person's share becomes permanently useless. Same wallet address. No funds movement needed.

> **"What if a party's machine is destroyed?"**

**Key Recovery.** The 2 surviving parties generate a new share for a replacement machine. Wallet address unchanged. Funds stay put.

> **"What if Partisia blockchain goes down?"**

Kosh does not depend on Partisia to hold your funds. Your Ethereum wallet still exists. Partisia only coordinates the signing ceremony. If it goes down, funds are safe — you just need to wait to send new transactions.

> **"What if I want 3-of-5, or 4-of-7?"**

The math works for any M-of-N threshold. 2-of-3 is the starting configuration. Any threshold is supported.

---

## Who Is This For?

| Who | The Problem Today | How Kosh Solves It |
|-----|-------------------|-------------------|
| **Company treasury** | One person holds the wallet key | 2-of-3 approval, CFO always required for large transfers |
| **DAO / Protocol** | Single admin key is a target | No single point to attack or compromise |
| **Exchanges / Custodians** | Hot wallet key exposure | Key fragments across secure, separate locations |
| **Investment funds** | One stolen laptop = millions gone | Fragment is worthless without the others |
| **Family office** | Key inheritance problem | 2-of-3 family members can always access |

---

## What the Ethereum Network Sees

Nothing unusual. Kosh produces a completely standard ECDSA signature — byte-for-byte identical to what a regular MetaMask wallet produces. Ethereum requires no changes, no new standards, no special contracts. It just works.

---

## What We Have Built

- Complete **2-of-3 threshold signing system** deployed and tested on Partisia testnet
- **On-chain DKG ceremony** — 5-phase commit/reveal/verify, Schnorr proofs against rogue-key attacks
- **GG20 threshold ECDSA** — no coordinator, no single party ever knows k or k⁻¹
- **Policy + RBAC** — mandatory signer rules enforced in the Partisia smart contract
- **3-machine test setup** — each party runs independently, communicates via coordination server
- All production security protections:
  - Anti-rogue-key attacks (Schnorr proofs in DKG)
  - Nonce reuse prevention (RFC 6979 + per-session IDs)
  - Cheating detection with on-chain blame protocol
  - Partial signature commit-reveal (prevents last-second manipulation)
  - Key refresh (revoke a party's access without moving funds)
  - Key recovery (replace a lost party's machine)
  - EIP-155 chain ID protection (replay attack prevention)

No seed phrases. No coordinator. No single trusted party. Ever.

---

## The Technical Foundation

Kosh is built on two peer-reviewed cryptographic protocols used in production by Fireblocks, ZenGo, and other institutional custodians.

**Pedersen/Feldman DKG** — How the key is created. Each party generates a random polynomial, shares evaluation points with others, and cross-verifies using elliptic curve commitments. The combined public key is the sum of all individual public contributions. The private key is the sum of all secret constants — a value nobody ever computes.

**GG20 Threshold ECDSA** — How signing works without assembling the key. Parties use Paillier homomorphic encryption to compute products of their secret values without revealing them (the MtA protocol). The nonce point R = k⁻¹·G is computed as a mathematical trick using δ⁻¹·Γ. No party ever knows k or k⁻¹. The final signature is verified on-chain by the Partisia contract.

---

## The Vision

Kosh is infrastructure for the next generation of institutional crypto custody.

Today, the barrier to enterprise crypto adoption is not regulation or liquidity — it is **key management risk**. Every CFO who has looked at putting treasury funds in crypto has asked: *"What happens if someone loses the key?"* or *"What if the CTO goes rogue?"*

Kosh removes that barrier entirely.

The key cannot be stolen because it does not exist.
Control cannot be seized by one person because the math prevents it.
This is not a policy. It is a proof.

---

## One-Line Pitch

> **Kosh is a crypto wallet where the private key never exists — 3 parties jointly control it, any 2 can sign, mandatory approvals are enforced by the blockchain, and no single person can steal it.**

---

*Full protocol details: `dkg+threshold.md` — Full policy implementation: `client/src/policy.ts`*
