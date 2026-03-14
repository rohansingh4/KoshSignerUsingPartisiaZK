# Kosh ZK Signer — Never-Assemble Private Key

A decentralized key management and signing system on **Partisia Blockchain** where the **private key never exists** — not at creation, not at signing, not ever.

Uses **Distributed Key Generation (DKG)** + **GG20 Threshold ECDSA** so 3 parties each hold a random piece, and they produce valid Ethereum signatures **without any party ever knowing the full key**.

---

## Table of Contents

- [The Problem](#the-problem)
- [Architecture Overview](#architecture-overview)
- [Phase 1: DKG — Key Born Already Split](#phase-1-dkg--key-born-already-split)
- [Phase 2: GG20 Threshold Signing](#phase-2-gg20-threshold-signing)
- [How Paillier Encryption Makes It Work](#how-paillier-encryption-makes-it-work)
- [Why Random Sums Always Make Valid Keys](#why-random-sums-always-make-valid-keys)
- [Shamir vs GG20 — What Changed](#shamir-vs-gg20--what-changed)
- [Live Testnet Transactions](#live-testnet-transactions)
- [Contract Actions Reference](#contract-actions-reference)
- [Project Structure](#project-structure)
- [How to Run](#how-to-run)
- [Security Analysis](#security-analysis)

---

## Every Variable Explained — The Complete Glossary

Before diving into the protocol, here's **every symbol** you'll see and what it actually is:

### The Curve and Constants

| Symbol | What It Is | Plain English |
|--------|-----------|---------------|
| **secp256k1** | The elliptic curve | A specific mathematical curve used by Bitcoin and Ethereum. It's the "playing field" where all the math happens. |
| **G** | Generator point | A fixed, publicly known point on the curve. Everyone uses the same G. Think of it as the "starting point" — you multiply it by a number to get a new point. |
| **n** | Curve order | How many valid points exist on the curve. n ≈ 2²⁵⁶ ≈ 10⁷⁷. All arithmetic is done "mod n" (wraps around like a clock with n hours). |
| **× G** | Point multiplication | "Multiply a number by the generator point" = slide along the curve that many times. Easy to compute forward (number → point), impossible to reverse (point → number). This is the "trapdoor" that makes crypto work. |

### Private Key Pieces (Secret — nobody should see these)

| Symbol | What It Is | Who Has It | Plain English |
|--------|-----------|------------|---------------|
| **s** | The "full" private key | **NOBODY** — it never exists! | s = s₁ + s₂ + s₃ mod n. This sum is never computed. It's a ghost — mathematically real but never materialized. |
| **s₁** | Party 1's secret share | Only Party 1 | A random 256-bit number that Party 1 picked. Stored encrypted on ZK nodes. |
| **s₂** | Party 2's secret share | Only Party 2 | A random 256-bit number that Party 2 picked. Stored encrypted on ZK nodes. |
| **s₃** | Party 3's secret share | Only Party 3 | A random 256-bit number that Party 3 picked. Stored encrypted on ZK nodes. |

### Public Key Pieces (Public — everyone can see these)

| Symbol | What It Is | Plain English |
|--------|-----------|---------------|
| **P** | Combined public key | The Ethereum wallet address is derived from this. P = P₁ + P₂ + P₃. Stored on the contract. |
| **P₁** | Party 1's public key share | P₁ = s₁ × G. Party 1's secret, multiplied by G, gives this point. You can see P₁ but cannot figure out s₁ from it. |
| **P₂** | Party 2's public key share | P₂ = s₂ × G. Same idea. |
| **P₃** | Party 3's public key share | P₃ = s₃ × G. Same idea. |

### Signing Variables (The Nonce) — Born Split, Just Like the Private Key

**k = k₁ + k₂ + k₃** — each party picks their own kᵢ. The sum k is **NEVER computed** by anyone. Same idea as the private key s = s₁+s₂+s₃.

The rule "never reuse k" means: don't use the same k for **two different messages**. Each new message gets fresh k₁, k₂, k₃.

```
  Signing message A:  k₁=random, k₂=random, k₃=random  →  k = k₁+k₂+k₃ (never computed)
  Signing message B:  k₁=NEW,    k₂=NEW,    k₃=NEW     →  different k (never computed)
  Reuse same k₁,k₂,k₃ for message B?  ← DANGER! Private key leaks!
```

| Symbol | What It Is | Who Has It | Same or Different per party? | Plain English |
|--------|-----------|------------|-----|---------------|
| **k** | The full nonce | **NOBODY** — never computed! | Ghost value (like s) | k = k₁+k₂+k₃. This sum is NEVER computed by any machine. It's a ghost — mathematically real but never materialized. Just like the private key s. |
| **k₁** | Party 1's nonce share | Only Party 1 | **DIFFERENT** — each party picks their own | A random number Party 1 generates using HMAC-DRBG seeded with their secret s₁. Nobody else knows k₁. |
| **k₂** | Party 2's nonce share | Only Party 2 | **DIFFERENT** | Same idea, Party 2's own random nonce share. |
| **k₃** | Party 3's nonce share | Only Party 3 | **DIFFERENT** | Same idea, Party 3's own random nonce share. |
| **k⁻¹** | Modular inverse of k | **NOBODY** — never computed as a number | Ghost value | k⁻¹ is never computed explicitly. Instead, the contract computes R = δ⁻¹ × Γ = (k×γ)⁻¹ × (γ×G) = k⁻¹×G. The POINT k⁻¹×G is known, but the NUMBER k⁻¹ never exists. |
| **R** | Nonce point | Computed on-chain | **SAME** — one R per signature | R = k⁻¹ × G (computed as δ⁻¹ × Γ). A point on the curve. Its x-coordinate becomes part of the signature. |
| **r** | x-coordinate of R | Public (part of signature) | **SAME** — one r per signature | r = R.x mod n. This is one half of the final ECDSA signature (r, s). |

### Signing Variables (Gamma) — DIFFERENT per party

**These ARE different per party.** Each party picks their OWN random γᵢ. The gammas are used to mask k so that δ = k×γ can be safely revealed.

| Symbol | What It Is | Who Has It | Same or Different per party? | Plain English |
|--------|-----------|------------|-----|---------------|
| **γ₁** | Party 1's gamma secret | Only Party 1 | **DIFFERENT** — each party has their own | A random masking number Party 1 picks. Used in MtA to compute shares of k×γ without revealing k. |
| **γ₂** | Party 2's gamma secret | Only Party 2 | **DIFFERENT** | Same idea, Party 2's own random masking number. |
| **γ₃** | Party 3's gamma secret | Only Party 3 | **DIFFERENT** | Same idea, Party 3's own random masking number. |
| **Γ₁** | Party 1's gamma point | Public (sent to contract) | **DIFFERENT** | Γ₁ = γ₁ × G. The public version of Party 1's gamma. Sent to the contract. |
| **Γ₂** | Party 2's gamma point | Public | **DIFFERENT** | Γ₂ = γ₂ × G |
| **Γ₃** | Party 3's gamma point | Public | **DIFFERENT** | Γ₃ = γ₃ × G |
| **Γ** | Combined gamma point | Computed on-chain | **SAME** — one Γ per signature | Γ = Γ₁ + Γ₂ + Γ₃. Contract adds all gamma points together. |
| **δᵢ** | Party i's delta share | Only Party i | **DIFFERENT** | δᵢ = kᵢ×γᵢ + Σ(MtA cross-terms from other pairs). Each party computes their own using Paillier MtA results. |
| **δ** | Combined k×γ value | Computed on-chain from δ₁+δ₂+δ₃ | **SAME** — one δ per signature | δ = δ₁+δ₂+δ₃ = k×γ. Safe to reveal because γ masks k (knowing k×γ doesn't tell you k). Used to compute R = δ⁻¹ × Γ = k⁻¹×G. |
| **σᵢ** | Party i's share of k×s | Only Party i | **DIFFERENT** | σᵢ = kᵢ×sᵢ + Σ(MtA cross-terms). Used in partial signature computation. Never revealed. |

### Quick Reference: What's Same vs Different

```
    GHOST VALUES (never computed)            PER PARTY (different for each)
    ─────────────────────────────           ──────────────────────────────
    s    ← private key (s₁+s₂+s₃)          s₁, s₂, s₃  ← each party's key share
    k    ← nonce (k₁+k₂+k₃)               k₁, k₂, k₃  ← each party's nonce share
    k⁻¹  ← never exists as number           γ₁, γ₂, γ₃  ← each party's gamma
                                            Γ₁, Γ₂, Γ₃  ← each party's gamma point
    PER SIGNATURE (computed on-chain)        δ₁, δ₂, δ₃  ← each party's delta share
    ─────────────────────────────           σᵢ            ← each party's k×s share
    R    ← nonce point (δ⁻¹ × Γ)           sᵢ            ← each party's partial sig
    r    ← x-coordinate of R               P₁, P₂, P₃  ← each party's public share
    δ    ← k×γ (from δ₁+δ₂+δ₃)
    Γ    ← γ×G (from Γ₁+Γ₂+Γ₃)
    P    ← combined public key
    s    ← combined final signature
```

### Signing Variables (Partial Signatures)

| Symbol | What It Is | Who Has It | Plain English |
|--------|-----------|------------|---------------|
| **z** | Message hash | Everyone | The SHA-256 hash of the message being signed (e.g., an Ethereum transaction). 32 bytes. |
| **σ₁** | Party 1's partial signature | Party 1 computes, sends to contract | σ₁ = k⁻¹ × (z/3 + r × s₁) mod n. Party 1's "piece" of the signature, using only their secret s₁. |
| **σ₂** | Party 2's partial signature | Party 2 computes, sends to contract | σ₂ = k⁻¹ × (z/3 + r × s₂) mod n |
| **σ₃** | Party 3's partial signature | Party 3 computes, sends to contract | σ₃ = k⁻¹ × (z/3 + r × s₃) mod n |
| **σ** | Final combined signature | Computed on-chain | σ = σ₁ + σ₂ + σ₃ mod n. This is the valid ECDSA signature! |
| **(r, σ)** | The complete signature | Stored on-chain | Standard ECDSA signature. r comes from the nonce point R, σ from combining partial signatures. Ethereum can verify this against public key P. |

### Commitment Variables (Anti-Cheating)

| Symbol | What It Is | Plain English |
|--------|-----------|---------------|
| **C₁, C₂, C₃** | DKG commitments | Cᵢ = SHA-256(Pᵢ). Hash of each party's public key share, submitted BEFORE revealing Pᵢ. Prevents changing your mind after seeing others. |
| **SHA-256(δᵢ)** | Delta commitment | Hash of each party's δᵢ, committed before revealing. Prevents a party from changing their δᵢ after seeing others' values. |

### Why Reusing k Leaks the Private Key (The Math)

```
    Suppose you sign TWO messages with the SAME k:

    Message A (hash = z₁):   σ₁ = k⁻¹ × (z₁ + r × s)
    Message B (hash = z₂):   σ₂ = k⁻¹ × (z₂ + r × s)

    An attacker sees both signatures (σ₁, σ₂) and both hashes (z₁, z₂).
    Same k means same r (since R = k×G is the same).

    Subtract:  σ₁ - σ₂ = k⁻¹ × (z₁ - z₂)
    Solve:     k⁻¹ = (σ₁ - σ₂) / (z₁ - z₂)      ← attacker now has k⁻¹
               k = (z₁ - z₂) / (σ₁ - σ₂)          ← attacker now has k

    From either signature:
               s = (σ₁ × k - z₁) / r               ← PRIVATE KEY LEAKED!

    This is why k MUST be fresh for every signature.
    This is a real attack — it's how the PS3 was hacked (Sony reused k).
```

### Distributed Nonce & MtA Variables (IMPLEMENTED)

These are all implemented in `paillier.ts`, `mta.ts`, and `gg20-signing.ts`.

| Symbol | What It Is | Plain English |
|--------|-----------|---------------|
| **k₁, k₂, k₃** | Distributed nonce shares | Nobody has the full nonce k. Each party picks kᵢ independently, and k = k₁ + k₂ + k₃. Same idea as the private key — the nonce is also "born split." Each kᵢ is generated using HMAC-DRBG seeded with the party's secret sᵢ. |
| **Enc(x)** | Paillier encryption | Homomorphic encryption: you can do math on encrypted numbers without decrypting them. Each party generates 1024-bit Paillier keys. Used to compute cross-terms like k₁ × γ₂ without either party revealing their secret. |
| **α, β** | MtA output shares | After the MtA protocol, Party 1 has α and Party 2 has β, where α + β = k₁ × γ₂. Neither party learns the cross-term alone. 12 MtA exchanges run for 3 parties (each pair does 2: one for k×γ, one for k×s). |
| **δᵢ** | Party i's share of k×γ | δᵢ = kᵢ×γᵢ + Σ(MtA cross-terms). When all δᵢ are summed: δ = k×γ. This is safe to reveal because γ masks k. |
| **σᵢ** | Party i's share of k×s | σᵢ = kᵢ×sᵢ + Σ(MtA cross-terms). Kept secret — used in partial signature computation. |

---

## Visual Guide — How Variables Flow Through the System

### Graph 1: DKG — How the Public Key is Born

```
    Party 1                    Party 2                    Party 3
    ────────                   ────────                   ────────
    picks random s₁            picks random s₂            picks random s₃
    (256-bit number)           (256-bit number)           (256-bit number)
         │                          │                          │
         │  s₁ × G                  │  s₂ × G                 │  s₃ × G
         │  (multiply by            │  (multiply by            │  (multiply by
         │   generator point)       │   generator point)       │   generator point)
         ▼                          ▼                          ▼
        P₁                         P₂                         P₃
    (a point on                (a point on                (a point on
     the curve)                 the curve)                 the curve)
         │                          │                          │
         │  SHA-256(P₁)             │  SHA-256(P₂)             │  SHA-256(P₃)
         ▼                          ▼                          ▼
    ┌─── C₁ ──────────────────── C₂ ──────────────────── C₃ ───┐
    │              PARTISIA CONTRACT — Commit Phase              │
    │   Stores all 3 commitments. Nobody can change their mind.  │
    └────────────────────────────────────────────────────────────┘
         │                          │                          │
         │  reveal P₁               │  reveal P₂               │  reveal P₃
         ▼                          ▼                          ▼
    ┌─── P₁ ──────────────────── P₂ ──────────────────── P₃ ───┐
    │              PARTISIA CONTRACT — Reveal Phase               │
    │   Checks: SHA-256(P₁)==C₁?  SHA-256(P₂)==C₂?  SHA-256(P₃)==C₃?  │
    │   All match ✓                                               │
    └─────────────────────────┬──────────────────────────────────┘
                              │
                              │  EC Point Addition
                              │  P = P₁ + P₂ + P₃
                              ▼
                    ┌───────────────────┐
                    │  Combined Public  │
                    │  Key P is stored  │
                    │  on-chain         │
                    │                   │
                    │  This is your     │
                    │  Ethereum wallet  │
                    │  address!         │
                    └───────────────────┘

    Meanwhile, the private key s = s₁ + s₂ + s₃ is NEVER computed.
    Nobody knows it. Nobody CAN know it. It's a mathematical ghost.
```

### Graph 2: Signing — How a Signature is Built Without the Key

```
    ┌─────────────────────────────────────────────────────────────────┐
    │  INPUT: Message hash z (e.g., hash of "send 0.1 ETH to Bob")  │
    └───────────────────────────────┬─────────────────────────────────┘
                                    │
    ════════════════════════════════════════════════════════════════════
    ROUND 1: BUILD THE NONCE R (without anyone knowing k)
    ════════════════════════════════════════════════════════════════════

    Party 1              Party 2              Party 3
    ────────             ────────             ────────
    picks k₁, γ₁        picks k₂, γ₂        picks k₃, γ₃
    (random each)        (random each)        (random each)
        │                    │                    │
        │ γ₁ × G             │ γ₂ × G             │ γ₃ × G
        ▼                    ▼                    ▼
       Γ₁                   Γ₂                   Γ₃
        │                    │                    │
        │    ┌───── MtA ROUNDS (Paillier encrypted) ─────┐
        │    │ For each pair (i,j): compute shares of     │
        │    │   kᵢ×γⱼ → αᵢⱼ + βᵢⱼ                      │
        │    │   kᵢ×sⱼ → μᵢⱼ + νᵢⱼ                      │
        │    │ 12 exchanges total (3 pairs × 2 products)  │
        │    └────────────────────────────────────────────┘
        │                    │                    │
        │  δ₁ = k₁γ₁+Σ     │  δ₂ = k₂γ₂+Σ     │  δ₃ = k₃γ₃+Σ
        │  (share of k×γ)   │  (share of k×γ)   │  (share of k×γ)
        ▼                    ▼                    ▼
        ┌───────────────────────────────────────────────────────┐
        │  CONTRACT collects δ₁, δ₂, δ₃ and Γ₁, Γ₂, Γ₃       │
        │                                                       │
        │  Computes:                                            │
        │     δ = δ₁ + δ₂ + δ₃ = k×γ                           │
        │     Γ = Γ₁ + Γ₂ + Γ₃ = γ×G                           │
        │     R = δ⁻¹ × Γ                                      │
        │       = (k×γ)⁻¹ × (γ×G)                              │
        │       = k⁻¹ × γ⁻¹ × γ × G                            │
        │       = k⁻¹ × G              ← γ cancels out!        │
        │                                                       │
        │     r = R.x mod n             ← x-coordinate of R    │
        └──────────┬───────────────────────────────────────────────────
                   │
    ════════════════════════════════════════════════════════════════════
    ROUND 2: COMPUTE PARTIAL SIGNATURES
    ════════════════════════════════════════════════════════════════════
                   │
                   │  k⁻¹ distributed to all parties
                   │
    Party 1              Party 2              Party 3
    ────────             ────────             ────────
    has: s₁, k⁻¹, r, z  has: s₂, k⁻¹, r, z  has: s₃, k⁻¹, r, z
        │                    │                    │
        │ σ₁ = k⁻¹ ×        │ σ₂ = k⁻¹ ×        │ σ₃ = k⁻¹ ×
        │  (z/3 + r×s₁)     │  (z/3 + r×s₂)     │  (z/3 + r×s₃)
        ▼                    ▼                    ▼
       σ₁                   σ₂                   σ₃
    (partial sig)        (partial sig)        (partial sig)
        │                    │                    │
        └──────────┬─────────┘                    │
                   │                              │
        ┌──────────▼──────────────────────────────▼───────┐
        │  CONTRACT combines:                             │
        │     σ = σ₁ + σ₂ + σ₃  mod n                    │
        │                                                 │
        │  Why this works:                                │
        │     σ = k⁻¹(z/3 + r×s₁) + k⁻¹(z/3 + r×s₂)    │
        │       + k⁻¹(z/3 + r×s₃)                        │
        │     = k⁻¹(z/3 + z/3 + z/3 + r×s₁ + r×s₂ + r×s₃) │
        │     = k⁻¹(z + r×(s₁+s₂+s₃))                   │
        │     = k⁻¹(z + r×s)        ← standard ECDSA!    │
        │                                                 │
        │  Low-s normalization:                           │
        │     if σ > n/2: σ = n − σ  (EIP-2 / BIP-62)    │
        │                                                 │
        │  ECDSA verify(P, z, r, σ) → ✓ VALID!           │
        └──────────┬──────────────────────────────────────┘
                   │
                   ▼
        ┌─────────────────────────────────────────────────┐
        │  SIGNATURE (r, σ) stored on-chain               │
        │  → Can be used to send Ethereum transactions    │
        │  → Verified by any EVM chain                    │
        │  → The key s=s₁+s₂+s₃ was NEVER computed       │
        └─────────────────────────────────────────────────┘
```

### Graph 3: Why the Gammas Cancel Out (The Clever Trick)

```
    The problem: We need R = k⁻¹ × G, but NOBODY knows k or k⁻¹.

    The solution: Use MtA to compute δ = k×γ without revealing k or γ.
                  Then R = δ⁻¹ × Γ = (k×γ)⁻¹ × (γ×G) = k⁻¹×G.

                    k = k₁ + k₂ + k₃       (nobody knows the sum)
                    γ = γ₁ + γ₂ + γ₃       (nobody knows the sum)
                         │         │
                         ▼         ▼
                    MtA computes shares of k×γ
                    without revealing k or γ

    The math:

        δ = k × γ              ← computed via MtA, safe to reveal
        Γ = γ × G              ← computed from public Γᵢ points

        R = δ⁻¹ × Γ
          = (k×γ)⁻¹ × (γ×G)   ← substitute
          = k⁻¹ × γ⁻¹ × γ × G ← inverse distributes
          = k⁻¹ × G            ← γ cancels out!

    Nobody computed k, k⁻¹, or γ as full values.
    Only additive shares (from MtA) were ever known by any party.
```

### Graph 4: The "Ghost Key" — Why s Never Needs to Exist

```
    ECDSA needs: σ = k⁻¹ × (z + r × s)

    We need s in the equation... but we HAVE s₁, s₂, s₃ where s = s₁+s₂+s₃

    Watch the algebra:

    σ = k⁻¹ × (z + r × s)
      = k⁻¹ × (z + r × (s₁ + s₂ + s₃))               ← substitute s
      = k⁻¹ × (z + r×s₁ + r×s₂ + r×s₃)               ← distribute r
      = k⁻¹×z + k⁻¹×r×s₁ + k⁻¹×r×s₂ + k⁻¹×r×s₃     ← distribute k⁻¹

    Split z equally: z = z/3 + z/3 + z/3

      = k⁻¹×(z/3 + r×s₁) + k⁻¹×(z/3 + r×s₂) + k⁻¹×(z/3 + r×s₃)
        ────────────────     ────────────────     ────────────────
              σ₁                    σ₂                   σ₃

    Each σᵢ can be computed by Party i using ONLY:
      - k⁻¹  (distributed to everyone)
      - z     (the message hash, public)
      - r     (from the nonce point, public)
      - sᵢ   (their OWN secret — they already have this)

    Party 1 never sees s₂ or s₃
    Party 2 never sees s₁ or s₃
    Party 3 never sees s₁ or s₂

    Yet σ₁ + σ₂ + σ₃ = k⁻¹(z + r×s)  ← perfect ECDSA signature!

    The value s = s₁+s₂+s₃ appears in the final equation
    but was never computed by any machine.
    It's a GHOST KEY — real in math, nonexistent in reality.
```

### Graph 5: Full Transaction Flow — Bird's Eye View

```
    ┌─────────────────────────────────────────────────────────────────┐
    │                        DKG PHASE                                │
    │                   (12 transactions)                             │
    │                                                                 │
    │  Tx 1:  Create key slot ──────────────────────────► Key #1      │
    │                                                     exists      │
    │  Tx 2:  Party 1 commits SHA-256(P₁) ──┐                        │
    │  Tx 3:  Party 2 commits SHA-256(P₂) ──┼── Nobody can          │
    │  Tx 4:  Party 3 commits SHA-256(P₃) ──┘   change their mind   │
    │                                                                 │
    │  Tx 5:  Party 1 reveals P₁ ──┐                                 │
    │  Tx 6:  Party 2 reveals P₂ ──┼── Contract checks each         │
    │  Tx 7:  Party 3 reveals P₃ ──┘   hash matches commitment      │
    │                                                                 │
    │  Tx 8:  Finalize ── P = P₁ + P₂ + P₃ ── public key on-chain  │
    │                                                                 │
    │  Tx 9:  Party 1 stores s₁ on ZK nodes (encrypted) ──┐         │
    │  Tx 10: Party 2 stores s₂ on ZK nodes (encrypted) ──┼── Safe  │
    │  Tx 11: Party 3 stores s₃ on ZK nodes (encrypted) ──┘         │
    │                                                                 │
    │  Tx 12: Complete keygen ── ready for signing ✓                  │
    └────────────────────────────────┬────────────────────────────────┘
                                     │
                                     ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │                       SIGNING PHASE                             │
    │                   (12 transactions)                             │
    │                                                                 │
    │  Tx 13: Start signing with message hash z                       │
    │                                                                 │
    │  Tx 14: Party 1 sends Γ₁ = γ₁×G ──┐                           │
    │  Tx 15: Party 2 sends Γ₂ = γ₂×G ──┼── Building the nonce      │
    │  Tx 16: Party 3 sends Γ₃ = γ₃×G ──┘   without revealing k     │
    │                                                                 │
    │  Tx 17: Commit SHA-256(δ) ── lock in the correction factor     │
    │  Tx 18: Reveal δ ── contract checks hash matches               │
    │  Tx 19: Finalize nonce ── R = Γ + δ×G, extract r               │
    │                                                                 │
    │  Tx 20: Party 1 sends σ₁ ──┐                                   │
    │  Tx 21: Party 2 sends σ₂ ──┼── Each uses ONLY their own sᵢ    │
    │  Tx 22: Party 3 sends σ₃ ──┘                                   │
    │                                                                 │
    │  Tx 23: Finalize sig ── σ = σ₁+σ₂+σ₃, ECDSA verify ✓          │
    │  Tx 24: Signing complete ── signature stored on-chain           │
    └────────────────────────────────┬────────────────────────────────┘
                                     │
                                     ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │                    ETHEREUM TRANSACTION                         │
    │                                                                 │
    │  Signature (r, σ) from Partisia                                 │
    │       + message (send 0.1 ETH to Bob)                           │
    │       = valid Ethereum transaction                              │
    │                                                                 │
    │  Sepolia Tx: 0x09ec739d...b98d41                                │
    │  Block: 10432151                                                │
    │  Status: ✓ Confirmed                                            │
    │                                                                 │
    │  The Ethereum network verified (r, σ) against P                 │
    │  and accepted the transaction. It has NO IDEA                   │
    │  the private key never existed.                                 │
    └─────────────────────────────────────────────────────────────────┘
```

### Graph 6: What Each Party Knows vs What They'd Need to Steal

```
    ┌─────────────────────────────────────────────────────────────────┐
    │                    KNOWLEDGE MAP                                │
    │                                                                 │
    │              Public          Secret          Would Need         │
    │              (everyone)      (only them)     (to steal key)     │
    │                                                                 │
    │  Party 1:    P, P₁,P₂,P₃    s₁             s₂ AND s₃          │
    │              Γ₁,Γ₂,Γ₃       γ₁                                 │
    │              r, z, k⁻¹      σ₁                                 │
    │                                                                 │
    │  Party 2:    P, P₁,P₂,P₃    s₂             s₁ AND s₃          │
    │              Γ₁,Γ₂,Γ₃       γ₂                                 │
    │              r, z, k⁻¹      σ₂                                 │
    │                                                                 │
    │  Party 3:    P, P₁,P₂,P₃    s₃             s₁ AND s₂          │
    │              Γ₁,Γ₂,Γ₃       γ₃                                 │
    │              r, z, k⁻¹      σ₃                                 │
    │                                                                 │
    │  Contract:   P, all Pᵢ,     nothing        s₁ AND s₂ AND s₃   │
    │              all Γᵢ, δ       (just math)                       │
    │              r, σ, z                                            │
    │                                                                 │
    │  ZK Node 1:  nothing         encrypted       decryption keys   │
    │              useful          fragment of      of other 2 nodes  │
    │                              one share                          │
    │                                                                 │
    │  Attacker:   can see all     nothing         ALL 3 of:         │
    │              public values                   s₁, s₂, s₃        │
    │                                              (from 3 different │
    │                                               ZK nodes)         │
    └─────────────────────────────────────────────────────────────────┘
```

### Graph 7: Shamir (Old) vs GG20 (New) — Side by Side

```
    ═══════════════════════════════════════════════════════════════
    SHAMIR (OLD WAY) — Key exists twice
    ═══════════════════════════════════════════════════════════════

    Step 1: Generate key
    ┌──────────────────┐
    │  s = random()    │ ◄── KEY EXISTS HERE (in RAM)
    │  P = s × G       │     Anyone who hacks this machine NOW
    └────────┬─────────┘     gets everything
             │
    Step 2: Split into shares
             │ Shamir polynomial f(x) where f(0) = s
             ├── share₁ = f(1)
             ├── share₂ = f(2)
             └── share₃ = f(3)
                 │
    Step 3: Store shares on ZK nodes, delete s
                 │
    Step 4: To sign — reconstruct s from any 2 shares
    ┌──────────────────────────────────┐
    │  s = lagrange(share₁, share₂)   │ ◄── KEY EXISTS AGAIN
    │  sig = ECDSA_sign(s, message)    │     (in RAM, vulnerable)
    │  delete s                        │
    └──────────────────────────────────┘


    ═══════════════════════════════════════════════════════════════
    GG20 (NEW WAY) — Key NEVER exists
    ═══════════════════════════════════════════════════════════════

    Step 1: Each party picks random piece
    ┌────────┐  ┌────────┐  ┌────────┐
    │ s₁     │  │ s₂     │  │ s₃     │  ◄── Only pieces exist
    │ random │  │ random │  │ random │     Nobody has s=s₁+s₂+s₃
    └───┬────┘  └───┬────┘  └───┬────┘
        │           │           │
    Step 2: Compute public key from pieces (no private key needed)
        │ ×G        │ ×G        │ ×G
        ▼           ▼           ▼
       P₁    +     P₂    +    P₃    =    P  (combined public key)

    Step 3: Store pieces encrypted on ZK nodes

    Step 4: To sign — each party makes PARTIAL signature
    ┌──────────┐  ┌──────────┐  ┌──────────┐
    │ σ₁ using │  │ σ₂ using │  │ σ₃ using │  ◄── Only partials
    │ only s₁  │  │ only s₂  │  │ only s₃  │     Key NEVER rebuilt
    └────┬─────┘  └────┬─────┘  └────┬─────┘
         │             │             │
         └──────┬──────┘             │
                │                    │
    Contract: σ = σ₁ + σ₂ + σ₃ ◄── Valid ECDSA signature!
              verify(P, z, r, σ) ✓   No key needed!
```

---

## The Problem

**Traditional approach** (Shamir Secret Sharing):
```
Generate full private key  →  Split into shares  →  Store shares  →  Reconstruct to sign
     ↑                                                                      ↑
  KEY EXISTS HERE                                                     KEY EXISTS HERE
  (vulnerable)                                                        (vulnerable)
```

**Our approach** (DKG + GG20):
```
3 parties each pick random number  →  Math combines them into public key  →  Sign without combining
     ↑                                        ↑                                    ↑
  ONLY PIECES EXIST                    ONLY PUBLIC KEY                      ONLY PARTIAL SIGS
  (no full key ever)                   (computed, not derived)              (combined into final sig)
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    DISTRIBUTED KEY GENERATION (DKG)                     │
│              Private key is NEVER created — born already split          │
│                                                                         │
│   Party 1: picks random s₁        Party 2: picks random s₂     Party 3 │
│   Computes P₁ = s₁ × G           Computes P₂ = s₂ × G          ...    │
│        │                               │                                │
│        ├── Commits SHA256(P₁) ────────►│                                │
│        ├── Reveals P₁ ────────────────►│                                │
│        │                               │                                │
│   Contract computes: P = P₁ + P₂ + P₃  (combined public key)           │
│   Each s₁, s₂, s₃ stored as ZK secret — NOBODY has full key            │
│                                                                         │
│   The private key s = s₁ + s₂ + s₃  but this sum is NEVER computed     │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    GG20 THRESHOLD SIGNING                                │
│              Private key is NEVER reconstructed                         │
│                                                                         │
│   Each party picks kᵢ, γᵢ independently (NO coordinator)                │
│   MtA protocol (Paillier) computes shares of k×γ and k×s               │
│   Contract computes R = δ⁻¹ × Γ = k⁻¹×G (nobody knows k⁻¹)            │
│                                                                         │
│   Each party computes: sᵢ = m×kᵢ + r×σᵢ  (using only their shares)     │
│   Contract combines: s = s₁ + s₂ + s₃ mod n                            │
│   Final signature (r, σ) is valid ECDSA — verified on-chain!            │
│                                                                         │
│   No party ever sees s = s₁ + s₂ + s₃                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: DKG — Key Born Already Split

### The Math

The secp256k1 curve has a generator point **G** and order **n** ≈ 2²⁵⁶.

Any integer `s` where `1 ≤ s < n` is a valid private key. The corresponding public key is `P = s × G` (point multiplication on the elliptic curve).

**Key insight**: Elliptic curve point addition is homomorphic:

```
If   s = s₁ + s₂ + s₃  (mod n)
Then P = s × G = (s₁ + s₂ + s₃) × G = s₁×G + s₂×G + s₃×G = P₁ + P₂ + P₃
```

So we can compute the combined public key **P** by adding individual public keys **P₁ + P₂ + P₃**, without ever computing the combined private key **s = s₁ + s₂ + s₃**.

### Step-by-Step DKG Protocol

#### Step 1: Create Key Slot
```
Transaction: dkg_create_key(key_id=1, num_parties=3)
Contract creates an empty key entry and sets phase = Committing
```

#### Step 2: Commit Phase (prevents rogue key attack)

Each party `i` independently:
1. Picks random scalar `sᵢ ∈ [1, n-1]`
2. Computes public key share `Pᵢ = sᵢ × G` (compressed, 33 bytes)
3. Computes commitment `Cᵢ = SHA-256(Pᵢ)`
4. Sends `Cᵢ` to the contract

```
Party 1: C₁ = SHA-256(P₁)  →  dkg_commit(key_id=1, party_index=1, C₁)
Party 2: C₂ = SHA-256(P₂)  →  dkg_commit(key_id=1, party_index=2, C₂)
Party 3: C₃ = SHA-256(P₃)  →  dkg_commit(key_id=1, party_index=3, C₃)
```

**Why commit first?** Without commitments, Party 3 could wait to see P₁ and P₂, then choose s₃ to make the combined key equal any value they want (rogue key attack). The commit forces everyone to lock in their choice before seeing others.

#### Step 3: Reveal Phase

Each party reveals their actual public key share `Pᵢ`:
```
Party 1: dkg_reveal(key_id=1, party_index=1, P₁)  →  Contract checks SHA-256(P₁) == C₁ ✓
Party 2: dkg_reveal(key_id=1, party_index=2, P₂)  →  Contract checks SHA-256(P₂) == C₂ ✓
Party 3: dkg_reveal(key_id=1, party_index=3, P₃)  →  Contract checks SHA-256(P₃) == C₃ ✓
```

If any `SHA-256(Pᵢ) ≠ Cᵢ`, the contract rejects it — the party changed their mind.

#### Step 4: Finalize

```
dkg_finalize(key_id=1)

Contract decompresses P₁, P₂, P₃ as secp256k1 points
Computes: P = P₁ + P₂ + P₃  (EC point addition using k256 crate)
Stores compressed P as the combined public key
Sets phase = WaitingForShares
```

#### Step 5: Store Shares as ZK Secrets

Each party submits their secret scalar `sᵢ` to Partisia's ZK nodes:
```
sᵢ is 256 bits → split into two 128-bit halves (high, low)
Each half encrypted separately for each ZK node
Submitted via: submit_key_share(key_id=1, party_index=i, half)
```

The ZK nodes store these encrypted — no single node sees the full share.

#### Step 6: Complete Keygen

```
dkg_complete_keygen(key_id=1)
Contract marks key as phase = Complete, ready for signing
```

**Result**: A valid secp256k1 keypair exists where:
- Public key `P` is stored on-chain (anyone can see it)
- Private key `s = s₁ + s₂ + s₃` was **NEVER computed by anyone**
- Each `sᵢ` is stored encrypted on ZK nodes

---

## Phase 2: GG20 Threshold Signing

### The ECDSA Signature Equation

A standard ECDSA signature for message hash `z` using private key `s`:

```
Pick random nonce k
R = k × G          (a point on the curve)
r = R.x mod n      (x-coordinate of R)
σ = k⁻¹ × (z + r × s) mod n

Signature = (r, σ)
```

### How GG20 Distributes This

Since `s = s₁ + s₂ + s₃`, we can expand:

```
σ = k⁻¹ × (z + r × s)
  = k⁻¹ × (z + r × (s₁ + s₂ + s₃))
  = k⁻¹ × z  +  k⁻¹ × r × s₁  +  k⁻¹ × r × s₂  +  k⁻¹ × r × s₃
```

Each party `i` computes their partial signature:

```
σᵢ = k⁻¹ × (z/3 + r × sᵢ) mod n

(z is split equally: each party adds z/3 to avoid triple-counting)
```

Then:
```
σ = σ₁ + σ₂ + σ₃ mod n     ← this gives the correct full signature!
```

### Nonce Generation — Fully Distributed (No Coordinator)

The nonce `k` must be random and secret. In our implementation, **nobody ever knows k**:

1. Each party picks random `kᵢ` (using HMAC-DRBG seeded with their secret sᵢ)
2. Each party picks random `γᵢ` (masking value)
3. **MtA rounds** (Paillier encryption): for every pair (i,j), compute additive shares of `kᵢ × γⱼ` and `kᵢ × sⱼ` without revealing either secret
4. Each party computes `δᵢ = kᵢ×γᵢ + Σ(MtA cross-terms)` — their share of `k×γ`
5. Each party computes `σᵢ = kᵢ×sᵢ + Σ(MtA cross-terms)` — their share of `k×s`
6. Contract computes `R = δ⁻¹ × Γ = (k×γ)⁻¹ × (γ×G) = k⁻¹×G`

Nobody computed k, k⁻¹, or k×s. Only additive shares exist.

### The Complete Signing Flow

```
Step 1: gg20_start_signing(key_id, task_id, num_parties)
        → Contract prepares for signing session

Step 2: OFF-CHAIN — Each party generates kᵢ, γᵢ independently
        MtA rounds between all pairs (12 Paillier exchanges for 3 parties)
        Each party now has δᵢ (share of k×γ) and σᵢ (share of k×s)

Step 3: Each party submits δᵢ and Γᵢ = γᵢ × G to contract
        → submit_delta(key_id, party_index, δᵢ)
        → submit_gamma_point(key_id, party_index, Γᵢ)

Step 4: Contract computes R on-chain (gg20_finalize_r):
        δ = δ₁ + δ₂ + δ₃          (sum of delta shares = k×γ)
        Γ = Γ₁ + Γ₂ + Γ₃          (sum of gamma points = γ×G)
        R = δ⁻¹ × Γ               (= (k×γ)⁻¹ × (γ×G) = k⁻¹×G)
        r = R.x mod n              (x-coordinate — part of signature)

Step 5: Each party computes partial signature:
        sᵢ = m × kᵢ + r × σᵢ  mod n
        → commit_partial_sig(hash(sᵢ)), then submit_partial_sig(sᵢ)

Step 6: Contract combines:
        s = s₁ + s₂ + s₃ mod n   (= m×k + r×k×x = k×(m + r×x))
        Applies low-s normalization (EIP-2): if s > n/2, set s = n - s
        Verifies (r, s) against stored public key P
        Stores verified signature on-chain ✓
```

### Low-s Normalization (EIP-2 / BIP-62)

Ethereum and Bitcoin require signatures in "low-s" form to prevent malleability:

```
If σ > n/2:
    σ = n - σ        (flip to the lower half)
    recovery_id ^= 1  (flip recovery bit)
```

Both `(r, σ)` and `(r, n-σ)` are mathematically valid ECDSA signatures, but the blockchain only accepts the one where `σ ≤ n/2`.

---

## How Paillier Encryption Makes It Work

In the production GG20 protocol (not yet implemented here), the **MtA (Multiplicative-to-Additive)** protocol uses Paillier encryption to let parties multiply their secrets without revealing them.

### The Problem MtA Solves

Each party needs to compute `k⁻¹ × sᵢ`, but in the full protocol `k` is also distributed as `k = k₁ + k₂ + k₃`. So nobody has `k⁻¹` directly.

The product `k⁻¹ × s` needs to be split into additive shares, but:
- Party 1 has `k₁` and `s₁`
- Party 2 has `k₂` and `s₂`
- `k₁ × s₂` requires both parties to interact without revealing their secrets

### How Paillier Solves It

Paillier encryption is **additively homomorphic**:

```
Enc(a) × Enc(b) = Enc(a + b)        (add encrypted values without decrypting)
Enc(a)^b = Enc(a × b)                (multiply by a known value without decrypting)
```

**MtA protocol between Party 1 and Party 2**:

```
Party 1 encrypts k₁:           c = Enc(k₁)
Party 1 sends c to Party 2

Party 2 computes:               c' = c^s₂ × Enc(β)  =  Enc(k₁ × s₂ + β)
                                where β is random
Party 2 sends c' back to Party 1

Party 1 decrypts:               α = Dec(c') = k₁ × s₂ + β

Result:
  Party 1 has: α = k₁ × s₂ + β
  Party 2 has: β

  α - β = k₁ × s₂   ← the cross-term, additively shared!
```

Our implementation uses the full MtA protocol: each party picks kᵢ independently, Paillier encryption computes the cross-terms, and nobody ever knows the full k or k⁻¹.

---

## Why Random Sums Always Make Valid Keys

### The Math

The secp256k1 private key space is `{1, 2, ..., n-1}` where `n` is the curve order:

```
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  ≈ 1.158 × 10⁷⁷
```

When 3 parties pick random `s₁, s₂, s₃ ∈ [1, n-1]`, the sum is:

```
s = (s₁ + s₂ + s₃) mod n
```

**Why is `s` always valid?**

1. **Modular arithmetic wraps around**: `s₁ + s₂ + s₃` might exceed `n`, but `mod n` brings it back to `[0, n-1]`
2. **The only invalid value is 0**: `s = 0` would mean `s₁ + s₂ + s₃ ≡ 0 (mod n)`, which means `s₃ = n - s₁ - s₂`. The probability of randomly hitting this exact value is `1/n ≈ 1/10⁷⁷` — essentially impossible
3. **Every non-zero value works**: For any `s ∈ [1, n-1]`, there exists a valid public key `P = s × G` on the curve

So: pick any 3 random numbers, add them mod n, and you get a valid private key with probability `1 - 10⁻⁷⁷`.

### Analogy

Think of a clock with `n` hours (where `n` is astronomically large). Each party picks a random position. The sum wraps around the clock. The only "bad" position is exactly `0` — but with `10⁷⁷` positions, you'll never land there by chance.

---

## Shamir vs GG20 — What Changed

| Aspect | Shamir (Old) | GG20 (New) |
|--------|-------------|------------|
| **Key creation** | Full key generated on client, then split | Key born split — 3 random pieces, never combined |
| **Key exists?** | Yes, briefly in RAM during creation and signing | **Never** — not even for a nanosecond |
| **Signing** | Reconstruct full key from 2 shares, sign locally | Each party makes partial signature, contract combines |
| **Vulnerability** | Attacker can grab key during reconstruction | No reconstruction — nothing to grab |
| **On-chain verification** | Client sends complete signature | Contract builds signature from partials |
| **Transactions** | ~10 (create, post PK, 6 shares, sign, verify) | ~24 (DKG commit/reveal/finalize + signing rounds) |
| **Complexity** | Simple polynomial math | EC point addition, Paillier encryption, MtA |
| **EVM compatible?** | Yes (standard ECDSA) | Yes (produces identical ECDSA signatures) |

---

## Live Testnet Transactions

**Contract**: [`03d6cbcafc3d4784b6f34356b3b3ec94f2f25e8ee9`](https://browser.testnet.partisiablockchain.com/contracts/03d6cbcafc3d4784b6f34356b3b3ec94f2f25e8ee9)

All transactions viewable at: `https://browser.testnet.partisiablockchain.com/transactions/<HASH>`

### DKG Phase — Creating the Key

| # | Action | Tx Hash | What Happened |
|---|--------|---------|---------------|
| 1 | `dkg_create_key` | `c890897e3d2cd5017e1977d9715cf35bad60e1faacdc29cf4eda4c172f7da3fd` | Created key slot for 3 parties, phase → Committing |
| 2 | `dkg_commit` P1 | `80c0d0710cdbe238a09791d5e4ab30c5d14cff933d0c404d0a2820a6935de223` | Party 1 committed SHA-256(P₁) — locked in their choice |
| 3 | `dkg_commit` P2 | `23a7ac5fb832d25e5778e99783350307bfb9f6b2c69740493022d8952c170113` | Party 2 committed SHA-256(P₂) |
| 4 | `dkg_commit` P3 | `facdbb30712af48df6a4686ac2329c8343c350e5cfe0689b2169d2fdf016f2a9` | Party 3 committed SHA-256(P₃). All committed → phase = Revealing |
| 5 | `dkg_reveal` P1 | `570650277facf4f29fea83c2f2e2fc0d9546adb33d21fe8be77dd6d86f996f44` | Party 1 revealed P₁. Contract verified SHA-256(P₁) == C₁ ✓ |
| 6 | `dkg_reveal` P2 | `6bb08325b66fee5c5d1efa47aaf54e2a6cbd041569c7a749b7f8a7551d6ce8de` | Party 2 revealed P₂. Contract verified SHA-256(P₂) == C₂ ✓ |
| 7 | `dkg_reveal` P3 | `e6a0acc9539288d58909224b2736e80b7d227f186f001e74c9f0b580d020257c` | Party 3 revealed P₃. All revealed → ready to finalize |
| 8 | `dkg_finalize` | `92046089780a4ef3d55a0c5343218bd431313fcdbd25cdc6f0c2e3dc423dfe66` | Contract computed P = P₁ + P₂ + P₃ (EC point addition) |
| 9-12 | `submit_key_share` ×4 | `65b3b..1f1df`, `196ae..f3ed5`, `66121..9b1cc`, `cefd6..1342e` | 3 parties × 2 halves each → s₁, s₂, s₃ encrypted on ZK nodes |
| 13 | `dkg_complete_keygen` | `94573a073ab8ea0cdf177542cf4fef81f1260c27a1db54fe096fed10202c10df` | Key marked Complete. Public key stored, ready for signing |

### GG20 Signing Phase — Signing Without the Key

| # | Action | Tx Hash | What Happened |
|---|--------|---------|---------------|
| 14 | `sign_message` | `8d6491a6160a4e2c164b4ebb9aa8ce946db3a4e41f751bebb8a81d40ebbc59e9` | Queued EVM transaction hash for signing |
| 15 | `gg20_start_signing` | `5e5595fde234f2207f9ead56c6920035305f6b939521013a30c93d9c545d856b` | Begin signing ceremony, phase → ThresholdSigning |
| 16 | `submit_delta` P1 | `4f8846ab8fbb641caf6d76ca4171be5b0de57e56508bbe71987f964666ac0b35` | Party 1 submits δ₁ (share of k×γ) |
| 17 | `submit_delta` P2 | `1e2892f24ecc6587b9e3c862f9ddf5f622d79b0b291f3a2e361ea510679b2dce` | Party 2 submits δ₂ |
| 18 | `submit_delta` P3 | `01a57cb1b2f27c4bb787515000916de472353f6ef8f64de5d1fab729aec4390f` | Party 3 submits δ₃. δ = δ₁+δ₂+δ₃ = k×γ |
| 19 | `submit_gamma_point` P1 | `e5ee5f306ba6cef63f639f4b5dd53bb85437e685fde2d60760ae3fb4916761fe` | Party 1 submits Γ₁ = γ₁ × G |
| 20 | `submit_gamma_point` P2 | `1040ca81d9dd53ae2bd9a12da0dc4766870a3cd93913562f368b67d7a0cd4586` | Party 2 submits Γ₂ = γ₂ × G |
| 21 | `submit_gamma_point` P3 | `76c479845b3686c0ae26b7a1cf6c747b0be0198ecf4c5acce742c8f1cd8a032e` | Party 3 submits Γ₃ = γ₃ × G. Γ = Γ₁+Γ₂+Γ₃ |
| 22 | `gg20_finalize_r` | `377e484146a1fbf710029c9df113d2d5016feb3def544299b9b355146b42df46` | R = δ⁻¹ × Γ = k⁻¹ × G (THE MAGIC). Extract r = R.x mod n |
| 23 | `commit_partial_sig` P1 | `7354e882f1873d46625c5e22e74a8b41f6f0c16244cb6d324409bbd59e2af9d4` | Party 1 commits hash(σ₁) — sealed envelope |
| 24 | `commit_partial_sig` P2 | `8d96efbc8d7d4222fa65e2673a7931048dbf4b523e4f66c2097d6c807ae2f960` | Party 2 commits hash(σ₂) |
| 25 | `commit_partial_sig` P3 | `e788515e8c1e9949eb88f61e363201a3b4e3d183cfa78858e46a13e989fe5be8` | Party 3 commits hash(σ₃) |
| 26 | `submit_partial_sig` P1 | `8ffe306954515d73c2fde2386d724ce1d0326e0fd4a0ed2375d68422ada6b977` | Party 1 reveals σ₁, contract checks hash ✓ |
| 27 | `submit_partial_sig` P2 | `9a31f873c75f1a18c99f1ed9c721eafe22930fb6ecaa3f18302fd8810198577d` | Party 2 reveals σ₂, contract checks hash ✓ |
| 28 | `submit_partial_sig` P3 | `3a292217ee3ce98d55cf4af090df96ab51d30e04f4c9c11379395a3370b09036` | Party 3 reveals σ₃. σ = σ₁+σ₂+σ₃, low-s normalize, ECDSA verify ✓ |

### Ethereum Verification

| Item | Value |
|------|-------|
| Sepolia Tx | [`0x09ec739d1e7cf9a91019c393abc9eee91042eedf20b4ec9f70630f7b93b98d41`](https://sepolia.etherscan.io/tx/0x09ec739d1e7cf9a91019c393abc9eee91042eedf20b4ec9f70630f7b93b98d41) |
| Block | 10432151 |
| From | `0x46fe38ef06876C3d76E03D1e5991eD28FF2714ad` (derived from DKG public key) |
| To | `0x742d35cc6634c0532925a3b844bc9e7595f2bd00` |
| Value | 0.0001 ETH |
| Proof | The signature produced by GG20 (without ever having the private key) successfully sent an ETH transaction |

---

## Contract Actions Reference

### DKG Actions (Key Generation)

| Shortname | Action | Parameters | What It Does |
|-----------|--------|------------|-------------|
| `0x20` | `dkg_create_key` | `key_id: u32, num_parties: u8` | Create key slot, set phase → Committing |
| `0x21` | `dkg_commit` | `key_id: u32, party_index: u8, hash: Vec<u8>` | Store SHA-256(Pᵢ) commitment |
| `0x22` | `dkg_reveal` | `key_id: u32, party_index: u8, pubkey: Vec<u8>` | Reveal Pᵢ, verify against commitment |
| `0x23` | `dkg_finalize` | `key_id: u32` | Compute P = ΣPᵢ via EC point addition |
| `0x10` | `submit_key_share` | `key_id: u32, party_index: u8, half: ZK` | Store sᵢ half on ZK nodes |
| `0x24` | `dkg_complete_keygen` | `key_id: u32` | Mark key as Complete |

### GG20 Signing Actions

| Shortname | Action | Parameters | What It Does |
|-----------|--------|------------|-------------|
| `0x50` | `gg20_start_signing` | `key_id: u32, msg_hash: Vec<u8>` | Begin signing, phase → ThresholdSigning |
| `0x46` | `submit_gamma_point` | `key_id: u32, party_index: u8, Γᵢ: Vec<u8>` | Submit gamma point for nonce |
| `0x41` | `nonce_commit` | `key_id: u32, party_index: u8, hash: Vec<u8>` | Commit SHA-256(δ) |
| `0x42` | `nonce_reveal` | `key_id: u32, party_index: u8, δ: Vec<u8>` | Reveal δ, verify against commitment |
| `0x43` | `finalize_nonce_and_sign` | `key_id: u32` | Compute R = Γ + δ×G, r = R.x mod n |
| `0x30` | `submit_partial_sig` | `key_id: u32, party_index: u8, σᵢ: Vec<u8>` | Submit partial signature |
| `0x31` | `finalize_gg20_sig` | `key_id: u32` | Combine σ = Σσᵢ, verify ECDSA, store sig |
| `0x48` | `abort_signing` | `key_id: u32` | Cancel signing (timeout/error) |

### Legacy Shamir Actions (still available)

| Shortname | Action | What It Does |
|-----------|--------|-------------|
| `0x02` | `create_key_with_id` | Create key with Shamir setup |
| `0x05` | `post_public_key` | Store public key directly |
| `0x03` | `sign_message` | Queue message for Shamir signing |
| `0x07` | `signing_complete` | Submit pre-computed signature |

---

## Project Structure

```
KoshSignerUsingPartisiaZK/
│
├── contracts/
│   └── kosh-zk-signer/
│       └── src/
│           ├── lib.rs              ← All contract actions (DKG + GG20 + Shamir)
│           ├── signing_state.rs    ← State types, phases, key storage
│           ├── dkg.rs              ← DKG logic: commit, reveal, verify, EC point add
│           ├── shamir.rs           ← Legacy Shamir split/reconstruct
│           ├── off_chain.rs        ← ZK node callback handlers
│           └── zk_compute.rs       ← ZK compiler stub
│
├── client/
│   └── src/
│       ├── dkg-party.ts            ← DKG client: generate shares, build commit/reveal args
│       ├── gg20-signing.ts         ← GG20 protocol: init, MtA rounds, R computation, partials
│       ├── paillier.ts             ← Paillier cryptosystem (1024-bit safe primes, homomorphic ops)
│       ├── mta.ts                  ← MtA protocol (Paillier-based multiplicative-to-additive)
│       ├── test-gg20-sign.ts       ← Full end-to-end DKG + GG20 test (24 transactions)
│       ├── shamir-ts.ts            ← Shamir math (TypeScript)
│       ├── zk-signer.ts            ← ZK node encryption
│       ├── partisia.ts             ← Transaction sending
│       └── test-zk-flow.ts         ← Legacy Shamir test
│
└── README.md                       ← This file
```

---

## How to Run

### Prerequisites

```bash
# Rust + Partisia CLI
cargo install cargo-partisia-contract

# Node.js dependencies
cd client && npm install
```

### Environment Variables

```bash
export PARTISIA_SENDER_KEY=<your_hex_private_key>
export PARTISIA_SENDER_ADDRESS=<your_partisia_address>
export SIGNER_ADDRESS=<deployed_contract_address>
```

### Build & Deploy Contract

```bash
cd contracts/kosh-zk-signer
cargo pbc build --release
# Produces: target/wasm32-unknown-unknown/release/kosh_zk_signer.pbc
```

Deploy via the TypeScript deploy script (CLI can't parse complex init args):
```bash
cd client
npx tsx src/deploy.ts
```

### Run Full DKG + GG20 Test

```bash
cd client
npx tsx src/test-gg20-sign.ts
```

**Expected output** (24 successful transactions):
```
=== DKG + GG20 Threshold ECDSA Test ===

DKG Phase:
  ✓ Created key slot #1 for 3 parties
  ✓ Party 1 committed    Tx: e0a3a36f...
  ✓ Party 2 committed    Tx: 0e1dc99e...
  ✓ Party 3 committed    Tx: cdfc2b39...
  ✓ Party 1 revealed     Tx: 70e5f2d5...
  ✓ Party 2 revealed     Tx: b0fce68c...
  ✓ Party 3 revealed     Tx: 4c02e8b0...
  ✓ Finalized — P = P₁+P₂+P₃
  ✓ 3 shares stored on ZK nodes
  ✓ Keygen complete

GG20 Signing:
  ✓ Started signing for message hash
  ✓ 3 gamma points submitted
  ✓ Nonce committed & revealed
  ✓ R computed, r extracted
  ✓ 3 partial signatures submitted
  ✓ σ = σ₁+σ₂+σ₃ combined and verified ✓

Sepolia:
  ✓ ETH sent from DKG-generated wallet
  ✓ Tx confirmed on block 10432151
```

---

## Security Analysis

| Attack | Shamir (Old) | GG20 (New) | Why |
|--------|-------------|------------|-----|
| **Steal key during creation** | Possible — key exists in RAM | **Impossible** — key never created | DKG: each party picks random piece |
| **Steal key during signing** | Possible — key reconstructed | **Impossible** — only partials exist | Each party computes σᵢ with their sᵢ only |
| **Rogue key attack** | N/A | **Prevented** | Commit-reveal: can't adapt share after seeing others |
| **Compromise 1 ZK node** | Get 1 share (not enough) | Get 1 share (not enough) | Same protection |
| **Compromise 2 ZK nodes** | Can reconstruct key | Can reconstruct key | Same threshold — would need MPC for better |
| **Nonce reuse** | N/A | **Prevented** | Deterministic nonce via HMAC-DRBG |
| **Signature malleability** | Manual low-s | **Auto low-s** | Contract normalizes σ before storing |
| **Man-in-the-middle** | Possible | **Prevented** | Delta commit-reveal prevents tampering |

### Trust Model (Current Implementation — Fully Distributed)

No coordinator. Each party generates their own kᵢ using HMAC-DRBG seeded with their secret sᵢ. The Paillier MtA protocol computes cross-terms without revealing secrets. Nobody ever knows k, k⁻¹, or the full private key.

**Current assumptions:**
- Paillier key holders don't collude with threshold parties
- Majority of parties are honest
- secp256k1 discrete log is hard

### What Could Be Added for Even Stronger Security

1. **Range proofs**: Prove `kᵢ` and `γᵢ` are in valid range without revealing them (prevents overflow attacks)
2. **Feldman VSS**: Verifiable secret sharing so parties can verify each other's DKG shares
3. **Abort identification**: Identify and exclude malicious parties who submit bad values
4. **2048-bit Paillier**: Upgrade from 1024-bit to 2048-bit primes for stronger encryption

---

## Technology Stack

| Technology | Role |
|-----------|------|
| **secp256k1** | Elliptic curve for key generation and ECDSA signing |
| **k256 crate** | EC point arithmetic in the Rust contract (decompression, addition) |
| **@noble/curves** | EC math in TypeScript client |
| **Paillier encryption** | Homomorphic encryption for MtA protocol (partial, for production) |
| **SHA-256** | Commitment scheme (manual implementation in contract, no std crypto in wasm) |
| **HMAC-DRBG** | Deterministic nonce generation |
| **Partisia ZK nodes** | Encrypted secret storage (each node holds encrypted share halves) |
| **ECDH + AES-128** | ZK node encryption (share encrypted for each node's public key) |
| **viem** | Ethereum transaction construction and sending |
| **Sepolia testnet** | Ethereum test network for signature verification |

---

## Testnet Deployment Info

| Item | Value |
|------|-------|
| Partisia Network | Testnet |
| Contract Address | `03d6cbcafc3d4784b6f34356b3b3ec94f2f25e8ee9` |
| SDK Version | `v.16.126.0` |
| Parties | 3 (additive shares, no threshold reconstruction) |
| Deployer | `009b44f3cb729a0c37abd4a24549231e95f3a6dcb0` |
| Sepolia Block | 10432151 |

---

## The Key Insight

```
Traditional:     key = generate()           ← key exists here
                 shares = split(key)
                 key = reconstruct(shares)  ← key exists here too
                 sig = sign(key, msg)

GG20:            s₁ = random()              ← only pieces exist
                 s₂ = random()
                 s₃ = random()
                 P = s₁×G + s₂×G + s₃×G    ← public key from pieces
                 σᵢ = partial_sign(sᵢ, msg) ← each party signs with piece
                 σ = σ₁ + σ₂ + σ₃           ← valid signature, no key ever
```

**The private key `s = s₁ + s₂ + s₃` is a number that has never been computed by any computer, anywhere, ever. Yet we can sign valid Ethereum transactions with it.**
