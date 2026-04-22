# The Private Key That Was Never Born

A complete walkthrough of Distributed Key Generation and threshold ECDSA signing — with real numbers at every single step, no hand-waving.

---

Here is a question that sounds impossible.

Can you sign an Ethereum transaction using a private key that has never been computed by any computer?

Not stored securely. Not encrypted. Not split after being created. Never computed. Ever.

The answer is yes. And this article will show you exactly how — from key generation, to signing, to the 65 bytes Ethereum actually receives and verifies. Every step. Real numbers. Nothing skipped.

---

## The Problem With Every Wallet You Have Used

Every crypto wallet starts like this:

    privateKey = generateRandom()     ← key is born here
    publicKey  = privateKey × G
    address    = hash(publicKey)

At line one, a number was born. It lives in RAM. It lives on disk. It lives in your backup. One machine holds it. One hack, one subpoena, one insider — and it is gone.

Think about what that means for a company treasury, a DAO multisig, or a protocol that holds millions in funds. Someone has to hold the key. You either trust that person completely, or you build elaborate systems to avoid trusting them. Neither solution is satisfying.

People tried Shamir Secret Sharing: generate the key first, then split it into pieces and distribute. But notice the word generate. The full private key existed on one machine for one moment. That moment is the vulnerability. A clever attacker does not need to steal your key today — they just need to have been watching during that one moment of key creation.

DKG removes that moment entirely. The private key is never born. Not even for a millisecond. Not even in RAM. Not even in a secure enclave. It simply never exists as a complete number anywhere.

---

## Part 1: Key Generation — Where the Private Key Is Never Born

Three parties. Let's call them Signer 1, Signer 2, Signer 3. They want a shared Ethereum wallet. None of them trusts the others. None of them should ever know the full private key. They don't even need to be in the same country.

Each party independently picks their own secret number on their own machine:

    Signer 1  →  secret = 42
    Signer 2  →  secret = 73
    Signer 3  →  secret = 19

The combined private key would be 42 + 73 + 19 = 134.

But nobody computes this. 134 has never appeared on any machine, in any variable, in any log. The number 134 is implied by the math — but it does not exist anywhere physically. Think of it like this: three puzzle pieces exist, but the completed puzzle has never been assembled.

### Converting Secrets to Public EC Points

Now here is where elliptic curve math does something incredible.

In elliptic curve cryptography, G is a fixed public point on the secp256k1 curve — the same curve used by Bitcoin and Ethereum. Think of G as a one-way blender. You can put the number 42 into the blender and out comes 42G. But you cannot run the blender backwards. Given 42G, there is no algorithm that can recover 42 in any reasonable amount of time. This is the discrete logarithm problem, and it is the bedrock of all modern public key cryptography.

Each party computes their public piece using this one-way operation:

    Signer 1:  P₁ = 42 × G  =  42G
    Signer 2:  P₂ = 73 × G  =  73G
    Signer 3:  P₃ = 19 × G  =  19G

These are posted publicly. Anyone can see 42G without learning that the secret is 42. The blender only goes one way.

### Commit First — Then Reveal

Here is where most explanations skip an important detail that is actually critical to the entire security of the system.

You might think: great, each party posts their EC point, the contract adds them up, done. But there is a nasty attack hiding in that naive approach — we will see it in a moment. First, let us understand the fix.

Before anyone posts their EC point, each party first commits by posting only a hash of their EC point on-chain:

    Signer 1  posts:  SHA-256(42G)  →  "a3f8..."
    Signer 2  posts:  SHA-256(73G)  →  "c91d..."
    Signer 3  posts:  SHA-256(19G)  →  "77e2..."

A SHA-256 hash is also a one-way function. "a3f8..." tells you nothing about what 42G is. But crucially — once you post "a3f8...", you are locked in. You cannot change your EC point later without the hash failing to match.

Now, after all three parties have committed their hashes, each party reveals their actual EC point. The smart contract checks every reveal against its committed hash:

    Signer 1 reveals 42G  →  SHA-256(42G) matches "a3f8..."?  ✓
    Signer 2 reveals 73G  →  SHA-256(73G) matches "c91d..."?  ✓
    Signer 3 reveals 19G  →  SHA-256(19G) matches "77e2..."?  ✓

Anyone whose reveal does not match their hash is immediately rejected. Simple, elegant, and essential.

### Why Commit Exists — The Rogue Key Attack

Now let us look at what happens without the commit step. This attack is called the rogue key attack, and it is devastatingly simple.

Without commit, the last party to reveal can wait. They watch as Signer 1 and Signer 2 post their EC points. They now know that the partial sum is 42G + 73G = 115G.

Signer 3 wants to control the final wallet. She knows a private key — let's say 200 — so she knows 200G. She wants the final combined public key to be 200G, which she controls.

She computes: 200G − 115G = 85G. She submits 85G instead of her honest 19G.

    Final key: 42G + 73G + 85G = 200G

She just engineered the entire wallet to be under her control, and the other two parties have no idea. The wallet address looks valid. Signatures verify. But only Signer 3 can sign anything.

With the commit step, this attack is completely blocked. She already posted SHA-256(19G) before seeing anyone else's points. When she tries to reveal 85G, the hash check fails. She is rejected.

The commit step is not a formality. It is the entire security of DKG.

### Combining the Public Key On-Chain

Once all three reveals pass their hash checks, the smart contract adds all three EC points together. This is just point addition — a well-defined operation on elliptic curves:

    P = P₁ + P₂ + P₃
      = 42G + 73G + 19G
      = (42 + 73 + 19) × G
      = 134G

P = 134G is the combined public key. The Ethereum address is derived from it. It is posted on-chain. Anyone can see it.

The private key 134 was never computed. Only its EC shadow 134G exists. The blender went one way, and nobody knows what went in.

---

## Part 2: Signing — Where the Key Is Never Assembled

Months pass. Someone now wants to sign a transaction from this wallet. The same rule applies: the private key must never be assembled, even during signing.

This is where it gets really interesting — because signing with ECDSA normally requires the full private key. How do you produce a valid signature without ever having the number 134 on any machine?

The answer involves a protocol called GG20, which lets each party sign with only their piece, and the partial signatures combine into a valid full signature on-chain. Let us walk through it with real numbers.

Each signer independently generates two random numbers for this signing session:

    Signer 1:  k₁ = 5  (nonce share)     γ₁ = 3  (masking value)
    Signer 2:  k₂ = 7  (nonce share)     γ₂ = 4  (masking value)
    Signer 3:  k₃ = 2  (nonce share)     γ₃ = 6  (masking value)

Why two numbers? The k values are their shares of the signing nonce — a random number that ECDSA requires to produce a signature. The γ values are a masking trick that lets them compute things on-chain without exposing k. More on that in a moment.

The combined nonce: k = 5 + 7 + 2 = 14 — never computed.
The combined masking value: γ = 3 + 4 + 6 = 13 — never computed.

Each party also computes the public version of their masking value — again using that one-way EC multiplication:

    Signer 1:  Γ₁ = 3G
    Signer 2:  Γ₂ = 4G
    Signer 3:  Γ₃ = 6G

These public EC points will be posted to the contract. They are needed to compute the nonce point R on-chain — but they reveal nothing about the underlying γ values.

---

## Part 3: MtA — How Parties Multiply Secrets Without Revealing Them

This is the hardest part of the protocol, and it is also the most beautiful. Stay with it.

To compute a valid ECDSA signature, the parties collectively need two specific products:

    k × γ  =  14 × 13  =  182     (needed to compute the nonce point R)
    k × s  =  14 × 134 =  1876    (needed to compute the actual signature value)

Here is the problem: nobody has the full k, full γ, or full s. Each party only has their own piece. You cannot multiply pieces of two different secrets and get the product of the full secrets — multiplication does not work that way.

For example: (5 + 7 + 2) × (3 + 4 + 6) is not the same as 5×3 + 7×4 + 2×6. The cross terms are missing. So parties cannot just multiply their own pieces.

The solution is MtA — Multiplicative-to-Additive conversion. It is powered by Paillier homomorphic encryption, and it lets two parties compute their share of a product without either one learning the actual product or the other's input.

Paillier encryption has a magical property. You can do arithmetic on encrypted numbers without decrypting them first:

    Enc(a) × Enc(b)  =  Enc(a + b)    ← add two numbers while they are encrypted
    Enc(a) ^ k       =  Enc(a × k)    ← multiply an encrypted number by a known value

Think of it like a locked box. Paillier lets you add numbers to a locked box and multiply the contents of a locked box — all without ever opening it. Only the box's owner (who holds the decryption key) can eventually open it to see the result.

### How MtA Works for One Cross Term

Let's say Party 1 wants to help Party 2 compute their share of k₁ × γ₂ = 5 × 4 = 20, without either of them learning 20 or the other's value.

1. Party 1 encrypts their k₁: they compute Enc(5) using Paillier and send it to Party 2.
2. Party 2 uses Paillier's homomorphic property: they compute Enc(5)^4 = Enc(5 × 4) = Enc(20). They now hold an encryption of 20 — but they cannot open it because they don't have Party 1's decryption key.
3. Party 2 then picks a random number β = 8 and subtracts it: they compute Enc(20) × Enc(-8) = Enc(12). They send Enc(12) back to Party 1.
4. Party 1 decrypts to get 12. Party 1's piece of the product is 12. Party 2's piece is 8.

Result: 12 + 8 = 20 = k₁ × γ₂. Neither party knows the other's piece. Neither party knows the product is 20. The secret is split.

### Computing k × γ Shares — All 9 Terms

Now let's run this for the full product k × γ. Think about expanding it like algebra class:

    (k₁ + k₂ + k₃) × (γ₁ + γ₂ + γ₃)
    = k₁γ₁ + k₁γ₂ + k₁γ₃
    + k₂γ₁ + k₂γ₂ + k₂γ₃
    + k₃γ₁ + k₃γ₂ + k₃γ₃

Nine terms. Three of them are self-terms where one party provides both factors — those are easy, each party just multiplies their own numbers. The other six are cross-terms where two different parties each provide one factor — those go through MtA.

The 3 self terms (each party keeps these — no MtA needed):

    Party 1 keeps:  k₁ × γ₁ = 5 × 3 = 15
    Party 2 keeps:  k₂ × γ₂ = 7 × 4 = 28
    Party 3 keeps:  k₃ × γ₃ = 2 × 6 = 12

The 6 cross terms (MtA splits each into two random pieces — neither party learns the product):

    k₁γ₂ = 5×4 = 20  →  Party 1 gets 12,  Party 2 gets  8   (12 + 8 = 20 ✓)
    k₁γ₃ = 5×6 = 30  →  Party 1 gets 22,  Party 3 gets  8   (22 + 8 = 30 ✓)
    k₂γ₁ = 7×3 = 21  →  Party 2 gets 14,  Party 1 gets  7   (14 + 7 = 21 ✓)
    k₂γ₃ = 7×6 = 42  →  Party 2 gets 33,  Party 3 gets  9   (33 + 9 = 42 ✓)
    k₃γ₁ = 2×3 =  6  →  Party 3 gets  1,  Party 1 gets  5   ( 1 + 5 =  6 ✓)
    k₃γ₂ = 2×4 =  8  →  Party 3 gets  6,  Party 2 gets  2   ( 6 + 2 =  8 ✓)

Notice: every cross-term sum is correct, but each party only sees their own piece. Party 2 knows they got 8 from the k₁γ₂ MtA — but they do not know that 20 was the product, or that Party 1's piece was 12.

Now add up every piece each party received:

    Party 1:  δ₁ = 15 + 12 + 22 + 7 + 5 = 61  ✓
    Party 2:  δ₂ = 28 +  8 + 14 + 33 + 2 = 85  ✓
    Party 3:  δ₃ = 12 +  8 +  9 +  1 + 6 = 36  ✓

After all MtA rounds, the three shares sum to exactly the right answer:

    δ₁ + δ₂ + δ₃ = 61 + 85 + 36 = 182 = 14 × 13 = k × γ  ✓

Each party only knows their own δᵢ. Nobody knows 182 directly. The full product is split across three people, computed without anyone ever knowing what they were computing the product of.

### Computing k × s Shares

The same exact MtA process now runs again, but this time for k × s — the product of the nonce with the full private key.

    (k₁ + k₂ + k₃) × (s₁ + s₂ + s₃)
    = (5 + 7 + 2) × (42 + 73 + 19)
    = 14 × 134
    = 1876

After running MtA on all six cross-terms, each party ends up with an additive piece of k×s:

    Signer 1:  σ₁ = 620
    Signer 2:  σ₂ = 890
    Signer 3:  σ₃ = 366

    σ₁ + σ₂ + σ₃ = 620 + 890 + 366 = 1876 = 14 × 134 = k × s  ✓

Nobody knows 1876. Nobody knows 134. Each party holds only their piece.

---

## Part 4: Computing R — The Nonce Point

Now each party posts two things to the smart contract — their δᵢ (share of k×γ) and their Γᵢ (the EC point γᵢ × G):

    Signer 1:  δ₁ = 61    Γ₁ = 3G
    Signer 2:  δ₂ = 85    Γ₂ = 4G
    Signer 3:  δ₃ = 36    Γ₃ = 6G

The contract combines everything:

    δ = 61 + 85 + 36 = 182     (this is k × γ)
    Γ = 3G + 4G + 6G = 13G    (this is γ × G)

Now here is an elegant mathematical trick. ECDSA needs the nonce point R = k⁻¹ × G. But nobody knows k⁻¹ — nobody even knows k. How do you compute k⁻¹ × G without knowing k?

Watch what happens when we divide Γ by δ:

    R = δ⁻¹ × Γ
      = (k × γ)⁻¹ × (γ × G)
      = k⁻¹ × γ⁻¹ × γ × G
      = k⁻¹ × G              ✓

The γ cancels out perfectly. The contract computed R = k⁻¹ × G without any party ever revealing k or γ.

Substituting our actual numbers:

    R = 182⁻¹ × 13G
      = (13 × 14)⁻¹ × (13 × G)
      = G / 14
      = k⁻¹ × G              ✓

The masking value γ = 13 served its purpose — it masked the relationship between δ and k, then vanished in the algebra.

The value r — the first half of the ECDSA signature — is the x-coordinate of this point R. Let's say r = 50 for our example.

---

## Part 5: Partial Signatures — Each Party Signs With Their Piece

We now have m = 100 (the message hash) and r = 50 (the x-coordinate of R). Each party computes their partial signature using only their own local values:

    sᵢ = m × kᵢ + r × σᵢ

Substituting the actual numbers:

    Signer 1:  s₁ = 100 × 5  + 50 × 620  =  500 + 31000 = 31500
    Signer 2:  s₂ = 100 × 7  + 50 × 890  =  700 + 44500 = 45200
    Signer 3:  s₃ = 100 × 2  + 50 × 366  =  200 + 18300 = 18500

Each party commits their partial signature first (same commit-reveal pattern as DKG), then reveals. The contract sums:

    s = s₁ + s₂ + s₃ = 31500 + 45200 + 18500 = 95200

Let us verify this is mathematically correct by expanding the sum:

    s = 100×(5+7+2) + 50×(620+890+366)
      = 100 × 14   + 50 × 1876
      = 1400 + 93800
      = 95200
      = k × (m + r × s_private)
      = 14 × (100 + 50 × 134)
      = 14 × 6800
      = 95200  ✓

That last line is exactly the ECDSA signature formula: s = k(m + r·x) where x = 134 is the private key.

The magic is in the grouping. When each party computes m × kᵢ + r × σᵢ, they are not signing with a fraction of the key. They are each contributing a mathematically correct piece that, when summed, produces the exact same value as if someone had multiplied k × (m + r × 134) directly. The algebra works out perfectly.

The private key 134 never appeared in any computation. Each party used only their own numbers.

---

## Part 6: The Signature — What r, s, and v Actually Are

You have probably seen Ethereum signatures written as a hex blob. What is actually inside those 65 bytes?

    32 bytes  →  r = 50        (x-coordinate of the nonce point R)
    32 bytes  →  s = 95200     (the signature scalar)
     1 byte   →  v = 0 or 1   (the recovery ID)

r is the x-coordinate of the nonce point R = k⁻¹ × G. Think of it as a fingerprint of the nonce — it proves that a specific nonce point was used, without revealing what the nonce was. It is 32 bytes because secp256k1 x-coordinates are 256-bit numbers.

s is the signature scalar k(m + r·x). Computed from partial signatures as shown above. The full private key x = 134 was never assembled — it emerged from the algebra when the partial sigs were summed.

v is the recovery ID, and this one confuses a lot of people. Here is exactly why it exists.

On an elliptic curve, for every x-coordinate, there are two possible points — one with an even y-coordinate and one with an odd y-coordinate. When you compute r = R.x, you throw away the y-coordinate. You lose information. From r = 50 alone, you cannot tell if the actual nonce point R was the one at (50, y_even) or the one at (50, y_odd).

This matters for verification, because Ethereum wants to recover the signer's public key from the signature alone — without them sending their public key every time. To do that, it needs to know which of the two candidate points was the real R.

v is a single bit that tells you which one:
- v = 0 means the correct nonce point R has an even y-coordinate
- v = 1 means the correct nonce point R has an odd y-coordinate

In modern Ethereum (after EIP-155, which prevents replay attacks across chains), v is encoded with the chain ID:

    v = 35 + (2 × chainId) + recovery_id

    For Ethereum mainnet (chainId = 1):
      v = 37  →  recovery_id = 0  (even y)
      v = 38  →  recovery_id = 1  (odd y)

So when you see v = 27 or v = 28 in old Ethereum signatures — that is the same thing but without the chain ID protection (pre-EIP-155). The 27 offset is just a historical convention.

---

## Part 7: Verification — How Ethereum Checks the Signature

Here is the part that closes the loop. Ethereum receives (r=50, s=95200, v, message_hash=100) and knows the public key P = 134G. It needs to verify that this signature was produced by the holder of the private key corresponding to 134G, without knowing 134.

It runs four steps:

Step 1 — Compute w = s⁻¹ mod n

    w = 95200⁻¹  (mod n)

All arithmetic here is modular — done modulo n, the order of the secp256k1 curve. In our simplified example we are using regular division notation, but in reality everything wraps around n.

Step 2 — Compute two helper scalars

    u₁ = w × m = 95200⁻¹ × 100
    u₂ = w × r = 95200⁻¹ × 50

These are fractions scaled by w. u₁ represents the message's weight, u₂ represents r's weight.

Step 3 — Reconstruct the nonce point using only public information

    X = u₁ × G + u₂ × P
      = (100/95200) × G + (50/95200) × 134G
      = (100G + 6700G) / 95200
      = 6800G / 95200
      = G / 14
      = k⁻¹ × G
      = R

The verifier just reconstructed R — the nonce point — using nothing but public values. No private key. No nonce. Just the message, the signature, and the public key.

Step 4 — Check if X.x equals r

    X.x = R.x = r = 50  ✓   VALID

If the x-coordinate of the reconstructed point matches r, the signature is valid.

Why does this work mathematically? Let us trace through the algebra:

    X = u₁G + u₂P
      = (s⁻¹·m)G + (s⁻¹·r)(xG)
      = s⁻¹(m + r·x)G
      = k⁻¹ · G
      = R

So X.x = R.x = r. The verification is not checking a password — it is verifying a mathematical identity that only holds when the private key was used correctly.

What if someone tampers with the transaction?

An attacker changes the ETH amount, making the message hash m' = 999. They replay the same (r, s, v).

    X' = u₁'G + u₂'P   (computed with m' = 999 instead of m = 100)
    X'.x  ≠  50          ✗  REJECTED

The reconstruction gives a completely different point. The x-coordinate does not match r. The transaction is rejected. The signature is mathematically bound to the exact bytes that were signed. Change one bit — the entire verification collapses.

The only way to produce a valid (r, s) for a new message is to know the private key and rerun the entire signing protocol. Which, in our distributed system, requires all three parties to cooperate — each using only their own piece of a key that has never existed as a whole number.

---

## The Complete Picture in One Place

Key Generation:

    Secrets:    42, 73, 19     →  combined: 134 (never computed)
    EC Points:  42G, 73G, 19G  →  combined: 134G (on-chain, public)
    Ethereum address derived from 134G

Signing Inputs:

    Nonce shares:  k₁=5, k₂=7, k₃=2   →  k=14 (never computed)
    Mask values:   γ₁=3, γ₂=4, γ₃=6   →  γ=13 (never computed)

MtA Outputs:

    k×γ shares:  δ₁=61,  δ₂=85,  δ₃=36   →  δ=182=14×13
    k×s shares:  σ₁=620, σ₂=890, σ₃=366  →  σ=1876=14×134

Nonce Point:

    Γ = 3G+4G+6G = 13G
    R = 182⁻¹ × 13G = k⁻¹ × G
    r = R.x = 50

Partial Signatures (m=100, r=50):

    s₁ = 31500,  s₂ = 45200,  s₃ = 18500
    s  = 95200  =  k(m + r·x)  =  14×(100+50×134)  ✓

Final Signature (65 bytes):

    r = 50       (32 bytes)
    s = 95200    (32 bytes)
    v = 0 or 1   (1 byte)

Verification:

    X = (m·G + r·P) / s = 6800G / 95200 = G/14 = k⁻¹G = R
    X.x = r = 50  ✓

| Value | Lives Where |
|---|---|
| Secrets 42, 73, 19 | Each signer's machine only |
| Private key 134 | Nowhere. Never computed. |
| Nonce k = 14 | Nowhere. Never computed. |
| MtA shares δᵢ, σᵢ | Each signer locally |
| Public key 134G | On-chain |
| Partial sigs 31500, 45200, 18500 | On-chain |
| Final sig (50, 95200, v) | On-chain |

---

## One Honest Limitation

Everything above requires all three signers for every signing round. If even one signer goes offline — key lost, machine down, party unresponsive — the wallet is frozen. This is 3-of-3, and for a production system with real money, it is a real risk.

The upgrade is 2-of-3 threshold. The idea: instead of each party picking a single secret number, each party picks a line — described by two numbers: a constant and a slope. They evaluate that line at each other party's index and send those evaluations secretly. The final share for each party is the sum of evaluations they received from all parties.

With this Shamir structure in place, any 2 of 3 parties can reconstruct the full effect of the key using Lagrange coefficients — mathematical weights that adjust each party's partial signature so the result is still valid for the full key. One multiplication per party before signing. Everything else stays identical. The key is still never assembled.

But that is a full article of its own.

---

## Closing

The number 134 was never typed, stored, computed, or transmitted.

Three people — Signer 1, Signer 2, Signer 3 — each held a piece. They ran protocols. They exchanged Paillier-encrypted blobs. They computed their partial signatures locally. They posted them to a contract. The contract combined them.

Ethereum received 65 bytes. It ran four lines of math. It confirmed the signature was valid.

A number that does not exist signed a real transaction.

We are so accustomed to thinking of cryptography as "hide the number well." DKG inverts that completely. The private key does not need to exist to be useful. It just needs to be implied by the mathematics — present in the algebra, absent from every disk, every RAM chip, every log file, every mind.

The best-kept secret is the one that was never created.

---

Tags: Cryptography · Blockchain · Web3 · Ethereum · MPC · ECDSA · Zero Knowledge · Security
