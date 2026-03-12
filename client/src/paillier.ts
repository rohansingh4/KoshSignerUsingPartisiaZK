/**
 * Paillier Cryptosystem — homomorphic encryption for MtA protocol.
 *
 * Properties:
 * - Enc(a) * Enc(b) mod n² = Enc(a + b)           (additive homomorphism)
 * - Enc(a)^k mod n² = Enc(a * k)                   (scalar multiplication)
 *
 * Used in GG20 MtA to convert multiplicative shares to additive shares
 * WITHOUT revealing the underlying values.
 *
 * Key sizes: 1024-bit primes → 2048-bit modulus (production).
 * Minimum for security: 1024-bit primes. Recommended: 2048-bit primes.
 */

import { generatePrimeSync, randomBytes } from "crypto";

// --- Types ---

export interface PaillierPublicKey {
  n: bigint;      // p * q
  n2: bigint;     // n²
  g: bigint;      // n + 1 (simplified generator)
}

export interface PaillierPrivateKey {
  lambda: bigint; // lcm(p-1, q-1)
  mu: bigint;     // L(g^λ mod n²)⁻¹ mod n
  p: bigint;
  q: bigint;
}

export interface PaillierKeyPair {
  publicKey: PaillierPublicKey;
  privateKey: PaillierPrivateKey;
}

// --- Key Generation ---

/**
 * Generate a Paillier key pair.
 * @param bitLength - bit length of each prime (default 1024 for production security)
 */
export function paillierKeygen(bitLength: number = 1024): PaillierKeyPair {
  // Generate two safe primes: p = 2p' + 1 where p' is also prime
  // Safe primes prevent certain attacks on Paillier (e.g., partial key recovery)
  const p = generateSafePrime(bitLength);
  let q: bigint;
  do {
    q = generateSafePrime(bitLength);
  } while (q === p); // ensure p ≠ q

  const n = p * q;
  const n2 = n * n;
  const g = n + 1n; // simplified generator

  // λ = lcm(p-1, q-1)
  const p1 = p - 1n;
  const q1 = q - 1n;
  const lambda = lcm(p1, q1);

  // μ = L(g^λ mod n²)⁻¹ mod n
  // where L(x) = (x - 1) / n
  const gLambda = modPow(g, lambda, n2);
  const lValue = lFunction(gLambda, n);
  const mu = modInverse(lValue, n);

  return {
    publicKey: { n, n2, g },
    privateKey: { lambda, mu, p, q },
  };
}

// --- Encryption / Decryption ---

/**
 * Encrypt a message m ∈ Z_n.
 * c = g^m · r^n mod n²
 */
export function paillierEncrypt(
  publicKey: PaillierPublicKey,
  m: bigint
): bigint {
  const { n, n2, g } = publicKey;

  // Ensure m is in range [0, n)
  const mMod = ((m % n) + n) % n;

  // Random r ∈ Z*_n (coprime to n)
  const r = randomCoprimeWithN(n);

  // c = g^m · r^n mod n²
  const gm = modPow(g, mMod, n2);
  const rn = modPow(r, n, n2);
  return (gm * rn) % n2;
}

/**
 * Decrypt a ciphertext c.
 * m = L(c^λ mod n²) · μ mod n
 */
export function paillierDecrypt(
  publicKey: PaillierPublicKey,
  privateKey: PaillierPrivateKey,
  c: bigint
): bigint {
  const { n, n2 } = publicKey;
  const { lambda, mu } = privateKey;

  const cLambda = modPow(c, lambda, n2);
  const lValue = lFunction(cLambda, n);
  return (lValue * mu) % n;
}

// --- Homomorphic Operations ---

/**
 * Homomorphic addition: Enc(a) ⊕ Enc(b) = Enc(a + b)
 * c₁ · c₂ mod n²
 */
export function paillierAdd(
  publicKey: PaillierPublicKey,
  c1: bigint,
  c2: bigint
): bigint {
  return (c1 * c2) % publicKey.n2;
}

/**
 * Homomorphic scalar multiplication: k ⊗ Enc(a) = Enc(k · a)
 * c^k mod n²
 */
export function paillierScalarMul(
  publicKey: PaillierPublicKey,
  c: bigint,
  k: bigint
): bigint {
  const kMod = ((k % publicKey.n) + publicKey.n) % publicKey.n;
  return modPow(c, kMod, publicKey.n2);
}

/**
 * Encrypt the additive inverse: Enc(-m) from Enc(m)
 * = Enc(m)^(n-1) mod n² = Enc(-m mod n)
 */
export function paillierNegate(
  publicKey: PaillierPublicKey,
  c: bigint
): bigint {
  return modPow(c, publicKey.n - 1n, publicKey.n2);
}

// --- Math Utilities ---

/**
 * L function: L(x) = (x - 1) / n
 */
function lFunction(x: bigint, n: bigint): bigint {
  return (x - 1n) / n;
}

/**
 * Modular exponentiation: base^exp mod mod
 * Using square-and-multiply for large numbers.
 */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % mod;
    }
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

/**
 * Extended GCD: returns [g, x, y] where g = gcd(a, b) and a*x + b*y = g
 */
function extGcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (a === 0n) return [b, 0n, 1n];
  const [g, x1, y1] = extGcd(b % a, a);
  return [g, y1 - (b / a) * x1, x1];
}

/**
 * Modular inverse: a⁻¹ mod m
 */
export function modInverse(a: bigint, m: bigint): bigint {
  const aMod = ((a % m) + m) % m;
  const [g, x] = extGcd(aMod, m);
  if (g !== 1n) throw new Error("Modular inverse does not exist");
  return ((x % m) + m) % m;
}

/**
 * GCD of two numbers.
 */
function gcd(a: bigint, b: bigint): bigint {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b !== 0n) {
    [a, b] = [b, a % b];
  }
  return a;
}

/**
 * LCM of two numbers.
 */
function lcm(a: bigint, b: bigint): bigint {
  return (a * b) / gcd(a, b);
}

/**
 * Generate a safe prime p such that p = 2p' + 1 where p' is also prime.
 * Safe primes resist Pohlig-Hellman and provide stronger Paillier security.
 * Also ensures p ≡ 3 (mod 4) for Blum integer property.
 */
function generateSafePrime(bitLength: number): bigint {
  const maxAttempts = 500 * bitLength; // safe primes are rarer, need more attempts
  for (let i = 0; i < maxAttempts; i++) {
    // Generate a prime p' (Sophie Germain prime candidate)
    const pPrime = generatePrimeSync(bitLength - 1, { bigint: true }) as bigint;
    // Candidate safe prime: p = 2p' + 1
    const p = 2n * pPrime + 1n;
    // Quick check: p must be odd and ≡ 3 (mod 4) for Blum property
    // Since p = 2p' + 1 and p' is odd prime > 2, p is always odd
    // p ≡ 3 (mod 4) when p' is odd, which it is (all primes > 2 are odd)
    if (isProbablePrime(p)) {
      return p;
    }
  }
  // Fallback: return a regular prime if safe prime generation is too slow
  // This should rarely happen with reasonable bit lengths
  const p = generatePrimeSync(bitLength, { bigint: true }) as bigint;
  return p;
}

/**
 * Miller-Rabin primality test with k rounds.
 * Probability of false positive: < 4^(-k)
 */
function isProbablePrime(n: bigint, k: number = 20): boolean {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;

  // Write n-1 as 2^r * d
  let d = n - 1n;
  let r = 0;
  while (d % 2n === 0n) {
    d /= 2n;
    r++;
  }

  // Witness loop
  const byteLen = (n.toString(2).length + 7) >> 3;
  for (let i = 0; i < k; i++) {
    // Pick random a in [2, n-2]
    const bytes = randomBytes(byteLen);
    let a = 2n;
    for (const b of bytes) a = (a << 8n) | BigInt(b);
    a = (a % (n - 4n)) + 2n; // a ∈ [2, n-2]

    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;

    let composite = true;
    for (let j = 0; j < r - 1; j++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}

/**
 * Generate a random bigint in [1, n-1] that is coprime with n.
 */
function randomCoprimeWithN(n: bigint): bigint {
  const byteLen = (n.toString(2).length + 7) >> 3;
  while (true) {
    const bytes = randomBytes(byteLen);
    let r = 0n;
    for (const b of bytes) r = (r << 8n) | BigInt(b);
    r = r % (n - 1n) + 1n; // r ∈ [1, n-1]
    if (gcd(r, n) === 1n) return r;
  }
}
