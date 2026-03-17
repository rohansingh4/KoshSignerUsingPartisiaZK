/**
 * Simulated fingerprint minutiae generator for demo/testing.
 *
 * generateTemplate() produces deterministic "fingerprints" from seed strings.
 * addNoise() simulates realistic scan variation within quantization tolerance.
 *
 * For production: replace with real minutiae extraction from native capture APIs.
 */

import type { Minutia } from "./biometric-native.js";

export interface NoiseOptions {
  /** Position jitter as fraction of sensor space (default 0.02 = 2%). */
  positionJitter?: number;
  /** Angle jitter in radians (default 0.2 ~= 11 degrees). */
  angleJitter?: number;
  /** Probability of dropping a minutia (default 0.1 = 10%). */
  dropRate?: number;
  /** Number of spurious minutiae to add (default 3). */
  spuriousCount?: number;
  /** Random seed for reproducible noise (default: crypto.random). */
  seed?: string;
}

/**
 * Generate a deterministic "fingerprint" template from a seed string.
 *
 * Uses HKDF-like expansion (SHA-256 chaining) to place minutiae
 * deterministically across the sensor space.
 *
 * Same seed always produces the same set of minutiae.
 */
export async function generateTemplate(
  seed: string,
  count: number = 50
): Promise<Minutia[]> {
  const minutiae: Minutia[] = [];
  const encoder = new TextEncoder();

  for (let i = 0; i < count; i++) {
    // Chain: SHA-256(seed || i) → 32 bytes → extract x, y, angle
    const input = encoder.encode(`${seed}:minutia:${i}`);
    const hash = await globalThis.crypto.subtle.digest("SHA-256", input);
    const bytes = new Uint8Array(hash);

    // Use first 8 bytes for x (0-1), next 8 for y (0-1), next 8 for angle (0-2π)
    const x = bytesToFloat(bytes, 0);
    const y = bytesToFloat(bytes, 4);
    const angle = bytesToFloat(bytes, 8) * 2 * Math.PI;

    minutiae.push({ x, y, angle });
  }

  return minutiae;
}

/**
 * Add realistic noise to a minutiae template to simulate scan variation.
 *
 * Noise types:
 * - Position jitter (small spatial displacement)
 * - Angle jitter (small rotation)
 * - Dropout (some minutiae not detected)
 * - Spurious additions (false positives from sensor noise)
 *
 * The noise is calibrated so that quantized cell IDs agree ~70-90% of the time
 * for the same finger, and <20% for different fingers.
 */
export async function addNoise(
  template: Minutia[],
  options?: NoiseOptions
): Promise<Minutia[]> {
  const posJitter = options?.positionJitter ?? 0.01;
  const angJitter = options?.angleJitter ?? 0.1;
  const dropRate = options?.dropRate ?? 0.05;
  const spuriousCount = options?.spuriousCount ?? 2;

  // Get random bytes — deterministic if seed provided
  const randBytes = await getRandomBytes(
    template.length * 12 + spuriousCount * 12,
    options?.seed
  );
  let randIdx = 0;

  const nextFloat = (): number => {
    const val = bytesToFloat(randBytes, randIdx);
    randIdx += 4;
    return val;
  };

  const result: Minutia[] = [];

  for (const m of template) {
    // Drop some minutiae
    if (nextFloat() < dropRate) {
      continue;
    }

    // Add jitter
    const dx = (nextFloat() - 0.5) * 2 * posJitter;
    const dy = (nextFloat() - 0.5) * 2 * posJitter;
    const da = (nextFloat() - 0.5) * 2 * angJitter;

    result.push({
      x: clamp(m.x + dx, 0, 0.9999),
      y: clamp(m.y + dy, 0, 0.9999),
      angle: ((m.angle + da) % (2 * Math.PI) + 2 * Math.PI) % (2 * Math.PI),
    });
  }

  // Add spurious minutiae
  for (let i = 0; i < spuriousCount; i++) {
    result.push({
      x: nextFloat(),
      y: nextFloat(),
      angle: nextFloat() * 2 * Math.PI,
    });
  }

  return result;
}

// --- Helpers ---

/** Convert 4 bytes at offset to a float in [0, 1). */
function bytesToFloat(bytes: Uint8Array, offset: number): number {
  const val =
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>>
    0;
  return val / 0x100000000;
}

function clamp(v: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, v));
}

/** Generate random bytes, optionally deterministic from a seed. */
async function getRandomBytes(
  count: number,
  seed?: string
): Promise<Uint8Array> {
  if (!seed) {
    const bytes = new Uint8Array(count);
    globalThis.crypto.getRandomValues(bytes);
    return bytes;
  }

  // Deterministic: chain SHA-256 hashes from seed
  const encoder = new TextEncoder();
  const result = new Uint8Array(count);
  let filled = 0;
  let round = 0;

  while (filled < count) {
    const input = encoder.encode(`${seed}:noise:${round}`);
    const hash = await globalThis.crypto.subtle.digest("SHA-256", input);
    const chunk = new Uint8Array(hash);
    const toCopy = Math.min(32, count - filled);
    result.set(chunk.subarray(0, toCopy), filled);
    filled += toCopy;
    round++;
  }

  return result;
}
