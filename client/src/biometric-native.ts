/**
 * Partisia-native biometric fuzzy extractor — quantization & packing.
 *
 * Fingerprint minutiae are quantized into a 16×16 spatial grid with 8 angle bins.
 * The resulting cell IDs are packed into Sbi128 chunks for ZK secret input.
 *
 * Same finger scans agree on ~70-90% of cells after quantization.
 * Different fingers share <20%.
 */

export const GRID_X = 16;
export const GRID_Y = 16;
export const ANGLE_BINS = 8;
export const MAX_MINUTIAE = 64;
export const SENTINEL = 0xffff;
export const MATCH_THRESHOLD = 25;
export const CELLS_PER_CHUNK = 8;
export const NUM_CHUNKS = 8; // 8 chunks × 8 cells = 64 minutiae max

/** A single fingerprint minutia with spatial and angular attributes. */
export interface Minutia {
  /** X position in sensor space (0.0 - 1.0 normalized). */
  x: number;
  /** Y position in sensor space (0.0 - 1.0 normalized). */
  y: number;
  /** Ridge angle in radians (0 - 2π). */
  angle: number;
}

/**
 * Quantize a single minutia into a cell ID (u16).
 *
 * Cell ID = (y_bin * GRID_X + x_bin) * ANGLE_BINS + angle_bin
 * Range: 0 .. (16*16*8 - 1) = 0 .. 2047
 */
export function quantizeMinutia(m: Minutia): number {
  const xBin = Math.min(Math.floor(m.x * GRID_X), GRID_X - 1);
  const yBin = Math.min(Math.floor(m.y * GRID_Y), GRID_Y - 1);
  // Normalize angle to [0, 2π) then bin
  const normAngle = ((m.angle % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);
  const angleBin = Math.min(
    Math.floor((normAngle / (2 * Math.PI)) * ANGLE_BINS),
    ANGLE_BINS - 1
  );
  return (yBin * GRID_X + xBin) * ANGLE_BINS + angleBin;
}

/**
 * Encode a set of minutiae into a fixed-size template of 64 cell IDs.
 *
 * Steps:
 * 1. Quantize each minutia to a cell ID
 * 2. Sort and deduplicate
 * 3. Truncate to MAX_MINUTIAE
 * 4. Pad with SENTINEL (0xFFFF) to exactly 64 entries
 */
export function encodeTemplate(minutiae: Minutia[]): number[] {
  const cellIds = minutiae.map(quantizeMinutia);

  // Sort and deduplicate
  const unique = [...new Set(cellIds)].sort((a, b) => a - b);

  // Truncate to MAX_MINUTIAE
  const truncated = unique.slice(0, MAX_MINUTIAE);

  // Pad with sentinel
  while (truncated.length < MAX_MINUTIAE) {
    truncated.push(SENTINEL);
  }

  return truncated;
}

/**
 * Pack 64 cell IDs into 8 × Uint8Array(16) chunks for ZK submission.
 *
 * Each chunk holds 8 cell IDs as big-endian u16 values packed into 16 bytes (Sbi128).
 */
export function packForZk(cellIds: number[]): Uint8Array[] {
  if (cellIds.length !== MAX_MINUTIAE) {
    throw new Error(`Expected ${MAX_MINUTIAE} cell IDs, got ${cellIds.length}`);
  }

  const chunks: Uint8Array[] = [];
  for (let chunk = 0; chunk < NUM_CHUNKS; chunk++) {
    const buf = new Uint8Array(16);
    for (let cell = 0; cell < CELLS_PER_CHUNK; cell++) {
      const id = cellIds[chunk * CELLS_PER_CHUNK + cell];
      // Big-endian u16
      buf[cell * 2] = (id >> 8) & 0xff;
      buf[cell * 2 + 1] = id & 0xff;
    }
    chunks.push(buf);
  }
  return chunks;
}

/**
 * Unpack ZK chunks back to cell IDs (for verification/testing).
 */
export function unpackFromZk(chunks: Uint8Array[]): number[] {
  const cellIds: number[] = [];
  for (const buf of chunks) {
    for (let cell = 0; cell < CELLS_PER_CHUNK; cell++) {
      const id = (buf[cell * 2] << 8) | buf[cell * 2 + 1];
      cellIds.push(id);
    }
  }
  return cellIds;
}

/**
 * Compute SHA-256 commitment hash of a quantized template.
 *
 * The commitment is published on-chain during enrollment to bind the
 * biometric template without revealing cell IDs.
 */
export async function templateCommitment(
  cellIds: number[]
): Promise<Uint8Array> {
  // Serialize cell IDs as big-endian u16 bytes
  const buf = new Uint8Array(cellIds.length * 2);
  for (let i = 0; i < cellIds.length; i++) {
    buf[i * 2] = (cellIds[i] >> 8) & 0xff;
    buf[i * 2 + 1] = cellIds[i] & 0xff;
  }
  const hash = await globalThis.crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(hash);
}

/**
 * Count matching cell IDs between two templates (for local testing).
 * Ignores sentinels.
 */
export function countMatches(
  template1: number[],
  template2: number[]
): number {
  const set1 = new Set(template1.filter((id) => id !== SENTINEL));
  let matches = 0;
  for (const id of template2) {
    if (id !== SENTINEL && set1.has(id)) {
      matches++;
    }
  }
  return matches;
}
