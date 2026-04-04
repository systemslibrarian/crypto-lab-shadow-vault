export interface Argon2Params {
  memory: number;       // KiB — RFC 9106 recommends 64MB minimum (65536 KiB)
  iterations: number;   // time cost — RFC 9106 recommends 3 minimum
  parallelism: number;  // threads — 4 is reasonable for browser
  hashLength: number;   // 64 bytes — key(32) + nonce(12) + offsetSeeds(20)
}

export interface DerivedKeyMaterial {
  key: Uint8Array;            // bytes 0..31 — ChaCha20-Poly1305 key
  nonce: Uint8Array;          // bytes 32..43 — 12-byte nonce
  offsetSeeds: Uint8Array;    // bytes 44..63 — 20 bytes = 5 uint32 candidates for rejection sampling
}

export type ContainerSize = 4096 | 8192 | 16384 | 32768;

export interface VaultConfig {
  containerSize: ContainerSize;
  argon2Params: Argon2Params;
}

export interface EncryptResult {
  container: Uint8Array;
  realOffset: number;
  decoyOffset: number;
  derivationMs: { real: number; decoy: number };
}

export interface DecryptResult {
  success: boolean;
  message?: string;
  derivationMs: number;
  offsetPercent?: number;
}

export const VALID_CONTAINER_SIZES: readonly ContainerSize[] = [4096, 8192, 16384, 32768];

export const RECOMMENDED_PARAMS: Argon2Params = {
  memory: 65536,      // 64MB
  iterations: 3,
  parallelism: 4,
  hashLength: 64,
};

export const MINIMUM_PARAMS: Argon2Params = {
  memory: 16384,      // 16MB — allowed but warned
  iterations: 2,
  parallelism: 2,
  hashLength: 64,
};

/**
 * Maximum collision counter used during slot offset collision resolution.
 * Must be consistent between encryption (deriveAllKeys) and decryption (openContainer).
 * Higher values improve collision resolution reliability but increase decrypt time
 * for wrong passphrases (each cc is a full Argon2id derivation).
 */
export const MAX_COLLISION_COUNTER = 7;

/**
 * Compute a uniformly distributed offset via rejection sampling.
 *
 * Standard `seed % range` has modulo bias: offsets in [0, 2^32 mod range) are
 * slightly more likely. Rejection sampling discards seeds that fall in the
 * biased remainder at the top of the uint32 space.
 *
 * `offsetSeeds` provides up to 5 independent uint32 candidates (bytes 44-63
 * of the Argon2id output). With a worst-case bias probability of ~0.76%
 * (4KB container), the chance of all 5 candidates being rejected is < 2.5e-11.
 */
export function uniformOffset(offsetSeeds: Uint8Array, range: number): number {
  const dv = new DataView(offsetSeeds.buffer, offsetSeeds.byteOffset, offsetSeeds.byteLength);
  const limit = 0x100000000 - (0x100000000 % range); // largest multiple of range in uint32
  const candidates = Math.floor(offsetSeeds.length / 4);

  for (let i = 0; i < candidates; i++) {
    const seed = dv.getUint32(i * 4, true);
    if (seed < limit) {
      return seed % range;
    }
  }

  // Fallback: accept bias rather than fail (statistically unreachable)
  return dv.getUint32(0, true) % range;
}
