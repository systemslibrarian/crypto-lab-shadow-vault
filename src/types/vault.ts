export interface Argon2Params {
  memory: number;       // KiB — RFC 9106 recommends 64MB minimum (65536 KiB)
  iterations: number;   // time cost — RFC 9106 recommends 3 minimum
  parallelism: number;  // threads — 4 is reasonable for browser
  hashLength: number;   // 64 bytes — key(32) + nonce(12) + padding(4) + offset(4) + reserved(12)
}

export interface DerivedKeyMaterial {
  key: Uint8Array;      // bytes 0..31 — ChaCha20-Poly1305 key
  nonce: Uint8Array;    // bytes 32..43 — 12-byte nonce
  offsetSeed: number;   // uint32 from bytes 44..47
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
