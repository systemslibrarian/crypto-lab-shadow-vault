export interface Argon2Params {
  memory: number;       // KiB — RFC 9106 recommends 64MB minimum (65536 KiB)
  iterations: number;   // time cost — RFC 9106 recommends 3 minimum
  parallelism: number;  // threads — 4 is reasonable for browser
  hashLength: number;   // 64 bytes — key(32) + nonce(12) + offsetSeeds(20)
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

export function validateParams(params: Argon2Params): string[] {
  const errors: string[] = [];
  if (params.memory < 16384) {
    errors.push('Memory too low — minimum 16MB (16384 KiB)');
  } else if (params.memory < 65536) {
    errors.push('Memory below 64MB — below RFC 9106 recommendation for interactive use');
  }
  if (params.iterations < 2) {
    errors.push('Iterations too low — minimum 2');
  } else if (params.iterations < 3) {
    errors.push('Iterations below 3 — below RFC 9106 recommendation');
  }
  if (params.parallelism < 1) {
    errors.push('Parallelism must be at least 1');
  }
  return errors;
}
