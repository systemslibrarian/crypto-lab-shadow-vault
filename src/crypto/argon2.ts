/**
 * Argon2id wrapper — derives 64 bytes of key material from a passphrase.
 *
 * Salt is deterministic: SHA-256("shadow-vault:v1:" + role + optional collision counter).
 * This ensures the same passphrase+role always derives the same key material,
 * which is required for decryption without stored metadata.
 *
 * argon2-browser is loaded via a <script> tag (UMD bundle) to avoid
 * bundler issues with WASM. It exposes `window.argon2`.
 *
 * RFC 9106 minimum parameters:
 *   memory:      65536 KiB (64MB) — minimum for interactive use
 *   iterations:  3
 *   parallelism: 4
 */
import type { Argon2Params, DerivedKeyMaterial } from '../types/vault.js';

interface Argon2Global {
  ArgonType: { Argon2id: number };
  hash: (opts: {
    pass: string;
    salt: Uint8Array;
    type: number;
    mem: number;
    time: number;
    parallelism: number;
    hashLen: number;
  }) => Promise<{ hash: Uint8Array; hashHex: string }>;
}

function getArgon2(): Argon2Global {
  const a2 = (globalThis as unknown as Record<string, unknown>).argon2 as Argon2Global | undefined;
  if (!a2) throw new Error('argon2-browser not loaded. Ensure the script tag is present.');
  return a2;
}

export async function deriveKeyMaterial(
  passphrase: string,
  role: 'real' | 'decoy',
  params: Argon2Params,
  collisionCounter: number = 0,
): Promise<{ material: DerivedKeyMaterial; durationMs: number }> {
  const argon2 = getArgon2();
  const saltString = collisionCounter === 0
    ? `shadow-vault:v1:${role}`
    : `shadow-vault:v1:${role}:c${collisionCounter}`;
  const saltBytes = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(saltString))
  );

  const start = performance.now();

  const result = await argon2.hash({
    pass: passphrase,
    salt: saltBytes,
    type: argon2.ArgonType.Argon2id,
    mem: params.memory,
    time: params.iterations,
    parallelism: params.parallelism,
    hashLen: params.hashLength,
  });

  const durationMs = performance.now() - start;

  const output = result.hash;
  const material: DerivedKeyMaterial = {
    key: output.slice(0, 32),
    nonce: output.slice(32, 44),
    offsetSeed: new DataView(output.buffer, output.byteOffset, output.byteLength).getUint32(44, true),
  };

  // Zero the raw output buffer — material fields are already copied via .slice()
  output.fill(0);

  return { material, durationMs };
}

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

/**
 * Benchmark Argon2id with current params to estimate derivation time.
 */
export async function benchmarkArgon2(params: Argon2Params): Promise<number> {
  const argon2 = getArgon2();
  const start = performance.now();
  const saltBytes = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode('benchmark'))
  );
  await argon2.hash({
    pass: 'bench',
    salt: saltBytes,
    type: argon2.ArgonType.Argon2id,
    mem: params.memory,
    time: params.iterations,
    parallelism: params.parallelism,
    hashLen: 32,
  });
  return performance.now() - start;
}
