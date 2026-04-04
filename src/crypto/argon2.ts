/**
 * Argon2id wrapper — derives 64 bytes of key material from a passphrase.
 *
 * Salt is deterministic: SHA-256("shadow-vault:v1:" + role + optional collision counter).
 * This ensures the same passphrase+role always derives the same key material,
 * which is required for decryption without stored metadata.
 *
 * Primary path:  Web Worker  → keeps UI responsive during multi-second hashing.
 * Fallback path: Main thread → used if Worker creation fails (UMD script tag).
 *
 * RFC 9106 minimum parameters:
 *   memory:      65536 KiB (64MB) — minimum for interactive use
 *   iterations:  3
 *   parallelism: 4
 */
import type { Argon2Params, DerivedKeyMaterial } from '../types/vault.js';

// Argon2id type constant per RFC 9106 — will never change.
const ARGON2_TYPE_ID = 2;

// --- Worker-based Argon2 (primary path) ---

let argon2Worker: Worker | null = null;
let workerFailed = false;
let nextRequestId = 0;
const pendingRequests = new Map<number, {
  resolve: (hash: Uint8Array) => void;
  reject: (err: Error) => void;
}>();

function handleWorkerMessage(e: MessageEvent): void {
  const data = e.data;
  if (data.type === 'ready') return; // Initial readiness signal

  const req = pendingRequests.get(data.id);
  if (!req) return;
  pendingRequests.delete(data.id);

  if (data.error) {
    req.reject(new Error(data.error));
  } else {
    req.resolve(new Uint8Array(data.hash));
  }
}

function getWorker(): Worker | null {
  if (workerFailed) return null;
  if (argon2Worker) return argon2Worker;

  try {
    const w = new Worker(`${import.meta.env.BASE_URL}argon2.worker.js`);
    w.onmessage = handleWorkerMessage;
    w.onerror = () => {
      workerFailed = true;
      argon2Worker = null;
      // Reject all pending requests so they can retry on main thread
      for (const [, req] of pendingRequests) {
        req.reject(new Error('Argon2 worker crashed'));
      }
      pendingRequests.clear();
    };
    argon2Worker = w;
    return w;
  } catch {
    workerFailed = true;
    return null;
  }
}

function hashViaWorker(opts: {
  pass: string; salt: Uint8Array;
  mem: number; time: number; parallelism: number; hashLen: number;
}): Promise<Uint8Array> {
  const w = getWorker();
  if (!w) return Promise.reject(new Error('Worker unavailable'));

  const id = nextRequestId++;
  return new Promise((resolve, reject) => {
    pendingRequests.set(id, { resolve, reject });
    w.postMessage({
      id,
      pass: opts.pass,
      salt: opts.salt,
      type: ARGON2_TYPE_ID,
      mem: opts.mem,
      time: opts.time,
      parallelism: opts.parallelism,
      hashLen: opts.hashLen,
    });
  });
}

// --- Main-thread fallback (used if Worker fails) ---

interface Argon2Global {
  ArgonType: { Argon2id: number };
  hash: (opts: {
    pass: string; salt: Uint8Array; type: number;
    mem: number; time: number; parallelism: number; hashLen: number;
  }) => Promise<{ hash: Uint8Array; hashHex: string }>;
}

function getArgon2MainThread(): Argon2Global {
  const a2 = (globalThis as unknown as Record<string, unknown>).argon2 as Argon2Global | undefined;
  if (!a2) throw new Error('argon2-browser not loaded. Ensure the script tag is present.');
  return a2;
}

// --- Unified hash function ---

async function argon2Hash(opts: {
  pass: string; salt: Uint8Array;
  mem: number; time: number; parallelism: number; hashLen: number;
}): Promise<Uint8Array> {
  try {
    return await hashViaWorker(opts);
  } catch {
    // Worker unavailable or crashed — fall back to main thread
    const a2 = getArgon2MainThread();
    const result = await a2.hash({
      ...opts, type: ARGON2_TYPE_ID,
    });
    return result.hash;
  }
}

export async function deriveKeyMaterial(
  passphrase: string,
  role: 'real' | 'decoy',
  params: Argon2Params,
  collisionCounter: number = 0,
): Promise<{ material: DerivedKeyMaterial; durationMs: number }> {
  const saltString = collisionCounter === 0
    ? `shadow-vault:v1:${role}`
    : `shadow-vault:v1:${role}:c${collisionCounter}`;
  const saltBytes = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(saltString))
  );

  const start = performance.now();

  const output = await argon2Hash({
    pass: passphrase,
    salt: saltBytes,
    mem: params.memory,
    time: params.iterations,
    parallelism: params.parallelism,
    hashLen: params.hashLength,
  });

  const durationMs = performance.now() - start;

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
  const saltBytes = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode('benchmark'))
  );
  const start = performance.now();
  const output = await argon2Hash({
    pass: 'bench',
    salt: saltBytes,
    mem: params.memory,
    time: params.iterations,
    parallelism: params.parallelism,
    hashLen: 32,
  });
  const elapsed = performance.now() - start;
  output.fill(0);
  return elapsed;
}
