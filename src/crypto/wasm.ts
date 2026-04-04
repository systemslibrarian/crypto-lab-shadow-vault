/**
 * WASM crypto bridge — async interface to the Rust/WASM crypto Worker.
 *
 * All cryptographic operations run in a Web Worker. Key material never
 * leaves WASM linear memory. Only passphrases (JS strings — unavoidable),
 * plaintext messages, and container bytes cross the thread boundary.
 */
import type { VaultConfig, EncryptResult, DecryptResult, ContainerSize } from '../types/vault.js';
import { VALID_CONTAINER_SIZES } from '../types/vault.js';

// ─── Worker lifecycle ────────────────────────────────────────────────────

let worker: Worker | null = null;
let workerReady = false;
let nextRequestId = 0;
const pendingRequests = new Map<number, {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
}>();

interface SelfTestResult {
  passed: boolean;
  failures: string[];
}

/**
 * Initialize the crypto subsystem. Must be called once at app startup.
 * Returns the self-test result (RFC 8439 test vectors verified in WASM).
 */
export function initCrypto(): Promise<SelfTestResult> {
  return new Promise((resolve, reject) => {
    try {
      const w = new Worker(
        `${import.meta.env.BASE_URL}vault.worker.js`,
        { type: 'module' },
      );

      w.onmessage = (e: MessageEvent) => {
        const data = e.data;

        // Initialization messages
        if (data.type === 'ready') {
          worker = w;
          workerReady = true;
          resolve(data.selfTest as SelfTestResult);
          // Switch to normal message handler
          w.onmessage = handleWorkerMessage;
          return;
        }
        if (data.type === 'init-error') {
          reject(new Error(data.error));
          return;
        }
      };

      w.onerror = (event) => {
        reject(new Error(`Crypto worker failed: ${event.message || 'unknown error'}`));
      };
    } catch (err) {
      reject(new Error(`Cannot create crypto worker: ${err instanceof Error ? err.message : String(err)}`));
    }
  });
}

function handleWorkerMessage(e: MessageEvent): void {
  const { id, result, error } = e.data;
  const req = pendingRequests.get(id);
  if (!req) return;
  pendingRequests.delete(id);

  if (error) {
    req.reject(new Error(error));
  } else {
    req.resolve(result);
  }
}

function callWorker(command: string, args: Record<string, unknown>): Promise<unknown> {
  if (!worker || !workerReady) {
    return Promise.reject(new Error('Crypto not initialized — call initCrypto() first'));
  }
  const id = nextRequestId++;
  return new Promise((resolve, reject) => {
    pendingRequests.set(id, { resolve, reject });
    worker!.postMessage({ id, command, args });
  });
}

// ─── Public API ──────────────────────────────────────────────────────────

/**
 * Create an encrypted container with real and decoy messages.
 * All Argon2id derivation + ChaCha20-Poly1305 encryption happens in WASM.
 */
export async function createContainer(
  realMessage: string,
  decoyMessage: string,
  realPassphrase: string,
  decoyPassphrase: string,
  config: VaultConfig,
): Promise<EncryptResult> {
  const result = await callWorker('create_container', {
    realMessage,
    decoyMessage,
    realPassphrase,
    decoyPassphrase,
    containerSize: config.containerSize,
    memoryKib: config.argon2Params.memory,
    iterations: config.argon2Params.iterations,
    parallelism: config.argon2Params.parallelism,
  }) as {
    container: Uint8Array;
    realOffset: number;
    decoyOffset: number;
    collisionResolved: boolean;
  };

  return {
    container: result.container,
    realOffset: result.realOffset,
    decoyOffset: result.decoyOffset,
    derivationMs: { real: 0, decoy: 0 }, // Timing not available from WASM
  };
}

/**
 * Attempt to open an encrypted container with a passphrase.
 * Tries both roles × collision counters entirely in WASM.
 */
export async function openContainer(
  container: Uint8Array,
  passphrase: string,
  config: VaultConfig,
): Promise<DecryptResult> {
  const result = await callWorker('open_container', {
    containerData: container,
    passphrase,
    containerSize: config.containerSize,
    memoryKib: config.argon2Params.memory,
    iterations: config.argon2Params.iterations,
    parallelism: config.argon2Params.parallelism,
  }) as {
    success: boolean;
    message?: string;
    offsetPercent?: number;
  };

  return {
    success: result.success,
    message: result.message,
    derivationMs: 0,
    offsetPercent: result.offsetPercent,
  };
}

/**
 * Maximum message length for a given container size.
 * Pure arithmetic — no WASM needed.
 */
export function getMaxMessageLength(containerSize: number): number {
  return Math.floor(containerSize / 3) - 4;
}

// ─── Container file I/O (stays in JS — no crypto) ───────────────────────

export function downloadContainer(container: Uint8Array, filename?: string): void {
  const name = filename ?? `vault_${Date.now()}.bin`;
  const blob = new Blob([container.slice().buffer as ArrayBuffer], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export async function uploadContainer(file: File): Promise<Uint8Array> {
  const maxValid = VALID_CONTAINER_SIZES[VALID_CONTAINER_SIZES.length - 1];
  if (file.size > maxValid) {
    throw new Error(
      `File too large: ${file.size.toLocaleString()} bytes. ` +
      `Maximum container size is ${maxValid.toLocaleString()} bytes.`
    );
  }

  const buffer = await file.arrayBuffer();
  const container = new Uint8Array(buffer);

  if (!VALID_CONTAINER_SIZES.includes(container.length as ContainerSize)) {
    throw new Error(
      `Invalid container size: ${container.length} bytes. ` +
      `Expected one of: ${VALID_CONTAINER_SIZES.join(', ')} bytes.`
    );
  }

  return container;
}
