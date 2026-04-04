/**
 * Shadow Vault — Argon2id Web Worker.
 * Offloads memory-hard key derivation to a background thread
 * so the main thread stays responsive during multi-second hashing.
 */

/* global self, importScripts */

// argon2-bundled.min.js uses globalThis/self — compatible with Worker context.
importScripts('argon2-bundled.min.js');

self.onmessage = async function (e) {
  const { id, pass, salt, type, mem, time, parallelism, hashLen } = e.data;
  try {
    if (!self.argon2) {
      throw new Error('argon2-browser failed to load in worker');
    }
    // salt arrives as a structured-cloned Uint8Array
    const result = await self.argon2.hash({
      pass,
      salt: new Uint8Array(salt),
      type,
      mem,
      time,
      parallelism,
      hashLen,
    });
    // Send the hash back — small buffer (32-64 bytes), no need to transfer
    self.postMessage({ id, hash: Array.from(result.hash) });
  } catch (err) {
    self.postMessage({
      id,
      error: err instanceof Error ? err.message : String(err),
    });
  }
};

// Signal readiness
self.postMessage({ type: 'ready' });
