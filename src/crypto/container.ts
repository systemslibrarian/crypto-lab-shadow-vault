/**
 * Container operations — create and open deniable encryption containers.
 *
 * Container format:
 *   - Fixed size (4KB, 8KB, 16KB, or 32KB)
 *   - Filled with CSPRNG random bytes
 *   - Two message slots written at Argon2id-derived offsets
 *   - No headers, magic bytes, or detectable structure
 *
 * Message slot format (within container):
 *   Bytes 0..3      : message length (uint32 LE, part of encrypted plaintext)
 *   Bytes 4..N      : message content
 *   Bytes N+1..S-1  : random padding (encrypted)
 *   Bytes S..S+15   : Poly1305 authentication tag (16 bytes, appended by AEAD)
 */
import { chachaPoly1305Seal, chachaPoly1305Open } from './chacha20poly1305.js';
import { deriveKeyMaterial } from './argon2.js';
import { deriveAllKeys } from '../derive/keys.js';
import type { VaultConfig, EncryptResult, DecryptResult, ContainerSize } from '../types/vault.js';
import { VALID_CONTAINER_SIZES } from '../types/vault.js';

const AAD = new TextEncoder().encode('shadow-vault:v1');

function encodeSlot(message: string, slotSize: number): Uint8Array {
  const msgBytes = new TextEncoder().encode(message);
  if (msgBytes.length > slotSize - 4) {
    throw new Error(`Message too long: ${msgBytes.length} bytes, max ${slotSize - 4} bytes for this container size`);
  }
  const slot = new Uint8Array(slotSize);
  new DataView(slot.buffer).setUint32(0, msgBytes.length, true);
  slot.set(msgBytes, 4);
  // Fill remaining bytes with random padding (will be encrypted)
  crypto.getRandomValues(slot.subarray(4 + msgBytes.length));
  return slot;
}

function decodeSlot(plaintext: Uint8Array): string {
  const length = new DataView(
    plaintext.buffer, plaintext.byteOffset, plaintext.byteLength
  ).getUint32(0, true);
  if (length > plaintext.length - 4) {
    throw new Error('Invalid slot data');
  }
  return new TextDecoder().decode(plaintext.subarray(4, 4 + length));
}

export function getMaxMessageLength(containerSize: number): number {
  const slotSize = Math.floor(containerSize / 3);
  return slotSize - 4;
}

export async function createContainer(
  realMessage: string,
  decoyMessage: string,
  realPassphrase: string,
  decoyPassphrase: string,
  config: VaultConfig,
  onProgress: (step: string) => void,
): Promise<EncryptResult> {
  const slotSize = Math.floor(config.containerSize / 3);

  // Step 1: Fill container with random bytes
  onProgress('Generating random container...');
  const container = new Uint8Array(config.containerSize);
  crypto.getRandomValues(container);

  // Step 2: Derive keys + offsets
  onProgress('Deriving real key (Argon2id)...');
  const keys = await deriveAllKeys(realPassphrase, decoyPassphrase, config, (step, done) => {
    if (!done) {
      onProgress(`Deriving ${step} key (Argon2id)...`);
    } else {
      onProgress(`${step === 'real' ? 'Real' : 'Decoy'} key derived.`);
    }
  });

  // Step 3: Encode and encrypt real message
  onProgress('Encrypting real message...');
  const realSlot = encodeSlot(realMessage, slotSize);
  const realSealed = chachaPoly1305Seal(keys.real.key, keys.real.nonce, realSlot, AAD);
  container.set(realSealed, keys.real.offset);

  // Step 4: Encode and encrypt decoy message
  onProgress('Encrypting decoy message...');
  const decoySlot = encodeSlot(decoyMessage, slotSize);
  const decoySealed = chachaPoly1305Seal(keys.decoy.key, keys.decoy.nonce, decoySlot, AAD);
  container.set(decoySealed, keys.decoy.offset);

  onProgress('Container created.');

  return {
    container,
    realOffset: keys.real.offset,
    decoyOffset: keys.decoy.offset,
    derivationMs: keys.derivationMs,
  };
}

export async function openContainer(
  container: Uint8Array,
  passphrase: string,
  config: VaultConfig,
  onProgress: (step: string) => void,
): Promise<DecryptResult> {
  const slotSize = Math.floor(config.containerSize / 3);
  const safeRange = config.containerSize - slotSize - 16;

  // Try both roles — the passphrase might be real or decoy
  for (const role of ['real', 'decoy'] as const) {
    // Try with collision counters 0-3
    for (let cc = 0; cc <= 3; cc++) {
      onProgress(cc === 0 && role === 'real'
        ? 'Deriving key (Argon2id)...'
        : 'Locating slot...');

      const { material, durationMs } = await deriveKeyMaterial(
        passphrase, role, config.argon2Params, cc
      );
      const offset = material.offsetSeed % safeRange;

      onProgress('Verifying authentication tag...');
      const sealed = container.slice(offset, offset + slotSize + 16);
      const plaintext = chachaPoly1305Open(material.key, material.nonce, sealed, AAD);

      if (plaintext !== null) {
        try {
          const message = decodeSlot(plaintext);
          // Calculate offset percentage for visual indicator (no exact number)
          const offsetPercent = Math.round((offset / safeRange) * 100);
          return { success: true, message, derivationMs: durationMs, offsetPercent };
        } catch {
          // Slot decoded but data invalid — continue trying
        }
      }
    }
  }

  // Identical error for wrong passphrase vs. no message
  return { success: false, derivationMs: 0 };
}

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
