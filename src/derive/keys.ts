/**
 * Key derivation — derives key material for both passphrases and resolves offset collisions.
 */
import { deriveKeyMaterial } from '../crypto/argon2.js';
import type { DerivedKeyMaterial, VaultConfig } from '../types/vault.js';

export interface DerivedKeys {
  real: DerivedKeyMaterial & { offset: number };
  decoy: DerivedKeyMaterial & { offset: number };
  collisionResolved: boolean;
  derivationMs: { real: number; decoy: number };
}

export async function deriveAllKeys(
  realPassphrase: string,
  decoyPassphrase: string,
  config: VaultConfig,
  onProgress: (step: 'real' | 'decoy', done: boolean) => void,
): Promise<DerivedKeys> {
  const slotSize = Math.floor(config.containerSize / 3);
  const safeRange = config.containerSize - slotSize - 16;

  let collisionResolved = false;

  // Derive real key material
  onProgress('real', false);
  let realResult = await deriveKeyMaterial(realPassphrase, 'real', config.argon2Params, 0);
  let realOffset = realResult.material.offsetSeed % safeRange;
  onProgress('real', true);

  // Derive decoy key material
  onProgress('decoy', false);
  let decoyResult = await deriveKeyMaterial(decoyPassphrase, 'decoy', config.argon2Params, 0);
  let decoyOffset = decoyResult.material.offsetSeed % safeRange;
  let decoyTotalMs = decoyResult.durationMs;
  onProgress('decoy', true);

  // Collision resolution — if slots overlap (within slotSize + 16 bytes),
  // re-derive with incremented collision counter
  const maxAttempts = 3;
  let attempt = 0;
  while (Math.abs(realOffset - decoyOffset) < slotSize + 16 && attempt < maxAttempts) {
    attempt++;
    collisionResolved = true;
    // Re-derive the decoy with collision counter
    decoyResult = await deriveKeyMaterial(decoyPassphrase, 'decoy', config.argon2Params, attempt);
    decoyOffset = decoyResult.material.offsetSeed % safeRange;
    decoyTotalMs += decoyResult.durationMs;
  }

  if (Math.abs(realOffset - decoyOffset) < slotSize + 16) {
    throw new Error(
      'Slot collision could not be resolved after 3 attempts. ' +
      'Try a larger container size or different passphrases.'
    );
  }

  return {
    real: { ...realResult.material, offset: realOffset },
    decoy: { ...decoyResult.material, offset: decoyOffset },
    collisionResolved,
    derivationMs: { real: realResult.durationMs, decoy: decoyTotalMs },
  };
}
