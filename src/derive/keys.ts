/**
 * Key derivation — derives key material for both passphrases and resolves offset collisions.
 *
 * Collision resolution strategy:
 *   Phase 1: Re-derive the decoy with incrementing collision counters (cc 1..MAX).
 *   Phase 2: If all decoy attempts collide (e.g. real offset is in a "dead zone"),
 *            re-derive the real side with incrementing cc, checking against decoy cc=0.
 *
 * The decrypt side tries cc 0..MAX for each role independently, so any
 * (real_cc, decoy_cc) pair used here will be found during decryption.
 */
import { deriveKeyMaterial } from '../crypto/argon2.js';
import type { DerivedKeyMaterial, VaultConfig } from '../types/vault.js';
import { MAX_COLLISION_COUNTER, uniformOffset } from '../types/vault.js';

function slotsOverlap(offsetA: number, offsetB: number, slotWithTag: number): boolean {
  return Math.abs(offsetA - offsetB) < slotWithTag;
}

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
  const slotWithTag = slotSize + 16;
  const safeRange = config.containerSize - slotSize - 16;

  let collisionResolved = false;

  // Derive real key material (cc=0)
  onProgress('real', false);
  let realResult = await deriveKeyMaterial(realPassphrase, 'real', config.argon2Params, 0);
  let realOffset = uniformOffset(realResult.material.offsetSeeds, safeRange);
  let realTotalMs = realResult.durationMs;
  onProgress('real', true);

  // Derive decoy key material (cc=0)
  onProgress('decoy', false);
  let decoyResult = await deriveKeyMaterial(decoyPassphrase, 'decoy', config.argon2Params, 0);
  let decoyOffset = uniformOffset(decoyResult.material.offsetSeeds, safeRange);
  let decoyTotalMs = decoyResult.durationMs;
  onProgress('decoy', true);

  // Save initial decoy derivation for phase 2 fallback
  const initialDecoyResult = decoyResult;
  const initialDecoyOffset = decoyOffset;

  // --- Phase 1: Try re-deriving the decoy side ---
  for (let cc = 1; cc <= MAX_COLLISION_COUNTER; cc++) {
    if (!slotsOverlap(realOffset, decoyOffset, slotWithTag)) break;
    collisionResolved = true;
    decoyResult = await deriveKeyMaterial(decoyPassphrase, 'decoy', config.argon2Params, cc);
    decoyOffset = uniformOffset(decoyResult.material.offsetSeeds, safeRange);
    decoyTotalMs += decoyResult.durationMs;
  }

  // --- Phase 2: If still colliding, try moving the real side ---
  // This handles "dead zone" positions where no decoy offset avoids overlap.
  // For each new real offset, check against the original decoy (cc=0).
  if (slotsOverlap(realOffset, decoyOffset, slotWithTag)) {
    for (let cc = 1; cc <= MAX_COLLISION_COUNTER; cc++) {
      realResult = await deriveKeyMaterial(realPassphrase, 'real', config.argon2Params, cc);
      realOffset = uniformOffset(realResult.material.offsetSeeds, safeRange);
      realTotalMs += realResult.durationMs;

      if (!slotsOverlap(realOffset, initialDecoyOffset, slotWithTag)) {
        // Use the initial decoy derivation with this new real offset
        decoyResult = initialDecoyResult;
        decoyOffset = initialDecoyOffset;
        break;
      }
    }
  }

  if (slotsOverlap(realOffset, decoyOffset, slotWithTag)) {
    throw new Error(
      'Slot collision could not be resolved. ' +
      'Try a larger container size or different passphrases.'
    );
  }

  return {
    real: { ...realResult.material, offset: realOffset },
    decoy: { ...decoyResult.material, offset: decoyOffset },
    collisionResolved,
    derivationMs: { real: realTotalMs, decoy: decoyTotalMs },
  };
}
