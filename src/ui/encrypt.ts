/**
 * Encrypt flow UI — handles encrypt panel interactions.
 */
import { createContainer, openContainer, downloadContainer, getMaxMessageLength } from '../crypto/wasm.js';
import type { VaultConfig, ContainerSize } from '../types/vault.js';
import { getParams } from './params.js';
import { renderVisualizer, hideVisualizer, toggleAttackerView } from './visualizer.js';

/** Securely zero a Uint8Array */
function zeroBytes(arr: Uint8Array): void {
  arr.fill(0);
}

// ─── Passphrase strength estimator ───────────────────────────────────────

interface StrengthResult {
  bits: number;
  label: string;
  color: string;
  percent: number;
}

function estimateStrength(passphrase: string): StrengthResult {
  if (!passphrase) return { bits: 0, label: '', color: '', percent: 0 };

  // Estimate character-class entropy
  let charsetSize = 0;
  if (/[a-z]/.test(passphrase)) charsetSize += 26;
  if (/[A-Z]/.test(passphrase)) charsetSize += 26;
  if (/[0-9]/.test(passphrase)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(passphrase)) charsetSize += 32;
  if (charsetSize === 0) charsetSize = 26;

  const bits = Math.floor(passphrase.length * Math.log2(charsetSize));

  // Penalize obvious patterns
  const lower = passphrase.toLowerCase();
  const penalized = /^(.)\1+$/.test(passphrase) || // all same char
    /^(012|123|234|345|456|567|678|789|abc|bcd)/.test(lower) || // sequential
    passphrase.length < 4;

  const effectiveBits = penalized ? Math.min(bits, 20) : bits;

  if (effectiveBits < 40) return { bits: effectiveBits, label: 'Weak — easily brute-forced', color: '#dc2626', percent: 20 };
  if (effectiveBits < 60) return { bits: effectiveBits, label: 'Fair — vulnerable with Argon2id', color: '#f59e0b', percent: 40 };
  if (effectiveBits < 80) return { bits: effectiveBits, label: 'Good — resistant to most attacks', color: '#3b82f6', percent: 65 };
  if (effectiveBits < 100) return { bits: effectiveBits, label: 'Strong — computationally secure', color: '#10b981', percent: 85 };
  return { bits: effectiveBits, label: 'Excellent', color: '#10b981', percent: 100 };
}

function updateStrengthUI(passphrase: string, barId: string, labelId: string): void {
  const bar = document.getElementById(barId);
  const label = document.getElementById(labelId);
  if (!bar || !label) return;

  const result = estimateStrength(passphrase);
  const inner = bar.querySelector('div') as HTMLElement;

  if (!passphrase) {
    inner.style.width = '0%';
    inner.style.backgroundColor = '';
    label.innerHTML = '&nbsp;';
    return;
  }

  // The colored bar carries the strength cue; the label stays in the themed,
  // WCAG-AA-contrast text color and names the level in words (never color alone).
  inner.style.width = `${result.percent}%`;
  inner.style.backgroundColor = result.color;
  label.textContent = `~${result.bits} bits — ${result.label}`;
}

let lastContainer: Uint8Array | null = null;
let lastFilename = '';

// Material kept ONLY to script the coercion-scenario demo below. Both the
// container copy and the passphrases are cleared as soon as the demo runs (or
// the vault is downloaded / re-encrypted), so nothing lingers longer than the
// existing container already does.
interface DemoMaterial {
  container: Uint8Array;
  realPass: string;
  decoyPass: string;
  config: VaultConfig;
}
let demoMaterial: DemoMaterial | null = null;

function clearDemoMaterial(): void {
  if (demoMaterial) {
    demoMaterial.container.fill(0);
    demoMaterial.realPass = '';
    demoMaterial.decoyPass = '';
    demoMaterial = null;
  }
}

export function initEncrypt(): void {
  const realPass = document.getElementById('real-passphrase') as HTMLInputElement;
  const decoyPass = document.getElementById('decoy-passphrase') as HTMLInputElement;
  const realMsg = document.getElementById('real-message') as HTMLTextAreaElement;
  const decoyMsg = document.getElementById('decoy-message') as HTMLTextAreaElement;
  const realCount = document.getElementById('real-char-count')!;
  const decoyCount = document.getElementById('decoy-char-count')!;
  const btnEncrypt = document.getElementById('btn-encrypt') as HTMLButtonElement;
  const encryptError = document.getElementById('encrypt-error')!;
  const progressEl = document.getElementById('encrypt-progress')!;
  const stepsEl = document.getElementById('encrypt-steps')!;
  const downloadSection = document.getElementById('download-section')!;
  const btnDownload = document.getElementById('btn-download')!;
  const downloadFilename = document.getElementById('download-filename')!;
  const btnAttackerView = document.getElementById('btn-attacker-view');
  const coercionSection = document.getElementById('coercion-section')!;
  const btnCoercion = document.getElementById('btn-coercion-demo') as HTMLButtonElement;
  const coercionSteps = document.getElementById('coercion-steps')!;

  if (btnAttackerView) {
    btnAttackerView.addEventListener('click', () => toggleAttackerView());
  }

  // Byte counters (UTF-8 — matches validation logic)
  function updateByteCount(textarea: HTMLTextAreaElement, counter: HTMLElement): void {
    counter.textContent = String(new TextEncoder().encode(textarea.value).length);
  }
  realMsg.addEventListener('input', () => {
    updateByteCount(realMsg, realCount);
    validateForm();
  });
  decoyMsg.addEventListener('input', () => {
    updateByteCount(decoyMsg, decoyCount);
    validateForm();
  });
  realPass.addEventListener('input', () => {
    updateStrengthUI(realPass.value, 'real-strength-bar', 'real-strength-label');
    validateForm();
  });
  decoyPass.addEventListener('input', () => {
    updateStrengthUI(decoyPass.value, 'decoy-strength-bar', 'decoy-strength-label');
    validateForm();
  });

  function getContainerSize(): ContainerSize {
    const checked = document.querySelector('input[name="container-size"]:checked') as HTMLInputElement;
    return parseInt(checked.value) as ContainerSize;
  }

  // Listen for container size changes to revalidate
  document.querySelectorAll('input[name="container-size"]').forEach(radio => {
    radio.addEventListener('change', validateForm);
  });

  function validateForm(): boolean {
    let valid = true;
    encryptError.classList.add('hidden');

    if (!realPass.value || !decoyPass.value || !realMsg.value || !decoyMsg.value) {
      valid = false;
    }

    if (realPass.value && decoyPass.value && realPass.value === decoyPass.value) {
      encryptError.textContent = 'Passphrases must differ — identical passphrases cannot provide deniability';
      encryptError.classList.remove('hidden');
      valid = false;
    }

    if (valid) {
      const containerSize = getContainerSize();
      const maxLen = getMaxMessageLength(containerSize);
      const realBytes = new TextEncoder().encode(realMsg.value).length;
      const decoyBytes = new TextEncoder().encode(decoyMsg.value).length;

      if (realBytes > maxLen) {
        encryptError.textContent = `Real message too long: ${realBytes} bytes, max ${maxLen} bytes for this container size`;
        encryptError.classList.remove('hidden');
        valid = false;
      }
      if (decoyBytes > maxLen) {
        encryptError.textContent = `Decoy message too long: ${decoyBytes} bytes, max ${maxLen} bytes for this container size`;
        encryptError.classList.remove('hidden');
        valid = false;
      }
    }

    btnEncrypt.disabled = !valid;
    return valid;
  }

  function addStep(text: string): HTMLElement {
    const step = document.createElement('div');
    step.className = 'step-active';
    step.textContent = `▸ ${text}`;
    stepsEl.appendChild(step);
    return step;
  }

  function markStepDone(step: HTMLElement) {
    step.className = 'step-done';
    step.textContent = step.textContent!.replace('▸', '✓');
  }

  btnEncrypt.addEventListener('click', async () => {
    if (!validateForm()) return;

    // Disable form during encryption
    btnEncrypt.disabled = true;
    btnEncrypt.textContent = 'CREATING...';
    progressEl.classList.remove('hidden');
    stepsEl.innerHTML = '';
    downloadSection.classList.add('hidden');
    coercionSection.classList.add('hidden');
    coercionSteps.classList.add('hidden');
    coercionSteps.innerHTML = '';
    hideVisualizer();

    // Zero previous container if it exists
    if (lastContainer) {
      zeroBytes(lastContainer);
      lastContainer = null;
    }
    clearDemoMaterial();

    const config: VaultConfig = {
      containerSize: getContainerSize(),
      argon2Params: getParams(),
    };

    const workingStep = addStep('Deriving keys & encrypting (Rust/WASM)...');

    const realMsgVal = realMsg.value;
    const decoyMsgVal = decoyMsg.value;
    const realPassVal = realPass.value;
    const decoyPassVal = decoyPass.value;

    // Clear sensitive inputs from UI immediately (reduces DOM exposure time)
    realPass.value = '';
    decoyPass.value = '';
    realMsg.value = '';
    decoyMsg.value = '';
    realCount.textContent = '0';
    decoyCount.textContent = '0';

    try {
      const result = await createContainer(
        realMsgVal,
        decoyMsgVal,
        realPassVal,
        decoyPassVal,
        config,
      );

      markStepDone(workingStep);

      const summary = addStep('Container created.');
      markStepDone(summary);

      // Store container for download
      lastContainer = result.container;
      lastFilename = `vault_${Date.now()}.bin`;

      // Keep an independent copy + the passphrases so the coercion-scenario
      // demo can re-decrypt this exact container through the real WASM path.
      // Cleared on demo run, download, or re-encrypt.
      demoMaterial = {
        container: result.container.slice(),
        realPass: realPassVal,
        decoyPass: decoyPassVal,
        config,
      };

      // Show visualizer
      renderVisualizer(config.containerSize, result.realOffset, result.decoyOffset);

      // Offer the coercion-scenario demo
      coercionSection.classList.remove('hidden');

      // Show download section
      downloadSection.classList.remove('hidden');
      downloadFilename.textContent = lastFilename;
    } catch (err: unknown) {
      workingStep.className = 'text-vault-danger';
      workingStep.textContent = `✗ ${err instanceof Error ? err.message : 'Unknown error'}`;
    } finally {
      btnEncrypt.textContent = 'CREATE VAULT';
      btnEncrypt.disabled = false;
      validateForm();
    }
  });

  btnDownload.addEventListener('click', () => {
    if (lastContainer) {
      downloadContainer(lastContainer, lastFilename);
      // Zero and discard container after download
      zeroBytes(lastContainer);
      lastContainer = null;
      downloadSection.classList.add('hidden');
    }
  });

  // If the user leaves the demo behind by downloading, don't retain the
  // scenario's passphrase copy either — but keep it available while the
  // coercion section is still on screen and un-run.
  btnDownload.addEventListener('click', () => {
    if (!coercionSteps.classList.contains('hidden')) clearDemoMaterial();
  });

  // ─── Coercion-scenario demo ────────────────────────────────────────────
  // Re-decrypts the just-created container with BOTH passphrases through the
  // real WASM open path — no fabricated output — and narrates the guarantee.

  function coercionPanel(
    accent: 'crimson' | 'amber',
    heading: string,
    sub: string,
    message: string,
  ): HTMLElement {
    const wrap = document.createElement('div');
    wrap.className = 'border border-vault-border rounded-lg p-4 bg-vault-bg';
    const h = document.createElement('p');
    h.className = `text-sm font-semibold text-vault-${accent} mb-1`;
    h.textContent = heading;
    const s = document.createElement('p');
    s.className = 'text-xs text-vault-text-muted mb-2';
    s.textContent = sub;
    const body = document.createElement('div');
    body.className =
      'bg-vault-surface border border-vault-border rounded p-3 text-sm whitespace-pre-wrap break-words';
    body.setAttribute('tabindex', '0');
    body.setAttribute('role', 'region');
    body.setAttribute('aria-label', `${heading} — decrypted message`);
    body.textContent = message;
    wrap.append(h, s, body);
    return wrap;
  }

  btnCoercion.addEventListener('click', async () => {
    if (!demoMaterial) return;
    const { container, realPass, decoyPass, config } = demoMaterial;

    btnCoercion.disabled = true;
    btnCoercion.textContent = 'DECRYPTING BOTH SLOTS (Rust/WASM)…';
    coercionSteps.classList.remove('hidden');
    coercionSteps.innerHTML = '';

    try {
      // Adversary coerces the decoy passphrase and decrypts.
      const decoyResult = await openContainer(container.slice(), decoyPass, config);
      coercionSteps.appendChild(
        coercionPanel(
          'amber',
          '1 · Adversary forces out the DECOY passphrase',
          'They decrypt and recover a complete, plausible message. As far as they can tell, this is the whole vault.',
          decoyResult.success && decoyResult.message !== undefined
            ? decoyResult.message
            : '(decryption failed)',
        ),
      );

      const note1 = document.createElement('p');
      note1.className = 'text-xs text-vault-crimson font-semibold';
      note1.textContent =
        'This is all the adversary can prove exists. The rest of the container is indistinguishable from random padding.';
      coercionSteps.appendChild(note1);

      // You still hold the real passphrase.
      const realResult = await openContainer(container.slice(), realPass, config);
      coercionSteps.appendChild(
        coercionPanel(
          'crimson',
          '2 · You still hold the REAL passphrase',
          'The same container bytes, opened with a different passphrase, yield a second, independent message at a different offset.',
          realResult.success && realResult.message !== undefined
            ? realResult.message
            : '(decryption failed)',
        ),
      );

      const note2 = document.createElement('p');
      note2.className = 'text-sm text-vault-text font-semibold pt-1';
      note2.textContent =
        'The decoy decryption gave the adversary no information about this second message — not its content, not its offset, not even that it exists.';
      coercionSteps.appendChild(note2);
    } finally {
      // The demo has served its purpose — wipe the retained copy + passphrases.
      clearDemoMaterial();
      btnCoercion.textContent = '✓ SCENARIO COMPLETE';
    }
  });
}
