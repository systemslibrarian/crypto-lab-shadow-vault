/**
 * Encrypt flow UI — handles encrypt panel interactions.
 */
import { createContainer, downloadContainer, getMaxMessageLength } from '../crypto/container.js';
import type { VaultConfig, ContainerSize } from '../types/vault.js';
import { getParams } from './params.js';
import { renderVisualizer, hideVisualizer } from './visualizer.js';

/** Securely zero a Uint8Array */
function zeroBytes(arr: Uint8Array): void {
  arr.fill(0);
}

let lastContainer: Uint8Array | null = null;
let lastFilename = '';

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

  // Character counters
  realMsg.addEventListener('input', () => {
    realCount.textContent = String(realMsg.value.length);
    validateForm();
  });
  decoyMsg.addEventListener('input', () => {
    decoyCount.textContent = String(decoyMsg.value.length);
    validateForm();
  });
  realPass.addEventListener('input', validateForm);
  decoyPass.addEventListener('input', validateForm);

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
    hideVisualizer();

    // Zero previous container if it exists
    if (lastContainer) {
      zeroBytes(lastContainer);
      lastContainer = null;
    }

    const config: VaultConfig = {
      containerSize: getContainerSize(),
      argon2Params: getParams(),
    };

    let currentStep: HTMLElement | null = null;

    try {
      const result = await createContainer(
        realMsg.value,
        decoyMsg.value,
        realPass.value,
        decoyPass.value,
        config,
        (step: string) => {
          if (currentStep) markStepDone(currentStep);
          currentStep = addStep(step);
        },
      );

      if (currentStep) markStepDone(currentStep);

      const summary = addStep(
        `Complete — real: ${result.derivationMs.real.toFixed(0)}ms, decoy: ${result.derivationMs.decoy.toFixed(0)}ms`
      );
      markStepDone(summary);

      // Store container for download
      lastContainer = result.container;
      lastFilename = `vault_${Date.now()}.bin`;

      // Show visualizer
      renderVisualizer(config.containerSize, result.realOffset, result.decoyOffset);

      // Show download section
      downloadSection.classList.remove('hidden');
      downloadFilename.textContent = lastFilename;

      // Clear sensitive inputs for security
      realPass.value = '';
      decoyPass.value = '';
      realMsg.value = '';
      decoyMsg.value = '';
      realCount.textContent = '0';
      decoyCount.textContent = '0';
    } catch (err: unknown) {
      if (currentStep) {
        (currentStep as HTMLElement).className = 'text-vault-danger';
        (currentStep as HTMLElement).textContent = `✗ ${err instanceof Error ? err.message : 'Unknown error'}`;
      } else {
        encryptError.textContent = err instanceof Error ? err.message : 'Unknown error';
        encryptError.classList.remove('hidden');
      }
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
}
