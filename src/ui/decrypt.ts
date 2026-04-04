/**
 * Decrypt flow UI — handles decrypt panel interactions.
 */
import { openContainer, uploadContainer } from '../crypto/container.js';
import type { VaultConfig, ContainerSize } from '../types/vault.js';
import { getParams } from './params.js';

export function initDecrypt(): void {
  const dropZone = document.getElementById('drop-zone')!;
  const fileInput = document.getElementById('decrypt-file') as HTMLInputElement;
  const fileInfo = document.getElementById('file-info')!;
  const passInput = document.getElementById('decrypt-passphrase') as HTMLInputElement;
  const btnDecrypt = document.getElementById('btn-decrypt') as HTMLButtonElement;
  const decryptError = document.getElementById('decrypt-error')!;
  const progressEl = document.getElementById('decrypt-progress')!;
  const stepsEl = document.getElementById('decrypt-steps')!;
  const resultEl = document.getElementById('decrypt-result')!;
  const messageEl = document.getElementById('decrypted-message')!;
  const btnCopy = document.getElementById('btn-copy')!;
  const decryptTime = document.getElementById('decrypt-time')!;
  const offsetBar = document.getElementById('decrypt-offset-bar')!;

  let loadedContainer: Uint8Array | null = null;
  let detectedSize: ContainerSize | null = null;

  function validateForm(): boolean {
    const valid = loadedContainer !== null && passInput.value.length > 0;
    btnDecrypt.disabled = !valid;
    return valid;
  }

  async function handleFile(file: File) {
    decryptError.classList.add('hidden');
    resultEl.classList.add('hidden');
    progressEl.classList.add('hidden');

    try {
      loadedContainer = await uploadContainer(file);
      detectedSize = loadedContainer.length as ContainerSize;
      fileInfo.textContent = `${file.name} — ${loadedContainer.length.toLocaleString()} bytes`;
      fileInfo.classList.remove('hidden');
      dropZone.querySelector('p')!.textContent = file.name;
      validateForm();
    } catch (err) {
      loadedContainer = null;
      detectedSize = null;
      fileInfo.classList.add('hidden');
      decryptError.textContent = err instanceof Error ? err.message : 'Invalid file';
      decryptError.classList.remove('hidden');
      dropZone.querySelector('p')!.textContent = 'Drop file or click to upload';
      validateForm();
    }
  }

  // Click to upload
  dropZone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files[0]) {
      handleFile(fileInput.files[0]);
    }
  });

  // Drag and drop
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('border-vault-text-dim');
  });
  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('border-vault-text-dim');
  });
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('border-vault-text-dim');
    if (e.dataTransfer?.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  passInput.addEventListener('input', validateForm);

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

  btnDecrypt.addEventListener('click', async () => {
    if (!loadedContainer || !detectedSize || !passInput.value) return;

    btnDecrypt.disabled = true;
    btnDecrypt.textContent = 'OPENING...';
    decryptError.classList.add('hidden');
    resultEl.classList.add('hidden');
    progressEl.classList.remove('hidden');
    stepsEl.innerHTML = '';

    const config: VaultConfig = {
      containerSize: detectedSize,
      argon2Params: getParams(),
    };

    let currentStep: HTMLElement | null = null;

    try {
      const result = await openContainer(
        loadedContainer,
        passInput.value,
        config,
        (step: string) => {
          if (currentStep) markStepDone(currentStep);
          currentStep = addStep(step);
        },
      );

      if (currentStep) markStepDone(currentStep);

      if (result.success && result.message !== undefined) {
        const done = addStep('Message decrypted.');
        markStepDone(done);

        resultEl.classList.remove('hidden');
        messageEl.textContent = result.message;
        decryptTime.textContent = `${(result.derivationMs / 1000).toFixed(1)}s`;

        // Offset bar — visual only, no numeric value
        const barInner = offsetBar.querySelector('span')!;
        const pct = result.offsetPercent ?? Math.floor(Math.random() * 80 + 10);
        barInner.style.width = `${pct}%`;
      } else {
        const fail = addStep('No message found for this passphrase.');
        fail.className = 'text-vault-danger';
        fail.textContent = '✗ No message found for this passphrase.';
      }

      // Clear passphrase from memory
      passInput.value = '';
    } catch (err: unknown) {
      if (currentStep) {
        (currentStep as HTMLElement).className = 'text-vault-danger';
        (currentStep as HTMLElement).textContent = `✗ ${err instanceof Error ? err.message : 'Unknown error'}`;
      }
    } finally {
      btnDecrypt.textContent = 'OPEN VAULT';
      validateForm();
    }
  });

  btnCopy.addEventListener('click', async () => {
    const text = messageEl.textContent ?? '';
    await navigator.clipboard.writeText(text);
    btnCopy.textContent = 'COPIED';
    setTimeout(() => { btnCopy.textContent = 'COPY'; }, 1500);
  });
}
