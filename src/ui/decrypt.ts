/**
 * Decrypt flow UI — handles decrypt panel interactions.
 */
import { openContainer, uploadContainer } from '../crypto/wasm.js';
import type { VaultConfig, ContainerSize } from '../types/vault.js';

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
  const btnClear = document.getElementById('btn-clear-message')!;
  const offsetBar = document.getElementById('decrypt-offset-bar')!;
  const memoryInput = document.getElementById('decrypt-param-memory') as HTMLSelectElement;
  const iterationsInput = document.getElementById('decrypt-param-iterations') as HTMLSelectElement;
  const parallelismInput = document.getElementById('decrypt-param-parallelism') as HTMLSelectElement;
  const dropZoneText = dropZone.querySelector('p')!;

  function setDropZoneText(visibleText: string, accessibleName = visibleText): void {
    dropZoneText.textContent = visibleText;
    dropZone.setAttribute('aria-label', accessibleName);
  }

  let loadedContainer: Uint8Array | null = null;
  let detectedSize: ContainerSize | null = null;
  let fileRevision = 0;
  let attemptRevision = 0;

  // Auto-clear decrypted message after 2 minutes
  const MESSAGE_CLEAR_MS = 2 * 60 * 1000;
  let messageClearTimer: ReturnType<typeof setTimeout> | null = null;

  function clearDecryptedMessage(): void {
    messageEl.textContent = '';
    resultEl.classList.add('hidden');
    if (messageClearTimer !== null) {
      clearTimeout(messageClearTimer);
      messageClearTimer = null;
    }
  }

  function startMessageClearTimer(): void {
    if (messageClearTimer !== null) {
      clearTimeout(messageClearTimer);
    }
    messageClearTimer = setTimeout(clearDecryptedMessage, MESSAGE_CLEAR_MS);
  }

  function validateForm(): boolean {
    const valid = loadedContainer !== null && passInput.value.length > 0;
    btnDecrypt.disabled = !valid;
    return valid;
  }

  function invalidateAttempt(): void {
    attemptRevision++;
    clearDecryptedMessage();
    stepsEl.replaceChildren();
    progressEl.classList.add('hidden');
    btnDecrypt.textContent = 'OPEN VAULT';
    validateForm();
  }

  async function handleFile(file: File) {
    const revision = ++fileRevision;
    loadedContainer = null;
    detectedSize = null;
    invalidateAttempt();
    fileInfo.classList.add('hidden');
    decryptError.classList.add('hidden');
    setDropZoneText('Loading vault file…');

    try {
      const bytes = await uploadContainer(file);
      if (revision !== fileRevision) return;
      loadedContainer = bytes;
      detectedSize = loadedContainer.length as ContainerSize;
      fileInfo.textContent = `${file.name} — ${loadedContainer.length.toLocaleString()} bytes`;
      fileInfo.classList.remove('hidden');
      setDropZoneText(file.name, `${file.name} — activate to choose another vault file`);
      validateForm();
    } catch (err) {
      if (revision !== fileRevision) return;
      loadedContainer = null;
      detectedSize = null;
      fileInfo.classList.add('hidden');
      decryptError.textContent = err instanceof Error ? err.message : 'Invalid file';
      decryptError.classList.remove('hidden');
      setDropZoneText('Drop file or click to upload');
      validateForm();
    }
  }

  // Click to upload
  dropZone.addEventListener('click', () => fileInput.click());
  // Keyboard operability (WCAG 2.1.1) — drop-zone is role="button" tabindex="0"
  dropZone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });
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

  passInput.addEventListener('input', invalidateAttempt);
  for (const select of [memoryInput, iterationsInput, parallelismInput]) {
    select.addEventListener('change', invalidateAttempt);
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

  btnDecrypt.addEventListener('click', async () => {
    if (!loadedContainer || !detectedSize || !passInput.value) return;

    const revision = ++attemptRevision;
    btnDecrypt.disabled = true;
    btnDecrypt.textContent = 'OPENING...';
    decryptError.classList.add('hidden');
    clearDecryptedMessage();
    progressEl.classList.remove('hidden');
    stepsEl.innerHTML = '';

    const config: VaultConfig = {
      containerSize: detectedSize,
      argon2Params: {
        memory: Number(memoryInput.value) * 1024,
        iterations: Number(iterationsInput.value),
        parallelism: Number(parallelismInput.value),
        hashLength: 64,
      },
    };

    const passVal = passInput.value;
    // Clear passphrase from memory early
    passInput.value = '';

    const workingStep = addStep('Deriving key & searching slots (Rust/WASM)...');

    try {
      const result = await openContainer(
        loadedContainer,
        passVal,
        config,
      );

      if (revision !== attemptRevision) return;
      markStepDone(workingStep);

      if (result.success && result.message !== undefined) {
        const done = addStep('Message decrypted.');
        markStepDone(done);

        resultEl.classList.remove('hidden');
        messageEl.textContent = result.message;
        startMessageClearTimer();

        // Offset bar — visual only, no numeric value
        const barInner = offsetBar.querySelector('span')!;
        const pct = result.offsetPercent ?? 0;
        barInner.style.width = `${pct}%`;
      } else {
        const fail = addStep('No message found for this passphrase.');
        fail.className = 'text-vault-danger';
        fail.textContent = '✗ No message found for this passphrase.';
      }
    } catch (err: unknown) {
      // SECURITY: All errors (WASM crash, Worker timeout, malformed input)
      // MUST show the same generic message as wrong-passphrase.
      // Do NOT log the error detail to the console in production —
      // it could leak information about container validity.
      if (revision !== attemptRevision) return;
      markStepDone(workingStep);
      const fail = addStep('No message found for this passphrase.');
      fail.className = 'text-vault-danger';
      fail.textContent = '✗ No message found for this passphrase.';
    } finally {
      if (revision === attemptRevision) {
        btnDecrypt.textContent = 'OPEN VAULT';
        validateForm();
      }
    }
  });

  btnCopy.addEventListener('click', async () => {
    const text = messageEl.textContent ?? '';
    await navigator.clipboard.writeText(text);
    btnCopy.textContent = 'COPIED';
    setTimeout(() => { btnCopy.textContent = 'COPY'; }, 1500);
    // Clear clipboard after 30 seconds to limit exposure
    setTimeout(() => {
      navigator.clipboard.writeText('').catch(() => { /* ignore */ });
    }, 30_000);
  });

  btnClear.addEventListener('click', clearDecryptedMessage);
}
