/**
 * Shadow Vault — main entry point.
 * Initializes WASM crypto worker, self-test, UI modules, and security cleanup.
 */
import './style.css';
import { initCrypto } from './crypto/wasm.js';
import { initTabs } from './ui/tabs.js';
import { initEncrypt } from './ui/encrypt.js';
import { initDecrypt } from './ui/decrypt.js';
import { initParams } from './ui/params.js';

// --- WASM init + self-test ---
async function initSelfTest(): Promise<void> {
  const statusEl = document.getElementById('self-test-status')!;
  statusEl.textContent = '⏳ Loading crypto engine (Rust/WASM)...';

  try {
    const result = await initCrypto();

    if (result.passed) {
      statusEl.textContent = '✅ Crypto self-test passed (ChaCha20-Poly1305 · Rust/WASM)';
      statusEl.classList.add('text-vault-success');
    } else {
      statusEl.textContent = '❌ ChaCha20-Poly1305 self-test FAILED — do not use this tool';
      statusEl.classList.add('text-vault-danger');
      const btnEncrypt = document.getElementById('btn-encrypt') as HTMLButtonElement;
      const btnDecrypt = document.getElementById('btn-decrypt') as HTMLButtonElement;
      if (btnEncrypt) btnEncrypt.disabled = true;
      if (btnDecrypt) btnDecrypt.disabled = true;
      console.error('Self-test failures:', result.failures);
    }
  } catch (err) {
    statusEl.textContent = `❌ Crypto engine failed to load: ${err instanceof Error ? err.message : 'unknown error'}`;
    statusEl.classList.add('text-vault-danger');
    const btnEncrypt = document.getElementById('btn-encrypt') as HTMLButtonElement;
    const btnDecrypt = document.getElementById('btn-decrypt') as HTMLButtonElement;
    if (btnEncrypt) btnEncrypt.disabled = true;
    if (btnDecrypt) btnDecrypt.disabled = true;
  }
}

// --- How It Works modal ---
function initModal(): void {
  const btn = document.getElementById('btn-how-it-works')!;
  const modal = document.getElementById('modal-how') as HTMLDialogElement;
  const overlay = document.getElementById('modal-overlay')!;
  const closeBtn = document.getElementById('btn-close-modal')!;

  function openModal() {
    modal.showModal();
    overlay.classList.remove('hidden');
    overlay.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
  }

  function closeModal() {
    modal.close();
    overlay.classList.add('hidden');
    overlay.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
  }

  btn.addEventListener('click', openModal);
  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', closeModal);
  modal.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
  });
}

// --- Password toggle ---
function initPasswordToggles(): void {
  document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = (btn as HTMLElement).dataset.target;
      if (!targetId) return;
      const input = document.getElementById(targetId) as HTMLInputElement;
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '\ud83d\ude48';
      } else {
        input.type = 'password';
        btn.textContent = '\ud83d\udc41';
      }
    });
  });
}

// --- Security: clear sensitive data on unload and idle ---
const IDLE_CLEAR_MS = 5 * 60 * 1000; // 5 minutes
let idleTimer: ReturnType<typeof setTimeout> | null = null;

function clearSensitiveData(): void {
  document.querySelectorAll('input[type="password"], input[type="text"]').forEach(el => {
    (el as HTMLInputElement).value = '';
  });
  document.querySelectorAll('textarea').forEach(el => {
    (el as HTMLTextAreaElement).value = '';
  });
  const msgEl = document.getElementById('decrypted-message');
  if (msgEl) msgEl.textContent = '';
}

function initSecurityCleanup(): void {
  // Clear on page unload (best-effort — not guaranteed on crash/force-quit)
  window.addEventListener('beforeunload', clearSensitiveData);

  // Clear after 5 minutes of tab being hidden (defense-in-depth)
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      idleTimer = setTimeout(clearSensitiveData, IDLE_CLEAR_MS);
    } else {
      if (idleTimer !== null) {
        clearTimeout(idleTimer);
        idleTimer = null;
      }
    }
  });
}

// --- Init ---
document.addEventListener('DOMContentLoaded', async () => {
  initTabs();
  initParams();
  initEncrypt();
  initDecrypt();
  initModal();
  initPasswordToggles();
  initSecurityCleanup();
  await initSelfTest();
});
