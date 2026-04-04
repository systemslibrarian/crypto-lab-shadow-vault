/**
 * Shadow Vault — main entry point.
 * Initializes crypto self-test, UI modules, and security cleanup.
 */
import './style.css';
import { runSelfTest } from './crypto/chacha20poly1305.js';
import { initTabs } from './ui/tabs.js';
import { initEncrypt } from './ui/encrypt.js';
import { initDecrypt } from './ui/decrypt.js';
import { initParams } from './ui/params.js';

// --- Self-test on load ---
function initSelfTest(): void {
  const statusEl = document.getElementById('self-test-status')!;
  const result = runSelfTest();

  if (result.passed) {
    statusEl.textContent = '\u2705 Crypto self-test passed (ChaCha20-Poly1305 RFC 8439)';
    statusEl.classList.add('text-vault-success');
  } else {
    statusEl.textContent = '\u274c ChaCha20-Poly1305 self-test FAILED \u2014 do not use this tool';
    statusEl.classList.add('text-vault-danger');
    // Disable encrypt/decrypt buttons
    const btnEncrypt = document.getElementById('btn-encrypt') as HTMLButtonElement;
    const btnDecrypt = document.getElementById('btn-decrypt') as HTMLButtonElement;
    if (btnEncrypt) btnEncrypt.disabled = true;
    if (btnDecrypt) btnDecrypt.disabled = true;
    console.error('Self-test failures:', result.failures);
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
  }

  function closeModal() {
    modal.close();
    overlay.classList.add('hidden');
    overlay.setAttribute('aria-hidden', 'true');
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

// --- Security: clear passphrases on unload ---
function initSecurityCleanup(): void {
  window.addEventListener('beforeunload', () => {
    // Clear all password/text inputs
    const inputs = document.querySelectorAll('input[type="password"], input[type="text"]');
    inputs.forEach(input => {
      (input as HTMLInputElement).value = '';
    });
    // Clear all textareas (message inputs)
    const textareas = document.querySelectorAll('textarea');
    textareas.forEach(ta => {
      (ta as HTMLTextAreaElement).value = '';
    });
    // Clear decrypted message display
    const msgEl = document.getElementById('decrypted-message');
    if (msgEl) msgEl.textContent = '';
  });
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
  initSelfTest();
  initTabs();
  initParams();
  initEncrypt();
  initDecrypt();
  initModal();
  initPasswordToggles();
  initSecurityCleanup();
});
