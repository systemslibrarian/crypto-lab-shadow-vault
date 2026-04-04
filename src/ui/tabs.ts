/**
 * Tab switching — Encrypt / Decrypt tabs.
 */
export function initTabs(): void {
  const tabEncrypt = document.getElementById('tab-encrypt')!;
  const tabDecrypt = document.getElementById('tab-decrypt')!;
  const panelEncrypt = document.getElementById('panel-encrypt')!;
  const panelDecrypt = document.getElementById('panel-decrypt')!;

  function activate(tab: HTMLElement, panel: HTMLElement, other: HTMLElement, otherPanel: HTMLElement) {
    tab.setAttribute('aria-selected', 'true');
    tab.classList.add('border-vault-crimson', 'text-vault-text');
    tab.classList.remove('border-transparent', 'text-vault-text-dim');
    panel.classList.remove('hidden');

    other.setAttribute('aria-selected', 'false');
    other.classList.remove('border-vault-crimson', 'text-vault-text');
    other.classList.add('border-transparent', 'text-vault-text-dim');
    otherPanel.classList.add('hidden');
  }

  tabEncrypt.addEventListener('click', () => activate(tabEncrypt, panelEncrypt, tabDecrypt, panelDecrypt));
  tabDecrypt.addEventListener('click', () => activate(tabDecrypt, panelDecrypt, tabEncrypt, panelEncrypt));
}
