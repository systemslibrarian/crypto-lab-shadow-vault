/**
 * Tab switching — Encrypt / Decrypt tabs.
 */
export function initTabs(): void {
  const tabEncrypt = document.getElementById('tab-encrypt')!;
  const tabDecrypt = document.getElementById('tab-decrypt')!;
  const panelEncrypt = document.getElementById('panel-encrypt')!;
  const panelDecrypt = document.getElementById('panel-decrypt')!;

  const tabs = [tabEncrypt, tabDecrypt];
  const panels = [panelEncrypt, panelDecrypt];

  function activate(index: number) {
    tabs.forEach((tab, i) => {
      const isActive = i === index;
      tab.setAttribute('aria-selected', String(isActive));
      tab.setAttribute('tabindex', isActive ? '0' : '-1');
      tab.classList.toggle('border-vault-crimson', isActive);
      tab.classList.toggle('text-vault-text', isActive);
      tab.classList.toggle('border-transparent', !isActive);
      tab.classList.toggle('text-vault-text-dim', !isActive);
      panels[i].classList.toggle('hidden', !isActive);
    });
    tabs[index].focus();
  }

  tabEncrypt.addEventListener('click', () => activate(0));
  tabDecrypt.addEventListener('click', () => activate(1));

  // Keyboard navigation per WAI-ARIA tabs pattern
  tabs.forEach((tab, index) => {
    tab.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        e.preventDefault();
        const next = e.key === 'ArrowRight'
          ? (index + 1) % tabs.length
          : (index - 1 + tabs.length) % tabs.length;
        activate(next);
      }
    });
  });
}
