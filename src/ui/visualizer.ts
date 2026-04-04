/**
 * Container memory map visualizer.
 * Shows a horizontal grid of cells representing container contents.
 * Dark grey = padding, deep red = real slot, amber = decoy slot.
 * Only shown after encryption — never reveals positions during decryption.
 */

const TOTAL_CELLS = 512;

export function renderVisualizer(
  containerSize: number,
  realOffset: number,
  decoyOffset: number,
): void {
  const mapEl = document.getElementById('container-map')!;
  const statsEl = document.getElementById('container-stats')!;
  const vizEl = document.getElementById('container-visualizer')!;

  vizEl.classList.remove('hidden');

  const slotSize = Math.floor(containerSize / 3);
  const slotWithTag = slotSize + 16;

  // Calculate which cells belong to which slot
  const bytesPerCell = containerSize / TOTAL_CELLS;

  const cells: ('padding' | 'real' | 'decoy')[] = new Array(TOTAL_CELLS).fill('padding');

  for (let i = 0; i < TOTAL_CELLS; i++) {
    const byteStart = Math.floor(i * bytesPerCell);
    const byteEnd = Math.floor((i + 1) * bytesPerCell);

    // Check if this cell overlaps with real slot
    if (byteEnd > realOffset && byteStart < realOffset + slotWithTag) {
      cells[i] = 'real';
    }
    // Check if this cell overlaps with decoy slot
    if (byteEnd > decoyOffset && byteStart < decoyOffset + slotWithTag) {
      cells[i] = 'decoy';
    }
  }

  // Count encrypted bytes
  const encryptedBytes = slotWithTag * 2;
  const paddingBytes = containerSize - encryptedBytes;

  // Render cells
  mapEl.innerHTML = '';

  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  cells.forEach((type, index) => {
    const cell = document.createElement('div');
    cell.className = `container-cell container-cell--${type}`;
    cell.setAttribute('aria-hidden', 'true');

    if (!prefersReducedMotion) {
      cell.style.opacity = '0';
      cell.style.transition = 'opacity 0.3s ease, background-color 0.3s ease';
      setTimeout(() => {
        cell.style.opacity = '1';
      }, index * 2);
    }

    mapEl.appendChild(cell);
  });

  // Labels
  statsEl.textContent = '';
  const totalText = document.createTextNode(`${containerSize.toLocaleString()} bytes total \u2014 `);
  const realSpan = document.createElement('span');
  realSpan.className = 'text-vault-crimson';
  realSpan.textContent = '\u25A0';
  const realLabel = document.createTextNode(' real message ');
  const decoySpan = document.createElement('span');
  decoySpan.className = 'text-vault-amber ml-2';
  decoySpan.textContent = '\u25A0';
  const decoyLabel = document.createTextNode(' decoy message ');
  const padSpan = document.createElement('span');
  padSpan.className = 'text-vault-text-muted ml-2';
  padSpan.textContent = '\u25A0';
  const padLabel = document.createTextNode(` ${paddingBytes.toLocaleString()} bytes indistinguishable padding`);
  statsEl.append(totalText, realSpan, realLabel, decoySpan, decoyLabel, padSpan, padLabel);
}

export function hideVisualizer(): void {
  const vizEl = document.getElementById('container-visualizer');
  if (vizEl) vizEl.classList.add('hidden');
}
