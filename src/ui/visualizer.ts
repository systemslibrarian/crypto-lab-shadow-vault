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
  statsEl.innerHTML = `
    ${containerSize.toLocaleString()} bytes total —
    <span class="text-vault-crimson">■</span> real message
    <span class="text-vault-amber ml-2">■</span> decoy message
    <span class="text-vault-text-muted ml-2">■</span> ${paddingBytes.toLocaleString()} bytes indistinguishable padding
  `;
}

export function hideVisualizer(): void {
  const vizEl = document.getElementById('container-visualizer');
  if (vizEl) vizEl.classList.add('hidden');
}
