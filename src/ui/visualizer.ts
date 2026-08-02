/**
 * Container memory map visualizer.
 *
 * Teaches the single most important claim of the format — "the whole container
 * is indistinguishable from random noise" — by ANIMATING its lifecycle instead
 * of only showing the end state:
 *
 *   1. All cells paint as flickering random noise (the CSPRNG-filled container).
 *   2. The real + decoy slots "write in" at their derived offsets, overwriting
 *      noise (structure appears).
 *   3. The slot colours fade BACK to noise-grey (structure dissolves).
 *   4. A "What an attacker sees" toggle removes the legend entirely so the map
 *      becomes uniform random cells — the insider view vs. the attacker view.
 *
 * The visualiser is decorative (aria-hidden); the surrounding caption carries
 * the meaning for assistive tech.
 */

const TOTAL_CELLS = 512;

type CellType = 'padding' | 'real' | 'decoy';

interface VizState {
  cells: CellType[];
  containerSize: number;
  paddingBytes: number;
  attackerView: boolean;
}

let state: VizState | null = null;

/** A short pseudo-random noise-grey for a cell, so noise cells shimmer. */
function noiseShade(): string {
  // Keep within a tight band around the surface grey so it reads as texture,
  // not as structure. Range chosen to stay AA-irrelevant (decorative).
  const v = 60 + Math.floor(Math.random() * 60); // 60..119
  return `rgb(${v},${v},${v})`;
}

function computeCells(
  containerSize: number,
  realOffset: number,
  decoyOffset: number,
): CellType[] {
  const slotSize = Math.floor(containerSize / 3);
  const slotWithTag = slotSize + 16;
  const bytesPerCell = containerSize / TOTAL_CELLS;
  const cells: CellType[] = new Array(TOTAL_CELLS).fill('padding');

  for (let i = 0; i < TOTAL_CELLS; i++) {
    const byteStart = Math.floor(i * bytesPerCell);
    const byteEnd = Math.floor((i + 1) * bytesPerCell);
    if (byteEnd > realOffset && byteStart < realOffset + slotWithTag) {
      cells[i] = 'real';
    }
    if (byteEnd > decoyOffset && byteStart < decoyOffset + slotWithTag) {
      cells[i] = 'decoy';
    }
  }
  return cells;
}

function paintCaption(): void {
  const statsEl = document.getElementById('container-stats');
  if (!statsEl || !state) return;
  statsEl.textContent = '';

  if (state.attackerView) {
    // The whole point: with the legend removed, the insider structure vanishes.
    const t = document.createTextNode(
      `${state.containerSize.toLocaleString()} bytes — with no passphrase, every cell is `,
    );
    const em = document.createElement('span');
    em.className = 'text-vault-text';
    em.textContent = 'uniform random noise';
    const t2 = document.createTextNode(
      '. The bytes do not mark the slot locations or contents; the recognized file size and Shadow Vault format still imply that two slots exist.',
    );
    statsEl.append(t, em, t2);
    return;
  }

  const totalText = document.createTextNode(
    `${state.containerSize.toLocaleString()} bytes total — `,
  );
  const realSpan = document.createElement('span');
  realSpan.className = 'text-vault-crimson';
  realSpan.textContent = '■';
  const realLabel = document.createTextNode(' real message ');
  const decoySpan = document.createElement('span');
  decoySpan.className = 'text-vault-amber ml-2';
  decoySpan.textContent = '■';
  const decoyLabel = document.createTextNode(' decoy message ');
  const padSpan = document.createElement('span');
  padSpan.className = 'text-vault-text-muted ml-2';
  padSpan.textContent = '■';
  const padLabel = document.createTextNode(
    ` ${state.paddingBytes.toLocaleString()} bytes random padding`,
  );
  statsEl.append(
    totalText,
    realSpan,
    realLabel,
    decoySpan,
    decoyLabel,
    padSpan,
    padLabel,
  );
}

/** Re-colour every cell for the current view (insider = coloured slots, attacker = all noise). */
function repaintCells(instant: boolean): void {
  const mapEl = document.getElementById('container-map');
  if (!mapEl || !state) return;
  const children = mapEl.children;
  for (let i = 0; i < children.length; i++) {
    const cell = children[i] as HTMLElement;
    const type = state.cells[i];
    cell.style.boxShadow = '';
    if (state.attackerView || type === 'padding') {
      cell.className = 'container-cell';
      cell.style.backgroundColor = noiseShade();
    } else if (type === 'real') {
      cell.className = 'container-cell container-cell--real';
      cell.style.backgroundColor = '';
    } else {
      cell.className = 'container-cell container-cell--decoy';
      cell.style.backgroundColor = '';
    }
    if (instant) cell.style.transition = 'none';
  }
}

export function renderVisualizer(
  containerSize: number,
  realOffset: number,
  decoyOffset: number,
): void {
  const mapEl = document.getElementById('container-map')!;
  const statsEl = document.getElementById('container-stats')!;
  const vizEl = document.getElementById('container-visualizer')!;
  const toggleWrap = document.getElementById('viz-view-toggle');
  const toggleBtn = document.getElementById('btn-attacker-view') as HTMLButtonElement | null;

  vizEl.classList.remove('hidden');

  const slotSize = Math.floor(containerSize / 3);
  const slotWithTag = slotSize + 16;
  const paddingBytes = containerSize - slotWithTag * 2;

  const cells = computeCells(containerSize, realOffset, decoyOffset);
  state = { cells, containerSize, paddingBytes, attackerView: false };

  const prefersReducedMotion = window.matchMedia(
    '(prefers-reduced-motion: reduce)',
  ).matches;

  // Build the 512 noise cells up front.
  mapEl.innerHTML = '';
  const cellEls: HTMLElement[] = [];
  for (let i = 0; i < TOTAL_CELLS; i++) {
    const cell = document.createElement('div');
    cell.className = 'container-cell';
    cell.setAttribute('aria-hidden', 'true');
    cell.style.backgroundColor = noiseShade();
    mapEl.appendChild(cell);
    cellEls.push(cell);
  }

  // Reset the attacker-view toggle to the insider view each run.
  if (toggleWrap) toggleWrap.classList.remove('hidden');
  if (toggleBtn) {
    toggleBtn.setAttribute('aria-pressed', 'false');
    toggleBtn.textContent = 'What an attacker sees';
  }

  if (prefersReducedMotion) {
    // No animation: go straight to the informative insider view.
    repaintCells(true);
    paintCaption();
    return;
  }

  // --- Animate the lifecycle ---

  // Phase A: flicker the whole field as random noise for ~700ms.
  let flickerTicks = 0;
  const flicker = setInterval(() => {
    for (const cell of cellEls) cell.style.backgroundColor = noiseShade();
    flickerTicks += 1;
    if (flickerTicks >= 5) {
      clearInterval(flicker);
      writeSlots();
    }
  }, 130);

  // Phase B: the slots "write in" at their offsets, cell by cell.
  function writeSlots(): void {
    if (!state) return;
    const slotIndices = cellEls
      .map((_, i) => i)
      .filter((i) => state!.cells[i] !== 'padding');

    let n = 0;
    const writer = setInterval(() => {
      if (n >= slotIndices.length) {
        clearInterval(writer);
        // Insider view is now fully painted; show the caption, then dissolve.
        paintCaption();
        setTimeout(dissolve, 900);
        return;
      }
      const idx = slotIndices[n];
      const cell = cellEls[idx];
      const type = state!.cells[idx];
      cell.style.transition = 'background-color 0.25s ease';
      cell.style.backgroundColor = '';
      cell.className =
        type === 'real'
          ? 'container-cell container-cell--real'
          : 'container-cell container-cell--decoy';
      n += 1;
    }, 22);
  }

  // Phase C: fade the coloured slots BACK to noise-grey — the structure
  // dissolves into indistinguishability. Then flip on the attacker view label
  // hint by leaving the insider caption in place (toggle restores structure).
  function dissolve(): void {
    if (!state) return;
    for (let i = 0; i < cellEls.length; i++) {
      if (state.cells[i] === 'padding') continue;
      const cell = cellEls[i];
      cell.style.transition = 'background-color 0.6s ease';
      cell.className = 'container-cell';
      cell.style.backgroundColor = noiseShade();
    }
    // After the dissolve, the field is uniform noise — this IS the attacker
    // view. Reflect that in state + caption so the toggle round-trips cleanly.
    setTimeout(() => {
      if (!state) return;
      state.attackerView = true;
      if (toggleBtn) {
        toggleBtn.setAttribute('aria-pressed', 'true');
        toggleBtn.textContent = 'Show me where the messages are';
      }
      paintCaption();
    }, 650);
  }

  // Also refresh caption so the region isn't empty during the animation.
  statsEl.textContent = '';
}

/** Toggle between the insider view (coloured slots) and the attacker view (uniform noise). */
export function toggleAttackerView(): void {
  if (!state) return;
  state.attackerView = !state.attackerView;
  const toggleBtn = document.getElementById('btn-attacker-view');
  if (toggleBtn) {
    toggleBtn.setAttribute('aria-pressed', String(state.attackerView));
    toggleBtn.textContent = state.attackerView
      ? 'Show me where the messages are'
      : 'What an attacker sees';
  }
  repaintCells(false);
  paintCaption();
}

export function hideVisualizer(): void {
  const vizEl = document.getElementById('container-visualizer');
  if (vizEl) vizEl.classList.add('hidden');
  const toggleWrap = document.getElementById('viz-view-toggle');
  if (toggleWrap) toggleWrap.classList.add('hidden');
  state = null;
}
