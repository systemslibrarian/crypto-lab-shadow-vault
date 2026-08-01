/**
 * Argon2id parameter tuning panel UI.
 */
import type { Argon2Params } from '../types/vault.js';
import { RECOMMENDED_PARAMS, validateParams } from '../types/vault.js';
import { benchmarkArgon2 } from '../crypto/wasm.js';

/** Human-readable duration for very large second counts. */
function humanizeSeconds(seconds: number): string {
  if (!Number.isFinite(seconds)) return 'longer than the universe has existed';
  const YEAR = 365.25 * 24 * 3600;
  if (seconds < 1) return '< 1 second';
  if (seconds < 60) return `${seconds.toFixed(0)} seconds`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(0)} minutes`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hours`;
  if (seconds < YEAR) return `${(seconds / 86400).toFixed(0)} days`;
  const years = seconds / YEAR;
  if (years < 1e3) return `${years.toFixed(0)} years`;
  if (years < 1e6) return `${(years / 1e3).toFixed(0)} thousand years`;
  if (years < 1e9) return `${(years / 1e6).toFixed(0)} million years`;
  if (years < 1e12) return `${(years / 1e9).toFixed(0)} billion years`;
  if (years < 1e15) return `${(years / 1e12).toFixed(0)} trillion years`;
  return 'longer than the universe has existed';
}

let currentParams: Argon2Params = { ...RECOMMENDED_PARAMS };

export function getParams(): Argon2Params {
  return { ...currentParams };
}

export function initParams(): void {
  const btnToggle = document.getElementById('btn-toggle-params')!;
  const panel = document.getElementById('params-panel')!;
  const toggleIcon = document.getElementById('params-toggle-icon')!;

  const memSlider = document.getElementById('param-memory') as HTMLInputElement;
  const iterSlider = document.getElementById('param-iterations') as HTMLInputElement;
  const parSlider = document.getElementById('param-parallelism') as HTMLInputElement;

  const memVal = document.getElementById('param-memory-val')!;
  const memKib = document.getElementById('param-memory-kib')!;
  const iterVal = document.getElementById('param-iterations-val')!;
  const parVal = document.getElementById('param-parallelism-val')!;

  const displayMem = document.getElementById('param-display-mem')!;
  const displayIter = document.getElementById('param-display-iter')!;
  const displayPar = document.getElementById('param-display-par')!;

  const warnings = document.getElementById('param-warnings')!;
  const estimate = document.getElementById('param-estimate')!;
  const attackReadout = document.getElementById('param-attacker-cost');
  const btnDefaults = document.getElementById('btn-restore-defaults')!;

  let isOpen = false;
  let benchmarkTimeout: ReturnType<typeof setTimeout> | null = null;
  let benchRunId = 0;

  btnToggle.addEventListener('click', () => {
    isOpen = !isOpen;
    panel.classList.toggle('hidden', !isOpen);
    btnToggle.setAttribute('aria-expanded', String(isOpen));
    toggleIcon.textContent = isOpen ? '▾ close' : '▸ tune';
    if (isOpen) runBenchmark();
  });

  function updateDisplay() {
    const memMB = parseInt(memSlider.value);
    const iter = parseInt(iterSlider.value);
    const par = parseInt(parSlider.value);

    currentParams = {
      memory: memMB * 1024,
      iterations: iter,
      parallelism: par,
      hashLength: 64,
    };

    memVal.textContent = String(memMB);
    memKib.textContent = String(memMB * 1024);
    iterVal.textContent = String(iter);
    parVal.textContent = String(par);

    displayMem.textContent = `${memMB} MB`;
    displayIter.textContent = String(iter);
    displayPar.textContent = String(par);

    // Validate and show warnings
    const errors = validateParams(currentParams);
    if (errors.length > 0) {
      warnings.classList.remove('hidden');
      warnings.textContent = '';
      errors.forEach((e, i) => {
        if (i > 0) warnings.appendChild(document.createElement('br'));
        warnings.appendChild(document.createTextNode(`\u26A0 ${e}`));
      });
    } else {
      warnings.classList.add('hidden');
      warnings.textContent = '';
    }

    // Debounce benchmark
    if (benchmarkTimeout) clearTimeout(benchmarkTimeout);
    benchmarkTimeout = setTimeout(runBenchmark, 500);
  }

  async function runBenchmark() {
    // Run ONE real Argon2id derivation on this device and report the measured
    // wall-clock time — no hard-coded formula. Then derive an honest attacker
    // cost from that measurement.
    const runId = ++benchRunId;
    estimate.textContent = 'measuring…';
    if (attackReadout) attackReadout.textContent = '';

    let msPerGuess: number;
    try {
      msPerGuess = await benchmarkArgon2(
        currentParams.memory,
        currentParams.iterations,
        currentParams.parallelism,
      );
    } catch {
      if (runId === benchRunId) estimate.textContent = 'measurement unavailable';
      return;
    }

    // A slower/faster later run may have superseded this one.
    if (runId !== benchRunId) return;

    estimate.textContent = `${(msPerGuess / 1000).toFixed(2)}s (measured on this device)`;

    if (attackReadout) {
      // Attacker cost = time per guess × number of guesses to exhaust the
      // keyspace. Expected work is half the keyspace, so 2^(bits-1) guesses.
      // This is single-machine; real attackers parallelize, but the point is
      // how tuning the KDF moves the exponent's coefficient.
      const secPerGuess = msPerGuess / 1000;
      const guesses40 = Math.pow(2, 40 - 1);
      const guesses60 = Math.pow(2, 60 - 1);
      attackReadout.textContent = '';
      const intro = document.createTextNode(
        'At this cost, one machine brute-forcing a passphrase would need about ',
      );
      const s40 = document.createElement('span');
      s40.className = 'text-vault-text font-mono';
      s40.textContent = humanizeSeconds(secPerGuess * guesses40);
      const mid = document.createTextNode(' for 40 bits of entropy, or ');
      const s60 = document.createElement('span');
      s60.className = 'text-vault-text font-mono';
      s60.textContent = humanizeSeconds(secPerGuess * guesses60);
      const end = document.createTextNode(
        ' for 60 bits. Deniability holds only while BOTH passphrases sit on the far side of that wall — raise memory to push it further.',
      );
      // The figures above model one machine exhausting a keyspace from scratch,
      // which badly understates a precomputing adversary: Shadow Vault's salt is
      // a constant (SHA-256 of the role string), so the whole world shares two
      // salts and the table is built once, ever. See THREAT_MODEL.md §2.9.
      const caveat = document.createElement('span');
      caveat.className = 'block mt-2 text-vault-crimson';
      caveat.textContent =
        'Caveat: that is one machine starting from scratch. Shadow Vault has no per-container salt — the headerless format has nowhere to put one, so every container in the world shares the same two salts. An attacker who has already built an Argon2id dictionary at these parameters replays it against your container for free. Read the numbers above as the cost of being the FIRST attacker, not the cost of attacking you. Only passphrase entropy stands behind that. (THREAT_MODEL.md §2.9)';
      attackReadout.append(intro, s40, mid, s60, end, caveat);
    }
  }

  memSlider.addEventListener('input', updateDisplay);
  iterSlider.addEventListener('input', updateDisplay);
  parSlider.addEventListener('input', updateDisplay);

  btnDefaults.addEventListener('click', () => {
    memSlider.value = '64';
    iterSlider.value = '3';
    parSlider.value = '4';
    updateDisplay();
  });
}
