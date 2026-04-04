/**
 * Argon2id parameter tuning panel UI.
 */
import type { Argon2Params } from '../types/vault.js';
import { RECOMMENDED_PARAMS, validateParams } from '../types/vault.js';

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
  const btnDefaults = document.getElementById('btn-restore-defaults')!;

  let isOpen = false;
  let benchmarkTimeout: ReturnType<typeof setTimeout> | null = null;

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
    // Rough estimate based on params — actual timing depends on hardware.
    // Argon2id with 64MB/3iter/4par typically takes 1-3s in WASM.
    const memFactor = currentParams.memory / 65536;
    const iterFactor = currentParams.iterations / 3;
    const baseMs = 1500; // ~1.5s baseline for 64MB/3iter
    const estimatedMs = baseMs * memFactor * iterFactor;
    estimate.textContent = `~${(estimatedMs / 1000).toFixed(1)}s (est.)`;
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
