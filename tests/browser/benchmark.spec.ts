import { expect, test, type Page } from '@playwright/test';

// Real Worker for positive controls. Negative controls replace only benchmark
// responses; initialization, self-test, encryption and opening remain real.
async function observeWorker(page: Page, mode: string | null = null) {
  await page.addInitScript(({ mode }) => {
    const NativeWorker = Worker;
    const calls: { command: string; args: Record<string, number> }[] = [];
    (window as any).__benchmarkCalls = calls;
    let sample = 0;
    (window as any).Worker = class extends NativeWorker {
      postMessage(message: any, transfer?: Transferable[]) {
        calls.push({ command: message.command, args: { memoryKib: message.args?.memoryKib, iterations: message.args?.iterations, parallelism: message.args?.parallelism } });
        if (message.command === 'benchmark_argon2' && mode) {
          const value = [1000, 30, 10, 20][sample++ % 4];
          let result: any = { ...message.args, derivationMs: value, derivations: 1 };
          if (mode === 'partial') result = { derivationMs: value };
          if (mode === 'nonfinite') result.derivationMs = NaN;
          if (mode === 'zero') result.derivationMs = 0;
          if (mode === 'wrong-parameters') result.memoryKib += 1024;
          if (mode === 'extra-derivation') result.derivations = 2;
          const data = mode === 'provider-error' ? { id: message.id, error: 'Deliberate benchmark fixture failure' } : { id: message.id, result };
          const reply = () => this.dispatchEvent(new MessageEvent('message', { data }));
          if (mode === 'delayed-final' && sample === 4) {
            // Hold the old run's final sample until a slider changes. Release
            // it inside the debounce window, before the new run can start.
            (window as any).__releaseBenchmark = reply;
          } else {
            setTimeout(reply, 2);
          }
          return;
        }
        super.postMessage(message, transfer ?? []);
      }
    };
  }, { mode });
}

for (const width of [1280, 380, 320]) {
  test(`real single-derivation benchmark uses dedicated calls at ${width}px`, async ({ page }) => {
    await observeWorker(page);
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    await expect(page.locator('#self-test-status')).toContainText('self-test passed');
    await page.click('#btn-toggle-params');
    await expect(page.locator('#param-attacker-cost')).not.toHaveText('', { timeout: 30000 });
    await expect(page.locator('#param-estimate')).toContainText('median of 3');
    let calls = await page.evaluate(() => (window as any).__benchmarkCalls);
    expect(calls.map((c: any) => c.command)).toEqual(Array(4).fill('benchmark_argon2'));
    expect(calls.every((c: any) => c.args.memoryKib === 65536 && c.args.iterations === 3 && c.args.parallelism === 4)).toBe(true);
    await page.evaluate(() => { (window as any).__benchmarkCalls.length = 0; });
    for (const [id, value] of [['memory', '16'], ['iterations', '2'], ['parallelism', '1']]) {
      await page.locator('#param-' + id).fill(value);
      await page.locator('#param-' + id).dispatchEvent('input');
    }
    await expect(page.locator('#param-estimate')).toHaveText('measuring…');
    await expect(page.locator('#param-attacker-cost')).toHaveText('');
    await expect(page.locator('#param-estimate')).toContainText('median of 3', { timeout: 120000 });
    calls = await page.evaluate(() => (window as any).__benchmarkCalls);
    expect(calls.map((c: any) => c.command)).toEqual(Array(4).fill('benchmark_argon2'));
    expect(calls.every((c: any) => c.args.memoryKib === 16384 && c.args.iterations === 2 && c.args.parallelism === 1)).toBe(true);
    await expect(page.locator('#param-attacker-cost')).toContainText('starting from scratch');
    await expect(page.locator('#param-attacker-cost')).toContainText('not a measured attacker throughput');
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
  });
}

test('warmup is excluded and repeated sample median is used', async ({ page }) => {
  await observeWorker(page, 'median');
  await page.goto('.');
  await expect(page.locator('#self-test-status')).toContainText('self-test passed');
  await page.click('#btn-toggle-params');
  await expect(page.locator('#param-estimate')).toHaveText('0.02s (median of 3; one warm-up excluded)');
  expect(await page.evaluate(() => (window as any).__benchmarkCalls.length)).toBe(4);
});

test('an old response cannot label new parameters during the debounce window', async ({ page }) => {
  await observeWorker(page, 'delayed-final');
  await page.goto('.');
  await expect(page.locator('#self-test-status')).toContainText('self-test passed');
  await page.click('#btn-toggle-params');
  await page.waitForFunction(() => typeof (window as any).__releaseBenchmark === 'function');
  const beforeNextRun = await page.evaluate(async () => {
    const slider = document.getElementById('param-memory') as HTMLInputElement;
    slider.value = '32';
    slider.dispatchEvent(new Event('input', { bubbles: true }));
    (window as any).__releaseBenchmark();
    await new Promise(resolve => setTimeout(resolve, 30));
    return {
      estimate: document.getElementById('param-estimate')?.textContent,
      cost: document.getElementById('param-attacker-cost')?.textContent,
      calls: (window as any).__benchmarkCalls.length,
    };
  });
  expect(beforeNextRun).toEqual({ estimate: 'measuring…', cost: '', calls: 4 });
  await expect(page.locator('#param-estimate')).toHaveText('0.02s (median of 3; one warm-up excluded)');
  const calls = await page.evaluate(() => (window as any).__benchmarkCalls);
  expect(calls.length).toBe(8);
  expect(calls.slice(4).every((c: any) => c.args.memoryKib === 32768)).toBe(true);
});

for (const mode of ['partial', 'nonfinite', 'zero', 'wrong-parameters', 'extra-derivation', 'provider-error']) {
  test(`invalid ${mode} benchmark evidence cannot produce a cost claim`, async ({ page }) => {
    await observeWorker(page, mode);
    await page.goto('.');
    await expect(page.locator('#self-test-status')).toContainText('self-test passed');
    await page.click('#btn-toggle-params');
    await expect(page.locator('#param-estimate')).toHaveText('measurement unavailable');
    await expect(page.locator('#param-attacker-cost')).toHaveText('');
    await expect(page.locator('#self-test-status')).toContainText('self-test passed');
    expect(await page.evaluate(() => (window as any).__benchmarkCalls.length)).toBe(1);
  });
}

test('controlled samples wait for real initialization on a slow WASM connection', async ({ page }) => {
  await observeWorker(page, 'median');
  let delayedLoads = 0;
  await page.context().route('**/shadow_vault_crypto_bg.wasm', async route => {
    delayedLoads++;
    await new Promise(resolve => setTimeout(resolve, 1000));
    await route.continue();
  });
  await page.goto('.');
  await expect(page.locator('#self-test-status')).toContainText('self-test passed');
  expect(delayedLoads).toBe(1);
  await page.click('#btn-toggle-params');
  await expect(page.locator('#param-estimate')).toHaveText('0.02s (median of 3; one warm-up excluded)');
  expect(await page.evaluate(() => (window as any).__benchmarkCalls.length)).toBe(4);
});
