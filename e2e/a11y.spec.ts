import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the Rust crypto KATs;
 * this gates them on accessibility the same way. Scans the full page — both
 * tab panels, every collapsible section expanded, in both themes — so the
 * whole surface a keyboard/AT user can reach is covered.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** Neutralize transitions/animations so nothing is mid-fade when axe samples color. */
async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{transition:none!important;animation:none!important}`,
  });
}

/**
 * Reveal every panel axe should see: open the Argon2 params section, un-hide
 * both tab panels and their result/progress regions, and drop `hidden` on any
 * class-toggled container so its contents are in the accessibility tree.
 */
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) d.open = true;

    // Un-collapse the Argon2id parameters panel.
    document.getElementById('params-panel')?.classList.remove('hidden');
    document
      .getElementById('btn-toggle-params')
      ?.setAttribute('aria-expanded', 'true');

    // Show both tab panels at once so decrypt-side markup is scanned too.
    for (const id of ['panel-encrypt', 'panel-decrypt']) {
      document.getElementById(id)?.classList.remove('hidden');
    }

    // Reveal progress / result / visualizer / download regions that start hidden.
    for (const id of [
      'encrypt-progress',
      'container-visualizer',
      'download-section',
      'decrypt-progress',
      'decrypt-result',
      'file-info',
    ]) {
      document.getElementById(id)?.classList.remove('hidden');
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function primePage(page: Page): Promise<void> {
  await page.goto('.');
  // Let the WASM engine load and the self-test render its status text so the
  // footer status line is in its final (colored) state when we scan.
  await expect(page.locator('#self-test-status')).toContainText(
    /self-test passed|FAILED/,
    { timeout: 30_000 },
  );
  await killMotion(page);
  await revealAll(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await primePage(page);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await primePage(page);
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealAll(page);
  await scan(page);
});
