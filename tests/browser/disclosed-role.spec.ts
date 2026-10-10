import { expect, test } from '@playwright/test';

for (const width of [1280, 380, 320]) {
  test(`disclosed-role limitation stays visible in the real coercion flow at ${width}px`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    await expect(page.locator('#self-test-status')).toContainText('self-test passed');
    await expect(page.locator('#role-privacy-warning')).toBeVisible();
    await expect(page.locator('#role-privacy-warning')).toContainText('classify a disclosed passphrase as real or decoy');
    await page.click('#btn-toggle-params');
    for (const [id, value] of [['memory', '16'], ['iterations', '2'], ['parallelism', '1']]) {
      await page.locator('#param-' + id).fill(value);
      await page.locator('#param-' + id).dispatchEvent('input');
    }
    await page.check('input[name="container-size"][value="4096"]');
    await page.fill('#real-passphrase', 'strong-real-demo');
    await page.fill('#decoy-passphrase', 'weak-decoy-demo');
    await page.fill('#real-message', 'secret message');
    await page.fill('#decoy-message', 'decoy message');
    await page.click('#btn-encrypt');
    await expect(page.locator('#coercion-section')).toBeVisible({ timeout: 120000 });
    await expect(page.locator('#coercion-section')).toContainText('role privacy');
    await page.click('#btn-coercion-demo');
    await expect(page.locator('#btn-coercion-demo')).toContainText('SCENARIO COMPLETE', { timeout: 120000 });
    await expect(page.locator('#coercion-steps [role=region]')).toHaveCount(2);
    await expect(page.locator('#coercion-steps [role=region]').nth(0)).toHaveText('decoy message');
    await expect(page.locator('#coercion-steps [role=region]').nth(1)).toHaveText('secret message');
    await expect(page.locator('#coercion-steps')).toContainText('authenticated decoy role');
    await expect(page.locator('#coercion-steps')).not.toContainText('this is the whole vault');
    await page.click('#btn-how-it-works');
    await expect(page.locator('#modal-how')).toContainText('classify the disclosed role');
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
    expect(errors).toEqual([]);
  });
}
