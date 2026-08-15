import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, encrypt
 * tab active, every derived-state region hidden and both primary buttons
 * disabled behind the WASM self-test; both skip links focused — with an
 * occlusion check, because this page's own skip link used to slide UNDER the
 * sticky top bar (`focus:z-50` vs `z-index:1000`); the passphrase eye toggle
 * pressed; the strength meter on a weak and a strong passphrase; the
 * identical-passphrase and oversized-message errors; the Argon2id params
 * panel open with a genuinely measured derivation cost, driven to its legal
 * 16 MB floor for the RFC 9106 warning and restored; a real vault derived
 * through the Argon2id/ChaCha20-Poly1305 worker, its container map asserted
 * to be in the reduced-motion end state, flipped to the attacker view; the
 * coercion scenario played out with two more real derivations; the container
 * downloaded, fed back through the decrypt tab's drop zone, refused with a
 * wrong passphrase (the deliberately uniform verdict) and opened with the
 * real one — the decrypted text asserted to BE the message that went in; the
 * How It Works modal; hover on the buttons that repaint their fill; and
 * finally the theme switched live through the shared bar with everything on
 * screen. Every one of those states is scanned, in both themes, at desktop
 * and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page (`visualizer.ts`
 * branches on `matchMedia`, which the old gate's style tag could not reach,
 * and its animation is `setInterval` chains that style tag never touched
 * anyway), why no region is revealed from script (the old gate scanned eight
 * force-revealed EMPTY regions), why the lab's defaults are asserted rather
 * than assumed, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
