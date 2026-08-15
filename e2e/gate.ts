import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects something the gate
 * this replaces did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec's
 *     `killMotion()` pushed `transition:none!important; animation:none!important`
 *     through `addStyleTag`. That BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it —
 *     and on this page that block is not the only thing motion depends on.
 *     `visualizer.ts` reads `matchMedia('(prefers-reduced-motion: reduce)')` in
 *     JavaScript and, when it matches, SKIPS the whole container-map lifecycle
 *     (flicker, slot write-in, dissolve — all `setInterval` chains a style tag
 *     cannot touch anyway) and paints the insider end state directly. So the old
 *     gate froze CSS transitions while the JS animation it thought it had killed
 *     ran anyway, and it never once produced the reduced-motion rendering that a
 *     reader with the preference set is the only rendering to ever see. This
 *     gate sets the preference through `emulateMedia`, asserts from inside the
 *     page that it took effect, and injects nothing.
 *
 *  2. NO STATE IS REACHED FROM SCRIPT. `revealAll()` stripped the `hidden` class
 *     off EIGHT regions at once — both tab panels side by side, the progress
 *     logs, the visualizer, the coercion section, the download section — and
 *     forced `params-panel` open with `classList.remove`. Every one of those
 *     regions was EMPTY: no vault had been derived, so it scanned a blank
 *     `#encrypt-steps`, a container map with zero cells, a coercion section with
 *     no scenario, a decrypt result with no message — renderings no reader can
 *     ever see, in place of the populated ones every reader who derives a vault
 *     does see. This drive reaches every region through the control a reader
 *     has: it types the passphrases, derives a real vault through the WASM
 *     worker, plays the coercion scenario, downloads the container and decrypts
 *     it back on the other tab.
 *
 *  3. EVERY ERROR AND FAILED-VERDICT STATE IS A STATE. Identical passphrases
 *     paint the deniability alert; an oversized message paints the length
 *     alert; sub-recommended Argon2id parameters paint the RFC 9106 warning; a
 *     wrong passphrase paints the deliberately uniform "No message found"
 *     verdict. None of those existed in the old gate's single forced rendering.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. The surfaces axe
 *     declines to judge here include everything composited over the body's
 *     `url()` noise texture, the top bar's `color-mix()` ink and edges, and the
 *     hero aside's `color-mix(in oklab, …)` wash — all filed under `incomplete`
 *     rather than judged. So is `aria-prohibited-attr`, where an `aria-label`
 *     on a role-less element hides.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR OCCLUSION ORACLE. axe has no
 *     reflow rule at all, so the 380px half of this gate is the only thing
 *     standing between a wide flex row and a sideways-scrolling phone. axe has
 *     no non-text-contrast rule either — `nontext.ts` judges every control
 *     boundary on this form-heavy page. And nothing in axe notices a focused
 *     element painting UNDERNEATH a sticky header, which is exactly what this
 *     lab's own skip link did: `focus:z-50` under the top bar's `z-index:1000`
 *     (see `expectFocusedOnTop`).
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it: elsewhere in
 * this fleet that produced a phantom 2.00:1 failure on a button whose settled
 * ratio is 9:1. Transitions also drain in waves rather than in one batch, so a
 * poll for "nothing running right now" can exit through a gap between waves —
 * hence six consecutive quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish (`iterations: Infinity`) are excluded from the
 * quiescence test rather than waited on, a wall-clock budget inside the page
 * gives up and proceeds, and Playwright's own timeout is the backstop.
 *
 * Under the reduced motion this gate asserts, `style.css`'s
 * `* { transition-duration: 0ms !important; animation-duration: 0ms !important }`
 * means Chromium still creates zero-duration transition Animation objects that
 * finish within a frame, and `getAnimations()` is quiet by the sixth. It is
 * still load-bearing: this page repaints `transition-colors` on nearly every
 * control, and a scan that raced one would measure a colour no settled state
 * has. The container-map lifecycle is `setInterval` chains the Animation API
 * cannot see at all — which is why the drive waits on each flow's own
 * completion signal (a step marked done, a caption painted, a verdict rendered)
 * rather than on this alone.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * `style.css` cannot currently be in that shape, and this assertion is what
 * makes that a measurement rather than a reading. Its reduced-motion block was
 * read declaration by declaration: it zeroes `transition-duration` and
 * `animation-duration` and nothing else — no `opacity`, no `display`, no
 * `transform` — and the file declares no `@keyframes` at all. The one
 * JavaScript animation (`visualizer.ts`) branches on `matchMedia` and paints
 * its end state directly. The check runs in every state anyway, because all of
 * that is a property of the current stylesheet rather than of the page.
 *
 * `aria-hidden` subtrees are excluded; see the note on `ariaHidden` in
 * `contrast.ts` for what this lab hides (textless container-map cells, the
 * modal overlay, the top bar's decorative SVGs) and why that was enumerated.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. This lab's decrypt path deliberately catches EVERYTHING — a WASM
 * crash, a Worker timeout and a wrong passphrase all render the same "No
 * message found" verdict, by design (the error text must not leak container
 * validity) — so a genuinely thrown failure leaves a plausible-looking page
 * behind that a gate would scan and report green. Attach before `boot`, assert
 * after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  // One exact, named exemption, not a pattern: `index.html` declares
  // `frame-ancestors 'none'` in its meta CSP, and Chromium prints this exact
  // advisory on every load because that directive is only enforceable via an
  // HTTP header — which GitHub Pages cannot send. The directive is kept
  // deliberately (AUDIT.md §16 and SECURITY.md document it as the intended
  // policy, and a future host that CAN send headers would copy it from here),
  // so the advisory is deterministic boot noise, not a page malfunction.
  // Anything else — including any other CSP message — still fails the gate.
  const KNOWN =
    "console.error: The Content Security Policy directive 'frame-ancestors' is ignored when delivered via a <meta> element.";
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    const entry = `console.error: ${m.text()}`;
    if (entry === KNOWN) return;
    errors.push(entry);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * This page ships two `<header>`s: the shared `.cl-topbar` with an explicit
 * `role="banner"`, and the lab's own `.cl-hero` — which sits inside
 * `<div id="app">`, NOT inside sectioning content, so it implies `banner` on
 * its own. The single banner is therefore not a property of the markup; it
 * depends entirely on the shared bar's `dedupeBanner()` demoting the hero to
 * `role="group"` on `DOMContentLoaded`. Asserting the OUTCOME rather than
 * either mechanism is what catches a change to that ordering.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * An explicit role on a list REPLACES its implicit `list` role, orphaning every
 * `<li>` under it — and a redundant `role="list"` makes axe apply
 * `aria-required-children`, which fails whenever the list is empty. Neither is
 * reliably visible to a source grep, because a role can be assigned as a JS
 * property in an element-creation helper rather than as markup. Ask the DOM.
 *
 * This lab has two lists — the modal's "cannot protect against" `<ul>` and its
 * related-projects `<ul>` — and neither carries a role. They are also never
 * empty, which is a property of the content, not of the code, and is exactly
 * why the assertion is cheap enough to keep.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els.map(
      (e) => `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
    )
  );
  expect(broken, 'an explicit role on a list deletes its list semantics').toEqual([]);
}

/**
 * A focused element must actually be ON TOP where it lands (WCAG 2.4.7 — a
 * focus indicator painted underneath an opaque sticky bar is not visible).
 *
 * No other oracle can see this. axe has no occlusion rule; the contrast walk
 * measures the element's own composite, not what paints OVER it; and
 * `expectNoInvisibleFocusTargets` checks opacity and box size, both of which
 * are fine for an element that is simply underneath something. `elementFromPoint`
 * at the element's own centre is the compositor's answer to "what would a click
 * here hit", which is the same question as "what does the reader see here".
 *
 * This is the check that caught this lab's own skip link: `focus:z-50` put its
 * focused rendering at `z-index: 50` while the sticky top bar it slides over
 * sits at `z-index: 1000` — a keyboard reader's very first Tab landed on a
 * control that painted nothing. The fix (`focus:z-[1002]`) is one class; this
 * assertion is what stops it quietly regressing.
 */
export async function expectFocusedOnTop(page: Page, selector: string, label: string): Promise<void> {
  const result = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return `no such element: ${sel}`;
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) return 'zero-size box';
    const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    if (!hit) return 'nothing at its centre';
    if (hit === el || el.contains(hit) || hit.contains(el)) return 'ok';
    return `covered by ${hit.tagName.toLowerCase()}.${(hit.getAttribute('class') ?? '').trim()}`;
  }, selector);
  expect(result, `the focused element must paint on top in state: ${label}`).toBe('ok');
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. That assertion is load-bearing in this repo
 * beyond the usual: `visualizer.ts` branches on `matchMedia` in JavaScript, so
 * if the emulation silently failed the gate would scan the mid-flicker noise
 * animation while claiming to scan the reduced-motion rendering.
 *
 * The theme is seeded through `localStorage` rather than by clicking the
 * toggle, which pins down a real failure mode as a side effect: `index.html`'s
 * anti-flash script reads `localStorage.getItem('theme')`, the shared bar's
 * toggle writes the same key, and this lab ALSO has a toggle of its own in
 * `main.ts` reading and writing it. All three agree on `'theme'`; if any
 * drifted, this boot fails on `data-theme` rather than quietly scanning dark
 * twice.
 *
 * The defaults are asserted at length because which half of this lab a scan
 * sees depends entirely on them: the encrypt tab is the shipped tab, every
 * derived-state region ships `hidden`, both primary buttons ship disabled
 * behind the WASM self-test, and the 8 KB container is the shipped size. A
 * navigation that resolves proves nothing here — the crypto engine loads in a
 * Worker after the fact, and a worker that failed leaves a permanently
 * disabled page that a scan reports as perfectly accessible.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);
  await assertListSemantics(page);

  // ── The page really rendered ────────────────────────────────────────────
  await expect(page.locator('main#main-content')).toHaveCount(1);
  await expect(page.locator('#app')).toHaveCount(1);

  // Both skip links exist and point at ids that exist. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it — a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run
  // says nothing about. This page has TWO, with DIFFERENT targets: the shared
  // bar's goes to `#app` and the lab's own goes to `#main-content`.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('a[href="#main-content"]')).toHaveCount(1);

  // ── The lab's own theme toggle is hidden, AND actually hidden ───────────
  // The shared bar hides every lab's in-page toggle with
  // `body :is(#theme-toggle,…) { display: none !important }`
  // and leaves the element in the DOM so `main.ts`'s theme code keeps working.
  // That is only correct if it is genuinely removed: `opacity: 0` with
  // `pointer-events: none` would leave a `<button>` at `tabIndex: 0`, tabbable
  // and invisible. Measured from the live element by trying to focus it,
  // rather than inferred from the CSS.
  expect(
    await page.evaluate(() => {
      const t = document.getElementById('theme-toggle');
      if (!t) return 'the lab theme toggle is missing entirely';
      t.focus();
      return document.activeElement === t ? 'it took focus while hidden' : 'ok';
    }),
    'the lab own theme toggle must be hidden in a way that also removes it from the tab order'
  ).toBe('ok');

  // ── The crypto engine is up and the self-test PASSED ────────────────────
  // The footer status is the only visible witness of the WASM worker's RFC
  // 8439 self-test, and everything the drive does depends on it. The gate this
  // replaces accepted /passed|FAILED/ — a page whose crypto just failed was a
  // perfectly acceptable thing to certify. It is not.
  await expect(page.locator('#self-test-status')).toContainText('Crypto self-test passed', {
    timeout: 60_000,
  });

  // ── Every shipped default ───────────────────────────────────────────────
  await expect(page.locator('#tab-encrypt')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#tab-decrypt')).toHaveAttribute('aria-selected', 'false');
  await expect(page.locator('#panel-encrypt')).toBeVisible();
  await expect(page.locator('#panel-decrypt')).toBeHidden();
  await expect(page.locator('input[name="container-size"][value="8192"]')).toBeChecked();
  await expect(page.locator('#btn-toggle-params')).toHaveAttribute('aria-expanded', 'false');
  await expect(page.locator('#params-panel')).toBeHidden();
  await expect(page.locator('#btn-encrypt')).toBeDisabled();
  await expect(page.locator('#btn-decrypt')).toBeDisabled();

  // Every derived-state region ships hidden and EMPTY — the regions the old
  // gate force-revealed and scanned blank.
  for (const id of [
    '#encrypt-progress',
    '#container-visualizer',
    '#coercion-section',
    '#download-section',
    '#decrypt-progress',
    '#decrypt-result',
    '#file-info',
  ]) {
    await expect(page.locator(id)).toBeHidden();
  }
  await expect(page.locator('#container-map > *')).toHaveCount(0);
  await expect(page.locator('#modal-how[open]')).toHaveCount(0);
  await expect(page.locator('#modal-overlay')).toBeHidden();
  await expect(page.locator('#real-strength-label')).not.toContainText('bits');

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all. The shapes at
 * risk on this page are its flex rows — the two-card message grid (which
 * collapses under `md:`), the radio row, the tab row, and the 512-cell
 * container map (`flex-wrap` on all of them is what this protects) — plus the
 * top bar, whose touch-target `min-width` is deliberately gated to
 * `min-width: 380px` for exactly this reason.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab's scrollers all satisfy the rule through their own content, which
 * is why the assertion is on the OUTCOME rather than any mechanism: the How It
 * Works dialog (`overflow-y-auto` at 90vh) holds links and its close button,
 * and a textarea is its own focus target. The assertion runs at every driven
 * state because scrollability is a property of the current content — the modal
 * only overflows once it is open at phone height.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden` DO
 * remove an element from the tab order, so those are skipped here rather than
 * flagged — the failure is specifically the invisible-but-tabbable pair.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks off the top edge and the
 * lab's own is `sr-only` (a 1×1 clipped box), and each becomes fully visible on
 * focus. The drive scans both focused — and `expectFocusedOnTop` is what
 * verifies the focused rendering actually reaches the screen.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      // display:none / visibility:hidden already remove it from the tab order.
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the
 * committed workflow, and a run with it set prints every finding as it happens
 * and then fails at the end, so a green collection run cannot be mistaken for
 * a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    // Generous, not 900: a truncated oracle dump is how a second and third
    // finding in the same state get missed on a collection pass.
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no
 * text node.
 *
 * IT IS CALLED FROM `scan()`, deliberately and not by accident. Fleet-wide
 * this oracle had been called from inside a soft wrapper AFTER its
 * `if (!COLLECTING) return` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves
 * clean on an oracle that had never looked. Calling it here means it runs at
 * every driven state, including `:hover`.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption. This
 * repo's baseline is empty — see `nontext-baseline.ts` for why that is a
 * measurement, not a hope.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the
 * point — or the drive stopped reaching the state that shows it, which is a
 * coverage regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Eight assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less element hides. This page depends on
 *    getting that right in several places: the drop zone pairs its
 *    `aria-label` with `role="button"`, the container map and the offset bar
 *    pair theirs with `role="img"`, and each coercion panel pairs its label
 *    with `role="region"`. Drop any of those roles and the label is silently
 *    discarded.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. On this form-heavy page it is the only
 *    oracle that judges an input's or the drop zone's boundary against the
 *    card OUTSIDE it.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - no focusable element that paints nothing — WCAG 2.4.3/2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has the shape they catch: a sticky `<header role="banner">` above a
  // `<div id="app">` that itself contains a demoted `<header class="cl-hero">`
  // with an `<aside class="cl-hero-why">` inside it, plus two `<nav>`s (one of
  // them doubling as the tablist) and a `<footer>`.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  // The `incomplete` bucket is asserted, not skimmed. `aria-prohibited-attr`
  // and `aria-required-children` appear ONLY here — never in `violations` — so
  // a gate that ignores this bucket cannot see either. Only `color-contrast`
  // is allowed to remain, and only because the arithmetic walk below judges
  // those ratios for real; no other rule is filtered out.
  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/** The gate's own vault material — asserted back out of the decrypt path. */
const REAL_PASS = 'gate-real-passphrase 7&Kq11';
const DECOY_PASS = 'gate-decoy-passphrase 3!Zx22';
const REAL_MSG = 'The real message the gate hid.';
const DECOY_MSG = 'A plausible decoy for the gate.';

/**
 * Prove a parameter change really re-ran the benchmark, then wait for it.
 *
 * `runBenchmark` performs a REAL `create_container` (two Argon2id derivations
 * at the current parameters) and only then paints the measured figure, so the
 * wait is on genuine work, not a timer. But the completion text is the same
 * wording before and after — "N.NNs (measured on this device)" — so a poll for
 * it after a change would happily accept the STALE figure. And the transient
 * `measuring…` cannot be polled for either: the benchmark is debounced 500ms
 * behind the slider and at the 16 MB floor finishes in ~130ms, so the whole
 * transient fits between two expect polls — the first collect run of this gate
 * timed out waiting to observe a state that had already come and gone. A
 * `MutationObserver` armed BEFORE the change latches the `measuring…` repaint
 * the moment it happens; a latch cannot be missed the way a poll can.
 */
async function armBenchmarkLatch(page: Page): Promise<void> {
  await page.evaluate(() => {
    const el = document.getElementById('param-estimate');
    if (!el) throw new Error('no #param-estimate');
    const w = window as unknown as { __benchStarted?: boolean; __benchObs?: MutationObserver };
    w.__benchObs?.disconnect();
    w.__benchStarted = false;
    const obs = new MutationObserver(() => {
      if ((el.textContent ?? '').includes('measuring')) {
        w.__benchStarted = true;
        obs.disconnect();
      }
    });
    obs.observe(el, { childList: true, characterData: true, subtree: true });
    w.__benchObs = obs;
  });
}

async function awaitBenchmark(page: Page, changed: boolean): Promise<void> {
  if (changed) {
    await page.waitForFunction(
      () => (window as unknown as { __benchStarted?: boolean }).__benchStarted === true,
      undefined,
      { timeout: 30_000 }
    );
  }
  await expect(page.locator('#param-estimate')).toContainText('measured on this device', {
    timeout: 180_000,
  });
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Six things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, with the encrypt tab active, every
 *    derived-state region hidden and both primary buttons disabled behind the
 *    WASM self-test — the state every reader actually arrives in, which the
 *    gate this replaces never once scanned (it force-revealed eight empty
 *    regions before its only scan).
 *
 *  - THE VAULT IS REAL. The drive types both passphrases, derives a container
 *    through the Argon2id/ChaCha20-Poly1305 WASM worker, plays the coercion
 *    scenario (two more real derivations), downloads the container file, and
 *    decrypts it back on the decrypt tab — first with a wrong passphrase for
 *    the deliberately uniform failure verdict, then with the real one, and the
 *    decrypted text is asserted to BE the message that went in. Argon2id
 *    memory is driven to its legal 16 MB floor first — that is itself a state
 *    worth scanning (the RFC 9106 warning alert) and it keeps the six
 *    derivations this drive performs affordable at both viewports.
 *
 *  - EVERY ERROR STATE IS DRIVEN: identical passphrases, an oversized message
 *    for the chosen container, sub-recommended KDF parameters, and the
 *    wrong-passphrase verdict. None is reachable without doing something
 *    wrong on purpose, and none had ever been looked at.
 *
 *  - HOVER IS A STATE, AND IT PERSISTS AFTER A CLICK. `:hover` stays on the
 *    element under the pointer after `page.click()` resolves, so it is the
 *    state a reader occupies the instant after pressing CREATE VAULT — and
 *    this page repaints fills and text on hover everywhere (`hover:bg-*`,
 *    `hover:text-*`, the top bar's `.cl-btn:hover`). The enabled CREATE VAULT
 *    and coercion buttons are hovered and scanned explicitly, because their
 *    hover fills are different surfaces from their rest fills.
 *
 *  - REDUCED MOTION IS ASSERTED AT THE POINT IT MATTERS. After the derive,
 *    the container map must be in `visualizer.ts`'s `matchMedia` branch: the
 *    insider end state painted directly, the attacker-view toggle still
 *    unpressed. If the emulation had silently failed, the map would be
 *    mid-flicker noise with `aria-pressed` flipping underneath the scan.
 *
 *  - NO FIXED TIMEOUTS. Every wait is on a real DOM completion signal: a step
 *    marked done, a caption painted, a verdict rendered, a benchmark figure
 *    replacing `measuring…`, an `aria-pressed` flip, a `download` event.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('arrival, encrypt tab active, nothing derived');

  // ── The two skip links, focused — and actually on top ───────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await expectFocusedOnTop(page, 'a.cl-skip-link', 'shared skip link focused');
  await scanAt('shared skip link focused, slid down over the top bar');

  await page.locator('a[href="#main-content"]').focus();
  await expect(page.locator('a[href="#main-content"]')).toBeFocused();
  await expectFocusedOnTop(page, 'a[href="#main-content"]', 'lab skip link focused');
  await scanAt('lab skip link focused — its sr-only clip undone');

  // ── The passphrase reveal toggle ────────────────────────────────────────
  const eye = page.locator('.toggle-password[data-target="real-passphrase"]');
  await eye.click();
  await expect(eye).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#real-passphrase')).toHaveAttribute('type', 'text');
  await scanAt('real passphrase revealed by the eye toggle');
  await eye.click();
  await expect(page.locator('#real-passphrase')).toHaveAttribute('type', 'password');

  // ── The strength meter, weak then strong ────────────────────────────────
  await page.fill('#real-passphrase', 'abc');
  await expect(page.locator('#real-strength-label')).toContainText('Weak');
  await scanAt('weak passphrase — the strength meter and its wording');

  await page.fill('#real-passphrase', REAL_PASS);
  await expect(page.locator('#real-strength-label')).toContainText('bits');

  // ── Identical passphrases — the deniability alert ───────────────────────
  await page.fill('#decoy-passphrase', REAL_PASS);
  await expect(page.locator('#encrypt-error')).toBeVisible();
  await expect(page.locator('#encrypt-error')).toContainText('must differ');
  await scanAt('identical passphrases rejected — the deniability error');

  await page.fill('#decoy-passphrase', DECOY_PASS);
  await expect(page.locator('#encrypt-error')).toBeHidden();
  await page.fill('#real-message', REAL_MSG);
  await page.fill('#decoy-message', DECOY_MSG);
  await expect(page.locator('#real-char-count')).toHaveText(String(REAL_MSG.length));
  await expect(page.locator('#btn-encrypt')).toBeEnabled();

  // ── An oversized message for the chosen container ───────────────────────
  await page.check('input[name="container-size"][value="4096"]');
  await page.fill('#real-message', 'A'.repeat(1500));
  await expect(page.locator('#encrypt-error')).toContainText('too long');
  await expect(page.locator('#btn-encrypt')).toBeDisabled();
  await scanAt('a 1500-byte message refused by the 4 KB container');

  await page.check('input[name="container-size"][value="8192"]');
  await page.fill('#real-message', REAL_MSG);
  await expect(page.locator('#encrypt-error')).toBeHidden();
  await expect(page.locator('#btn-encrypt')).toBeEnabled();

  // ── The Argon2id params panel: measured cost, warning, defaults ─────────
  await page.click('#btn-toggle-params');
  await expect(page.locator('#btn-toggle-params')).toHaveAttribute('aria-expanded', 'true');
  await expect(page.locator('#params-panel')).toBeVisible();
  await awaitBenchmark(page, false);
  await expect(page.locator('#param-attacker-cost')).toContainText('per-container salt');
  await scanAt('params open — measured derivation cost and the constant-salt caveat');

  // Home is the keyboard route to the slider's minimum — a real reader route,
  // not a value poked in from script.
  await armBenchmarkLatch(page);
  await page.locator('#param-memory').press('Home');
  await expect(page.locator('#param-display-mem')).toHaveText('16 MB');
  await expect(page.locator('#param-warnings')).toBeVisible();
  await expect(page.locator('#param-warnings')).toContainText('below 64MB');
  await awaitBenchmark(page, true);
  await scanAt('16 MB memory — the RFC 9106 warning alert, still allowed');

  await armBenchmarkLatch(page);
  await page.click('#btn-restore-defaults');
  await expect(page.locator('#param-display-mem')).toHaveText('64 MB');
  await expect(page.locator('#param-warnings')).toBeHidden();
  await awaitBenchmark(page, true);

  // Back to the legal floor: the four derivations that follow (create ×2,
  // coercion ×2, plus the decrypt attempts) each cost ~4× less at 16 MB, and
  // the warned state is a real configuration the app permits.
  await armBenchmarkLatch(page);
  await page.locator('#param-memory').press('Home');
  await expect(page.locator('#param-display-mem')).toHaveText('16 MB');
  await awaitBenchmark(page, true);

  // ── CREATE VAULT, hovered then pressed ──────────────────────────────────
  await page.locator('#btn-encrypt').hover();
  await scanAt('CREATE VAULT hovered while enabled — its hover fill');

  await page.click('#btn-encrypt');
  await expect(page.locator('#encrypt-progress')).toBeVisible();
  await expect(page.locator('#download-section')).toBeVisible({ timeout: 180_000 });
  await expect(page.locator('#encrypt-steps .step-done')).toHaveCount(2);

  // The reduced-motion branch of visualizer.ts, asserted at the point it
  // matters: insider end state painted directly, no flicker running, the
  // attacker-view toggle still unpressed.
  await expect(page.locator('#container-visualizer')).toBeVisible();
  await expect(page.locator('#container-map .container-cell')).toHaveCount(512);
  await expect(page.locator('#btn-attacker-view')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#container-stats')).toContainText('bytes total');
  await scanAt('vault derived — steps done, insider map, coercion and download offered');

  // ── The attacker view ───────────────────────────────────────────────────
  await page.click('#btn-attacker-view');
  await expect(page.locator('#btn-attacker-view')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#container-stats')).toContainText('uniform random noise');
  await scanAt('attacker view — the structure dissolved into noise');

  // ── The coercion scenario, hovered then played ──────────────────────────
  await page.locator('#btn-coercion-demo').hover();
  await scanAt('coercion button hovered while enabled — its inverted fill');

  await page.click('#btn-coercion-demo');
  await expect(page.locator('#btn-coercion-demo')).toContainText('SCENARIO COMPLETE', {
    timeout: 180_000,
  });
  await expect(page.locator('#coercion-steps [role=region]')).toHaveCount(2);
  await expect(page.locator('#coercion-steps')).toContainText(DECOY_MSG);
  await expect(page.locator('#coercion-steps')).toContainText(REAL_MSG);
  await scanAt('coercion scenario played out — decoy surrendered, real slot intact');

  // ── Download the container — the bytes the decrypt half will eat ────────
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.click('#btn-download'),
  ]);
  const vaultPath = await download.path();
  await expect(page.locator('#download-section')).toBeHidden();

  // ── The How It Works modal ──────────────────────────────────────────────
  await page.click('#btn-how-it-works');
  await expect(page.locator('#modal-how[open]')).toHaveCount(1);
  await expect(page.locator('#modal-title')).toBeVisible();
  await scanAt('How It Works modal open over the dimmed page');
  await page.keyboard.press('Escape');
  await expect(page.locator('#modal-how[open]')).toHaveCount(0);
  await expect(page.locator('#modal-overlay')).toBeHidden();

  // ── The shared bar, hovered ─────────────────────────────────────────────
  await page.locator('.cl-btn').first().hover();
  await scanAt('shared bar Menu button hovered');

  // ── The decrypt tab ─────────────────────────────────────────────────────
  await page.click('#tab-decrypt');
  await expect(page.locator('#tab-decrypt')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#panel-decrypt')).toBeVisible();
  await expect(page.locator('#panel-encrypt')).toBeHidden();
  await expect(page.locator('#tab-decrypt')).toBeFocused();
  await scanAt('decrypt tab — drop zone, creation params, OPEN VAULT disabled');

  // Tab from the tablist reaches the drop zone — the keyboard route into the
  // file upload (role="button", tabindex="0"), with its focus-visible ring.
  await page.keyboard.press('Tab');
  await expect(page.locator('#drop-zone')).toBeFocused();
  await scanAt('drop zone reached by keyboard, focus ring showing');

  // ── Feed it the real container, params matching creation ────────────────
  await page.setInputFiles('#decrypt-file', vaultPath);
  await expect(page.locator('#file-info')).toBeVisible();
  await expect(page.locator('#file-info')).toContainText('8,192 bytes');
  await page.selectOption('#decrypt-param-memory', '16');

  // ── The wrong passphrase: the deliberately uniform failure verdict ──────
  await page.fill('#decrypt-passphrase', 'wrong-passphrase-on-purpose');
  await expect(page.locator('#btn-decrypt')).toBeEnabled();
  await page.click('#btn-decrypt');
  await expect(page.locator('#decrypt-steps')).toContainText('No message found', {
    timeout: 180_000,
  });
  await scanAt('decrypt failed — the uniform wrong-passphrase verdict');

  // ── The real passphrase opens the real slot ─────────────────────────────
  await page.fill('#decrypt-passphrase', REAL_PASS);
  await page.click('#btn-decrypt');
  await expect(page.locator('#decrypt-result')).toBeVisible({ timeout: 180_000 });
  await expect(page.locator('#decrypted-message')).toHaveText(REAL_MSG);
  await scanAt('vault opened — the real message and the redacted offset bar');
}
