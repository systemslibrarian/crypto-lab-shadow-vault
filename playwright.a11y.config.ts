import { defineConfig } from '@playwright/test';

/**
 * Accessibility gate. Runs against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Kept separate from playwright.config.ts (the WASM crypto integration
 * suite in tests/browser) so each has its own testDir/port and neither
 * collects the other's specs. Run `npm run build` first (CI does).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  timeout: 60_000,
  use: {
    baseURL: 'http://localhost:4364/crypto-lab-shadow-vault/',
    colorScheme: 'dark',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { channel: undefined },
    },
  ],
  webServer: {
    command: 'npm run preview -- --port 4364 --strictPort',
    url: 'http://localhost:4364/crypto-lab-shadow-vault/',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
