import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: false, // Crypto tests are CPU-intensive
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'list',
  timeout: 120_000, // Argon2id derivation can be slow

  use: {
    baseURL: 'http://localhost:4708/crypto-lab-shadow-vault/',
    trace: 'on-first-retry',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  webServer: {
    // Build before serving: `vite preview` only serves whatever is already in
    // dist/, so without this a failing build leaves the previous good bundle in
    // place and the suite passes green against code that no longer compiles.
    command: 'npm run build && npm run preview -- --port 4708 --strictPort',
    url: 'http://localhost:4708/crypto-lab-shadow-vault/',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
