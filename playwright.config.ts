import { defineConfig, devices } from '@playwright/test';

const PORT = process.env.E2E_PORT || '8123';

// E2E runs against a throwaway copy of public_html in .e2e/docroot, seeded with
// a known admin. The copy is prepared (and the server started) by
// tests/e2e/scripts/server.mjs, so the real deployment and data/ are untouched.
export default defineConfig({
  testDir: './tests/e2e/specs',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
  ],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'off',
    actionTimeout: 10_000,
    navigationTimeout: 30_000,
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'node tests/e2e/scripts/server.mjs',
    url: `http://127.0.0.1:${PORT}/login.php`,
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
