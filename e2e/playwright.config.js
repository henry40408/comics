const { defineConfig, devices } = require('@playwright/test');
const { defineBddConfig } = require('playwright-bdd');

const PORT = 3030;
const BASE_URL = `http://127.0.0.1:${PORT}`;

// bcrypt hash of "password" (cost 11) — a throwaway credential that only
// unlocks the committed test fixtures.
const TEST_PASSWORD_HASH = '$2y$11$s4aVgLTIMwW5RUu.OeWsLu8UZL1fxLsB31iRsCiljfT.8V1VEp4dO';

const testDir = defineBddConfig({
  features: 'features/**/*.feature',
  steps: 'steps/**/*.js',
});

module.exports = defineConfig({
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
  },
  webServer: {
    command: `cargo run --release -- --bind 127.0.0.1:${PORT} --data-dir fixtures/data`,
    cwd: '..',
    url: `${BASE_URL}/healthz`,
    timeout: 180_000,
    reuseExistingServer: !process.env.CI,
    env: {
      COMICS_AUTH_USERNAME: 'user',
      COMICS_AUTH_PASSWORD_HASH: TEST_PASSWORD_HASH,
      COMICS_SEED: '1',
    },
  },
  projects: [
    {
      name: 'e2e',
      testDir,
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'screenshots',
      testDir: __dirname,
      testMatch: /screenshots\.spec\.js$/,
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
