const { defineConfig, devices } = require('@playwright/test');
const { defineBddConfig } = require('playwright-bdd');

const PORT = 3030;
const BASE_URL = `http://127.0.0.1:${PORT}`;

// Argon2id hash of "password", from `comics hash-password` — a throwaway
// credential that only unlocks the committed test fixtures. The server refuses
// to start on a hash it cannot use, so if this ever goes stale the e2e run says
// so directly rather than failing at the login step.
const TEST_PASSWORD_HASH =
  '$argon2id$v=19$m=19456,t=2,p=1$C2qIDpzPcTL0a5wYL1152Q$2MWeEDjhoNnp8oRwz9DkFoLgYH3NTe+qArT3vPHN14g';

const testDir = defineBddConfig({
  features: 'features/**/*.feature',
  steps: 'steps/**/*.js',
  tags: 'not @nojs and not @logout',
});

// `POST /logout` ends every live session, not just the caller's — comics has
// one set of credentials, so that is the point of it. It also means logging out
// in one worker signs the others out mid-scenario, which surfaces as a login
// that "worked" and then bounced off `/` to `/login?next=…`. Kept in its own
// project so it runs after everything else rather than alongside it.
const logoutTestDir = defineBddConfig({
  outputDir: '.features-gen-logout',
  features: 'features/**/*.feature',
  steps: 'steps/**/*.js',
  tags: '@logout',
});

// `javaScriptEnabled` is a browser-context option, so the scripted and the
// script-less runs cannot share one project — hence the second generation pass
// and the `@nojs` tag that splits the scenarios between them.
const nojsTestDir = defineBddConfig({
  // A sibling of the default `.features-gen`, never a child: the `e2e` project
  // points at that directory, and would otherwise pick these specs up too.
  outputDir: '.features-gen-nojs',
  features: 'features/**/*.feature',
  steps: 'steps/**/*.js',
  tags: '@nojs',
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
      COMICS_SECRET:
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    },
  },
  projects: [
    {
      name: 'e2e',
      testDir,
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'e2e-nojs',
      testDir: nojsTestDir,
      use: { ...devices['Desktop Chrome'], javaScriptEnabled: false },
    },
    {
      name: 'e2e-logout',
      testDir: logoutTestDir,
      // Last, because it signs out every other project's sessions too.
      dependencies: ['e2e', 'e2e-nojs'],
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
