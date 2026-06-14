const { test } = require('@playwright/test');
const path = require('node:path');

const OUT = path.join(__dirname, '..', 'docs', 'screenshots');
const THEMES = ['light', 'dark'];

async function login(page) {
  await page.goto('/login');
  await page.getByTestId('login-username').fill('user');
  await page.getByTestId('login-password').fill('password');
  await page.getByTestId('login-submit').click();
  await page.waitForURL('/');
}

for (const theme of THEMES) {
  test.describe(`theme: ${theme}`, () => {
    // No stored preference + emulated colorScheme exercises the app's
    // system-follow path, picking the matching palette pre-paint.
    test.use({ colorScheme: theme });

    test(`library ${theme}`, async ({ page }) => {
      await login(page);
      await page.goto('/');
      await page.getByTestId('book-card').first().waitFor();
      await page.waitForLoadState('networkidle');
      await page.screenshot({
        path: path.join(OUT, `library-${theme}.png`),
        fullPage: true,
      });
    });

    test(`reader ${theme}`, async ({ page }) => {
      await login(page);
      await page.goto('/');
      await page.getByTestId('book-card').first().click();
      await page.locator('body.reader').waitFor();
      await page.locator('#pages img').first().waitFor({ state: 'visible' });
      await page.waitForLoadState('networkidle');
      await page.screenshot({
        path: path.join(OUT, `reader-${theme}.png`),
        fullPage: true,
      });
    });
  });
}
