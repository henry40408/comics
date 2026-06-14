const { expect } = require('@playwright/test');
const { Given, When, Then } = require('./fixtures');

Given('I am on the login page', async ({ loginPage }) => {
  await loginPage.goto();
});

When(
  'I sign in with username {string} and password {string}',
  async ({ loginPage }, username, password) => {
    await loginPage.login(username, password);
  },
);

Then('I should see the library', async ({ page }) => {
  await expect(page).toHaveURL('/');
  await expect(page.getByTestId('book-card').first()).toBeVisible();
});

Then('I should see the login error', async ({ loginPage }) => {
  await expect(loginPage.error()).toBeVisible();
});

Then('I should be on the login page', async ({ page }) => {
  await expect(page).toHaveURL(/\/login/);
});
