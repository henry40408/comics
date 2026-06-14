const { expect } = require('@playwright/test');
const { Given, When, Then } = require('./fixtures');

Given('I am logged in', async ({ page, loginPage }) => {
  await loginPage.goto();
  await loginPage.login('user', 'password');
  await expect(page).toHaveURL('/');
});

When('I open the library', async ({ libraryPage }) => {
  await libraryPage.goto();
});

Then('I should see {int} books', async ({ libraryPage }, count) => {
  await expect(libraryPage.cards()).toHaveCount(count);
});

When('I open the first book', async ({ libraryPage }) => {
  await libraryPage.openFirstBook();
});

Then('I should be in the reader', async ({ page }) => {
  await expect(page).toHaveURL(/\/book\//);
  await expect(page.locator('body.reader')).toBeVisible();
});
