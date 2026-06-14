const { test: base, createBdd } = require('playwright-bdd');
const { LoginPage } = require('../pages/login.page');
const { LibraryPage } = require('../pages/library.page');
const { ReaderPage } = require('../pages/reader.page');

// Expose the page objects as Playwright fixtures so steps can request them.
const test = base.extend({
  loginPage: async ({ page }, use) => {
    await use(new LoginPage(page));
  },
  libraryPage: async ({ page }, use) => {
    await use(new LibraryPage(page));
  },
  readerPage: async ({ page }, use) => {
    await use(new ReaderPage(page));
  },
});

const { Given, When, Then } = createBdd(test);

module.exports = { test, Given, When, Then };
