const { expect } = require('@playwright/test');
const { Given, When, Then } = require('./fixtures');

Given('I am reading the first book', async ({ libraryPage }) => {
  await libraryPage.goto();
  await libraryPage.openFirstBook();
});

Then('the current page should be {string}', async ({ readerPage }, n) => {
  await expect(readerPage.currentPage()).toHaveText(n);
});

When('I advance to the next page', async ({ readerPage }) => {
  await readerPage.advance();
});

When('I switch to scroll mode', async ({ readerPage }) => {
  await readerPage.setScrollMode();
});

Then('the reader should be in {string} mode', async ({ readerPage }, mode) => {
  await expect(readerPage.mode()).toHaveAttribute('data-mode', mode);
});

When('I log out', async ({ libraryPage }) => {
  await libraryPage.logout();
});
