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

Then('page {string} should be the only one showing', async ({ readerPage }, n) => {
  await expect(readerPage.page_(n)).toBeVisible();
  await expect(readerPage.visiblePages()).toHaveCount(1);
});

When('I follow the next-page link', async ({ readerPage }) => {
  await readerPage.followNext();
});

When('I follow the previous-page link', async ({ readerPage }) => {
  await readerPage.followPrevious();
});

When('I jump to page {string} from the rail', async ({ readerPage }, n) => {
  await readerPage.jumpFromRail(n);
});

Then('the page counter should read {string}', async ({ readerPage }, text) => {
  await expect(readerPage.counter()).toHaveText(text);
});

When('I log out', async ({ libraryPage }) => {
  await libraryPage.logout();
});
