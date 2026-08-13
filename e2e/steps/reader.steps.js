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

Then('the shared mode control should not be visible', async ({ readerPage }) => {
  await expect(readerPage.sharedModeControl()).toBeHidden();
});

When('I switch mode from page {string}', async ({ readerPage }, n) => {
  await readerPage.switchModeFrom(n);
});

// In scroll mode every page is displayed, so "showing" proves nothing about
// where the browser landed — the viewport is what carries the answer.
Then('page {string} should be in view', async ({ readerPage }, n) => {
  await expect(readerPage.page_(n)).toBeInViewport();
});

Then('the theme toggle should not be visible', async ({ readerPage }) => {
  await expect(readerPage.themeToggle()).toBeHidden();
});

Then('the top bar should not show the current page', async ({ readerPage }) => {
  await expect(readerPage.currentPage()).toBeHidden();
});

Then('the top bar should still read {string}', async ({ readerPage }, text) => {
  // innerText, not textContent: a `display: none` span keeps its characters in
  // textContent, so the default comparison sees the dropped half either way and
  // cannot tell a hidden counter from a visible one.
  await expect(readerPage.topbarTitle()).toHaveText(text, { useInnerText: true });
});

Then('all {string} pages should be showing', async ({ readerPage }, n) => {
  await expect(readerPage.visiblePages()).toHaveCount(Number(n));
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
