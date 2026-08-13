// Page object for the reader (/book/{id}).
class ReaderPage {
  constructor(page) {
    this.page = page;
  }

  currentPage() {
    return this.page.getByTestId('reader-current');
  }

  async advance() {
    await this.page.getByTestId('reader-next').click();
  }

  async setScrollMode() {
    await this.page.getByTestId('reader-mode-scroll').click();
  }

  mode() {
    // The reader stores its mode on <body data-mode="...">.
    return this.page.locator('body');
  }

  // --- no-JavaScript paging (the `e2e-nojs` project) ---
  // Only one .pg is displayed at a time, so "visible" is the assertion that
  // matters: it proves the CSS resolved a page, not merely that one exists.

  page_(n) {
    return this.page.locator(`#p${n}`);
  }

  visiblePages() {
    return this.page.locator('.pg:visible');
  }

  async followNext() {
    await this.page.locator('.pg:visible .nojs-next').click();
  }

  async followPrevious() {
    await this.page.locator('.pg:visible .nojs-prev').click();
  }
}

module.exports = { ReaderPage };
