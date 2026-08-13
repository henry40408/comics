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

  // The rail is anchors in both projects; with scripting on app.js cancels the
  // jump, so this exercises the two paths through one control.
  async jumpFromRail(n) {
    await this.page.locator(`.thumbs a[href="#p${n}"]`).click();
  }

  counter() {
    return this.page.locator('.pg:visible .nojs-counter');
  }

  themeToggle() {
    return this.page.locator('#theme');
  }

  topbarTitle() {
    return this.page.locator('.titleblock .s');
  }
}

module.exports = { ReaderPage };
