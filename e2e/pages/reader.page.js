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
}

module.exports = { ReaderPage };
