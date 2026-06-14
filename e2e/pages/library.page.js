// Page object for the library (/).
class LibraryPage {
  constructor(page) {
    this.page = page;
  }

  async goto() {
    await this.page.goto('/');
  }

  cards() {
    return this.page.getByTestId('book-card');
  }

  async openFirstBook() {
    await this.cards().first().click();
  }

  async logout() {
    await this.page.getByTestId('logout').click();
  }
}

module.exports = { LibraryPage };
