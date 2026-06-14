// Page object for /login. Locators use data-testid only.
class LoginPage {
  constructor(page) {
    this.page = page;
  }

  async goto() {
    await this.page.goto('/login');
  }

  async login(username, password) {
    await this.page.getByTestId('login-username').fill(username);
    await this.page.getByTestId('login-password').fill(password);
    await this.page.getByTestId('login-submit').click();
  }

  error() {
    return this.page.getByTestId('login-error');
  }
}

module.exports = { LoginPage };
