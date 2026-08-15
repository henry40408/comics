//! Step definitions, ported from `e2e/steps/*.js`.
//!
//! They live in the test binary rather than the library because the `#[given]`
//! / `#[when]` / `#[then]` macros register through `inventory`, and a step that
//! is only reachable through an rlib can be dropped by the linker.
//!
//! Where the old steps wrote `await expect(...)`, these call [`eventually`] or
//! [`eventually_eq`]: `WebDriver` has no retrying-assertion layer, and several of
//! these assertions land while `app.js` is still mid-animation.

use comics_e2e::wait::{eventually, eventually_eq};
use comics_e2e::world::ComicsWorld;
use cucumber::{given, then, when};

// --- login ---------------------------------------------------------------

#[given("I am on the login page")]
async fn on_the_login_page(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.login_page()?.goto().await
}

#[when(expr = "I sign in with username {string} and password {string}")]
async fn sign_in(
    world: &mut ComicsWorld,
    username: String,
    password: String,
) -> anyhow::Result<()> {
    world.login_page()?.login(&username, &password).await
}

#[then("I should see the library")]
async fn should_see_the_library(world: &mut ComicsWorld) -> anyhow::Result<()> {
    eventually_eq("url after signing in", "/", || async { world.path().await }).await?;
    // The first card, not merely the route: a 503 from a scan still in flight
    // renders at `/` too.
    eventually("a book card is on the page", || async {
        Ok(!world.library_page()?.cards().await?.is_empty())
    })
    .await
}

#[then("I should see the login error")]
async fn should_see_the_login_error(world: &mut ComicsWorld) -> anyhow::Result<()> {
    eventually("the login error is showing", || async {
        is_displayed(world.login_page()?.error().await?).await
    })
    .await
}

#[then("I should be on the login page")]
async fn should_be_on_the_login_page(world: &mut ComicsWorld) -> anyhow::Result<()> {
    eventually("url is the login page", || async {
        Ok(world.path().await?.starts_with("/login"))
    })
    .await
}

// --- library -------------------------------------------------------------

#[given("I am logged in")]
async fn logged_in(world: &mut ComicsWorld) -> anyhow::Result<()> {
    let login = world.login_page()?;
    login.goto().await?;
    login
        .login(comics_e2e::server::USERNAME, comics_e2e::server::PASSWORD)
        .await?;
    eventually_eq("url after signing in", "/", || async { world.path().await }).await
}

#[when("I open the library")]
async fn open_the_library(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.library_page()?.goto().await
}

#[then(expr = "I should see {int} books")]
async fn should_see_n_books(world: &mut ComicsWorld, count: usize) -> anyhow::Result<()> {
    eventually_eq("book count", count, || async {
        Ok(world.library_page()?.cards().await?.len())
    })
    .await
}

#[when("I open the first book")]
async fn open_the_first_book(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.library_page()?.open_first_book().await
}

#[then("I should be in the reader")]
async fn should_be_in_the_reader(world: &mut ComicsWorld) -> anyhow::Result<()> {
    eventually("url is a book", || async {
        Ok(world.path().await?.starts_with("/book/"))
    })
    .await?;
    eventually("the reader body is showing", || async {
        world.reader_page()?.is_showing().await
    })
    .await
}

// --- reader --------------------------------------------------------------

#[given("I am reading the first book")]
async fn reading_the_first_book(world: &mut ComicsWorld) -> anyhow::Result<()> {
    let library = world.library_page()?;
    library.goto().await?;
    library.open_first_book().await?;
    eventually("url is a book", || async {
        Ok(world.path().await?.starts_with("/book/"))
    })
    .await
}

#[then(expr = "the current page should be {string}")]
async fn current_page_should_be(world: &mut ComicsWorld, n: String) -> anyhow::Result<()> {
    eventually_eq("the topbar page number", n.as_str(), || async {
        match world.reader_page()?.current_page().await? {
            Some(element) => Ok(element.text().await?),
            None => Ok(String::new()),
        }
    })
    .await
}

#[when("I advance to the next page")]
async fn advance(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.reader_page()?.advance().await
}

#[when("I switch to scroll mode")]
async fn switch_to_scroll_mode(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.reader_page()?.set_scroll_mode().await
}

#[then(expr = "the reader should be in {string} mode")]
async fn reader_should_be_in_mode(world: &mut ComicsWorld, mode: String) -> anyhow::Result<()> {
    eventually_eq("the reader mode", mode.as_str(), || async {
        world.reader_page()?.mode().await
    })
    .await
}

#[then(expr = "page {string} should be the only one showing")]
async fn only_page_showing(world: &mut ComicsWorld, n: String) -> anyhow::Result<()> {
    eventually("exactly one page is showing", || async {
        Ok(world.reader_page()?.visible_pages().await?.len() == 1)
    })
    .await?;
    eventually_eq("the showing page", format!("p{n}"), || async {
        let reader = world.reader_page()?;
        let showing = reader.visible_pages().await?;
        match showing.first() {
            Some(page) => Ok(page.id().await?.unwrap_or_default()),
            None => Ok(String::new()),
        }
    })
    .await
}

#[when("I follow the next-page link")]
async fn follow_next(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.reader_page()?.follow_next().await
}

#[when("I follow the previous-page link")]
async fn follow_previous(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.reader_page()?.follow_previous().await
}

#[then("the shared mode control should not be visible")]
async fn shared_mode_control_hidden(world: &mut ComicsWorld) -> anyhow::Result<()> {
    assert_hidden(
        "the shared mode control",
        world.reader_page()?.shared_mode_control().await?,
    )
    .await
}

#[when(expr = "I switch mode from page {string}")]
async fn switch_mode_from_page(world: &mut ComicsWorld, n: String) -> anyhow::Result<()> {
    world.reader_page()?.switch_mode_from(&n).await
}

#[then(expr = "page {string} should be in view")]
async fn page_should_be_in_view(world: &mut ComicsWorld, n: String) -> anyhow::Result<()> {
    // In scroll mode every page is displayed, so "showing" proves nothing about
    // where the browser landed — the viewport is what carries the answer.
    eventually(&format!("page {n} is in the viewport"), || async {
        world.browser()?.is_in_viewport(&format!("p{n}")).await
    })
    .await
}

#[then("the theme toggle should not be visible")]
async fn theme_toggle_hidden(world: &mut ComicsWorld) -> anyhow::Result<()> {
    assert_hidden(
        "the theme toggle",
        world.reader_page()?.theme_toggle().await?,
    )
    .await
}

#[then("the top bar should not show the current page")]
async fn topbar_page_number_hidden(world: &mut ComicsWorld) -> anyhow::Result<()> {
    assert_hidden(
        "the topbar page number",
        world.reader_page()?.current_page().await?,
    )
    .await
}

#[then(expr = "the top bar should still read {string}")]
async fn topbar_should_read(world: &mut ComicsWorld, text: String) -> anyhow::Result<()> {
    // Rendered text, not `textContent`: a `display: none` span keeps its
    // characters in `textContent`, so that comparison could not tell a hidden
    // counter from a visible one. WebDriver's "Get Element Text" is already the
    // rendered form, which is what the old step asked for with `useInnerText`.
    eventually_eq("the topbar subtitle", text.as_str(), || async {
        world.reader_page()?.topbar_subtitle().await
    })
    .await
}

#[then(expr = "all {string} pages should be showing")]
async fn all_pages_showing(world: &mut ComicsWorld, n: String) -> anyhow::Result<()> {
    let expected: usize = n.parse()?;
    eventually_eq("the number of showing pages", expected, || async {
        Ok(world.reader_page()?.visible_pages().await?.len())
    })
    .await
}

#[when(expr = "I jump to page {string} from the rail")]
async fn jump_from_rail(world: &mut ComicsWorld, n: String) -> anyhow::Result<()> {
    world.reader_page()?.jump_from_rail(&n).await
}

#[then(expr = "the page counter should read {string}")]
async fn counter_should_read(world: &mut ComicsWorld, text: String) -> anyhow::Result<()> {
    eventually_eq("the page counter", text.as_str(), || async {
        world.reader_page()?.counter_text().await
    })
    .await
}

#[when("I log out")]
async fn log_out(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.library_page()?.logout().await
}

// --- helpers -------------------------------------------------------------

/// Playwright's `toBeHidden`: absent counts as hidden, which is what the
/// script-less templates rely on for controls only a script can operate.
async fn assert_hidden(what: &str, element: Option<thirtyfour::WebElement>) -> anyhow::Result<()> {
    if let Some(element) = element {
        anyhow::ensure!(
            !element.is_displayed().await?,
            "{what} is showing, but nothing should offer it without a script"
        );
    }
    Ok(())
}

async fn is_displayed(element: Option<thirtyfour::WebElement>) -> anyhow::Result<bool> {
    match element {
        Some(element) => Ok(element.is_displayed().await?),
        None => Ok(false),
    }
}
