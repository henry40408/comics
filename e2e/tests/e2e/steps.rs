//! Step definitions.
//!
//! They live in the test binary, not the library: the step macros register
//! through `inventory`, and a step only reachable through an rlib can be
//! dropped by the linker.

use comics_e2e::pages::click_theme_toggle;
use comics_e2e::server::BASE_URL;
use comics_e2e::wait::{eventually, eventually_eq};
use comics_e2e::world::ComicsWorld;
use cucumber::{given, then, when};

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
    // A card, not merely the route: a 503 during the initial scan is at `/` too.
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
    // In scroll mode every page is displayed, so only the viewport says where
    // the browser landed.
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
    // Rendered text, not `textContent`, which keeps a hidden span's characters.
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

#[when(expr = "I visit {string}")]
async fn visit(world: &mut ComicsWorld, path: String) -> anyhow::Result<()> {
    world.driver()?.goto(format!("{BASE_URL}{path}")).await?;
    Ok(())
}

#[when("I reload the page")]
async fn reload(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.driver()?.refresh().await?;
    Ok(())
}

#[then(expr = "I should be at {string}")]
async fn should_be_at(world: &mut ComicsWorld, expected: String) -> anyhow::Result<()> {
    eventually_eq("path and query", expected.as_str(), || async {
        let url = world.driver()?.current_url().await?;
        Ok(match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_string(),
        })
    })
    .await
}

#[then(expr = "the login form should remember {string}")]
async fn login_form_remembers(world: &mut ComicsWorld, expected: String) -> anyhow::Result<()> {
    eventually_eq(
        "the login form's next target",
        expected.as_str(),
        || async { world.login_page()?.next_target().await },
    )
    .await
}

#[then("the username field should be focused")]
async fn username_field_focused(world: &mut ComicsWorld) -> anyhow::Result<()> {
    eventually_eq("the focused field", "login-username", || async {
        world.login_page()?.focused_testid().await
    })
    .await
}

#[then(expr = "the page should have no element {string}")]
async fn page_has_no_element(world: &mut ComicsWorld, css: String) -> anyhow::Result<()> {
    let found = world
        .driver()?
        .find_all(thirtyfour::By::Css(css.as_str()))
        .await?;
    anyhow::ensure!(
        found.is_empty(),
        "found {} element(s) for `{css}`",
        found.len()
    );
    Ok(())
}

#[then(expr = "the library should list {string} with {string}")]
async fn library_lists(
    world: &mut ComicsWorld,
    title: String,
    pages: String,
) -> anyhow::Result<()> {
    let cards = world.library_page()?.card_summaries().await?;
    let card = cards
        .iter()
        .find(|card| card.title == title)
        .ok_or_else(|| anyhow::anyhow!("no card titled {title:?} among {cards:?}"))?;
    anyhow::ensure!(card.pages == pages, "{title:?} shows {:?}", card.pages);
    anyhow::ensure!(
        card.cover_alt == title,
        "{title:?} has cover alt {:?}",
        card.cover_alt
    );
    Ok(())
}

#[then(expr = "the cards should be numbered {string}")]
async fn cards_numbered(world: &mut ComicsWorld, expected: String) -> anyhow::Result<()> {
    let cards = world.library_page()?.card_summaries().await?;
    let indexes: Vec<&str> = cards.iter().map(|card| card.index.as_str()).collect();
    anyhow::ensure!(indexes.join(", ") == expected, "numbered {indexes:?}");
    Ok(())
}

#[then(expr = "the library should report {int} volumes")]
async fn library_reports_volumes(world: &mut ComicsWorld, count: usize) -> anyhow::Result<()> {
    let (header, note) = world.library_page()?.volume_counts().await?;
    anyhow::ensure!(header == count.to_string(), "header says {header:?}");
    anyhow::ensure!(note.contains(&count.to_string()), "note says {note:?}");
    Ok(())
}

#[then("the scan times should be shown")]
async fn scan_times_shown(world: &mut ComicsWorld) -> anyhow::Result<()> {
    let times = world.library_page()?.scan_times().await?;
    anyhow::ensure!(times.len() == 2, "expected two <time> elements: {times:?}");
    anyhow::ensure!(
        times.iter().all(|t| !t.trim().is_empty()),
        "blank: {times:?}"
    );
    anyhow::ensure!(times[1].ends_with("ms"), "duration reads {:?}", times[1]);
    Ok(())
}

#[then(expr = "the page title should start with {string}")]
async fn title_starts_with(world: &mut ComicsWorld, prefix: String) -> anyhow::Result<()> {
    let title = world.driver()?.title().await?;
    anyhow::ensure!(title.starts_with(&prefix), "title is {title:?}");
    Ok(())
}

#[then("every image and asset on the page should be served")]
async fn assets_served(world: &mut ComicsWorld) -> anyhow::Result<()> {
    let audit = world.browser()?.audit_resources().await?;
    anyhow::ensure!(
        audit.failed.is_empty(),
        "failed requests: {:?}",
        audit.failed
    );
    anyhow::ensure!(
        audit.undecodable.is_empty(),
        "undecodable images: {:?}",
        audit.undecodable
    );
    // No entries means no failures, so a page that dropped its tags would pass.
    for asset in ["/assets/app.css", "/assets/app.js", "/assets/theme.js"] {
        anyhow::ensure!(
            audit.linked.iter().any(|path| path == asset),
            "the page never loaded {asset}: {:?}",
            audit.linked
        );
    }
    Ok(())
}

#[then("the page should show images")]
async fn page_shows_images(world: &mut ComicsWorld) -> anyhow::Result<()> {
    let audit = world.browser()?.audit_resources().await?;
    anyhow::ensure!(audit.images > 0, "the page has no <img>");
    Ok(())
}

#[then("the reader should have remembered the first-visit hint")]
async fn hint_remembered(world: &mut ComicsWorld) -> anyhow::Result<()> {
    let flag = world
        .driver()?
        .execute(
            "return localStorage.getItem('comics-reader-hinted');",
            Vec::new(),
        )
        .await?;
    anyhow::ensure!(
        flag.json().as_str() == Some("1"),
        "flag is {:?}",
        flag.json()
    );
    Ok(())
}

#[then("the page should have no inline script or style")]
async fn no_inline_code(world: &mut ComicsWorld) -> anyhow::Result<()> {
    let count = world.browser()?.inline_code_count().await?;
    anyhow::ensure!(count == 0, "{count} inline <script>/<style> element(s)");
    Ok(())
}

#[when("I shuffle from the library")]
async fn shuffle_from_library(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.library_page()?.shuffle().await
}

#[when("I re-scan the library")]
async fn rescan_library(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.library_page()?.rescan().await
}

#[given(expr = "the system prefers the {string} colour scheme")]
async fn system_prefers(world: &mut ComicsWorld, scheme: String) -> anyhow::Result<()> {
    world.browser()?.emulate_color_scheme(&scheme).await
}

#[when("I toggle the theme")]
async fn toggle_theme(world: &mut ComicsWorld) -> anyhow::Result<()> {
    let before = world.browser()?.theme().await?;
    click_theme_toggle(world.driver()?, &before).await
}

#[then(expr = "the theme should be {string}")]
async fn theme_should_be(world: &mut ComicsWorld, theme: String) -> anyhow::Result<()> {
    eventually_eq("the theme", theme.as_str(), || async {
        world.browser()?.theme().await
    })
    .await
}

#[when(expr = "I press {string}")]
async fn press_key(world: &mut ComicsWorld, key: String) -> anyhow::Result<()> {
    world.browser()?.press(&key).await
}

#[when("I go back to the previous page")]
async fn go_back(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.reader_page()?.go_back().await
}

#[then(expr = "the progress bar should be {string} wide")]
async fn progress_width(world: &mut ComicsWorld, width: String) -> anyhow::Result<()> {
    eventually_eq("the progress bar width", width.as_str(), || async {
        world.reader_page()?.progress_width().await
    })
    .await
}

#[then("the reader should be hinting")]
async fn reader_hinting(world: &mut ComicsWorld) -> anyhow::Result<()> {
    eventually("the first-visit hint is showing", || async {
        world.reader_page()?.is_hinting().await
    })
    .await
}

#[when("I follow the back link")]
async fn follow_back_link(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.reader_page()?.go_home().await
}

#[when("I shuffle from the reader")]
async fn shuffle_from_reader(world: &mut ComicsWorld) -> anyhow::Result<()> {
    world.reader_page()?.shuffle().await
}

#[then(expr = "the reader title should be {string}")]
async fn reader_title(world: &mut ComicsWorld, title: String) -> anyhow::Result<()> {
    eventually_eq("the reader title", title.as_str(), || async {
        world.reader_page()?.title().await
    })
    .await
}

#[when(expr = "I reload the reader in {string} mode")]
async fn reload_reader_in_mode(world: &mut ComicsWorld, mode: String) -> anyhow::Result<()> {
    let mut url = world.driver()?.current_url().await?;
    url.set_query(Some(&format!("mode={mode}")));
    url.set_fragment(None);
    world.driver()?.goto(url.as_str()).await?;
    Ok(())
}

#[then(expr = "the segmented control should highlight {string}")]
async fn segmented_control_highlights(world: &mut ComicsWorld, mode: String) -> anyhow::Result<()> {
    let highlighted = world.reader_page()?.highlighted_mode().await?;
    anyhow::ensure!(
        highlighted.as_deref() == Some(mode.as_str()),
        "highlights {highlighted:?}"
    );
    Ok(())
}

#[then(expr = "page {string} should offer no previous-page link")]
async fn no_previous_link(world: &mut ComicsWorld, n: String) -> anyhow::Result<()> {
    assert_page_has_no(world, &n, ".nojs-prev").await
}

#[then(expr = "page {string} should offer no next-page link")]
async fn no_next_link(world: &mut ComicsWorld, n: String) -> anyhow::Result<()> {
    assert_page_has_no(world, &n, ".nojs-next").await
}

async fn assert_page_has_no(world: &ComicsWorld, n: &str, css: &str) -> anyhow::Result<()> {
    let page = world.reader_page()?.page(n).await?;
    let found = page.find_all(thirtyfour::By::Css(css)).await?;
    anyhow::ensure!(found.is_empty(), "page {n} carries `{css}`");
    Ok(())
}

/// Fails if the element is displayed; absent counts as hidden.
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
