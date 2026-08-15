//! The Cucumber runner.
//!
//! `harness = false`: cucumber drives the scenarios itself, so there is no
//! libtest harness collecting `#[test]` functions. Run it with
//! `cargo test --test e2e` from `e2e/`.
//!
//! What `playwright.config.js` expressed as four projects is expressed here as
//! a tag read in a `before` hook plus two sequential passes:
//!
//! * `@nojs` — the scripted and script-less runs cannot share a session, since
//!   `Emulation.setScriptExecutionDisabled` applies to the next document. The
//!   hook opens each scenario's session accordingly.
//! * `@logout` — `POST /logout` ends *every* live session, not just the
//!   caller's: comics has one set of credentials, so that is the point of it.
//!   Run alongside the others it signs them out mid-scenario, which surfaces as
//!   a login that "worked" and then bounced off `/` to `/login?next=…`. It gets
//!   the second pass, after everything else has finished.

mod steps;

use comics_e2e::Server;
use comics_e2e::browser::{Browser, Scripting};
use comics_e2e::world::ComicsWorld;
use cucumber::World as _;
use cucumber::gherkin;
use cucumber::writer::Stats as _;

const FEATURES: &str = "features";

/// The most scenarios — and so browsers — to run at once, whatever the machine.
const CONCURRENCY_CEILING: usize = 4;

/// How many scenarios run at once, one per core up to [`CONCURRENCY_CEILING`].
///
/// A fixed four was wrong: it is fine on a developer's machine and too many for
/// a two-core CI runner, where four browsers contend for two cores until pages
/// take longer to settle than the steps wait for. That failed one scenario in
/// thirteen — the kind of flake that is worse than being slow.
///
/// The login rate limiter is *not* what bounds this, though it looks like it
/// should: `POST /login` allows 5 attempts per IP per 60 s and every scenario
/// signs in from 127.0.0.1. A successful login refunds its slot immediately, so
/// only sign-ins actually in flight are charged — measured at 8 concurrent
/// scenarios without the limiter ever refusing one.
fn max_concurrent_scenarios() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(CONCURRENCY_CEILING)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Killed when this binding drops at the end of `main`.
    let _server = Server::start()?;
    // Before anything runs in parallel — see `Browser::prepare`.
    Browser::prepare().await?;

    let others = run(|_, _, scenario| !tagged(scenario, "logout")).await;
    let logout = run(|_, _, scenario| tagged(scenario, "logout")).await;

    // Both passes run before either can fail the process: a broken logout is
    // worth seeing on the same run that showed the rest passing.
    let failures = others + logout;
    anyhow::ensure!(failures == 0, "{failures} cucumber failure(s)");
    Ok(())
}

/// Runs the scenarios a filter selects, reporting how many ways it failed.
async fn run<F>(filter: F) -> usize
where
    F: Fn(&gherkin::Feature, Option<&gherkin::Rule>, &gherkin::Scenario) -> bool + 'static,
{
    let writer = ComicsWorld::cucumber()
        // Each scenario gets its own browser and signs in for itself, so they
        // do not interfere. `Browser::prepare` must have run first.
        .max_concurrent_scenarios(max_concurrent_scenarios())
        .fail_on_skipped()
        .before(|_feature, _rule, scenario, world| {
            Box::pin(async move {
                let scripting = if tagged(scenario, "nojs") {
                    Scripting::Disabled
                } else {
                    Scripting::Enabled
                };
                world
                    .open(scripting)
                    .await
                    .expect("could not open a browser session");
            })
        })
        .after(|_feature, _rule, _scenario, _finished, world| {
            Box::pin(async move {
                if let Some(world) = world {
                    world.close().await.expect("could not close the session");
                }
            })
        })
        .filter_run(FEATURES, filter)
        .await;

    writer.failed_steps() + writer.parsing_errors() + writer.hook_errors()
}

fn tagged(scenario: &gherkin::Scenario, tag: &str) -> bool {
    scenario.tags.iter().any(|candidate| candidate == tag)
}
