//! The Cucumber runner (`harness = false`). Run with `cargo test --test e2e`
//! from `e2e/`.
//!
//! * `@nojs` — the `before` hook opens that scenario's session with scripting
//!   disabled.
//! * `@logout` — `POST /logout` ends *every* live session, so it would sign
//!   concurrent scenarios out mid-run. It gets a second pass of its own.

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
/// More browsers than cores makes pages settle slower than the steps wait.
/// The login rate limiter (5 per IP per 60 s, all from 127.0.0.1) is not a
/// constraint: a successful login refunds its slot, and 8 concurrent scenarios
/// never tripped it.
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

    // Both passes run before either can fail the process.
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
