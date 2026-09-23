//! The comics server under test.
//!
//! An already-listening port is adopted, which makes a local re-run fast.
//! Spawned directly rather than through `cargo run`: killing `cargo` would
//! leave its child holding the port.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// Fixed, so a developer can leave a server running between runs.
pub const PORT: u16 = 3030;

/// Base URL every page object navigates against.
pub const BASE_URL: &str = "http://127.0.0.1:3030";

/// Argon2id hash of "password" — a throwaway credential for the fixtures.
const TEST_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$C2qIDpzPcTL0a5wYL1152Q$2MWeEDjhoNnp8oRwz9DkFoLgYH3NTe+qArT3vPHN14g";

const TEST_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The username the login steps sign in with.
pub const USERNAME: &str = "user";

/// The password the login steps sign in with.
pub const PASSWORD: &str = "password";

/// How long to wait for the server to start listening.
const STARTUP_TIMEOUT: Duration = Duration::from_mins(1);

/// A running comics server. Killed when dropped — unless it was already
/// listening before the suite started, in which case it is left alone.
pub struct Server {
    child: Option<Child>,
}

impl Server {
    /// Starts the server, or adopts one already listening on [`PORT`].
    pub fn start() -> Result<Self> {
        if port_is_open() {
            return Ok(Self { child: None });
        }

        let binary = ensure_binary()?;
        let child = Command::new(&binary)
            .current_dir(repo_root())
            .args([
                "--bind",
                &format!("127.0.0.1:{PORT}"),
                "--data-dir",
                "fixtures/data",
            ])
            .env("COMICS_AUTH_USERNAME", USERNAME)
            .env("COMICS_AUTH_PASSWORD_HASH", TEST_PASSWORD_HASH)
            .env("COMICS_SECRET", TEST_SECRET)
            // Inherited, so a refusal to start shows in the test output.
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("spawning the comics server at {}", binary.display()))?;

        // Bound before the wait, so a server that never answers is still killed.
        let server = Self { child: Some(child) };
        wait_until_listening()?;
        Ok(server)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Path to the server binary, building it first when it is not there.
///
/// The **dev** profile, deliberately: the release profile's LTO buys nothing
/// for eight fixture pages, dependencies still build at `opt-level = 3`, and
/// the artefacts are shared with `cargo nextest run`. CI builds it beforehand.
fn ensure_binary() -> Result<PathBuf> {
    let binary = repo_root().join("target/debug/comics");
    if binary.is_file() {
        return Ok(binary);
    }

    eprintln!("e2e: {} is missing — building it", binary.display());
    let status = Command::new("cargo")
        .current_dir(repo_root())
        .arg("build")
        .status()
        .context("running `cargo build`")?;
    if !status.success() {
        bail!("`cargo build` failed with {status}");
    }
    if !binary.is_file() {
        bail!("`cargo build` did not produce {}", binary.display());
    }
    Ok(binary)
}

fn wait_until_listening() -> Result<()> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        if port_is_open() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("comics server did not start listening on 127.0.0.1:{PORT} within {STARTUP_TIMEOUT:?}")
}

fn port_is_open() -> bool {
    TcpStream::connect(("127.0.0.1", PORT)).is_ok()
}

/// The repository root — the parent of this crate's directory.
fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e/ always has a parent")
}
