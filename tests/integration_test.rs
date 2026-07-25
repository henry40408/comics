use snapbox::{
    cmd::{self, Command},
    str,
};
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn list() {
    Command::new(cmd::cargo_bin!("comics"))
        .args(["--data-dir", "fixtures/data", "list"])
        .assert()
        .success()
        .stdout_eq(str![[r"
Pepper and Carrot 01 - Potion of Flight (3P)
Pepper and Carrot 02 - Rainbow Potions (5P)
2 book(s), 8 page(s), scanned in [..]

"]])
        .stderr_eq(str![]);
}

#[test]
fn initial_scan_finished() {
    Command::new(cmd::cargo_bin!("comics"))
        .env("NO_COLOR", "true")
        .env(
            "COMICS_SECRET",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .timeout(Duration::from_secs(1))
        .args(["--bind", "127.0.0.1:0", "--data-dir", "fixtures/data"])
        .assert()
        .interrupted()
        .stdout_eq(str![[r"
[..]  WARN comics: no authorization enabled, server is publicly accessible
[..]  INFO comics: server started addr=127.0.0.1:[..] version=[..]
[..]  INFO comics: initial scan finished books=2 pages=8 duration_ms=[..]

"]])
        .stderr_eq(str![]);
}

#[test]
fn legacy_env_var_aborts_startup() {
    // A stale, pre-prefix env var name must fail fast instead of being ignored.
    // `env_clear` makes the check deterministic regardless of the ambient env.
    Command::new(cmd::cargo_bin!("comics"))
        .env_clear()
        .env("BIND", "127.0.0.1:0")
        .args(["--data-dir", "fixtures/data"])
        .assert()
        .failure()
        .stdout_eq(str![])
        .stderr_eq(str![[r"
Error: these environment variables no longer exist; rename (or unset) them to continue:
  BIND -> COMICS_BIND

"]]);
}

#[test]
fn folded_env_vars_abort_startup() {
    // COMICS_SEED and COMICS_SESSION_KEY were folded into COMICS_SECRET.
    // Ignoring a leftover one would silently fall back to a random secret,
    // logging everyone out and reshuffling every URL on each restart while the
    // deployment's configuration still looked correct.
    Command::new(cmd::cargo_bin!("comics"))
        .env_clear()
        .env("COMICS_SEED", "1")
        .env("COMICS_SESSION_KEY", "0123456789abcdef")
        .args(["--data-dir", "fixtures/data"])
        .assert()
        .failure()
        .stdout_eq(str![])
        .stderr_eq(str![[r"
Error: these environment variables no longer exist; rename (or unset) them to continue:
  COMICS_SEED -> COMICS_SECRET
  COMICS_SESSION_KEY -> COMICS_SECRET

"]]);
}

#[test]
fn initial_scan_failed() {
    let dir = tempdir().unwrap();
    let non_exist = dir.path().join("non_exist");
    let path = non_exist.to_string_lossy();
    Command::new(cmd::cargo_bin!("comics"))
        .env("NO_COLOR", "true")
        .env(
            "COMICS_SECRET",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .timeout(Duration::from_secs(1))
        .args(["--bind", "127.0.0.1:0", "--data-dir", &path])
        .assert()
        .success()
        .stdout_eq(str![[r"
[..]  WARN comics: no authorization enabled, server is publicly accessible
[..]  INFO comics: server started addr=[..] version=[..]
[..] ERROR comics: initial scan failed err=No such file or directory (os error 2)
[..]  WARN comics: fatal error occurred, shutdown the server

"]])
        .stderr_eq(str![]);
}
