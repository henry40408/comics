use snapbox::{
    assert_data_eq,
    cmd::{self, Command},
    str,
};
use std::io::{BufRead as _, BufReader};
use std::process::{Command as Process, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

/// Ceiling for waiting on a log line, not an expected duration — the waits
/// below finish in milliseconds. Generous on purpose: it exists so a wedged
/// binary fails the run instead of hanging it, and a machine under load must
/// never be able to reach it.
const LOG_WAIT: Duration = Duration::from_secs(30);

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

/// The scan runs on a background thread *after* the listener is up, so the log
/// is the only place it reports in. This reads until that line arrives and then
/// stops the server, rather than sampling the output after a fixed timeout: the
/// server never exits on its own, so a timeout here is the test's whole runtime
/// and any value short enough to be tolerable is also short enough to lose on a
/// loaded machine. Reading is both faster and not a race.
#[test]
fn initial_scan_finished() {
    let mut server = Process::new(cmd::cargo_bin!("comics"))
        .env("NO_COLOR", "true")
        .env(
            "COMICS_SECRET",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .args(["--bind", "127.0.0.1:0", "--data-dir", "fixtures/data"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start comics");

    let stdout = server.stdout.take().expect("a piped stdout");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut logs = String::new();
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let reported = line.contains("initial scan finished");
            logs.push_str(&line);
            logs.push('\n');
            if reported {
                break;
            }
        }
        // A closed channel means the test already gave up; nothing to do.
        drop(tx.send(logs));
    });

    let logs = rx
        .recv_timeout(LOG_WAIT)
        .expect("the scan never reported in");

    server.kill().expect("failed to stop comics");
    let rest = server.wait_with_output().expect("failed to reap comics");

    assert_data_eq!(
        logs,
        str![[r"
[..]  WARN comics: no authorization enabled, server is publicly accessible
[..]  INFO comics: server started addr=127.0.0.1:[..] version=[..]
[..]  INFO comics: initial scan finished books=2 pages=8 duration_ms=[..]

"]]
    );
    assert_data_eq!(String::from_utf8_lossy(&rest.stderr).as_ref(), str![]);
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
        // A failed scan shuts the server down, so this bounds a hang rather
        // than pacing the test — it costs nothing to be generous, and at one
        // second a loaded machine could be interrupted before it exits.
        .timeout(LOG_WAIT)
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
