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
        .stdout_eq(str![[r#"
Pepper and Carrot 01 - Potion of Flight (3P)
Pepper and Carrot 02 - Rainbow Potions (5P)
2 book(s), 8 page(s), scanned in [..]

"#]])
        .stderr_eq(str![]);
}

#[test]
fn initial_scan_finished() {
    Command::new(cmd::cargo_bin!("comics"))
        .env("NO_COLOR", "true")
        .env("SEED", "0")
        .timeout(Duration::from_secs(1))
        .args(["--bind", "127.0.0.1:0", "--data-dir", "fixtures/data"])
        .assert()
        .interrupted()
        .stdout_eq(str![[r#"
[..]  WARN comics: no authorization enabled, server is publicly accessible
[..]  INFO comics: server started addr=127.0.0.1:[..] version=[..]
[..]  INFO comics: initial scan finished books=2 pages=8 duration_ms=[..]

"#]])
        .stderr_eq(str![]);
}

#[test]
fn initial_scan_failed() {
    let dir = tempdir().unwrap();
    let non_exist = dir.path().join("non_exist");
    let path = non_exist.to_string_lossy();
    Command::new(cmd::cargo_bin!("comics"))
        .env("NO_COLOR", "true")
        .env("SEED", "0")
        .timeout(Duration::from_secs(1))
        .args(["--bind", "127.0.0.1:0", "--data-dir", &path])
        .assert()
        .success()
        .stdout_eq(str![[r#"
[..]  WARN comics: no authorization enabled, server is publicly accessible
[..]  INFO comics: server started addr=[..] version=[..]
[..] ERROR comics: initial scan failed err=No such file or directory (os error 2)
[..]  WARN comics: fatal error occurred, shutdown the server

"#]])
        .stderr_eq(str![]);
}
