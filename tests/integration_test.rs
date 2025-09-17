use snapbox::{
    cmd::{Command, cargo_bin},
    str,
};
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn list() {
    Command::new(cargo_bin("comics"))
        .args(["--data-dir", "fixtures/data", "list"])
        .assert()
        .success()
        .stdout_eq(str![[r#"
Netherworld Nomads Journey to the Jade Jungle (9P)
Quantum Quest Legacy of the Luminous League (9P)
2 book(s), 18 page(s), scanned in [..]

"#]])
        .stderr_eq(str![]);
}

#[test]
fn initial_scan_finished() {
    Command::new(cargo_bin("comics"))
        .env("NO_COLOR", "true")
        .env("SEED", "0")
        .timeout(Duration::from_secs(1))
        .args(["--bind", "127.0.0.1:0", "--data-dir", "fixtures/data"])
        .assert()
        .failure()
        .stdout_eq(str![[r#"
[..]  WARN comics: no authorization enabled, server is publicly accessible
[..]  INFO comics: server started addr=127.0.0.1:[..] version=[..]
[..]  INFO comics: initial scan finished total_books=2 total_pages=18 duration=[..]

"#]])
        .stderr_eq(str![]);
}

#[test]
fn initial_scan_failed() {
    let dir = tempdir().unwrap();
    let non_exist = dir.path().join("non_exist");
    let path = non_exist.to_string_lossy();
    Command::new(cargo_bin("comics"))
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
