use assert_cmd::Command;
use std::time::Duration;
use tempdir::TempDir;

#[test]
fn initial_scan_finished() {
    let mut cmd = Command::cargo_bin("comics").unwrap();
    cmd.args(["--bind", "127.0.0.1:3000", "--data-dir", "fixtures/data"]);
    cmd.timeout(Duration::from_millis(100));
    cmd.assert()
        .stdout(predicates::str::contains("initial scan finished"));
}

#[test]
fn initial_scan_failed() {
    let dir = TempDir::new("temp").unwrap();
    let mut cmd = Command::cargo_bin("comics").unwrap();
    let non_exist = dir.path().join("non_exist");
    let path = non_exist.to_string_lossy();
    cmd.args(["--bind", "127.0.0.1:3001", "--data-dir", &path]);
    cmd.timeout(Duration::from_millis(100));
    cmd.assert()
        .stdout(predicates::str::contains("initial scan failed"));
}
