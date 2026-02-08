use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let git_version = get_git_version();
    println!("cargo:rustc-env=APP_VERSION={}", git_version);
}

fn get_git_version() -> String {
    // First, check if GIT_VERSION is set via environment variable
    // This is used for Docker builds where .git directory is not available
    if let Ok(version) = std::env::var("GIT_VERSION")
        && !version.is_empty()
        && version != "dev"
    {
        return version;
    }

    // git describe --tags --always --dirty
    Command::new("git")
        .args(["describe", "--always", "--dirty=-modified", "--tags"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map_or_else(
            || "unknown".to_string(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
        )
}
