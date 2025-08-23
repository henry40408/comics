use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");

    let output = Command::new("git")
        .args(["describe", "--always", "--dirty=-modified", "--tags"])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let git_desc = String::from_utf8_lossy(&out.stdout).trim().to_string();
            println!("cargo:rustc-env=APP_VERSION={}", git_desc);
        }
        Ok(out) => {
            println!("cargo:rustc-env=APP_VERSION=unknown");
            println!(
                "cargo:warning=git describe failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Err(e) => {
            println!("cargo:rustc-env=APP_VERSION=unknown");
            println!("cargo:warning=failed to run git: {}", e);
        }
    }
}
