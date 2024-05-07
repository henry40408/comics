use git_version::git_version;

fn main() {
    let version = git_version!();
    println!("cargo:rustc-env=APP_VERSION={version}");
}
