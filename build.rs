use git_version::git_version;

fn main() {
    let version = git_version!(args = ["--always", "--dirty=-modified", "--tags"]);
    println!("cargo:rustc-env=APP_VERSION={version}");
}
