use git2::Repository;

fn main() {
    let repo = Repository::open(".").expect("Failed to find git repository");
    let rev = repo
        .describe(git2::DescribeOptions::new().describe_tags())
        .expect("Failed to describe HEAD");
    let version = rev.format(None).expect("Failed to format description");
    println!("cargo:rustc-env=APP_VERSION={version}");
}
