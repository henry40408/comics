/// Authentication configuration
#[derive(Clone)]
pub enum AuthConfig {
    None,
    Some {
        username: String,
        password_hash: String,
    },
}
