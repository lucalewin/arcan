pub mod login;
pub mod register;
pub mod salt;

pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}
