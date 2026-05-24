pub mod login;
pub mod register;

pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}
