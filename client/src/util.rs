use rand::seq::{IndexedRandom, SliceRandom};

pub struct PasswordOptions {
    pub length: usize,
    pub numbers: bool,
    pub uppercase: bool,
    pub symbols: bool,
}

pub fn generate_password(options: &PasswordOptions) -> String {
    // Return early if the requested length is 0
    if options.length == 0 {
        return String::new();
    }

    let mut rng = rand::rng();

    // Character pools
    let lowercase = b"abcdefghijklmnopqrstuvwxyz";
    let uppercase = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let numbers = b"0123456789";
    let symbols = b"!@#$%^&*()-_=+[]{}|;:,.<>?/~";

    let mut charset: Vec<u8> = lowercase.to_vec();
    let mut password: Vec<u8> = Vec::with_capacity(options.length);

    // Build the charset pool and guarantee at least one of each requested type
    if options.uppercase {
        charset.extend_from_slice(uppercase);
        password.push(*uppercase.choose(&mut rng).unwrap());
    }

    if options.numbers {
        charset.extend_from_slice(numbers);
        password.push(*numbers.choose(&mut rng).unwrap());
    }

    if options.symbols {
        charset.extend_from_slice(symbols);
        password.push(*symbols.choose(&mut rng).unwrap());
    }

    // Handle edge case: requested length is smaller than the number of required character types
    if options.length < password.len() {
        password.truncate(options.length);
        password.shuffle(&mut rng);
        return String::from_utf8(password).expect("Invalid UTF-8");
    }

    // Fill the remainder of the password length
    let remaining = options.length - password.len();
    for _ in 0..remaining {
        password.push(*charset.choose(&mut rng).unwrap());
    }

    // Shuffle so the guaranteed characters aren't always at the start
    password.shuffle(&mut rng);

    String::from_utf8(password).expect("Generated password contains invalid UTF-8")
}

pub fn score_password(password: &str) -> u8 {
    let length_score = match password.len() {
        0..=7 => 0,
        8..=11 => 1,
        12..=15 => 2,
        16..=19 => 3,
        _ => 4,
    };

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_numbers = password.chars().any(|c| c.is_numeric());
    let has_symbols = password.chars().any(|c| !c.is_alphanumeric());

    let variety_score = [has_uppercase, has_lowercase, has_numbers, has_symbols]
        .iter()
        .filter(|&&x| x)
        .count() as u8;

    length_score + variety_score
}
