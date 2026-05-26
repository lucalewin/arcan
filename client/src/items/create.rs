use inquire::{CustomType, Password, PasswordDisplayMode, Select, Text};
use sqlx::SqlitePool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    crypto::encrypt_payload,
    items::{
        envelop::{CardItem, ItemPayload, LoginItem, NoteItem, SshKeyItem, TotpItem},
        handlers::get_decrypted_vsk,
    },
};

enum ItemType {
    Login,
    TOTP,
    SshKey,
    Note,
    Card,
}

impl std::fmt::Display for ItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ItemType::Note => "Note",
            ItemType::Login => "Login",
            ItemType::SshKey => "SSH Key",
            ItemType::Card => "Card",
            ItemType::TOTP => "TOTP",
        };
        write!(f, "{}", s)
    }
}

// pub async fn create_item_handler(
//     pool: &SqlitePool,
//     kek: &[u8; 32],
//     vault: &str,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let type_options = vec![
//         // "Note".to_string(),
//         // "Login".to_string(),
//         // "Card".to_string(),
//         // "TOTP".to_string(),
//         ItemType::Login,
//         ItemType::TOTP,
//         ItemType::SshKey,
//         ItemType::Note,
//         ItemType::Card,
//     ];

//     let item_type = inquire::Select::new("Select item type:", type_options)
//         .prompt()
//         .unwrap();

//     let title = inquire::Text::new("Item Title:").prompt().unwrap();

//     let payload = match item_type {
//         ItemType::Login => {
//             let username = inquire::Text::new("Username:").prompt().unwrap();
//             let password = inquire::Password::new("Password:")
//                 .with_display_mode(inquire::PasswordDisplayMode::Masked)
//                 .with_display_toggle_enabled()
//                 .prompt()
//                 .unwrap();
//             let url = inquire::Text::new("URL (optional):").prompt().unwrap();
//             // println!(
//             //     "Creating Login item with title '{}', username '{}', and URL '{}'",
//             //     title, username, url
//             // );

//             ItemPayload::Login(LoginItem {
//                 username,
//                 password,
//                 url: if url.is_empty() { None } else { Some(url) },
//             })
//         }
//         ItemType::TOTP => {
//             let secret = inquire::Text::new("TOTP Secret:").prompt().unwrap();
//             let account_name = inquire::Text::new("Account Name (optional):")
//                 .prompt()
//                 .unwrap();
//             // println!(
//             //     "Creating TOTP item with title '{}', secret '{}', and account name '{}'",
//             //     title, secret, account_name
//             // );
//             ItemPayload::Totp(crate::items::envelop::TotpItem {
//                 secret,
//                 account_name: if account_name.is_empty() {
//                     None
//                 } else {
//                     Some(account_name)
//                 },
//                 issuer: None,
//             })
//         }
//         ItemType::SshKey => {
//             let public_key = inquire::Text::new("Public Key:").prompt().unwrap();
//             let private_key = inquire::Text::new("Private Key:").prompt().unwrap();
//             // println!(
//             //     "Creating SSH Key item with title '{}', public key '{}'",
//             //     title, public_key
//             // );
//             ItemPayload::SshKey(crate::items::envelop::SshKeyItem {
//                 public_key: Some(public_key),
//                 private_key,
//                 passphrase: None,
//                 hostname: None,
//             })
//         }
//         ItemType::Note => {
//             let content = inquire::Text::new("Note Content:").prompt().unwrap();
//             // println!(
//             //     "Creating Note item with title '{}' and content '{}'",
//             //     title, content
//             // );

//             ItemPayload::Note(crate::items::envelop::NoteItem { content })
//         }
//         ItemType::Card => {
//             let cardholder = inquire::Text::new("Cardholder Name:").prompt().unwrap();
//             let number = inquire::Text::new("Card Number:").prompt().unwrap();
//             let exp_month = inquire::Text::new("Expiration Month (MM):")
//                 .prompt()
//                 .unwrap();
//             let exp_year = inquire::Text::new("Expiration Year (YYYY):")
//                 .prompt()
//                 .unwrap();
//             // println!(
//             //     "Creating Card item with title '{}', cardholder '{}', and number '{}'",
//             //     title, cardholder, number
//             // );
//             ItemPayload::Card(crate::items::envelop::CardItem {
//                 cardholder_name: cardholder,
//                 number,
//                 exp_month: exp_month.parse().unwrap_or(0),
//                 exp_year: exp_year.parse().unwrap_or(0),
//                 cvv: String::new(), // For simplicity, we're not asking for CVV here
//             })
//         }
//     };

//     Ok(())
// }

pub async fn create_item_interactive(
    pool: &SqlitePool,
    kek: &[u8; 32],
    vault: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let vault = crate::items::interactive::resolve_vault(pool, kek, vault).await?;
    let type_options = vec![
        ItemType::Login,
        ItemType::TOTP,
        ItemType::SshKey,
        ItemType::Note,
        ItemType::Card,
    ];

    // Using `?` instead of unwrap() safely exits if the user hits Esc or Ctrl+C
    let item_type = Select::new("Select item type:", type_options).prompt()?;
    let title = Text::new("Item Title:").prompt()?;

    let payload = match item_type {
        ItemType::Login => {
            let username = Text::new("Username:").prompt()?;
            let password = prompt_password()?;
            let url = Text::new("URL (optional):").prompt()?;

            ItemPayload::Login(LoginItem {
                username,
                password,
                url: if url.is_empty() { None } else { Some(url) },
            })
        }
        ItemType::TOTP => {
            let secret = Text::new("TOTP Secret:").prompt()?;
            let account_name = Text::new("Account Name (optional):").prompt()?;

            ItemPayload::Totp(TotpItem {
                secret,
                account_name: if account_name.is_empty() {
                    None
                } else {
                    Some(account_name)
                },
                issuer: None,
            })
        }
        ItemType::SshKey => {
            let public_key = Text::new("Public Key (optional):").prompt()?;
            let private_key = Text::new("Private Key:").prompt()?;

            ItemPayload::SshKey(SshKeyItem {
                public_key: if public_key.is_empty() {
                    None
                } else {
                    Some(public_key)
                },
                private_key,
                passphrase: None,
                hostname: None,
            })
        }
        ItemType::Note => {
            let content = Text::new("Note Content:").prompt()?;
            ItemPayload::Note(NoteItem { content })
        }
        ItemType::Card => {
            let cardholder = Text::new("Cardholder Name:").prompt()?;
            let number = Text::new("Card Number:").prompt()?;

            // CustomType enforces that the user types a valid u8/u16
            // It will reprompt them automatically if they type text!
            let exp_month = CustomType::<u8>::new("Expiration Month (MM):")
                .with_error_message("Please enter a valid number between 1 and 12")
                .prompt()?;

            let exp_year = CustomType::<u16>::new("Expiration Year (YYYY):")
                .with_error_message("Please enter a valid year")
                .prompt()?;

            let cvv = Password::new("CVV:")
                .with_display_mode(PasswordDisplayMode::Masked)
                .prompt()?;

            ItemPayload::Card(CardItem {
                cardholder_name: cardholder,
                number,
                exp_month,
                exp_year,
                cvv,
            })
        }
    };

    // 1. Wrap in ItemEnvelope
    let envelope = crate::items::envelop::ItemEnvelope {
        title,
        tags: vec![],
        payload,
    };

    // 2. Fetch VSK, Serialize, Encrypt, and Insert into SQLite
    // (This follows the exact same logic as your previous create handler)
    // ...
    let item_id = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // 1. Fetch and decrypt the VSK for this vault
    let vsk = get_decrypted_vsk(pool, kek, &vault).await?;
    // 4. Serialize and Encrypt
    let payload_json = serde_json::to_string(&envelope)?;
    let packed_payload = encrypt_payload(&vsk, payload_json.as_bytes(), &item_id)?.pack();

    // 4. Save to DB
    sqlx::query!(
        "INSERT INTO items (id, vault_id, encrypted_payload, server_revision, is_deleted, is_dirty, created_at, updated_at)
         VALUES (?1, ?2, ?3, 0, 0, 1, ?4, ?5)",
        item_id,
        vault,
        packed_payload,
        now,
        now
    )
    .execute(pool)
    .await?;

    println!("Item created successfully. ID: {}", item_id);
    Ok(())
}

fn prompt_password() -> Result<String, Box<dyn std::error::Error>> {
    let pass_action = Select::new(
        "Password Options:",
        vec!["Type manually", "Generate randomly"],
    )
    .prompt()?;

    let password = if pass_action == "Generate randomly" {
        // Prompt for length with a secure default
        let length = CustomType::<usize>::new("Password length:")
            .with_default(20)
            .with_error_message("Please enter a valid number")
            .prompt()?;

        let generated = crate::util::generate_password(&crate::util::PasswordOptions {
            length,
            numbers: true,
            uppercase: true,
            symbols: true,
        });

        // You must print the generated password so the user knows what was saved
        println!("Generated Password: {}", generated);

        generated
    } else {
        Password::new("Password:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .with_display_toggle_enabled()
            .prompt()?
    };

    Ok(password)
}
