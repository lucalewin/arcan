use clap::{Parser, Subcommand};
use uuid::Uuid;

use crate::APP_NAME;

#[derive(Parser)]
#[command(name = APP_NAME)]
#[command(about = "Zero-knowledge password manager", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initial setup: create account, generate salts, register with server
    Onboard {
        #[arg(short, long)]
        email: String,

        #[arg(long)]
        login: bool,
    },

    /// Unlock the vault and generate the session environment variable
    Unlock,

    /// Manage vaults (Create, List, Delete)
    Vault {
        #[command(subcommand)]
        action: VaultCommands,
    },

    /// Manage items (Create, List, Read, Delete)
    Item {
        #[command(subcommand)]
        action: ItemCommands,
    },

    /// Generate a strong, random password
    Password {
        #[arg(short, long, default_value_t = 32)]
        length: usize,
    },

    /// Manually sync local changes with the remote server
    Sync,

    Totp {
        id: Uuid,
        #[arg(long, default_value_t = false)]
        copy: bool,
        #[arg(long, default_value_t = false)]
        watch: bool,
    },
}

// Subcommands for Vault and Item remain the same as previously defined
#[derive(Subcommand)]
pub enum VaultCommands {
    Create {
        #[arg(long)]
        name: Option<String>,
    },
    List,
    Delete {
        id: String,
    },
}

#[derive(Subcommand)]
pub enum ItemCommands {
    Create {
        #[arg(long)]
        vault: Option<String>,
        // #[arg(long)]
        // title: String,

        // #[arg(long, value_delimiter = ',', default_value = "")]
        // tags: Vec<String>,

        // #[command(subcommand)]
        // payload: CreateItemPayload,
    },
    List {
        vault_id: String,
    },
    View {
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        item: Option<String>,
    },
    Delete {
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        item: Option<String>,
    },
}

// This maps 1:1 with your ItemPayload enum
#[derive(Subcommand)]
pub enum CreateItemPayload {
    Login {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        url: Option<String>,
    },
    Note {
        #[arg(long)]
        content: String,
    },
    Totp {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        account_name: Option<String>,
    },
    Card {
        #[arg(long)]
        cardholder: String,
        #[arg(long)]
        number: String,
        #[arg(long)]
        exp_month: u8,
        #[arg(long)]
        exp_year: u16,
        #[arg(long)]
        cvv: String,
    },
}
