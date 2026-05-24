use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use std::env;

#[derive(Parser)]
#[command(name = "arcan")]
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
}

// Subcommands for Vault and Item remain the same as previously defined
#[derive(Subcommand)]
pub enum VaultCommands {
    Create { name: String },
    List,
    Delete { id: String },
}

#[derive(Subcommand)]
pub enum ItemCommands {
    Create {
        vault_id: String,
        item_type: String,
        #[arg(short, long, num_args = 1..)]
        fields: Vec<String>,
    },
    List {
        vault_id: String,
    },
    View {
        item_id: String,
    },
    Delete {
        item_id: String,
    },
}
