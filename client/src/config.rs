use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::APP_NAME;

#[derive(Serialize, Deserialize, Debug)]
pub struct ArcanConfig {
    pub api_url: String,
    pub sync_timeout_secs: u64,
}

impl Default for ArcanConfig {
    fn default() -> Self {
        Self {
            // Default to local dev, users can change this in the file
            api_url: "http://127.0.0.1:3000".to_string(),
            sync_timeout_secs: 30,
        }
    }
}

impl ArcanConfig {
    fn get_config_dir() -> Result<PathBuf, String> {
        if let Ok(env_path) = std::env::var("ARCAN_CONFIG_DIR") {
            return Ok(PathBuf::from(env_path));
        }

        // Creates a directory path like: ~/.config/arcan/
        let proj_dirs = ProjectDirs::from("com", "lucalewin", APP_NAME)
            .ok_or("Could not determine the home directory for this OS")?;

        Ok(proj_dirs.config_dir().to_path_buf())
    }

    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let config_dir = Self::get_config_dir()?;
        let config_file = config_dir.join("config.toml");

        if !config_file.exists() {
            // Ensure the directory exists
            fs::create_dir_all(&config_dir)?;

            // Write the default config
            let default_config = Self::default();
            let toml_string = toml::to_string_pretty(&default_config)?;
            fs::write(&config_file, toml_string)?;

            return Ok(default_config);
        }

        let toml_string = fs::read_to_string(config_file)?;
        let config: ArcanConfig = toml::from_str(&toml_string)?;

        Ok(config)
    }

    // /// Helper to print the config location for the user
    // pub fn print_location() {
    //     if let Ok(dir) = Self::get_config_dir() {
    //         println!("Config loaded from: {}", dir.join("config.toml").display());
    //     }
    // }
}
