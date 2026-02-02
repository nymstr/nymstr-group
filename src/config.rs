//! Group server configuration management.
//!
//! On first launch, if config doesn't exist, prompts user via CLI.
//! Config is stored as TOML in the config directory.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Group server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupConfig {
    /// Unique identifier for the group (alphanumeric, -, _)
    pub group_id: String,
    /// Display name for the group
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Whether the group is publicly discoverable
    pub is_public: bool,
    /// Discovery server Nym address (optional - for registration)
    pub discovery_server: Option<String>,
    /// Admin's PGP public key (ASCII-armored) - required before registration
    pub admin_public_key: Option<String>,
    /// Whether this group has been registered with discovery server
    pub registered: bool,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            group_id: String::new(),
            name: String::new(),
            description: None,
            is_public: true,
            discovery_server: None,
            admin_public_key: None,
            registered: false,
        }
    }
}

impl GroupConfig {
    /// Load config from file, or create interactively if it doesn't exist
    pub fn load_or_create(config_path: &Path) -> Result<Self> {
        if config_path.exists() {
            Self::load(config_path)
        } else {
            log::info!(
                "No config found at {:?}, starting interactive setup",
                config_path
            );
            let config = Self::create_interactive()?;
            config.save(config_path)?;
            Ok(config)
        }
    }

    /// Load config from TOML file
    pub fn load(config_path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config from {:?}", config_path))?;
        let config: GroupConfig =
            toml::from_str(&content).with_context(|| "Failed to parse config TOML")?;
        log::info!("Loaded config for group '{}'", config.group_id);
        Ok(config)
    }

    /// Save config to TOML file
    pub fn save(&self, config_path: &Path) -> Result<()> {
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self).with_context(|| "Failed to serialize config")?;
        std::fs::write(config_path, content)
            .with_context(|| format!("Failed to write config to {:?}", config_path))?;
        log::info!("Saved config to {:?}", config_path);
        Ok(())
    }

    /// Interactive CLI configuration
    fn create_interactive() -> Result<Self> {
        println!("\n=== Group Server Configuration ===\n");

        let group_id = prompt_required("Group ID (unique identifier, alphanumeric/-/_)")?;
        if !is_valid_id(&group_id) {
            anyhow::bail!("Invalid group ID. Use only alphanumeric characters, '-', or '_'");
        }

        let name = prompt_required("Group Name (display name)")?;

        let description = prompt_optional("Description (optional, press Enter to skip)")?;

        let is_public = prompt_yes_no("Make group publicly discoverable?", true)?;

        let discovery_server =
            prompt_optional("Discovery server Nym address (optional, press Enter to skip)")?;

        println!("\n=== Configuration Summary ===");
        println!("  Group ID: {}", group_id);
        println!("  Name: {}", name);
        println!(
            "  Description: {}",
            description.as_deref().unwrap_or("(none)")
        );
        println!("  Public: {}", is_public);
        println!(
            "  Discovery Server: {}",
            discovery_server.as_deref().unwrap_or("(none)")
        );
        println!();

        if !prompt_yes_no("Save this configuration?", true)? {
            anyhow::bail!("Configuration cancelled by user");
        }

        Ok(Self {
            group_id,
            name,
            description,
            is_public,
            discovery_server,
            admin_public_key: None,
            registered: false,
        })
    }

    /// Set admin public key from file and save config
    pub fn set_admin_from_file(&mut self, key_path: &Path, config_path: &Path) -> Result<()> {
        let key = std::fs::read_to_string(key_path)
            .with_context(|| format!("Failed to read admin public key from {:?}", key_path))?;

        // Basic validation - should start with PGP header
        if !key.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
            anyhow::bail!("Invalid PGP public key format");
        }

        self.admin_public_key = Some(key.trim().to_string());
        self.save(config_path)?;
        println!("Admin public key set successfully.");
        Ok(())
    }

    /// Check if admin is configured
    pub fn has_admin(&self) -> bool {
        self.admin_public_key.is_some()
    }

    /// Check if ready for registration (has admin and discovery server)
    #[allow(dead_code)] // Part of public API for registration workflow
    pub fn can_register(&self) -> bool {
        self.has_admin() && self.discovery_server.is_some() && !self.registered
    }

    /// Mark as registered and save
    pub fn mark_registered(&mut self, config_path: &Path) -> Result<()> {
        self.registered = true;
        self.save(config_path)
    }

    /// Get default config path
    pub fn default_path() -> PathBuf {
        PathBuf::from("config/group.toml")
    }
}

/// Validate ID format: non-empty, max 128 chars, alphanumeric + '-' or '_'
fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Prompt for required input
fn prompt_required(prompt: &str) -> Result<String> {
    loop {
        print!("{}: ", prompt);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_string();

        if !input.is_empty() {
            return Ok(input);
        }
        println!("This field is required.");
    }
}

/// Prompt for optional input
fn prompt_optional(prompt: &str) -> Result<Option<String>> {
    print!("{}: ", prompt);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_string();

    Ok(if input.is_empty() { None } else { Some(input) })
}

/// Prompt for yes/no
fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    print!("{} {}: ", prompt, hint);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    Ok(match input.as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        "" => default,
        _ => default,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_save_and_load() {
        let tmp = tempdir().unwrap();
        let config_path = tmp.path().join("test.toml");

        let config = GroupConfig {
            group_id: "test-group".to_string(),
            name: "Test Group".to_string(),
            description: Some("A test group".to_string()),
            is_public: true,
            discovery_server: Some("abc123@gateway".to_string()),
            admin_public_key: None,
            registered: false,
        };

        config.save(&config_path).unwrap();
        let loaded = GroupConfig::load(&config_path).unwrap();

        assert_eq!(loaded.group_id, "test-group");
        assert_eq!(loaded.name, "Test Group");
        assert_eq!(loaded.description, Some("A test group".to_string()));
        assert!(loaded.is_public);
        assert!(!loaded.registered);
        assert!(!loaded.has_admin());
        assert!(!loaded.can_register());
    }

    #[test]
    fn test_is_valid_id() {
        assert!(is_valid_id("valid-id"));
        assert!(is_valid_id("valid_id"));
        assert!(is_valid_id("ValidId123"));
        // Max length (128 chars)
        assert!(is_valid_id(&"a".repeat(128)));

        assert!(!is_valid_id(""));
        assert!(!is_valid_id("invalid id"));
        assert!(!is_valid_id("invalid@id"));
        // Over max length (129 chars)
        assert!(!is_valid_id(&"a".repeat(129)));
    }
}
