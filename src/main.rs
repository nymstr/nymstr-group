mod config;
mod crypto_utils;
mod db_utils;
mod log_config;
mod message_utils;
mod rate_limiter;

use crate::config::GroupConfig;
use crate::crypto_utils::CryptoUtils;
use crate::db_utils::DbUtils;
use crate::log_config::init_logging;
use crate::message_utils::MessageUtils;
use nym_sdk::mixnet::{MixnetClientBuilder, MixnetMessageSender, StoragePaths};
use std::path::PathBuf;
use tokio_stream::StreamExt;

/// Attempts to extract a challenge nonce from a message.
/// Returns the nonce string if this is a valid challenge message.
fn try_extract_challenge_nonce(raw: &str) -> Option<String> {
    let data: serde_json::Value = serde_json::from_str(raw).ok()?;
    if data.get("action").and_then(|v| v.as_str()) != Some("challenge") {
        return None;
    }
    let content = data.get("content").and_then(|v| v.as_str())?;
    let challenge: serde_json::Value = serde_json::from_str(content).ok()?;
    challenge.get("nonce").and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Attempts to extract registration response content from a message.
/// Returns the content string if this is a valid registerGroupResponse message.
fn try_extract_register_response(raw: &str) -> Option<String> {
    let data: serde_json::Value = serde_json::from_str(raw).ok()?;
    if data.get("action").and_then(|v| v.as_str()) != Some("registerGroupResponse") {
        return None;
    }
    data.get("content").and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn print_usage() {
    eprintln!("Usage: nymstr-groupd [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --set-admin <path>   Set admin public key from PGP file");
    eprintln!("  --register           Register group with discovery server");
    eprintln!("  --help               Show this help message");
    eprintln!();
    eprintln!("Environment variables:");
    eprintln!("  CONFIG_PATH          Path to config file (default: config/group.toml)");
    eprintln!("  DATABASE_PATH        Path to SQLite database (default: storage/groupd.db)");
    eprintln!("  LOG_FILE_PATH        Path to log file (default: logs/groupd.log)");
    eprintln!("  NYM_CLIENT_ID        Nym client identity (default: groupd)");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Parse CLI arguments
    let mut set_admin_path: Option<PathBuf> = None;
    let mut do_register = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            "--set-admin" => {
                if i + 1 >= args.len() {
                    return Err(anyhow::anyhow!("--set-admin requires a path argument"));
                }
                set_admin_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--register" => {
                do_register = true;
                i += 1;
            }
            _ => {
                print_usage();
                return Err(anyhow::anyhow!("Unknown option: {}", args[i]));
            }
        }
    }

    // Load or create group configuration first (may require interactive input)
    let config_path = std::env::var("CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| GroupConfig::default_path());
    let mut group_config = GroupConfig::load_or_create(&config_path)?;

    // Handle --set-admin
    if let Some(key_path) = set_admin_path {
        group_config.set_admin_from_file(&key_path, &config_path)?;
        return Ok(());
    }

    // Handle --register
    if do_register {
        if !group_config.has_admin() {
            return Err(anyhow::anyhow!("Admin not set. Use --set-admin <path> first."));
        }
        if group_config.discovery_server.is_none() {
            return Err(anyhow::anyhow!("Discovery server not configured. Edit config file to add discovery_server."));
        }
        if group_config.registered {
            log::info!("Group is already registered with discovery server.");
            return Ok(());
        }

        return run_registration(&mut group_config, &config_path).await;
    }

    // Normal server mode
    run_server(group_config).await
}

/// Run the registration flow with discovery server
async fn run_registration(config: &mut GroupConfig, config_path: &PathBuf) -> anyhow::Result<()> {
    println!("Registering group '{}' with discovery server...", config.group_id);

    // Initialize logging
    let log_file = std::env::var("LOG_FILE_PATH").unwrap_or_else(|_| "logs/groupd.log".to_string());
    if let Some(parent) = PathBuf::from(&log_file).parent() {
        std::fs::create_dir_all(parent)?;
    }
    init_logging(&log_file)?;

    // Setup crypto
    let keys_dir = std::env::var("KEYS_DIR").unwrap_or_else(|_| "storage/keys".to_string());
    std::fs::create_dir_all(&keys_dir)?;
    let secret_path = std::env::var("SECRET_PATH")
        .unwrap_or_else(|_| "secrets/encryption_password".to_string());
    let secret_path_buf = PathBuf::from(&secret_path);
    if let Some(parent) = secret_path_buf.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let password = if !secret_path_buf.exists() {
        // Generate a secure random password on first run
        use rand::distributions::{Alphanumeric, DistString};
        let generated = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
        std::fs::write(&secret_path_buf, &generated)?;
        #[cfg(unix)]
        std::fs::set_permissions(&secret_path_buf, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        log::info!("Generated new encryption password and stored at: {}", secret_path_buf.display());
        generated
    } else {
        let pwd = std::fs::read_to_string(&secret_path_buf)?.trim().to_string();
        if pwd.is_empty() {
            anyhow::bail!(
                "Encryption password file {} is empty. Delete it and restart to generate a new one.",
                secret_path_buf.display()
            );
        }
        pwd
    };
    let client_id = std::env::var("NYM_CLIENT_ID").unwrap_or_else(|_| "groupd".to_string());
    let crypto = CryptoUtils::new(PathBuf::from(&keys_dir), client_id.clone(), password)?;

    // Ensure keypair exists
    let pub_key_path = PathBuf::from(&keys_dir).join(format!("{}_public.asc", client_id));
    let public_key = if !pub_key_path.exists() {
        log::info!("Generating new PGP keypair for registration");
        crypto.generate_key_pair(&client_id)?
    } else {
        std::fs::read_to_string(&pub_key_path)?
    };

    // Connect to mixnet
    let storage_dir = std::env::var("NYM_SDK_STORAGE")
        .unwrap_or_else(|_| format!("storage/{}", client_id));
    std::fs::create_dir_all(&storage_dir)?;
    let storage_paths = StoragePaths::new_from_dir(PathBuf::from(&storage_dir))?;
    let builder = MixnetClientBuilder::new_with_default_storage(storage_paths).await?;
    let client = builder.build()?.connect_to_mixnet().await?;
    let our_address = client.nym_address().to_string();
    println!("Connected to mixnet. Our address: {}", our_address);

    // Send registration request
    let discovery_address = config.discovery_server.as_ref().unwrap();
    let register_msg = serde_json::json!({
        "action": "registerGroup",
        "groupId": config.group_id,
        "name": config.name,
        "nymAddress": our_address,
        "publicKey": public_key,
        "description": config.description,
        "isPublic": config.is_public
    });

    println!("Sending registration request to {}...", discovery_address);
    let recipient = discovery_address.parse()?;
    client.send_plain_message(recipient, register_msg.to_string()).await?;

    // Wait for challenge response
    println!("Waiting for challenge...");
    let mut stream = client;
    let timeout = tokio::time::Duration::from_secs(60);
    let challenge_result = tokio::time::timeout(timeout, async {
        while let Some(msg) = stream.next().await {
            let raw = String::from_utf8_lossy(&msg.message);
            if let Some(nonce) = try_extract_challenge_nonce(&raw) {
                return Some((nonce, msg.sender_tag));
            }
        }
        None
    }).await;

    let (nonce, sender_tag) = match challenge_result {
        Ok(Some((n, tag))) => (n, tag),
        Ok(None) => {
            return Err(anyhow::anyhow!("Did not receive challenge from discovery server"));
        }
        Err(_) => {
            return Err(anyhow::anyhow!("Timeout waiting for challenge from discovery server"));
        }
    };

    println!("Received challenge, signing nonce...");

    // Sign the nonce
    let signature = crypto.sign_message(&client_id, &nonce)?;

    // Send response
    let response_msg = serde_json::json!({
        "action": "registerGroupResponse",
        "signature": signature
    });

    let sender = stream.split_sender();
    if let Some(tag) = sender_tag {
        sender.send_reply(tag, response_msg.to_string()).await?;
    } else {
        // Fallback to sending to discovery address
        sender.send_plain_message(recipient, response_msg.to_string()).await?;
    }

    // Wait for final response
    println!("Waiting for registration confirmation...");
    let final_result = tokio::time::timeout(timeout, async {
        while let Some(msg) = stream.next().await {
            let raw = String::from_utf8_lossy(&msg.message);
            if let Some(content) = try_extract_register_response(&raw) {
                return Some(content);
            }
        }
        None
    }).await;

    match final_result {
        Ok(Some(result)) if result == "success" => {
            println!("Registration successful!");
            config.mark_registered(config_path)?;
            stream.disconnect().await;
            Ok(())
        }
        Ok(Some(result)) => {
            stream.disconnect().await;
            return Err(anyhow::anyhow!("Registration failed: {}", result));
        }
        Ok(None) => {
            stream.disconnect().await;
            return Err(anyhow::anyhow!("Did not receive confirmation from discovery server"));
        }
        Err(_) => {
            stream.disconnect().await;
            return Err(anyhow::anyhow!("Timeout waiting for registration confirmation"));
        }
    }
}

/// Run the normal group server
async fn run_server(group_config: GroupConfig) -> anyhow::Result<()> {
    // Initialize logging
    let log_file = std::env::var("LOG_FILE_PATH").unwrap_or_else(|_| "logs/groupd.log".to_string());
    if let Some(parent) = PathBuf::from(&log_file).parent() {
        std::fs::create_dir_all(parent)?;
    }
    init_logging(&log_file)?;

    log::info!("Starting group server: {} ({})", group_config.name, group_config.group_id);

    if !group_config.has_admin() {
        log::warn!("No admin configured. Use --set-admin <path> to set admin public key.");
    }

    if !group_config.registered {
        if group_config.discovery_server.is_some() {
            log::warn!("Group not registered with discovery server. Run with --register to register.");
        } else {
            log::info!("No discovery server configured. Group will operate in standalone mode.");
        }
    }

    // Prepare database path
    let db_path = std::env::var("DATABASE_PATH")
        .unwrap_or_else(|_| "storage/groupd.db".to_string());
    if let Some(parent) = PathBuf::from(&db_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let db_path_buf = PathBuf::from(&db_path);
    if !db_path_buf.exists() {
        std::fs::File::create(&db_path_buf)?;
    }
    let db = DbUtils::new(&db_path).await?;

    // Prepare key storage for signing
    let keys_dir = std::env::var("KEYS_DIR").unwrap_or_else(|_| "storage/keys".to_string());
    std::fs::create_dir_all(&keys_dir)?;
    let secret_path = std::env::var("SECRET_PATH")
        .unwrap_or_else(|_| "secrets/encryption_password".to_string());
    let secret_path_buf = PathBuf::from(&secret_path);
    if let Some(parent) = secret_path_buf.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let password = if !secret_path_buf.exists() {
        // Generate a secure random password on first run
        use rand::distributions::{Alphanumeric, DistString};
        let generated = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
        std::fs::write(&secret_path_buf, &generated)?;
        #[cfg(unix)]
        std::fs::set_permissions(&secret_path_buf, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        log::info!("Generated new encryption password and stored at: {}", secret_path_buf.display());
        generated
    } else {
        let pwd = std::fs::read_to_string(&secret_path_buf)?.trim().to_string();
        if pwd.is_empty() {
            anyhow::bail!(
                "Encryption password file {} is empty. Delete it and restart to generate a new one.",
                secret_path_buf.display()
            );
        }
        pwd
    };

    let client_id = std::env::var("NYM_CLIENT_ID").unwrap_or_else(|_| "groupd".to_string());
    let crypto = CryptoUtils::new(PathBuf::from(&keys_dir), client_id.clone(), password)?;

    // Ensure the server has a PGP keypair
    let pub_key_path = PathBuf::from(&keys_dir).join(format!("{}_public.asc", client_id));
    if !pub_key_path.exists() {
        log::info!("Server keypair not found, generating new PGP keypair for '{}'", client_id);
        crypto.generate_key_pair(&client_id)?;
    }

    let storage_dir = std::env::var("NYM_SDK_STORAGE")
        .unwrap_or_else(|_| format!("storage/{}", client_id));
    std::fs::create_dir_all(&storage_dir)?;
    let storage_paths = StoragePaths::new_from_dir(PathBuf::from(&storage_dir))?;

    // Build and connect the mixnet client
    let builder = MixnetClientBuilder::new_with_default_storage(storage_paths).await?;
    let client_inner = builder.build()?.connect_to_mixnet().await?;
    let sender = client_inner.split_sender();
    let address = client_inner.nym_address();
    log::info!("Connected to mixnet. Nym Address: {}", address);

    let mut client_stream = client_inner;

    // Start processing incoming messages
    let admin_key = group_config.admin_public_key.clone();
    let mut message_utils = MessageUtils::new(client_id, sender, db, crypto, admin_key);

    tokio::select! {
        _ = async {
            while let Some(msg) = client_stream.next().await {
                message_utils.process_received_message(msg).await;
            }
        } => {},
        _ = tokio::signal::ctrl_c() => {
            log::info!("Shutting down mixnet client.");
            client_stream.disconnect().await;
        }
    }

    Ok(())
}
