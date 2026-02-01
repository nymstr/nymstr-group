use crate::crypto_utils::CryptoUtils;
use crate::db_utils::DbUtils;
use crate::rate_limiter::RateLimiter;
use chrono::Utc;
use nym_sdk::mixnet::{
    AnonymousSenderTag, MixnetClientSender, MixnetMessageSender, ReconstructedMessage,
};
use serde_json::{json, Value};

// ============================================================
// Common request structs for format-agnostic handling
// ============================================================

/// Common representation for register requests
struct RegisterRequest {
    username: String,
    public_key: String,
    server_address: String,
    timestamp: i64,
    signature: String,
    key_package: Option<Vec<u8>>,
}

/// Common representation for approve group requests
struct ApproveGroupRequest {
    username: String,
    signature: String,
}

/// Common representation for send group requests
struct SendGroupRequest {
    username: String,
    ciphertext: String,
    signature: String,
}

/// Common representation for fetch group requests
struct FetchGroupRequest {
    username: String,
    last_seen_id: i64,
    signature: String,
}

/// Common representation for authentication requests
struct AuthRequest {
    username: String,
    signature: String,
}

// ============================================================
// Format parsers - convert legacy/unified formats to common structs
// ============================================================

impl RegisterRequest {
    /// Parse from legacy format (fields at root level)
    fn from_legacy(data: &Value) -> Option<Self> {
        let username = data.get("username").and_then(Value::as_str)?.to_string();
        let public_key = data.get("publicKey").and_then(Value::as_str)?.to_string();
        let server_address = data.get("serverAddress").and_then(Value::as_str)?.to_string();
        let timestamp = data.get("timestamp").and_then(Value::as_i64)?;
        let signature = data.get("signature").and_then(Value::as_str)?.to_string();

        let key_package = data
            .get("keyPackage")
            .and_then(Value::as_str)
            .and_then(|kp| {
                use base64::{Engine as _, engine::general_purpose::STANDARD};
                STANDARD.decode(kp).ok()
            });

        Some(Self {
            username,
            public_key,
            server_address,
            timestamp,
            signature,
            key_package,
        })
    }

    /// Parse from unified format (fields in payload, signature at top level)
    fn from_unified(payload: &Value, sender_username: &str, signature: &str) -> Option<Self> {
        let username = payload
            .get("username")
            .and_then(Value::as_str)
            .unwrap_or(sender_username)
            .to_string();
        let public_key = payload.get("publicKey").and_then(Value::as_str)?.to_string();
        let server_address = payload.get("serverAddress").and_then(Value::as_str)?.to_string();
        let timestamp = payload.get("timestamp").and_then(Value::as_i64)?;

        let key_package = payload
            .get("keyPackage")
            .and_then(Value::as_str)
            .and_then(|kp| {
                use base64::{Engine as _, engine::general_purpose::STANDARD};
                STANDARD.decode(kp).ok()
            });

        Some(Self {
            username,
            public_key,
            server_address,
            timestamp,
            signature: signature.to_string(),
            key_package,
        })
    }
}

impl ApproveGroupRequest {
    /// Parse from legacy format
    fn from_legacy(data: &Value) -> Option<Self> {
        let username = data.get("username").and_then(Value::as_str)?.to_string();
        let signature = data.get("signature").and_then(Value::as_str)?.to_string();

        Some(Self { username, signature })
    }

    /// Parse from unified format
    fn from_unified(payload: &Value, signature: &str) -> Option<Self> {
        let username = payload.get("username").and_then(Value::as_str)?.to_string();

        Some(Self {
            username,
            signature: signature.to_string(),
        })
    }
}

impl SendGroupRequest {
    /// Parse from legacy format
    fn from_legacy(data: &Value) -> Option<Self> {
        let username = data.get("username").and_then(Value::as_str)?.to_string();
        let ciphertext = data.get("ciphertext").and_then(Value::as_str)?.to_string();
        let signature = data.get("signature").and_then(Value::as_str)?.to_string();

        Some(Self { username, ciphertext, signature })
    }

    /// Parse from unified format
    fn from_unified(payload: &Value, sender_username: &str, signature: &str) -> Option<Self> {
        let ciphertext = payload.get("ciphertext").and_then(Value::as_str)?.to_string();

        Some(Self {
            username: sender_username.to_string(),
            ciphertext,
            signature: signature.to_string(),
        })
    }
}

impl FetchGroupRequest {
    /// Parse from legacy format
    fn from_legacy(data: &Value) -> Option<Self> {
        let username = data.get("username").and_then(Value::as_str)?.to_string();
        let signature = data.get("signature").and_then(Value::as_str)?.to_string();
        let last_seen_id = match data.get("lastSeenId") {
            Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
            Some(Value::String(s)) => s.parse::<i64>().unwrap_or(0),
            _ => 0,
        };

        Some(Self { username, last_seen_id, signature })
    }

    /// Parse from unified format
    fn from_unified(payload: &Value, sender_username: &str, signature: &str) -> Option<Self> {
        let last_seen_id = match payload.get("lastSeenId") {
            Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
            Some(Value::String(s)) => s.parse::<i64>().unwrap_or(0),
            _ => 0,
        };

        Some(Self {
            username: sender_username.to_string(),
            last_seen_id,
            signature: signature.to_string(),
        })
    }
}


/// Handler for incoming mixnet messages and command processing for group chat server.
///
/// Uses a pure Store & Fetch model:
/// - Messages are stored in SQLite with sequential IDs
/// - Clients fetch messages by providing their last seen ID
/// - No presence tracking, no push notifications
pub struct MessageUtils {
    db: DbUtils,
    crypto: CryptoUtils,
    sender: MixnetClientSender,
    client_id: String,
    admin_public_key: Option<String>,
    /// Rate limiter for registration endpoint
    rate_limiter: RateLimiter,
}

impl MessageUtils {
    /// Maximum authentication attempts per sender within the rate limit window
    const RATE_LIMIT_MAX_ATTEMPTS: usize = 10;

    /// Rate limit window in seconds (1 minute)
    const RATE_LIMIT_WINDOW_SECS: u64 = 60;

    /// Check if a username is valid: non-empty, max 64 chars, alphanumeric + '-' or '_'.
    fn is_valid_username(username: &str) -> bool {
        !username.is_empty()
            && username.len() <= 64
            && username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    /// Check if a group ID is valid: non-empty, max 128 chars, alphanumeric + '-' or '_'.
    fn is_valid_group_id(group_id: &str) -> bool {
        !group_id.is_empty()
            && group_id.len() <= 128
            && group_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    /// Create a new MessageUtils instance.
    pub fn new(
        client_id: String,
        sender: MixnetClientSender,
        db: DbUtils,
        crypto: CryptoUtils,
        admin_public_key: Option<String>,
    ) -> Self {
        MessageUtils {
            db,
            crypto,
            sender,
            client_id,
            admin_public_key,
            rate_limiter: RateLimiter::new(
                Self::RATE_LIMIT_MAX_ATTEMPTS,
                Self::RATE_LIMIT_WINDOW_SECS,
            ),
        }
    }

    /// Process an incoming mixnet message.
    /// Supports both unified format (with "type" field) and legacy format.
    pub async fn process_received_message(&mut self, msg: ReconstructedMessage) {
        // Clean up rate limiter entries with no recent attempts
        self.rate_limiter.cleanup();

        let sender_tag = if let Some(tag) = msg.sender_tag {
            tag
        } else {
            log::warn!("Received message without sender tag, ignoring");
            return;
        };

        let raw = match String::from_utf8(msg.message) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Invalid UTF-8 in message: {}", e);
                return;
            }
        };
        log::debug!("Incoming raw message: {}", raw);
        let data: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                log::error!("JSON decode error: {}", e);
                return;
            }
        };
        log::debug!("Parsed JSON message: {}", data);

        // Check if this is the unified format (has "type" field) or legacy format
        if data.get("type").and_then(Value::as_str).is_some() {
            // Unified format
            if let Some(action) = data.get("action").and_then(Value::as_str) {
                let payload = data.get("payload").unwrap_or(&Value::Null);
                let sender_username = data.get("sender").and_then(Value::as_str).unwrap_or("unknown");
                let signature = data.get("signature").and_then(Value::as_str).unwrap_or("");

                log::info!("Processing unified format - action: '{}', sender: '{}'", action, sender_username);

                match action {
                    "register" => {
                        if let Some(req) = RegisterRequest::from_unified(payload, sender_username, signature) {
                            self.handle_register_core(req, sender_tag).await;
                        } else {
                            self.send_encapsulated_reply(sender_tag, "error: missing required fields".into(), "registerResponse", None).await;
                        }
                    }
                    "approveGroup" => {
                        if let Some(req) = ApproveGroupRequest::from_unified(payload, signature) {
                            self.handle_approve_group_core(req, sender_tag).await;
                        } else {
                            self.send_encapsulated_reply(sender_tag, "error: missing required fields".into(), "approveGroupResponse", None).await;
                        }
                    }
                    "sendGroup" => {
                        if let Some(req) = SendGroupRequest::from_unified(payload, sender_username, signature) {
                            self.handle_send_group_core(req, sender_tag).await;
                        } else {
                            self.send_encapsulated_reply(sender_tag, "error: missing ciphertext".into(), "sendGroupResponse", None).await;
                        }
                    }
                    "fetchGroup" => {
                        if let Some(req) = FetchGroupRequest::from_unified(payload, sender_username, signature) {
                            self.handle_fetch_group_core(req, sender_tag).await;
                        } else {
                            self.send_encapsulated_reply(sender_tag, "error: missing credentials".into(), "fetchGroupResponse", None).await;
                        }
                    }
                    // MLS Delivery Service actions
                    "storeWelcome" => self.handle_store_welcome(payload, sender_tag, sender_username, signature).await,
                    "fetchWelcome" => self.handle_fetch_welcome(payload, sender_tag, sender_username, signature).await,
                    "syncEpoch" => self.handle_sync_epoch(payload, sender_tag, sender_username, signature).await,
                    "bufferCommit" => self.handle_buffer_commit(payload, sender_tag, sender_username, signature).await,
                    _ => log::error!("Unknown unified action: {}", action),
                }
            } else {
                log::error!("Unified format message missing 'action' field");
            }
        } else if let Some(action) = data.get("action").and_then(Value::as_str) {
            // Legacy format (for backward compatibility)
            log::info!("Processing legacy format action: '{}'", action);
            match action {
                "register" => self.handle_register(&data, sender_tag).await,
                "approveGroup" => self.handle_approve_group(&data, sender_tag).await,
                "sendGroup" => self.handle_send_group(&data, sender_tag).await,
                "fetchGroup" => self.handle_fetch_group(&data, sender_tag).await,
                _ => log::error!("Unknown legacy action: {}", action),
            }
        } else {
            log::error!("Message missing 'action' field");
        }
    }

    /// Core authentication logic - verifies username + signature.
    /// Returns the username if valid, None otherwise.
    async fn authenticate_request_core(
        &self,
        auth: &AuthRequest,
        sender_tag: AnonymousSenderTag,
        action_response: &str,
        signed_content: &str,
    ) -> Option<String> {
        // Validate username format (non-empty, max 64 chars, alphanumeric/-/_)
        if !Self::is_valid_username(&auth.username) || auth.username == "unknown" {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing or invalid username".into(),
                action_response,
                None,
            )
            .await;
            return None;
        }

        // Validate signature
        if auth.signature.is_empty() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing or invalid signature".into(),
                action_response,
                None,
            )
            .await;
            return None;
        }

        // Get user's public key from database
        let public_key = match self.db.get_user_by_username(&auth.username).await {
            Ok(Some((_u, pk))) => pk,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: user not registered".into(),
                    action_response,
                    None,
                )
                .await;
                return None;
            }
        };

        // Verify signature
        if !self.crypto.verify_pgp_signature(&public_key, signed_content, &auth.signature) {
            self.send_encapsulated_reply(
                sender_tag,
                "error: bad signature".into(),
                action_response,
                None,
            )
            .await;
            return None;
        }

        Some(auth.username.clone())
    }

    /// Handle a client 'register' (legacy format entry point).
    async fn handle_register(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let req = match RegisterRequest::from_legacy(data) {
            Some(r) => r,
            None => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing required fields".into(),
                    "registerResponse",
                    None,
                )
                .await;
                return;
            }
        };
        self.handle_register_core(req, sender_tag).await;
    }

    /// Core implementation for register - handles both legacy and unified formats.
    async fn handle_register_core(&mut self, req: RegisterRequest, sender_tag: AnonymousSenderTag) {
        // Rate limit check for registration attempts
        let rate_key = sender_tag.to_string();
        if !self.rate_limiter.check_and_record(&rate_key) {
            log::warn!("Rate limit exceeded for registration from sender_tag={:?}", sender_tag);
            self.send_encapsulated_reply(
                sender_tag,
                "error: rate limit exceeded, please try again later".into(),
                "registerResponse",
                None,
            )
            .await;
            return;
        }

        // Validate username format (non-empty, max 64 chars, alphanumeric/-/_)
        if !Self::is_valid_username(&req.username) {
            log::warn!("Invalid username format in registration: {}", req.username);
            self.send_encapsulated_reply(
                sender_tag,
                "error: invalid username format".into(),
                "registerResponse",
                None,
            )
            .await;
            return;
        }

        // Verify timestamp is within ±5 minutes (300 seconds)
        let now = chrono::Utc::now().timestamp();
        let time_diff = (now - req.timestamp).abs();
        if time_diff > 300 {
            log::warn!("Registration timestamp too old/new: diff={}s", time_diff);
            self.send_encapsulated_reply(
                sender_tag,
                "error: timestamp expired".into(),
                "registerResponse",
                None,
            )
            .await;
            return;
        }

        // Validate signature is present
        if req.signature.is_empty() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing signature".into(),
                "registerResponse",
                None,
            )
            .await;
            return;
        }

        // Verify signature over: "register:{username}:{server_address}:{timestamp}"
        let signed_content = format!("register:{}:{}:{}", req.username, req.server_address, req.timestamp);
        if !self
            .crypto
            .verify_pgp_signature(&req.public_key, &signed_content, &req.signature)
        {
            log::warn!("Bad signature for registration: {}", req.username);
            self.send_encapsulated_reply(
                sender_tag,
                "error: bad signature".into(),
                "registerResponse",
                None,
            )
            .await;
            return;
        }

        // Check if this is the admin (auto-approve)
        let is_admin = self.admin_public_key.as_ref()
            .map(|admin_key| admin_key.trim() == req.public_key.trim())
            .unwrap_or(false);

        if is_admin {
            // Auto-approve admin
            match self.db.add_user(&req.username, &req.public_key).await {
                Ok(true) => {
                    // Store KeyPackage if provided
                    if let Some(kp) = &req.key_package {
                        if let Err(e) = self.db.store_key_package(&req.username, kp).await {
                            log::warn!("Failed to store KeyPackage for admin {}: {}", req.username, e);
                        }
                    }
                    log::info!("Admin {} auto-approved and registered", req.username);
                    self.send_encapsulated_reply(
                        sender_tag,
                        "approved".into(),
                        "registerResponse",
                        None,
                    )
                    .await;
                }
                Ok(false) => {
                    self.send_encapsulated_reply(
                        sender_tag,
                        "error: user already registered".into(),
                        "registerResponse",
                        None,
                    )
                    .await;
                }
                Err(e) => {
                    log::error!("DB error during admin register: {}", e);
                    self.send_encapsulated_reply(
                        sender_tag,
                        "error: registration failed".into(),
                        "registerResponse",
                        None,
                    )
                    .await;
                }
            }
        } else {
            // Regular user - add to pending
            match self.db.add_pending_user(&req.username, &req.public_key).await {
                Ok(true) => {
                    // Store KeyPackage if provided (for later use when approved)
                    if let Some(kp) = &req.key_package {
                        if let Err(e) = self.db.store_key_package(&req.username, kp).await {
                            log::warn!("Failed to store KeyPackage for {}: {}", req.username, e);
                        }
                    }
                    log::info!("Registration pending for user: {}", req.username);
                    self.send_encapsulated_reply(
                        sender_tag,
                        "pending".into(),
                        "registerResponse",
                        None,
                    )
                    .await;
                }
                Ok(false) => {
                    self.send_encapsulated_reply(
                        sender_tag,
                        "error: user already registered".into(),
                        "registerResponse",
                        None,
                    )
                    .await;
                }
                Err(e) => {
                    log::error!("DB error during register: {}", e);
                    self.send_encapsulated_reply(
                        sender_tag,
                        "error: registration failed".into(),
                        "registerResponse",
                        None,
                    )
                    .await;
                }
            }
        }
    }

    /// Handle a client 'approveGroup' (legacy format entry point).
    async fn handle_approve_group(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let req = match ApproveGroupRequest::from_legacy(data) {
            Some(r) => r,
            None => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: unauthorized or bad signature".into(),
                    "approveGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        self.handle_approve_group_core(req, sender_tag).await;
    }

    /// Core implementation for approve group - handles both legacy and unified formats.
    async fn handle_approve_group_core(&mut self, req: ApproveGroupRequest, sender_tag: AnonymousSenderTag) {
        // Validate signature is present
        if req.signature.is_empty() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing signature".into(),
                "approveGroupResponse",
                None,
            )
            .await;
            return;
        }

        let admin_key = match &self.admin_public_key {
            Some(key) => key,
            None => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: no admin configured".into(),
                    "approveGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };

        if !self.crypto.verify_pgp_signature(admin_key, &req.username, &req.signature) {
            self.send_encapsulated_reply(
                sender_tag,
                "error: unauthorized or bad signature".into(),
                "approveGroupResponse",
                None,
            )
            .await;
            return;
        }

        // Fetch pending registration data
        let pubkey = match self.db.get_pending_user(&req.username).await {
            Ok(Some(pk)) => pk,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: user not in pending list".into(),
                    "approveGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };

        // Fetch the user's KeyPackage if available
        let key_package = self.db.get_key_package(&req.username).await.ok().flatten();

        // Approve user: add to users table
        match self.db.add_user(&req.username, &pubkey).await {
            Ok(true) => {
                if let Err(e) = self.db.remove_pending_user(&req.username).await {
                    log::warn!("Failed to remove pending user {}: {}", req.username, e);
                }

                // Build response with KeyPackage if available
                let response = if let Some(kp) = key_package {
                    use base64::{Engine as _, engine::general_purpose::STANDARD};
                    json!({
                        "status": "success",
                        "username": req.username,
                        "keyPackage": STANDARD.encode(&kp)
                    }).to_string()
                } else {
                    json!({
                        "status": "success",
                        "username": req.username
                    }).to_string()
                };

                self.send_encapsulated_reply(
                    sender_tag,
                    response,
                    "approveGroupResponse",
                    None,
                )
                .await;
            }
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: approve failed".into(),
                    "approveGroupResponse",
                    None,
                )
                .await;
            }
        }
    }

    /// Handle a client 'sendGroup' (legacy format entry point).
    async fn handle_send_group(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let req = match SendGroupRequest::from_legacy(data) {
            Some(r) => r,
            None => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing ciphertext or credentials".into(),
                    "sendGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        self.handle_send_group_core(req, sender_tag).await;
    }

    /// Core implementation for send group - handles both legacy and unified formats.
    async fn handle_send_group_core(&mut self, req: SendGroupRequest, sender_tag: AnonymousSenderTag) {
        // Validate ciphertext is present
        if req.ciphertext.is_empty() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing ciphertext".into(),
                "sendGroupResponse",
                None,
            )
            .await;
            return;
        }

        // Authenticate: signature should be over the ciphertext
        let auth = AuthRequest {
            username: req.username.clone(),
            signature: req.signature.clone(),
        };
        let username = match self
            .authenticate_request_core(&auth, sender_tag, "sendGroupResponse", &req.ciphertext)
            .await
        {
            Some(u) => u,
            None => return,
        };

        // Store message in SQLite
        match self.db.store_message(&username, &req.ciphertext).await {
            Ok(msg_id) => {
                let content = json!({
                    "status": "success",
                    "messageId": msg_id
                })
                .to_string();
                self.send_encapsulated_reply(sender_tag, content, "sendGroupResponse", None)
                    .await;
            }
            Err(e) => {
                log::error!("Failed to store message: {}", e);
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: failed to store message".into(),
                    "sendGroupResponse",
                    None,
                )
                .await;
            }
        }
    }

    /// Handle a client 'fetchGroup' (legacy format entry point).
    async fn handle_fetch_group(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let req = match FetchGroupRequest::from_legacy(data) {
            Some(r) => r,
            None => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing credentials".into(),
                    "fetchGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        self.handle_fetch_group_core(req, sender_tag).await;
    }

    /// Core implementation for fetch group - handles both legacy and unified formats.
    async fn handle_fetch_group_core(&mut self, req: FetchGroupRequest, sender_tag: AnonymousSenderTag) {
        // Authenticate: signature should be over the lastSeenId
        let signed_content = req.last_seen_id.to_string();
        let auth = AuthRequest {
            username: req.username.clone(),
            signature: req.signature.clone(),
        };
        if self
            .authenticate_request_core(&auth, sender_tag, "fetchGroupResponse", &signed_content)
            .await
            .is_none()
        {
            return;
        }

        // Fetch messages from SQLite
        match self.db.get_messages_since(req.last_seen_id).await {
            Ok(messages) => {
                let formatted: Vec<Value> = messages
                    .into_iter()
                    .map(|(id, sender, ciphertext, timestamp)| {
                        json!({
                            "id": id,
                            "sender": sender,
                            "ciphertext": ciphertext,
                            "timestamp": timestamp
                        })
                    })
                    .collect();

                let content = json!({ "messages": formatted }).to_string();
                self.send_encapsulated_reply(sender_tag, content, "fetchGroupResponse", None)
                    .await;
            }
            Err(e) => {
                log::error!("Failed to fetch messages: {}", e);
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: failed to fetch messages".into(),
                    "fetchGroupResponse",
                    None,
                )
                .await;
            }
        }
    }

    /// Sign and send a JSON reply over the mixnet using SURBs (unified format).
    async fn send_encapsulated_reply(
        &self,
        recipient: AnonymousSenderTag,
        content: String,
        action: &str,
        context: Option<&str>,
    ) {
        // Build payload object
        let mut payload_obj = json!({ "content": content });
        if let Some(ctx) = context {
            payload_obj["context"] = json!(ctx);
        }

        // Sign the content
        let to_sign = content.clone();
        let signature = match self.crypto.sign_message(&self.client_id, &to_sign) {
            Ok(sig) => sig,
            Err(_) => {
                log::error!("send_encapsulated_reply - failed to sign message");
                return;
            }
        };

        // Build unified format message
        let message = json!({
            "type": "response",
            "action": action,
            "sender": "group-server",
            "recipient": "client",
            "payload": payload_obj,
            "signature": signature,
            "timestamp": Utc::now().to_rfc3339()
        });

        let msg = message.to_string();
        log::debug!("Sending unified reply: {}", msg);
        if let Err(e) = self.sender.send_reply(recipient, msg).await {
            log::warn!("Failed to send unified reply: {}", e);
        }
    }

    // ============================================================
    // MLS Delivery Service handlers
    // ============================================================

    /// Handle 'storeWelcome': Admin stores a Welcome message for a user to fetch later.
    /// This is called after admin adds a user to the MLS group and generates a Welcome.
    async fn handle_store_welcome(
        &mut self,
        payload: &Value,
        sender_tag: AnonymousSenderTag,
        sender_username: &str,
        signature: &str,
    ) {
        // Extract and validate group_id
        let group_id = match payload.get("groupId").and_then(Value::as_str) {
            Some(g) if Self::is_valid_group_id(g) => g,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing or invalid groupId".into(),
                    "storeWelcomeResponse",
                    None,
                )
                .await;
                return;
            }
        };

        // Extract and validate target username
        let target_username = match payload.get("targetUsername").and_then(Value::as_str) {
            Some(u) if Self::is_valid_username(u) => u,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing or invalid targetUsername".into(),
                    "storeWelcomeResponse",
                    None,
                )
                .await;
                return;
            }
        };

        let welcome_b64 = match payload.get("welcome").and_then(Value::as_str) {
            Some(w) if !w.is_empty() => w,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing welcome".into(),
                    "storeWelcomeResponse",
                    None,
                )
                .await;
                return;
            }
        };

        // Decode the welcome from base64
        let welcome_bytes = match {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            STANDARD.decode(welcome_b64)
        } {
            Ok(bytes) => bytes,
            Err(_) => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: invalid base64 welcome".into(),
                    "storeWelcomeResponse",
                    None,
                )
                .await;
                return;
            }
        };

        // Authenticate the request (signature over groupId:targetUsername)
        let signed_content = format!("{}:{}", group_id, target_username);
        let auth = AuthRequest {
            username: sender_username.to_string(),
            signature: signature.to_string(),
        };
        if self
            .authenticate_request_core(&auth, sender_tag, "storeWelcomeResponse", &signed_content)
            .await
            .is_none()
        {
            return;
        }

        // Store the welcome
        match self.db.store_welcome(target_username, group_id, &welcome_bytes).await {
            Ok(true) => {
                log::info!("Stored Welcome for user {} in group {}", target_username, group_id);
                self.send_encapsulated_reply(
                    sender_tag,
                    json!({"status": "success"}).to_string(),
                    "storeWelcomeResponse",
                    None,
                )
                .await;
            }
            Ok(false) | Err(_) => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: failed to store welcome".into(),
                    "storeWelcomeResponse",
                    None,
                )
                .await;
            }
        }
    }

    /// Handle 'fetchWelcome': User fetches their pending Welcome messages.
    async fn handle_fetch_welcome(
        &mut self,
        payload: &Value,
        sender_tag: AnonymousSenderTag,
        sender_username: &str,
        signature: &str,
    ) {
        // Optional: filter by group_id
        let group_id = payload.get("groupId").and_then(Value::as_str);

        // Authenticate (signature over username or "fetch:{username}")
        let signed_content = format!("fetchWelcome:{}", sender_username);
        let auth = AuthRequest {
            username: sender_username.to_string(),
            signature: signature.to_string(),
        };
        if self
            .authenticate_request_core(&auth, sender_tag, "fetchWelcomeResponse", &signed_content)
            .await
            .is_none()
        {
            return;
        }

        // Fetch welcomes
        if let Some(gid) = group_id {
            // Fetch specific welcome
            match self.db.get_welcome(sender_username, gid).await {
                Ok(Some(welcome_bytes)) => {
                    use base64::{Engine as _, engine::general_purpose::STANDARD};
                    let response = json!({
                        "welcomes": [{
                            "groupId": gid,
                            "welcome": STANDARD.encode(&welcome_bytes)
                        }]
                    }).to_string();

                    // Remove the welcome after fetching
                    if let Err(e) = self.db.remove_welcome(sender_username, gid).await {
                        log::warn!("Failed to remove welcome for user {} in group {}: {}", sender_username, gid, e);
                    }

                    self.send_encapsulated_reply(sender_tag, response, "fetchWelcomeResponse", None)
                        .await;
                }
                Ok(None) => {
                    self.send_encapsulated_reply(
                        sender_tag,
                        json!({"welcomes": []}).to_string(),
                        "fetchWelcomeResponse",
                        None,
                    )
                    .await;
                }
                Err(e) => {
                    log::error!("Failed to fetch welcome: {}", e);
                    self.send_encapsulated_reply(
                        sender_tag,
                        "error: failed to fetch welcome".into(),
                        "fetchWelcomeResponse",
                        None,
                    )
                    .await;
                }
            }
        } else {
            // Fetch all welcomes for this user
            match self.db.get_pending_welcomes(sender_username).await {
                Ok(welcomes) => {
                    use base64::{Engine as _, engine::general_purpose::STANDARD};
                    let formatted: Vec<Value> = welcomes
                        .iter()
                        .map(|(gid, welcome_bytes)| {
                            json!({
                                "groupId": gid,
                                "welcome": STANDARD.encode(welcome_bytes)
                            })
                        })
                        .collect();

                    // Remove fetched welcomes
                    for (gid, _) in &welcomes {
                        if let Err(e) = self.db.remove_welcome(sender_username, gid).await {
                            log::warn!("Failed to remove welcome for user {} in group {}: {}", sender_username, gid, e);
                        }
                    }

                    let response = json!({"welcomes": formatted}).to_string();
                    self.send_encapsulated_reply(sender_tag, response, "fetchWelcomeResponse", None)
                        .await;
                }
                Err(e) => {
                    log::error!("Failed to fetch welcomes: {}", e);
                    self.send_encapsulated_reply(
                        sender_tag,
                        "error: failed to fetch welcomes".into(),
                        "fetchWelcomeResponse",
                        None,
                    )
                    .await;
                }
            }
        }
    }

    /// Handle 'syncEpoch': User requests commits since their last known epoch.
    async fn handle_sync_epoch(
        &mut self,
        payload: &Value,
        sender_tag: AnonymousSenderTag,
        sender_username: &str,
        signature: &str,
    ) {
        let group_id = match payload.get("groupId").and_then(Value::as_str) {
            Some(g) if Self::is_valid_group_id(g) => g,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing or invalid groupId".into(),
                    "syncEpochResponse",
                    None,
                )
                .await;
                return;
            }
        };

        let since_epoch = payload
            .get("sinceEpoch")
            .and_then(Value::as_i64)
            .unwrap_or(0);

        // Authenticate (signature over groupId:sinceEpoch)
        let signed_content = format!("{}:{}", group_id, since_epoch);
        let auth = AuthRequest {
            username: sender_username.to_string(),
            signature: signature.to_string(),
        };
        if self
            .authenticate_request_core(&auth, sender_tag, "syncEpochResponse", &signed_content)
            .await
            .is_none()
        {
            return;
        }

        // Get commits since the given epoch
        match self.db.get_commits_since_epoch(group_id, since_epoch).await {
            Ok(commits) => {
                use base64::{Engine as _, engine::general_purpose::STANDARD};
                let formatted: Vec<Value> = commits
                    .into_iter()
                    .map(|(epoch, commit_bytes, sender)| {
                        json!({
                            "epoch": epoch,
                            "commit": STANDARD.encode(&commit_bytes),
                            "sender": sender
                        })
                    })
                    .collect();

                // Get current epoch
                let current_epoch = self.db.get_group_epoch(group_id).await.unwrap_or(0);

                let response = json!({
                    "currentEpoch": current_epoch,
                    "commits": formatted
                }).to_string();

                // Update the member's tracked epoch
                if let Err(e) = self.db.update_member_epoch(group_id, sender_username, current_epoch).await {
                    log::warn!("Failed to update member epoch for {} in group {}: {}", sender_username, group_id, e);
                }

                self.send_encapsulated_reply(sender_tag, response, "syncEpochResponse", None)
                    .await;
            }
            Err(e) => {
                log::error!("Failed to sync epoch: {}", e);
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: failed to sync epoch".into(),
                    "syncEpochResponse",
                    None,
                )
                .await;
            }
        }
    }

    /// Handle 'bufferCommit': Store a commit message for epoch sync.
    /// Called by group members when they send commits, so late joiners can catch up.
    async fn handle_buffer_commit(
        &mut self,
        payload: &Value,
        sender_tag: AnonymousSenderTag,
        sender_username: &str,
        signature: &str,
    ) {
        let group_id = match payload.get("groupId").and_then(Value::as_str) {
            Some(g) if Self::is_valid_group_id(g) => g,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing or invalid groupId".into(),
                    "bufferCommitResponse",
                    None,
                )
                .await;
                return;
            }
        };

        let epoch = match payload.get("epoch").and_then(Value::as_i64) {
            Some(e) => e,
            None => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing epoch".into(),
                    "bufferCommitResponse",
                    None,
                )
                .await;
                return;
            }
        };

        let commit_b64 = match payload.get("commit").and_then(Value::as_str) {
            Some(c) if !c.is_empty() => c,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing commit".into(),
                    "bufferCommitResponse",
                    None,
                )
                .await;
                return;
            }
        };

        // Decode commit from base64
        let commit_bytes = match {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            STANDARD.decode(commit_b64)
        } {
            Ok(bytes) => bytes,
            Err(_) => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: invalid base64 commit".into(),
                    "bufferCommitResponse",
                    None,
                )
                .await;
                return;
            }
        };

        // Authenticate (signature over groupId:epoch)
        let signed_content = format!("{}:{}", group_id, epoch);
        let auth = AuthRequest {
            username: sender_username.to_string(),
            signature: signature.to_string(),
        };
        if self
            .authenticate_request_core(&auth, sender_tag, "bufferCommitResponse", &signed_content)
            .await
            .is_none()
        {
            return;
        }

        // Buffer the commit
        match self.db.buffer_commit(group_id, epoch, &commit_bytes, sender_username).await {
            Ok(_) => {
                // Update group epoch if this is newer
                let current = self.db.get_group_epoch(group_id).await.unwrap_or(0);
                if epoch > current {
                    if let Err(e) = self.db.update_group_epoch(group_id, epoch).await {
                        log::warn!("Failed to update group epoch for {}: {}", group_id, e);
                    }
                }

                // Clean up old commits (keep last 100 epochs)
                if let Err(e) = self.db.cleanup_old_commits(group_id, 100).await {
                    log::warn!("Failed to cleanup old commits for group {}: {}", group_id, e);
                }

                log::info!("Buffered commit for group {} at epoch {}", group_id, epoch);
                self.send_encapsulated_reply(
                    sender_tag,
                    json!({"status": "success", "epoch": epoch}).to_string(),
                    "bufferCommitResponse",
                    None,
                )
                .await;
            }
            Err(e) => {
                log::error!("Failed to buffer commit: {}", e);
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: failed to buffer commit".into(),
                    "bufferCommitResponse",
                    None,
                )
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_username() {
        assert!(MessageUtils::is_valid_username("valid_user123"));
        assert!(MessageUtils::is_valid_username("user-name"));
        assert!(MessageUtils::is_valid_username("user_name"));
        assert!(MessageUtils::is_valid_username("123user"));
        // Max length (64 chars)
        assert!(MessageUtils::is_valid_username(&"a".repeat(64)));

        assert!(!MessageUtils::is_valid_username(""));
        assert!(!MessageUtils::is_valid_username("invalid user"));
        assert!(!MessageUtils::is_valid_username("user@domain"));
        assert!(!MessageUtils::is_valid_username("user.name"));
        assert!(!MessageUtils::is_valid_username("user%name"));
        // Over max length (65 chars)
        assert!(!MessageUtils::is_valid_username(&"a".repeat(65)));
    }

    #[test]
    fn test_is_valid_group_id() {
        assert!(MessageUtils::is_valid_group_id("valid-group-123"));
        assert!(MessageUtils::is_valid_group_id("group_name"));
        assert!(MessageUtils::is_valid_group_id("GroupName123"));
        // Max length (128 chars)
        assert!(MessageUtils::is_valid_group_id(&"a".repeat(128)));

        assert!(!MessageUtils::is_valid_group_id(""));
        assert!(!MessageUtils::is_valid_group_id("invalid group"));
        assert!(!MessageUtils::is_valid_group_id("group@id"));
        assert!(!MessageUtils::is_valid_group_id("group.id"));
        // Over max length (129 chars)
        assert!(!MessageUtils::is_valid_group_id(&"a".repeat(129)));
    }
}
