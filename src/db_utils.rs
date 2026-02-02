use anyhow::Result;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};
use std::path::Path;
use std::time::Duration;

#[derive(Clone)]
pub struct DbUtils {
    pool: SqlitePool,
}

#[allow(dead_code)]
impl DbUtils {
    /// Open or create the SQLite database at the specified path.
    ///
    /// Configures the connection pool with:
    /// - max 5 connections (appropriate for SQLite's single-writer model)
    /// - 3 second acquire timeout to fail fast on overload
    pub async fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let db_url = format!("sqlite://{}", db_path.as_ref().display());
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&db_url)
            .await?;
        sqlx::query(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS users (
                username   TEXT PRIMARY KEY,
                publicKey  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS groups (
                groupId        TEXT PRIMARY KEY,
                groupName      TEXT NOT NULL,
                admin          TEXT NOT NULL,
                isPublic       INTEGER NOT NULL,
                isDiscoverable INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_members (
                groupId   TEXT NOT NULL,
                username  TEXT NOT NULL,
                PRIMARY KEY (groupId, username),
                FOREIGN KEY (groupId) REFERENCES groups(groupId),
                FOREIGN KEY (username) REFERENCES users(username)
            );
            CREATE TABLE IF NOT EXISTS group_invites (
                groupId  TEXT NOT NULL,
                username TEXT NOT NULL,
                PRIMARY KEY (groupId, username),
                FOREIGN KEY (groupId) REFERENCES groups(groupId),
                FOREIGN KEY (username) REFERENCES users(username)
            );
            CREATE TABLE IF NOT EXISTS pending_users (
                username  TEXT PRIMARY KEY,
                publicKey TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                sender     TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                timestamp  TEXT NOT NULL,
                FOREIGN KEY (sender) REFERENCES users(username)
            );
            CREATE INDEX IF NOT EXISTS idx_messages_id ON messages(id);

            -- MLS Delivery Service tables (RFC 9420 compliant)

            -- KeyPackages for users (used when adding them to MLS groups)
            CREATE TABLE IF NOT EXISTS key_packages (
                username    TEXT PRIMARY KEY,
                key_package BLOB NOT NULL,
                created_at  TEXT NOT NULL
            );

            -- Pending Welcome messages for users who haven't joined yet
            CREATE TABLE IF NOT EXISTS pending_welcomes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT NOT NULL,
                group_id    TEXT NOT NULL,
                welcome     BLOB NOT NULL,
                created_at  TEXT NOT NULL,
                UNIQUE(username, group_id)
            );
            CREATE INDEX IF NOT EXISTS idx_pending_welcomes_user ON pending_welcomes(username);

            -- Track current epoch for each MLS group
            CREATE TABLE IF NOT EXISTS group_epochs (
                group_id      TEXT PRIMARY KEY,
                current_epoch INTEGER NOT NULL DEFAULT 0,
                updated_at    TEXT NOT NULL
            );

            -- Buffer commits for epoch catch-up (users who missed commits)
            CREATE TABLE IF NOT EXISTS buffered_commits (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id   TEXT NOT NULL,
                epoch      INTEGER NOT NULL,
                commit_msg BLOB NOT NULL,
                sender     TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_buffered_commits_group_epoch ON buffered_commits(group_id, epoch);

            -- Track which epoch each member is at (for targeted sync)
            CREATE TABLE IF NOT EXISTS member_epochs (
                group_id TEXT NOT NULL,
                username TEXT NOT NULL,
                epoch    INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (group_id, username)
            );
            "#,
        )
        .execute(&pool)
        .await?;
        log::info!("DbUtils initialized with db_url={}", db_url);
        Ok(DbUtils { pool })
    }

    /// Retrieve a user by username. Returns (username, publicKey).
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<(String, String)>> {
        log::info!("get_user_by_username: username={}", username);
        let row = sqlx::query("SELECT username, publicKey FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        let result = row.map(|r| (r.get(0), r.get(1)));
        log::info!("get_user_by_username: result={:?}", result);
        Ok(result)
    }

    /// Add a new user. Returns true on success.
    pub async fn add_user(&self, username: &str, public_key: &str) -> Result<bool> {
        log::info!("add_user: username={}", username);
        let res = sqlx::query("INSERT OR IGNORE INTO users (username, publicKey) VALUES (?, ?)")
            .bind(username)
            .bind(public_key)
            .execute(&self.pool)
            .await?;
        let success = res.rows_affected() > 0;
        log::info!("add_user: success={}", success);
        Ok(success)
    }

    /// Create a new group. Returns true on success.
    pub async fn create_group(
        &self,
        group_id: &str,
        group_name: &str,
        admin: &str,
        is_public: bool,
        is_discoverable: bool,
    ) -> Result<bool> {
        log::info!(
            "create_group: group_id={}, group_name={}, admin={}, is_public={}, is_discoverable={}",
            group_id,
            group_name,
            admin,
            is_public,
            is_discoverable
        );
        let res = sqlx::query(
            "INSERT INTO groups (groupId, groupName, admin, isPublic, isDiscoverable) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(group_id)
        .bind(group_name)
        .bind(admin)
        .bind(is_public as i64)
        .bind(is_discoverable as i64)
        .execute(&self.pool)
        .await?;
        let success = res.rows_affected() > 0;
        log::info!("create_group: success={}", success);
        Ok(success)
    }

    /// Add a member to a group. Returns true on success.
    /// Add a member to a group. Returns true on success.
    pub async fn add_group_member(&self, group_id: &str, username: &str) -> Result<bool> {
        log::info!(
            "add_group_member: group_id={}, username={}",
            group_id,
            username
        );
        let res = sqlx::query("INSERT INTO group_members (groupId, username) VALUES (?, ?)")
            .bind(group_id)
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Get all usernames of members in a group.
    pub async fn get_group_members(&self, group_id: &str) -> Result<Vec<String>> {
        log::info!("get_group_members: group_id={}", group_id);
        let rows = sqlx::query("SELECT username FROM group_members WHERE groupId = ?")
            .bind(group_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }

    /// Check if the user is the admin of the group.
    pub async fn is_user_admin(&self, group_id: &str, username: &str) -> Result<bool> {
        log::info!(
            "is_user_admin: group_id={}, username={}",
            group_id,
            username
        );
        let row = sqlx::query("SELECT 1 FROM groups WHERE groupId = ? AND admin = ?")
            .bind(group_id)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// Check if a group is public.
    pub async fn is_group_public(&self, group_id: &str) -> Result<bool> {
        log::info!("is_group_public: group_id={}", group_id);
        let row = sqlx::query("SELECT isPublic FROM groups WHERE groupId = ?")
            .bind(group_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>(0) != 0)
    }

    /// Check if a group is discoverable.
    pub async fn is_group_discoverable(&self, group_id: &str) -> Result<bool> {
        log::info!("is_group_discoverable: group_id={}", group_id);
        let row = sqlx::query("SELECT isDiscoverable FROM groups WHERE groupId = ?")
            .bind(group_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>(0) != 0)
    }

    /// Add an invite for a user to join a private group.
    pub async fn add_group_invite(&self, group_id: &str, username: &str) -> Result<bool> {
        log::info!(
            "add_group_invite: group_id={}, username={}",
            group_id,
            username
        );
        let res = sqlx::query("INSERT INTO group_invites (groupId, username) VALUES (?, ?)")
            .bind(group_id)
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Remove an invite for a user.
    pub async fn remove_group_invite(&self, group_id: &str, username: &str) -> Result<bool> {
        log::info!(
            "remove_group_invite: group_id={}, username={}",
            group_id,
            username
        );
        let res = sqlx::query("DELETE FROM group_invites WHERE groupId = ? AND username = ?")
            .bind(group_id)
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Check if a user has been invited to a group.
    pub async fn is_user_invited(&self, group_id: &str, username: &str) -> Result<bool> {
        log::info!(
            "is_user_invited: group_id={}, username={}",
            group_id,
            username
        );
        let row = sqlx::query("SELECT 1 FROM group_invites WHERE groupId = ? AND username = ?")
            .bind(group_id)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// Add a new pending user registration. Returns true on success.
    /// Add a new pending user registration. Returns true on success.
    pub async fn add_pending_user(&self, username: &str, public_key: &str) -> Result<bool> {
        log::info!("add_pending_user: username={}", username);
        let res =
            sqlx::query("INSERT OR IGNORE INTO pending_users (username, publicKey) VALUES (?, ?)")
                .bind(username)
                .bind(public_key)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Retrieve a pending user by username. Returns the public key if found.
    pub async fn get_pending_user(&self, username: &str) -> Result<Option<String>> {
        log::info!("get_pending_user: username={}", username);
        let row = sqlx::query("SELECT publicKey FROM pending_users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get(0)))
    }

    /// Remove a pending user registration. Returns true on success.
    pub async fn remove_pending_user(&self, username: &str) -> Result<bool> {
        log::info!("remove_pending_user: username={}", username);
        let res = sqlx::query("DELETE FROM pending_users WHERE username = ?")
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Fetch all group IDs for which the given username is a member.
    pub async fn get_groups_for_user(&self, username: &str) -> Result<Vec<String>> {
        log::info!("get_groups_for_user: username={}", username);
        let rows = sqlx::query("SELECT groupId FROM group_members WHERE username = ?")
            .bind(username)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }

    /// Store a new message. Returns the message ID.
    pub async fn store_message(&self, sender: &str, ciphertext: &str) -> Result<i64> {
        log::info!("store_message: sender={}", sender);
        let timestamp = chrono::Utc::now().to_rfc3339();
        let res =
            sqlx::query("INSERT INTO messages (sender, ciphertext, timestamp) VALUES (?, ?, ?)")
                .bind(sender)
                .bind(ciphertext)
                .bind(&timestamp)
                .execute(&self.pool)
                .await?;
        let id = res.last_insert_rowid();
        log::info!("store_message: id={}", id);
        Ok(id)
    }

    /// Fetch messages with ID greater than `since_id`. Returns Vec<(id, sender, ciphertext, timestamp)>.
    pub async fn get_messages_since(
        &self,
        since_id: i64,
    ) -> Result<Vec<(i64, String, String, String)>> {
        log::info!("get_messages_since: since_id={}", since_id);
        let rows = sqlx::query(
            "SELECT id, sender, ciphertext, timestamp FROM messages WHERE id > ? ORDER BY id ASC LIMIT 100",
        )
        .bind(since_id)
        .fetch_all(&self.pool)
        .await?;
        let messages: Vec<(i64, String, String, String)> = rows
            .into_iter()
            .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
            .collect();
        log::info!("get_messages_since: found {} messages", messages.len());
        Ok(messages)
    }

    /// Get the latest message ID (for initial sync).
    pub async fn get_latest_message_id(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COALESCE(MAX(id), 0) FROM messages")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get(0))
    }

    // ========== MLS Delivery Service Methods ==========

    /// Store a KeyPackage for a user.
    pub async fn store_key_package(&self, username: &str, key_package: &[u8]) -> Result<bool> {
        log::info!("store_key_package: username={}", username);
        let timestamp = chrono::Utc::now().to_rfc3339();
        let res = sqlx::query(
            "INSERT OR REPLACE INTO key_packages (username, key_package, created_at) VALUES (?, ?, ?)",
        )
        .bind(username)
        .bind(key_package)
        .bind(&timestamp)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Get a user's KeyPackage.
    pub async fn get_key_package(&self, username: &str) -> Result<Option<Vec<u8>>> {
        log::info!("get_key_package: username={}", username);
        let row = sqlx::query("SELECT key_package FROM key_packages WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get(0)))
    }

    /// Remove a user's KeyPackage (after consuming it).
    pub async fn remove_key_package(&self, username: &str) -> Result<bool> {
        log::info!("remove_key_package: username={}", username);
        let res = sqlx::query("DELETE FROM key_packages WHERE username = ?")
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Store a Welcome message for a user to fetch later.
    pub async fn store_welcome(
        &self,
        username: &str,
        group_id: &str,
        welcome: &[u8],
    ) -> Result<bool> {
        log::info!(
            "store_welcome: username={}, group_id={}",
            username,
            group_id
        );
        let timestamp = chrono::Utc::now().to_rfc3339();
        let res = sqlx::query(
            "INSERT OR REPLACE INTO pending_welcomes (username, group_id, welcome, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(username)
        .bind(group_id)
        .bind(welcome)
        .bind(&timestamp)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Get pending Welcomes for a user. Returns Vec<(group_id, welcome_bytes)>.
    pub async fn get_pending_welcomes(&self, username: &str) -> Result<Vec<(String, Vec<u8>)>> {
        log::info!("get_pending_welcomes: username={}", username);
        let rows = sqlx::query("SELECT group_id, welcome FROM pending_welcomes WHERE username = ?")
            .bind(username)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    /// Get a specific Welcome for a user and group.
    pub async fn get_welcome(&self, username: &str, group_id: &str) -> Result<Option<Vec<u8>>> {
        log::info!("get_welcome: username={}, group_id={}", username, group_id);
        let row =
            sqlx::query("SELECT welcome FROM pending_welcomes WHERE username = ? AND group_id = ?")
                .bind(username)
                .bind(group_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| r.get(0)))
    }

    /// Remove a Welcome after it has been fetched.
    pub async fn remove_welcome(&self, username: &str, group_id: &str) -> Result<bool> {
        log::info!(
            "remove_welcome: username={}, group_id={}",
            username,
            group_id
        );
        let res = sqlx::query("DELETE FROM pending_welcomes WHERE username = ? AND group_id = ?")
            .bind(username)
            .bind(group_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Get or initialize the current epoch for a group.
    pub async fn get_group_epoch(&self, group_id: &str) -> Result<i64> {
        log::info!("get_group_epoch: group_id={}", group_id);
        let row = sqlx::query("SELECT current_epoch FROM group_epochs WHERE group_id = ?")
            .bind(group_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get(0)).unwrap_or(0))
    }

    /// Update the current epoch for a group.
    pub async fn update_group_epoch(&self, group_id: &str, epoch: i64) -> Result<bool> {
        log::info!("update_group_epoch: group_id={}, epoch={}", group_id, epoch);
        let timestamp = chrono::Utc::now().to_rfc3339();
        let res = sqlx::query(
            "INSERT OR REPLACE INTO group_epochs (group_id, current_epoch, updated_at) VALUES (?, ?, ?)",
        )
        .bind(group_id)
        .bind(epoch)
        .bind(&timestamp)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Buffer a commit message for epoch sync.
    pub async fn buffer_commit(
        &self,
        group_id: &str,
        epoch: i64,
        commit_msg: &[u8],
        sender: &str,
    ) -> Result<i64> {
        log::info!(
            "buffer_commit: group_id={}, epoch={}, sender={}",
            group_id,
            epoch,
            sender
        );
        let timestamp = chrono::Utc::now().to_rfc3339();
        let res = sqlx::query(
            "INSERT INTO buffered_commits (group_id, epoch, commit_msg, sender, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(group_id)
        .bind(epoch)
        .bind(commit_msg)
        .bind(sender)
        .bind(&timestamp)
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }

    /// Get buffered commits since a given epoch (for catch-up). Returns Vec<(epoch, commit_msg, sender)>.
    pub async fn get_commits_since_epoch(
        &self,
        group_id: &str,
        since_epoch: i64,
    ) -> Result<Vec<(i64, Vec<u8>, String)>> {
        log::info!(
            "get_commits_since_epoch: group_id={}, since_epoch={}",
            group_id,
            since_epoch
        );
        let rows = sqlx::query(
            "SELECT epoch, commit_msg, sender FROM buffered_commits WHERE group_id = ? AND epoch > ? ORDER BY epoch ASC",
        )
        .bind(group_id)
        .bind(since_epoch)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect())
    }

    /// Update or insert a member's epoch.
    pub async fn update_member_epoch(
        &self,
        group_id: &str,
        username: &str,
        epoch: i64,
    ) -> Result<bool> {
        log::info!(
            "update_member_epoch: group_id={}, username={}, epoch={}",
            group_id,
            username,
            epoch
        );
        let res = sqlx::query(
            "INSERT OR REPLACE INTO member_epochs (group_id, username, epoch) VALUES (?, ?, ?)",
        )
        .bind(group_id)
        .bind(username)
        .bind(epoch)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Get a member's current epoch.
    pub async fn get_member_epoch(&self, group_id: &str, username: &str) -> Result<i64> {
        log::info!(
            "get_member_epoch: group_id={}, username={}",
            group_id,
            username
        );
        let row =
            sqlx::query("SELECT epoch FROM member_epochs WHERE group_id = ? AND username = ?")
                .bind(group_id)
                .bind(username)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| r.get(0)).unwrap_or(0))
    }

    /// Clean up old buffered commits (keep last N epochs).
    pub async fn cleanup_old_commits(&self, group_id: &str, keep_epochs: i64) -> Result<u64> {
        log::info!(
            "cleanup_old_commits: group_id={}, keep_epochs={}",
            group_id,
            keep_epochs
        );
        let current_epoch = self.get_group_epoch(group_id).await?;
        let cutoff = current_epoch.saturating_sub(keep_epochs);
        let res = sqlx::query("DELETE FROM buffered_commits WHERE group_id = ? AND epoch < ?")
            .bind(group_id)
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        log::info!(
            "cleanup_old_commits: deleted {} commits",
            res.rows_affected()
        );
        Ok(res.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[tokio::test]
    async fn test_user_pending_and_group_flows() -> Result<()> {
        let db = DbUtils::new(":memory:").await?;
        // Test add/get user
        assert!(db.add_user("alice", "pk1").await?);
        assert!(!db.add_user("alice", "pk1").await?);
        let u = db.get_user_by_username("alice").await?;
        assert_eq!(u, Some(("alice".to_string(), "pk1".to_string())));

        // Test pending users
        assert!(db.add_pending_user("bob", "pk2").await?);
        assert!(!db.add_pending_user("bob", "pk2").await?);
        let p = db.get_pending_user("bob").await?;
        assert_eq!(p, Some("pk2".to_string()));
        assert!(db.remove_pending_user("bob").await?);

        // Test group flows
        assert!(
            db.create_group("g1", "Group1", "alice", true, false)
                .await?
        );
        assert!(db.is_group_public("g1").await?);
        assert!(db.add_group_member("g1", "alice").await?);
        let members = db.get_group_members("g1").await?;
        assert_eq!(members, vec!["alice".to_string()]);
        assert!(db.is_user_admin("g1", "alice").await?);
        let groups = db.get_groups_for_user("alice").await?;
        assert_eq!(groups, vec!["g1".to_string()]);
        Ok(())
    }

    #[tokio::test]
    async fn test_message_store_and_fetch() -> Result<()> {
        let db = DbUtils::new(":memory:").await?;

        // Add a user first (foreign key constraint)
        db.add_user("alice", "pk1").await?;
        db.add_user("bob", "pk2").await?;

        // Initially no messages
        let latest = db.get_latest_message_id().await?;
        assert_eq!(latest, 0);

        // Store some messages
        let id1 = db.store_message("alice", "encrypted_msg_1").await?;
        let id2 = db.store_message("bob", "encrypted_msg_2").await?;
        let id3 = db.store_message("alice", "encrypted_msg_3").await?;

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);

        // Latest message ID should be 3
        let latest = db.get_latest_message_id().await?;
        assert_eq!(latest, 3);

        // Fetch all messages (since 0)
        let msgs = db.get_messages_since(0).await?;
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].1, "alice");
        assert_eq!(msgs[0].2, "encrypted_msg_1");
        assert_eq!(msgs[1].1, "bob");
        assert_eq!(msgs[2].1, "alice");

        // Fetch messages since id 1 (should get 2 and 3)
        let msgs = db.get_messages_since(1).await?;
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].0, 2);
        assert_eq!(msgs[1].0, 3);

        // Fetch messages since id 3 (should get none)
        let msgs = db.get_messages_since(3).await?;
        assert_eq!(msgs.len(), 0);

        Ok(())
    }
}
