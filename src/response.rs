//! Standardized response formatting for the group server.
//!
//! Provides consistent error codes and response formats for all endpoints.

use serde_json::{json, Value};

/// Standardized error response codes
pub mod error_codes {
    pub const MISSING_FIELDS: &str = "MISSING_FIELDS";
    pub const INVALID_USERNAME: &str = "INVALID_USERNAME";
    pub const INVALID_GROUP_ID: &str = "INVALID_GROUP_ID";
    pub const USER_NOT_FOUND: &str = "USER_NOT_FOUND";
    pub const NOT_MEMBER: &str = "NOT_MEMBER";
    pub const INVALID_SIGNATURE: &str = "INVALID_SIGNATURE";
    pub const RATE_LIMITED: &str = "RATE_LIMITED";
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
    pub const UNAUTHORIZED: &str = "UNAUTHORIZED";
    pub const PENDING_APPROVAL: &str = "PENDING_APPROVAL";
}

/// Create a standardized error response JSON
pub fn error_response(code: &str, message: &str) -> String {
    json!({
        "status": "error",
        "error_code": code,
        "message": message
    })
    .to_string()
}

/// Create a standardized success response JSON with data
#[allow(dead_code)]
pub fn success_response(data: Value) -> String {
    json!({
        "status": "success",
        "data": data
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response_format() {
        let response = error_response(error_codes::MISSING_FIELDS, "Username required");
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(parsed["status"], "error");
        assert_eq!(parsed["error_code"], "MISSING_FIELDS");
        assert_eq!(parsed["message"], "Username required");
    }

    #[test]
    fn test_success_response_format() {
        let data = json!({"user": "alice", "id": 42});
        let response = success_response(data);
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(parsed["status"], "success");
        assert_eq!(parsed["data"]["user"], "alice");
        assert_eq!(parsed["data"]["id"], 42);
    }

    #[test]
    fn test_all_error_codes_defined() {
        // Verify error codes are non-empty strings
        assert!(!error_codes::MISSING_FIELDS.is_empty());
        assert!(!error_codes::INVALID_USERNAME.is_empty());
        assert!(!error_codes::INVALID_GROUP_ID.is_empty());
        assert!(!error_codes::USER_NOT_FOUND.is_empty());
        assert!(!error_codes::NOT_MEMBER.is_empty());
        assert!(!error_codes::INVALID_SIGNATURE.is_empty());
        assert!(!error_codes::RATE_LIMITED.is_empty());
        assert!(!error_codes::INTERNAL_ERROR.is_empty());
        assert!(!error_codes::UNAUTHORIZED.is_empty());
        assert!(!error_codes::PENDING_APPROVAL.is_empty());
    }
}
