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
