//! JWT token authentication and validation.
//!
//! This module provides JWT token parsing, validation, and signature verification
//! according to requirements F18-F24.
//!
//! Requirements: F17.1, F18, F19, F20, F21, F22, F23, F24

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// JWT token payload structure
#[derive(Debug, Serialize, Deserialize)]
struct JwtPayload {
    exp: Option<i64>,
    nbf: Option<i64>,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

/// Errors that can occur during JWT validation
#[derive(Debug, Clone, PartialEq)]
pub enum JwtError {
    InvalidFormat,
    InvalidAlgorithm,
    InvalidType,
    MissingKid,
    InvalidKid,
    InvalidSignature,
    Expired,
    NotYetValid,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::InvalidFormat => write!(f, "Invalid JWT format"),
            JwtError::InvalidAlgorithm => write!(f, "Invalid algorithm (must be HS256)"),
            JwtError::InvalidType => write!(f, "Invalid type (must be JWT)"),
            JwtError::MissingKid => write!(f, "Missing kid in header"),
            JwtError::InvalidKid => write!(f, "Invalid kid (not found in configuration)"),
            JwtError::InvalidSignature => write!(f, "Invalid signature"),
            JwtError::Expired => write!(f, "Token expired"),
            JwtError::NotYetValid => write!(f, "Token not yet valid"),
        }
    }
}

impl std::error::Error for JwtError {}

/// Check if a token string looks like a JWT token (has three parts separated by dots)
/// Requirement: F17.1, F18 - Check if token matches JWT format
pub fn is_jwt_format(token: &str) -> bool {
    token.split('.').count() == 3
}

/// Parse and validate a JWT token according to requirements F18-F24
/// Requirement: F18-F24 - Parse and validate JWT token
pub fn validate_jwt_token(
    token: &str,
    jwt_keys: &[(String, String)], // Vec of (id, key) pairs
) -> Result<String, JwtError> {
    // Requirement: F18 - Parse JWT token (three base64url-encoded parts)
    if !is_jwt_format(token) {
        return Err(JwtError::InvalidFormat);
    }

    // Requirement: F19, F20, F21 - Validate header (alg, typ, kid) BEFORE signature verification
    // This ensures we catch algorithm/type/kid errors before attempting signature verification
    let header = decode_header(token).map_err(|_| JwtError::InvalidFormat)?;

    // Requirement: F19 - alg must be HS256
    if header.alg != Algorithm::HS256 {
        return Err(JwtError::InvalidAlgorithm);
    }

    // Requirement: F20 - typ must be JWT
    if let Some(typ) = header.typ.as_ref() {
        if typ != "JWT" {
            return Err(JwtError::InvalidType);
        }
    } else {
        return Err(JwtError::InvalidType);
    }

    // Requirement: F21 - kid must be present and match a configured JWT key ID
    let kid = header.kid.ok_or(JwtError::MissingKid)?;
    if kid.trim().is_empty() {
        return Err(JwtError::MissingKid);
    }

    // Find the matching JWT key configuration
    let (jwt_id, jwt_key) = jwt_keys
        .iter()
        .find(|(id, _)| id == &kid)
        .ok_or(JwtError::InvalidKid)?;

    // Requirement: F22 - Verify signature using HS256
    // Note: We validate header fields first, so signature verification happens after
    // all header validations pass
    let decoding_key = DecodingKey::from_secret(jwt_key.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false; // We'll validate exp manually
    validation.validate_nbf = false; // We'll validate nbf manually
    validation.required_spec_claims.clear(); // Don't require any claims

    let token_data = decode::<JwtPayload>(token, &decoding_key, &validation).map_err(|_| {
        // Return InvalidSignature for any decode error
        // The error could be signature verification failure or other decode errors
        JwtError::InvalidSignature
    })?;

    // Requirement: F23 - Validate exp if present
    if let Some(exp) = token_data.claims.exp {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if now >= exp {
            return Err(JwtError::Expired);
        }
    }

    // Requirement: F24 - Validate nbf if present
    if let Some(nbf) = token_data.claims.nbf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if now < nbf {
            return Err(JwtError::NotYetValid);
        }
    }

    Ok(jwt_id.clone())
}
