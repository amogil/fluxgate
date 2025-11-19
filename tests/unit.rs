#[path = "unit/common.rs"]
mod common;

// Requirement categories (organized by requirement type)
// Note: These modules document unit tests organized by requirement categories
#[path = "unit/configuration.rs"]
mod configuration;

#[path = "unit/functional.rs"]
mod functional;

#[path = "unit/observability.rs"]
mod observability;

#[path = "unit/performance.rs"]
mod performance;

#[path = "unit/jwt_auth.rs"]
mod jwt_auth;
