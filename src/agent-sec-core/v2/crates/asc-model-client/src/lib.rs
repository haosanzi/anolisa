//! Local-only HTTP client for model inference backends.
//!
//! Only Ollama is supported today. A [`ModelClientConfig`] is validated once and
//! then reused for the process lifetime, and [`OllamaClient::from_config`] is the
//! only constructor — so a client can never exist for a host that is not
//! loopback.
//!
//! Configuration is a snapshot resolved once per process rather than an ambient
//! environment read per request. [`ModelClientConfig::from_env`] is the single
//! place the environment is consulted; every other path takes an explicit
//! endpoint.
//!
//! Both kinds of host need that property. A long-lived daemon must not be
//! redirected by an environment mutation after startup. A one-shot CLI must not
//! let the layers of a single scan disagree about the endpoint, nor pay a fresh
//! handshake per layer — one snapshot means one client and one connection pool.
//!
//! Recognised variables:
//!
//! - `AGENT_SEC_MODEL_SERVICE_BACKEND` (default `ollama`; nothing else accepted)
//! - `AGENT_SEC_MODEL_SERVICE_BASE_URL` (default `http://localhost:11434`)
//! - `AGENT_SEC_MODEL_SERVICE_TIMEOUT` in seconds (default `30`, max `300`)
//!
//! Consumers depend on the [`ModelClient`] trait, not on [`OllamaClient`], so
//! detection logic stays testable without a live inference service.
//!
//! # Examples
//!
//! ```
//! use std::time::Duration;
//!
//! use asc_model_client::{ModelClientConfig, OllamaClient};
//!
//! # fn main() -> Result<(), asc_model_client::ModelClientError> {
//! // Resolve once at startup, then reuse the client for every call.
//! let config = ModelClientConfig::new("http://127.0.0.1:11434", Duration::from_secs(5))?;
//! let client = OllamaClient::from_config(&config);
//! # let _: &dyn asc_model_client::ModelClient = &client;
//! # Ok(())
//! # }
//! ```
//!
//! A non-loopback endpoint is refused at construction:
//!
//! ```
//! use std::time::Duration;
//!
//! use asc_model_client::{ModelClientConfig, ModelClientError};
//!
//! let rejected = ModelClientConfig::new("https://model.internal:8443", Duration::from_secs(5));
//! assert!(matches!(rejected, Err(ModelClientError::Config(_))));
//! ```

mod client;
mod config;
mod error;

pub use client::{GenerateRequest, ModelClient, ModelOptions, OllamaClient};
pub use config::{DEFAULT_BASE_URL, DEFAULT_TIMEOUT_SECS, MAX_TIMEOUT_SECS, ModelClientConfig};
pub use error::ModelClientError;
