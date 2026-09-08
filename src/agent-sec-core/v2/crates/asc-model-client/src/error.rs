//! Errors raised by the local model inference client.

use thiserror::Error;

/// Failure to configure or use a local model inference backend.
#[derive(Debug, Error)]
pub enum ModelClientError {
    /// Rejected configuration: unsupported backend name, an unparseable or
    /// non-loopback `base_url`, or an out-of-range request timeout.
    #[error("invalid model client configuration: {0}")]
    Config(String),

    /// The service is unreachable or returned an unusable response.
    #[error("model inference failed: {0}")]
    Inference(String),
}
