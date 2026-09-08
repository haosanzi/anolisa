//! Validated configuration snapshot for a local model inference backend.
//!
//! A [`ModelClientConfig`] is built once per process and then reused. The
//! environment is read only by [`ModelClientConfig::from_env`], so no host can
//! change which model service it talks to by mutating environment variables
//! after that first resolution.

use std::time::Duration;

use url::{Host, Url};

use crate::error::ModelClientError;

/// Environment variable selecting the inference backend implementation.
const ENV_BACKEND: &str = "AGENT_SEC_MODEL_SERVICE_BACKEND";
/// Environment variable holding the backend endpoint.
const ENV_BASE_URL: &str = "AGENT_SEC_MODEL_SERVICE_BASE_URL";
/// Environment variable holding the request timeout in seconds.
const ENV_TIMEOUT: &str = "AGENT_SEC_MODEL_SERVICE_TIMEOUT";

/// The only supported backend name.
const DEFAULT_BACKEND: &str = "ollama";

/// Endpoint used when none is configured.
pub const DEFAULT_BASE_URL: &str = "http://localhost:11434";

/// Request timeout used when none is configured.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Upper bound for a configured timeout.
///
/// Values beyond this would let one inference call hang far longer than any
/// caller's own budget.
pub const MAX_TIMEOUT_SECS: u64 = 300;

/// Immutable endpoint and timeout used to build a model client.
///
/// Construction is the single place where the loopback restriction is enforced,
/// so no client can exist for a host that would receive scanned prompts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelClientConfig {
    base_url: String,
    timeout: Duration,
}

impl ModelClientConfig {
    /// Validates an explicit endpoint and timeout.
    ///
    /// A trailing slash is stripped so later path concatenation never produces
    /// a double slash.
    ///
    /// # Errors
    /// Returns [`ModelClientError::Config`] when `base_url` does not parse, its
    /// scheme is neither `http` nor `https`, its host is not loopback, the
    /// timeout is exactly zero, or the timeout exceeds [`MAX_TIMEOUT_SECS`].
    pub fn new(base_url: impl Into<String>, timeout: Duration) -> Result<Self, ModelClientError> {
        let base_url = base_url.into();
        validate_base_url(&base_url)?;
        validate_timeout(timeout)?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            timeout,
        })
    }

    /// Reads the configuration snapshot from the process environment.
    ///
    /// Recognised variables are `AGENT_SEC_MODEL_SERVICE_BACKEND`,
    /// `AGENT_SEC_MODEL_SERVICE_BASE_URL`, and
    /// `AGENT_SEC_MODEL_SERVICE_TIMEOUT`. An unusable timeout falls back to
    /// [`DEFAULT_TIMEOUT_SECS`] with a warning rather than failing, because an
    /// operator typo must not take the whole host down; an unusable endpoint
    /// always fails, because silently contacting a different host is worse than
    /// not starting.
    ///
    /// # Errors
    /// Returns [`ModelClientError::Config`] for an unsupported backend name or
    /// an endpoint rejected by [`ModelClientConfig::new`].
    pub fn from_env() -> Result<Self, ModelClientError> {
        let backend = env_or(ENV_BACKEND, DEFAULT_BACKEND);
        if backend != DEFAULT_BACKEND {
            return Err(ModelClientError::Config(format!(
                "unsupported model service backend: {backend:?}"
            )));
        }
        let timeout = Duration::from_secs(timeout_secs_or_default(std::env::var(ENV_TIMEOUT).ok()));
        Self::new(env_or(ENV_BASE_URL, DEFAULT_BASE_URL), timeout)
    }

    /// Returns the validated endpoint without a trailing slash.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Returns the timeout bounding connect, read, and write alike.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Rejects a `base_url` that is unparseable, whose scheme is not `http` or
/// `https`, or which targets a host other than loopback.
///
/// Scanned prompts carry credentials and PII, and the endpoint usually comes
/// from the environment, so a hijacked value would otherwise exfiltrate every
/// scanned prompt. Only a locally hosted model service is supported, so
/// refusing here turns that silent egress into a configuration error.
///
/// Parsing goes through [`Url`], the same crate `ureq` resolves requests with,
/// so this check cannot disagree with the transport about which host is being
/// contacted. A hand-rolled host scan does: in
/// `http://localhost:8080@attacker.example/` the leading label is userinfo and
/// the real destination is `attacker.example`.
fn validate_base_url(base_url: &str) -> Result<(), ModelClientError> {
    let url = Url::parse(base_url).map_err(|error| {
        ModelClientError::Config(format!("base_url is not a valid URL {base_url:?}: {error}"))
    })?;
    // `Url::parse` accepts any scheme, so `localhost:11434` parses with scheme
    // `localhost` rather than failing.
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ModelClientError::Config(format!(
            "base_url must use http:// or https:// scheme: {base_url:?}"
        )));
    }
    if !is_loopback_host(&url) {
        return Err(ModelClientError::Config(format!(
            "refusing non-loopback model service base_url {base_url:?}: only a local model \
             service is supported, and scanned prompts must not leave the host"
        )));
    }
    Ok(())
}

/// Whether the parsed URL's host is `localhost` or a loopback IP.
///
/// [`Url`] normalises the many spellings of a loopback address — `127.1`,
/// `2130706433`, `0x7f.0.0.1`, a trailing dot — into the same [`Host::Ipv4`],
/// so all of them are accepted here. That matches what the transport would have
/// resolved them to, which is the point of not enumerating hosts by hand.
fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(name)) => name == "localhost",
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        // Schemes without an authority (`file:`) never reach here, but a
        // hostless URL is not local either way.
        None => false,
    }
}

/// Rejects a timeout that cannot bound a request usefully.
///
/// Sub-second values are allowed so tests can fail fast against a dead port;
/// only an exactly zero duration (which `ureq` reads as "wait forever") and
/// values above [`MAX_TIMEOUT_SECS`] are refused.
fn validate_timeout(timeout: Duration) -> Result<(), ModelClientError> {
    if timeout.is_zero() {
        return Err(ModelClientError::Config(
            "timeout must not be zero: a zero timeout never bounds a request".to_owned(),
        ));
    }
    if timeout.as_secs() > MAX_TIMEOUT_SECS {
        return Err(ModelClientError::Config(format!(
            "timeout {}s exceeds the {MAX_TIMEOUT_SECS}s maximum",
            timeout.as_secs()
        )));
    }
    Ok(())
}

/// Parses a timeout in seconds, falling back to [`DEFAULT_TIMEOUT_SECS`] when
/// the value is missing.
///
/// A present but unusable value (unparseable, zero, or above
/// [`MAX_TIMEOUT_SECS`]) also falls back, but is logged rather than silently
/// dropped: the operator picked a scan budget deliberately, so quietly serving
/// a different one turns a typo into unexplained latency with nothing to trace
/// it to.
fn timeout_secs_or_default(raw: Option<String>) -> u64 {
    let Some(raw) = raw
        .map(|raw| raw.trim().to_owned())
        .filter(|raw| !raw.is_empty())
    else {
        return DEFAULT_TIMEOUT_SECS;
    };
    match raw.parse::<u64>() {
        Ok(secs) if (1..=MAX_TIMEOUT_SECS).contains(&secs) => secs,
        _ => {
            log::warn!(
                "ignoring {ENV_TIMEOUT}={raw:?}: expected an integer in 1..={MAX_TIMEOUT_SECS}; \
                 falling back to {DEFAULT_TIMEOUT_SECS}s"
            );
            DEFAULT_TIMEOUT_SECS
        }
    }
}

/// Returns a trimmed non-empty environment value, or `default`.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_in_range_is_used() {
        assert_eq!(timeout_secs_or_default(Some("45".into())), 45);
        assert_eq!(timeout_secs_or_default(Some("1".into())), 1);
        assert_eq!(timeout_secs_or_default(Some(" 45 ".into())), 45);
        assert_eq!(
            timeout_secs_or_default(Some(MAX_TIMEOUT_SECS.to_string())),
            MAX_TIMEOUT_SECS
        );
    }

    #[test]
    fn timeout_out_of_range_falls_back_to_default() {
        assert_eq!(
            timeout_secs_or_default(Some("0".into())),
            DEFAULT_TIMEOUT_SECS
        );
        assert_eq!(
            timeout_secs_or_default(Some((MAX_TIMEOUT_SECS + 1).to_string())),
            DEFAULT_TIMEOUT_SECS
        );
    }

    #[test]
    fn timeout_missing_or_unparseable_falls_back_to_default() {
        for raw in [
            None,
            Some(String::new()),
            Some("   ".into()),
            Some("not-a-number".into()),
            Some("-5".into()),
            // A digit-transposing typo: 30 mistyped as 3O.
            Some("3O".into()),
        ] {
            assert_eq!(
                timeout_secs_or_default(raw.clone()),
                DEFAULT_TIMEOUT_SECS,
                "{raw:?} must fall back to the default timeout"
            );
        }
    }

    #[test]
    fn explicit_timeout_bounds_are_enforced_instead_of_silently_clamped() {
        assert!(validate_timeout(Duration::from_millis(50)).is_ok());
        assert!(validate_timeout(Duration::from_secs(MAX_TIMEOUT_SECS)).is_ok());
        assert!(matches!(
            validate_timeout(Duration::ZERO),
            Err(ModelClientError::Config(_))
        ));
        assert!(matches!(
            validate_timeout(Duration::from_secs(MAX_TIMEOUT_SECS + 1)),
            Err(ModelClientError::Config(_))
        ));
    }

    #[test]
    fn base_url_without_http_scheme_is_rejected() {
        for bad in [
            "ftp://localhost:11434",
            "file:///etc/passwd",
            "localhost:11434",
            "//attacker.example",
        ] {
            assert!(
                matches!(validate_base_url(bad), Err(ModelClientError::Config(_))),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn loopback_base_url_is_accepted() {
        assert!(validate_base_url("http://localhost:11434").is_ok());
        assert!(validate_base_url("http://127.0.0.1:11434").is_ok());
        assert!(validate_base_url("http://[::1]:11434").is_ok());
    }

    /// Regression guard for the exfiltration path: a hijacked endpoint pointing
    /// at an arbitrary host must fail closed rather than ship prompts there.
    #[test]
    fn non_loopback_base_url_is_rejected() {
        for remote in [
            "https://model.internal:8443",
            "http://attacker.example:11434",
            "http://10.0.0.5:18099",
            "http://[2001:db8::1]:11434",
        ] {
            let error = validate_base_url(remote).expect_err("must be rejected");
            let ModelClientError::Config(message) = &error else {
                panic!("{remote:?} must fail with Config, got {error:?}");
            };
            assert!(
                message.contains(remote),
                "rejection must name the offending URL so operators can fix it; got {message:?}"
            );
        }
    }

    #[test]
    fn loopback_detection_matches_local_hosts_only() {
        for local in [
            "http://localhost:11434",
            "http://127.0.0.1:11434",
            "http://127.1.2.3:11434/api",
            "http://[::1]:11434",
        ] {
            assert!(
                validate_base_url(local).is_ok(),
                "{local:?} must be accepted"
            );
        }
        for remote in [
            "http://attacker.example:11434",
            "http://10.0.0.5:11434",
            "http://[2001:db8::1]:11434",
        ] {
            assert!(
                validate_base_url(remote).is_err(),
                "{remote:?} must be refused"
            );
        }
    }

    /// Userinfo makes the authority's leading label a red herring: in
    /// `http://localhost:8080@attacker.example/` the host is `attacker.example`,
    /// which is where `ureq` sends the body. Verified against a live listener:
    /// the request arrived with `Host: <post-@ authority>` and the fake loopback
    /// label demoted to an `Authorization: Basic` header.
    #[test]
    fn userinfo_does_not_disguise_a_remote_host() {
        for disguised in [
            "http://localhost@attacker.example:11434",
            "http://localhost:8080@attacker.example:11434",
            "http://127.0.0.1:8080@attacker.example/api",
            "http://[::1]:8080@attacker.example",
            "http://user:pass@attacker.example",
        ] {
            let error = validate_base_url(disguised).expect_err("must be refused");
            let ModelClientError::Config(message) = &error else {
                panic!("{disguised:?} must fail with Config, got {error:?}");
            };
            assert!(
                message.contains(disguised),
                "rejection must name the offending URL; got {message:?}"
            );
        }
        // Userinfo itself is not the thing being refused: here the real host is
        // loopback, so the credential never leaves the machine.
        assert!(validate_base_url("http://user:pass@127.0.0.1:11434").is_ok());
    }

    #[test]
    fn base_url_trailing_slash_is_stripped() {
        let config = ModelClientConfig::new("http://localhost:11434/", Duration::from_secs(1))
            .expect("a loopback endpoint must be accepted");
        assert_eq!(config.base_url(), "http://localhost:11434");
    }
}
