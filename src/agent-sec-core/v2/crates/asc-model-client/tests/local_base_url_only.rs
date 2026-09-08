//! Verifies that the only publicly reachable way to build a client keeps the
//! model service host-local.
//!
//! Lives outside `lib.rs` because it drives the crate's public surface — the
//! path a host actually uses — whereas the unit tests in `config.rs` exercise
//! the private validators directly.
//!
//! Endpoint validation is driven through [`ModelClientConfig::new`] rather than
//! by mutating the process environment: `std::env::set_var` is an `unsafe fn`
//! under edition 2024 and this workspace forbids `unsafe_code`. Driving the
//! constructor is also stricter, because every caller — including `from_env` —
//! funnels through it, so no code path can reach the transport while skipping
//! the loopback check.

use std::time::Duration;

use asc_model_client::{DEFAULT_BASE_URL, ModelClientConfig, ModelClientError};

/// Timeout is irrelevant to endpoint validation; keep it short and constant.
const TIMEOUT: Duration = Duration::from_secs(1);

fn config_for(base_url: &str) -> Result<ModelClientConfig, ModelClientError> {
    ModelClientConfig::new(base_url, TIMEOUT)
}

#[test]
fn the_default_base_url_is_usable_out_of_the_box() {
    let config = config_for(DEFAULT_BASE_URL).expect("the documented default must be accepted");
    assert_eq!(config.base_url(), DEFAULT_BASE_URL);
}

#[test]
fn a_local_service_on_a_non_default_port_stays_usable() {
    assert!(
        config_for("http://127.0.0.1:18099").is_ok(),
        "a non-default loopback port must remain usable"
    );
}

#[test]
fn an_off_host_base_url_fails_closed() {
    let error = config_for("http://attacker.example:18099").expect_err("must be refused");
    let message = error.to_string();
    assert!(
        message.contains("attacker.example"),
        "the refusal must name the offending host so operators can fix it; got {message:?}"
    );
}

/// Userinfo that mimics loopback must not smuggle a remote host through:
/// `ureq` would have sent the prompt body to whatever follows `@`.
#[test]
fn userinfo_mimicking_loopback_does_not_smuggle_a_remote_host() {
    let disguised = "http://localhost:11434@attacker.example";
    let error = config_for(disguised).expect_err("must be refused");
    assert!(
        error.to_string().contains("attacker.example"),
        "the refusal must name the offending URL; got {error}"
    );
}

/// Asserts the invariant that holds whatever the ambient environment says: a
/// host that successfully reads its configuration can only have ended up
/// pointed at a local service with a bounded timeout.
#[test]
fn from_env_can_only_yield_a_loopback_endpoint() {
    if let Ok(config) = ModelClientConfig::from_env() {
        let base_url = config.base_url();
        assert!(
            config_for(base_url).is_ok(),
            "from_env accepted {base_url:?}, which explicit validation refuses"
        );
        assert!(
            config.timeout() > Duration::ZERO,
            "a zero timeout never bounds a request"
        );
    }
}
