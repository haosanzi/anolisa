//! Ollama REST transport behind a backend-independent client port.
//!
//! Consumers depend on [`ModelClient`] rather than on `ureq`, so a capability's
//! detection logic stays testable without a live inference service.

use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::config::ModelClientConfig;
use crate::error::ModelClientError;

/// Pause before the single retry of a transient failure.
///
/// Long enough for an Ollama restart to finish binding, short enough to stay
/// invisible inside a caller's per-scan budget.
const RETRY_BACKOFF: Duration = Duration::from_millis(200);

/// Options forwarded verbatim to the backend's `options` field.
pub type ModelOptions = Map<String, Value>;

/// Parameters for a single-shot completion request.
#[derive(Debug, Clone)]
pub struct GenerateRequest<'a> {
    /// Backend-resolvable model name.
    pub model: &'a str,
    /// Prompt text sent to the model.
    pub prompt: &'a str,
    /// Bypass the server-side chat template; the caller supplies the fully
    /// templated prompt.
    pub raw: bool,
    /// Request per-token logprobs.
    pub logprobs: bool,
    /// How many alternatives per position to return; only meaningful when
    /// `logprobs` is set.
    pub top_logprobs: u32,
    /// Backend-specific sampling options.
    pub options: ModelOptions,
}

/// Backend-independent interface for local model inference.
///
/// Implemented by [`OllamaClient`]; tests inject fakes.
pub trait ModelClient: Send + Sync {
    /// Whether `model` is available in the backend.
    ///
    /// Never fails: network errors are reported as `false` so callers can treat
    /// availability as a simple predicate.
    fn check_model(&self, model: &str) -> bool;

    /// Single-shot completion (`POST /api/generate`).
    ///
    /// # Errors
    /// Returns [`ModelClientError::Inference`] when the service is unreachable
    /// or the response body is not valid JSON.
    fn generate(&self, request: &GenerateRequest<'_>) -> Result<Value, ModelClientError>;

    /// Chat completion with structured messages (`POST /api/chat`).
    ///
    /// `logprobs` requests per-token log probabilities in the response;
    /// `top_logprobs` limits how many candidate tokens are returned at each
    /// position and is ignored when `logprobs` is false. Requires Ollama
    /// v0.12.11 or newer; older versions silently omit the `logprobs` field and
    /// callers must treat that as "no confidence available".
    ///
    /// # Errors
    /// Returns [`ModelClientError::Inference`] when the service is unreachable
    /// or the response body is not valid JSON.
    fn chat(
        &self,
        model: &str,
        messages: &[(&str, &str)],
        options: &ModelOptions,
        logprobs: bool,
        top_logprobs: u32,
    ) -> Result<Value, ModelClientError>;
}

/// Ollama REST backend bound to one validated endpoint.
#[derive(Debug, Clone)]
pub struct OllamaClient {
    base_url: String,
    /// Built once and reused so repeated requests share the connection pool
    /// instead of paying a fresh TCP handshake each time.
    agent: ureq::Agent,
}

impl OllamaClient {
    /// Builds a client for an already validated configuration snapshot.
    ///
    /// This is the only constructor, so a client for a non-loopback host cannot
    /// be created through any public path.
    ///
    /// The configured timeout bounds connect, read, and write alike. Setting the
    /// connect phase explicitly matters: `ureq` defaults it to 30s, so leaving
    /// it unset would let one request block for `timeout + 30s` when the host is
    /// unreachable rather than the configured budget.
    pub fn from_config(config: &ModelClientConfig) -> Self {
        let timeout = config.timeout();
        Self {
            base_url: config.base_url().to_owned(),
            agent: ureq::AgentBuilder::new()
                .timeout_connect(timeout)
                .timeout_read(timeout)
                .timeout_write(timeout)
                .build(),
        }
    }

    /// POSTs `payload` to `path` and parses the JSON response body.
    ///
    /// Transient failures (see [`is_transient`]) are retried once after
    /// [`RETRY_BACKOFF`], since callers issue one request per scan and a lone
    /// hiccup would otherwise fail the whole operation.
    fn post(&self, path: &str, payload: &Value) -> Result<Value, ModelClientError> {
        let url = format!("{}{path}", self.base_url);
        let response = match self.send(&url, payload) {
            Err(error) if is_transient(&error) => {
                log::warn!("Ollama request failed (url={url}): {error}; retrying once");
                std::thread::sleep(RETRY_BACKOFF);
                self.send(&url, payload)
            }
            attempt => attempt,
        }
        .map_err(|error| {
            ModelClientError::Inference(format!("Ollama request failed (url={url}): {error}"))
        })?;
        response.into_json().map_err(|error| {
            ModelClientError::Inference(format!("Ollama returned invalid JSON: {error}"))
        })
    }

    /// Single POST attempt, kept separate so `post` can retry it.
    // The large Err (ureq::Error embeds a Response) is consumed immediately by
    // `post`; boxing it would only obscure the transient-error check.
    #[allow(clippy::result_large_err)]
    fn send(&self, url: &str, payload: &Value) -> Result<ureq::Response, ureq::Error> {
        self.agent
            .post(url)
            .set("Content-Type", "application/json")
            .send_json(payload)
    }
}

impl ModelClient for OllamaClient {
    fn check_model(&self, model: &str) -> bool {
        let url = format!("{}/api/tags", self.base_url);
        let response = match self.agent.get(&url).call() {
            Ok(response) => response,
            Err(error) => {
                log::warn!("Ollama check_model failed (url={}): {error}", self.base_url);
                return false;
            }
        };
        let body: Value = match response.into_json() {
            Ok(body) => body,
            Err(error) => {
                log::warn!("Ollama check_model returned invalid JSON: {error}");
                return false;
            }
        };
        let names: Vec<&str> = body
            .get("models")
            .and_then(Value::as_array)
            .map(|models| {
                models
                    .iter()
                    .filter_map(|entry| entry.get("name").and_then(Value::as_str))
                    .collect()
            })
            .unwrap_or_default();
        // Match the exact name or a name:tag prefix, so "warden" matches
        // "warden:latest" but not "warden-tmp".
        let prefix = format!("{model}:");
        let found = names
            .iter()
            .any(|name| *name == model || name.starts_with(&prefix));
        if found {
            log::info!("model {model:?} verified in Ollama");
        } else {
            log::warn!("Ollama reachable but model {model:?} not in: {names:?}");
        }
        found
    }

    fn generate(&self, request: &GenerateRequest<'_>) -> Result<Value, ModelClientError> {
        let mut payload = Map::new();
        payload.insert("model".into(), json!(request.model));
        payload.insert("prompt".into(), json!(request.prompt));
        payload.insert("stream".into(), json!(false));
        payload.insert("raw".into(), json!(request.raw));
        if request.logprobs {
            payload.insert("logprobs".into(), json!(true));
            payload.insert("top_logprobs".into(), json!(request.top_logprobs));
        }
        if !request.options.is_empty() {
            payload.insert("options".into(), Value::Object(request.options.clone()));
        }
        self.post("/api/generate", &Value::Object(payload))
    }

    fn chat(
        &self,
        model: &str,
        messages: &[(&str, &str)],
        options: &ModelOptions,
        logprobs: bool,
        top_logprobs: u32,
    ) -> Result<Value, ModelClientError> {
        let messages: Vec<Value> = messages
            .iter()
            .map(|(role, content)| json!({"role": role, "content": content}))
            .collect();
        let mut payload = Map::new();
        payload.insert("model".into(), json!(model));
        payload.insert("messages".into(), Value::Array(messages));
        payload.insert("stream".into(), json!(false));
        if logprobs {
            payload.insert("logprobs".into(), json!(true));
            payload.insert("top_logprobs".into(), json!(top_logprobs));
        }
        if !options.is_empty() {
            payload.insert("options".into(), Value::Object(options.clone()));
        }
        self.post("/api/chat", &Value::Object(payload))
    }
}

/// Whether `error` is transient enough that one short-backoff retry can
/// realistically succeed: an HTTP 5xx or a failed connect (refused or connect
/// timeout, e.g. Ollama mid-restart).
///
/// Read timeouts map to `ErrorKind::Io` and are deliberately excluded — retrying
/// them would double the caller's latency budget on slow inference instead of
/// masking a transient fault.
fn is_transient(error: &ureq::Error) -> bool {
    match error {
        ureq::Error::Status(code, _) => *code >= 500,
        ureq::Error::Transport(transport) => transport.kind() == ureq::ErrorKind::ConnectionFailed,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Builds a client for a loopback port, going through real validation.
    fn client_for(port: u16, timeout: Duration) -> OllamaClient {
        let config = ModelClientConfig::new(format!("http://127.0.0.1:{port}"), timeout)
            .expect("a loopback endpoint must be accepted");
        OllamaClient::from_config(&config)
    }

    /// Spawns a minimal keep-alive HTTP/1.1 server that answers `expected` GET
    /// requests, returning its port and the accepted-connection counter.
    fn spawn_counting_server(
        expected: usize,
    ) -> (u16, Arc<AtomicUsize>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_in_server = Arc::clone(&accepted);

        let handle = std::thread::spawn(move || {
            let mut served = 0;
            for stream in listener.incoming() {
                let mut stream = stream.expect("accept");
                accepted_in_server.fetch_add(1, Ordering::SeqCst);
                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                while served < expected {
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                        break; // client closed the connection
                    }
                    loop {
                        let mut header = String::new();
                        if reader.read_line(&mut header).unwrap_or(0) == 0 {
                            break;
                        }
                        if header == "\r\n" || header == "\n" {
                            break;
                        }
                    }
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\n\
                              Content-Type: application/json\r\n\
                              Content-Length: 2\r\n\r\n{}",
                        )
                        .expect("write response");
                    stream.flush().ok();
                    served += 1;
                }
                if served >= expected {
                    break;
                }
            }
        });
        (port, accepted, handle)
    }

    /// Spawns a minimal HTTP/1.1 server that answers each request with the next
    /// status in `statuses` (body `{}`), returning its port and a served-request
    /// counter. Exits once every status has been sent.
    fn spawn_scripted_server(
        statuses: &'static [u16],
    ) -> (u16, Arc<AtomicUsize>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let served = Arc::new(AtomicUsize::new(0));
        let served_in_server = Arc::clone(&served);

        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.expect("accept");
                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                loop {
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                        break; // client closed the connection
                    }
                    let mut content_length = 0usize;
                    loop {
                        let mut header = String::new();
                        if reader.read_line(&mut header).unwrap_or(0) == 0 {
                            break;
                        }
                        if header == "\r\n" || header == "\n" {
                            break;
                        }
                        let lower = header.to_ascii_lowercase();
                        if let Some(value) = lower.strip_prefix("content-length:") {
                            content_length = value.trim().parse().unwrap_or(0);
                        }
                    }
                    // Consume the request body so the client never sees a reset
                    // while still writing.
                    let mut body = vec![0u8; content_length];
                    reader.read_exact(&mut body).ok();

                    let index = served_in_server.fetch_add(1, Ordering::SeqCst);
                    let status = statuses.get(index).copied().unwrap_or(200);
                    let reason = if status < 400 { "OK" } else { "Error" };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: 2\r\n\r\n{{}}"
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("write response");
                    stream.flush().ok();
                    if index + 1 >= statuses.len() {
                        return;
                    }
                }
            }
        });
        (port, served, handle)
    }

    /// Minimal generate request for retry tests.
    fn generate_request(prompt: &str) -> GenerateRequest<'_> {
        GenerateRequest {
            model: "warden",
            prompt,
            raw: true,
            logprobs: false,
            top_logprobs: 0,
            options: Map::new(),
        }
    }

    #[test]
    fn requests_reuse_one_pooled_connection() {
        let (port, accepted, server) = spawn_counting_server(2);
        let client = client_for(port, Duration::from_secs(5));
        client.check_model("a");
        client.check_model("b");
        server.join().expect("server thread");

        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "two requests must share one pooled connection"
        );
    }

    #[test]
    fn unreachable_service_reports_model_missing() {
        // Port 1 is never a live Ollama; check_model must not propagate.
        let client = client_for(1, Duration::from_millis(50));
        assert!(!client.check_model("qwen3guard:0.6b"));
    }

    #[test]
    fn unreachable_service_generate_is_inference_error() {
        let client = client_for(1, Duration::from_millis(50));
        let request = GenerateRequest {
            model: "warden",
            prompt: "hi",
            raw: true,
            logprobs: true,
            top_logprobs: 10,
            options: Map::new(),
        };
        assert!(matches!(
            client.generate(&request),
            Err(ModelClientError::Inference(_))
        ));
    }

    #[test]
    fn transient_5xx_is_retried_once_and_succeeds() {
        let (port, served_requests, server) = spawn_scripted_server(&[500, 200]);
        let client = client_for(port, Duration::from_secs(5));
        let result = client.generate(&generate_request("hi"));
        server.join().expect("server thread");

        assert!(result.is_ok(), "retry after a 500 must succeed: {result:?}");
        assert_eq!(
            served_requests.load(Ordering::SeqCst),
            2,
            "exactly one retry"
        );
    }

    #[test]
    fn persistent_5xx_fails_after_single_retry() {
        let (port, served_requests, server) = spawn_scripted_server(&[500, 500]);
        let client = client_for(port, Duration::from_secs(5));
        let result = client.generate(&generate_request("hi"));
        server.join().expect("server thread");

        assert!(matches!(result, Err(ModelClientError::Inference(_))));
        assert_eq!(
            served_requests.load(Ordering::SeqCst),
            2,
            "one retry, then give up"
        );
    }

    #[test]
    fn client_error_is_not_retried() {
        let (port, served_requests, server) = spawn_scripted_server(&[400]);
        let client = client_for(port, Duration::from_secs(5));
        let result = client.generate(&generate_request("hi"));
        server.join().expect("server thread");

        assert!(matches!(result, Err(ModelClientError::Inference(_))));
        assert_eq!(
            served_requests.load(Ordering::SeqCst),
            1,
            "4xx must not be retried"
        );
    }
}
