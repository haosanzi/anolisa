//! Initial proposal acceptance tests using the real CLI, UDS, frozen models and kernel peer credentials.

mod common;

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use asc_daemon::{BootstrapConfig, serve};
use asc_daemon_core::{RootManagedPrincipalPolicy, intent::IntentService};
use asc_daemon_handler::{DaemonDispatcher, JsonRejectionEncoder};
use asc_daemon_service::{
    DispatchError, DispatchRequest, RequestDispatcher, ResponseDisposition, ShutdownToken,
};
use asc_model_client::provider::{ModelProvider, ProviderError};
use asc_pap::PapService;
use asc_policy_repository_sqlite::SqlitePolicyRepository;
use serde_json::{Value, json};

#[derive(Default)]
struct Replay {
    calls: AtomicUsize,
}
impl ModelProvider for Replay {
    fn complete(
        &self,
        _: &str,
        system: &str,
        input: &str,
        _: Instant,
    ) -> Result<String, ProviderError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert!(!system.contains("PRIVATE_FILE_BYTES"));
        assert!(!input.contains("PRIVATE_FILE_BYTES"));
        let input: Value = serde_json::from_str(input).unwrap();
        assert_eq!(input.as_object().unwrap().len(), 1);
        assert_eq!(input["task"].as_object().unwrap().len(), 2);
        let text = input["task"]["text"].as_str().unwrap();
        let (kind, name, action) = match text {
            "Read report.csv" | "Read revised report.csv" | "Read report.csv\u{1b}[2J\u{202e}" => {
                ("file", Some("report.csv"), "read")
            }
            "Review current changes" => ("changes", None, "read"),
            "Read docs" => ("directory", Some("docs"), "read"),
            "当前目录下有几个文件" => {
                ("current_directory", Some("当前目录"), "directory_listing")
            }
            "Read missing.csv" => ("file", Some("missing.csv"), "read"),
            "Run tests" => ("file", None, "process_execution"),
            _ => return Err(ProviderError::InvalidResponse),
        };
        let selector = match name {
            Some(name) => json!({"kind":kind,"name":name}),
            None => json!({"kind":kind}),
        };
        let mut draft = json!({"goal":text,"resources":{"read":[text],"write":[],"egress":[]},"read_selectors":[selector],"requested_actions":[action],"prohibitions":[],"assumptions":[],"observed_only":[],"unresolved":[],"external_influences":[]});
        let mut evidence = Vec::new();
        for field in [
            "/goal",
            "/resources/read/0",
            "/read_selectors/0/kind",
            "/requested_actions/0",
        ] {
            evidence
                .push(json!({"field":field,"source_id":input["task"]["source_id"],"quote":text}));
        }
        if name.is_some() {
            evidence.push(json!({"field":"/read_selectors/0/name","source_id":input["task"]["source_id"],"quote":text}));
        }
        if action == "process_execution" {
            draft["resources"]["read"] = json!([]);
            draft["read_selectors"] = json!([]);
            evidence.retain(|entry| {
                matches!(
                    entry["field"].as_str(),
                    Some("/goal" | "/requested_actions/0")
                )
            });
        }
        if action == "directory_listing" {
            draft["goal"] = json!("统计当前目录直接包含的文件数量");
            draft["resources"]["read"] = json!(["当前目录"]);
            draft["requested_actions"] = json!(["directory_listing", "metadata"]);
            for entry in &mut evidence {
                if entry["field"]
                    .as_str()
                    .unwrap()
                    .starts_with("/read_selectors/")
                    || entry["field"] == "/resources/read/0"
                {
                    entry["quote"] = json!("当前目录");
                }
            }
            evidence.push(json!({"field":"/requested_actions/1","source_id":input["task"]["source_id"],"quote":text}));
        }
        draft["evidence"] = json!(evidence);
        Ok(draft.to_string())
    }
}

struct Recording {
    inner: DaemonDispatcher,
    requests: Arc<Mutex<Vec<(u32, Value)>>>,
    timeout: Option<Duration>,
}
impl RequestDispatcher for Recording {
    fn dispatch_timeout(&self, payload: &[u8]) -> Option<Duration> {
        self.timeout
            .or_else(|| self.inner.dispatch_timeout(payload))
    }
    fn dispatch(
        &self,
        request: DispatchRequest,
        response: &mut dyn std::io::Write,
    ) -> Result<ResponseDisposition, DispatchError> {
        self.requests.lock().unwrap().push((
            request.peer.uid(),
            serde_json::from_slice(&request.payload).unwrap(),
        ));
        self.inner.dispatch(request, response)
    }
}

struct Server {
    shutdown: ShutdownToken,
    task: tokio::task::JoinHandle<()>,
    requests: Arc<Mutex<Vec<(u32, Value)>>>,
}
impl Server {
    async fn start(
        socket: &Path,
        provider: Arc<dyn ModelProvider>,
        timeout: Option<Duration>,
    ) -> Self {
        Self::start_with_capabilities(socket, provider, timeout, None).await
    }

    async fn start_with_capabilities(
        socket: &Path,
        provider: Arc<dyn ModelProvider>,
        timeout: Option<Duration>,
        capabilities: Option<
            std::collections::BTreeSet<asc_policy_types::filesystem::FilesystemPermission>,
        >,
    ) -> Self {
        let service = IntentService::new(provider, "fixture".into(), || {
            chrono::Utc::now().timestamp()
        });
        let service = Arc::new(match capabilities {
            Some(supported) => service.with_filesystem_capabilities(supported),
            None => service,
        });
        let inner = DaemonDispatcher::new(
            PapService::new(Arc::new(SqlitePolicyRepository::temporary().unwrap())),
            Arc::new(RootManagedPrincipalPolicy::default()),
            asc_daemon::scan_application(
                asc_action_runtime::testing::discarding_finalizer(),
                Arc::new(asc_capability_pii_scan::PiiRuleSet::builtin().unwrap()),
            ),
        )
        .with_intent(service);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let dispatcher = Arc::new(Recording {
            inner,
            requests: Arc::clone(&requests),
            timeout,
        });
        let mut config = BootstrapConfig::new(socket);
        config.socket_mode = 0o666;
        let shutdown = ShutdownToken::new();
        let signal = shutdown.clone();
        let task = tokio::spawn(async move {
            serve(config, dispatcher, Arc::new(JsonRejectionEncoder), signal)
                .await
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if tokio::net::UnixStream::connect(socket).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        Self {
            shutdown,
            task,
            requests,
        }
    }
    async fn stop(self) {
        self.shutdown.request();
        self.task.await.unwrap();
    }
}

fn cli(socket: &Path, directory: &Path, task: &str) -> Command {
    let copied = directory.join("agent-sec-cli");
    let binary = if copied.exists() {
        copied
    } else {
        env!("CARGO_BIN_EXE_agent-sec-cli").into()
    };
    let mut cli = Command::new(binary);
    cli.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir(directory)
        .arg("--socket")
        .arg(socket)
        .args(["intent", "propose", "--task", task]);
    cli
}
fn output_json(output: &Output, code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_FILE_BYTES"));
    value
}
fn git_output(directory: &Path, args: &[&str]) -> Output {
    Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", directory)
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .current_dir(directory)
        .output()
        .unwrap()
}

fn git(directory: &Path, args: &[&str]) {
    let result = git_output(directory, args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachments_formats_clarifications_and_real_peer_identity() {
    let directory = common::Directory::new();
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
    let socket = directory.0.join("daemon.sock");
    let provider = Arc::new(Replay::default());
    let server = Server::start(&socket, provider.clone(), None).await;
    let attachment = directory.0.join("report.csv");
    fs::write(&attachment, "PRIVATE_FILE_BYTES").unwrap();
    fs::set_permissions(&attachment, fs::Permissions::from_mode(0o644)).unwrap();
    for (task, code, outcome) in [
        ("Read report.csv", 0, "candidate"),
        ("Read missing.csv", 2, "needs_clarification"),
        ("Run tests", 3, "rejected"),
    ] {
        let output = cli(&socket, &directory.0, task)
            .arg("--attach")
            .arg(&attachment)
            .args(["--format", "json"])
            .output()
            .unwrap();
        let value = output_json(&output, code);
        assert_eq!(value["outcome"], outcome);
        assert!(value.get("decision").is_none());
        if code == 0 {
            assert_eq!(value["candidate"]["status"], "CANDIDATE");
            assert_eq!(value["candidate"]["reads"].as_array().unwrap().len(), 1);
            assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE_FILE_BYTES"));
        } else {
            assert!(value.get("candidate").is_none());
        }
    }
    for format in ["text", "cedar"] {
        let output = cli(&socket, &directory.0, "Read report.csv")
            .arg("--attach")
            .arg(&attachment)
            .args(["--format", format])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("not effective") || text.contains("not approved or effective"));
        assert!(!text.contains("[a]"));
        assert!(!text.contains("request_approval"));
    }
    if rustix::process::geteuid().as_raw() == 0 {
        common::executable(&directory.0);
        let value = output_json(
            &cli(&socket, &directory.0, "Read report.csv")
                .uid(65534)
                .gid(65534)
                .arg("--attach")
                .arg(&attachment)
                .args(["--format", "json"])
                .output()
                .unwrap(),
            0,
        );
        assert!(
            value["candidate"]["task_id"]
                .as_str()
                .unwrap()
                .starts_with("intent-65534-")
        );
        assert!(
            server
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|(uid, _)| *uid == 65534)
        );
        fs::set_permissions(&attachment, fs::Permissions::from_mode(0o600)).unwrap();
        let output = cli(&socket, &directory.0, "Read report.csv")
            .uid(65534)
            .gid(65534)
            .arg("--attach")
            .arg(&attachment)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    assert!(
        server
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|(_, request)| request["method"] == "intent.propose")
    );
    server.stop().await;
    let output = cli(&socket, &directory.0, "Read report.csv")
        .arg("--attach")
        .arg(&attachment)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_directory_counting_needs_no_materials_and_never_grants_content_reads() {
    let root = common::Directory::new();
    let caller = root.0.join("调用方");
    fs::create_dir(&caller).unwrap();
    // Oversized files, symlinks and hidden entries must not prevent context-only directory proposals.
    fs::write(caller.join("large"), vec![0; 1024 * 1024 + 1]).unwrap();
    fs::write(caller.join(".hidden"), "PRIVATE_FILE_BYTES").unwrap();
    symlink("/", caller.join("link")).unwrap();
    assert_ne!(std::env::current_dir().unwrap(), caller);
    let attachment = root.0.join("report.csv");
    fs::write(&attachment, "PRIVATE_FILE_BYTES").unwrap();
    let socket = root.0.join("daemon.sock");
    let server = Server::start(&socket, Arc::new(Replay::default()), None).await;
    for attached in [false, true] {
        let mut command = cli(&socket, &caller, "当前目录下有几个文件");
        command.args(["--format", "json"]);
        if attached {
            command.arg("--attach").arg(&attachment);
        }
        let result = output_json(&command.output().unwrap(), 0);
        let candidate = &result["candidate"];
        assert_eq!(
            candidate["binding_snapshot"]["working_directory"],
            caller.to_str().unwrap()
        );
        assert_eq!(
            candidate["directories"][0]["path"],
            caller.to_str().unwrap()
        );
        assert_eq!(candidate["reads"], json!([]));
        assert_eq!(
            candidate["required_permissions"],
            json!(["filesystem.list", "filesystem.metadata"])
        );
        assert_eq!(
            candidate["draft"]["field_evidence"]["/goal"]["quote"],
            "当前目录下有几个文件"
        );
        assert!(candidate["draft"]["field_evidence"].get("").is_none());
        assert!(
            candidate["forbidden_actions"]
                .as_array()
                .unwrap()
                .contains(&json!("filesystem.read"))
        );
        let requests = server.requests.lock().unwrap();
        let params = &requests.last().unwrap().1["params"];
        assert_eq!(params["working_directory"], caller.to_str().unwrap());
        assert_eq!(
            params["materials"].as_array().unwrap().len(),
            usize::from(attached)
        );
        assert!(
            params["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["kind"] == "attachment")
        );
    }
    let output = cli(&socket, &caller, "当前目录下有几个文件")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "Task understanding (unconfirmed)",
        "统计当前目录直接包含的文件数量",
        "Task quote: \"当前目录\"",
        "List directory entries",
        "Inspect file types and metadata",
        "File-content reads: none",
        caller.to_str().unwrap(),
    ] {
        assert!(text.contains(expected), "{text}");
    }
    for hidden in [
        "field_evidence",
        "start_byte",
        "quote_sha256",
        "source-intent-",
    ] {
        assert!(!text.contains(hidden), "{text}");
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_backends_must_support_every_exact_permission() {
    use asc_policy_types::filesystem::FilesystemPermission::{List, Metadata, Read};
    let root = common::Directory::new();
    let caller = root.0.clone();
    let socket = root.0.join("daemon.sock");
    // Exact directory capabilities must remain distinct from broad content-read support.
    for (capabilities, code, outcome) in [
        (vec![List, Metadata], 0, "candidate"),
        (vec![Read], 3, "rejected"),
        (vec![List], 3, "rejected"),
        (vec![Metadata], 3, "rejected"),
        (vec![Read, List, Metadata], 0, "candidate"),
        (vec![], 3, "rejected"),
    ] {
        let server = Server::start_with_capabilities(
            &socket,
            Arc::new(Replay::default()),
            None,
            Some(capabilities.into_iter().collect()),
        )
        .await;
        let result = output_json(
            &cli(&socket, &caller, "当前目录下有几个文件")
                .args(["--format", "json"])
                .output()
                .unwrap(),
            code,
        );
        assert_eq!(result["outcome"], outcome);
        if code == 3 {
            assert_eq!(result["reason"], "unsupported_backend");
            assert!(result.get("candidate").is_none());
        }
        server.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_net_changes_ignore_config_scripts_and_preserve_original_index() {
    let directory = common::Directory::new();
    let socket = directory.0.join("daemon.sock");
    let repo = directory.0.join("repo");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    for name in ["changed", "deleted", "renamed", "cancelled"] {
        fs::write(repo.join(name), "before").unwrap();
    }
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "baseline"]);
    fs::write(repo.join("changed"), "staged").unwrap();
    fs::write(repo.join("cancelled"), "staged").unwrap();
    git(&repo, &["add", "."]);
    fs::write(repo.join("changed"), "PRIVATE_FILE_BYTES").unwrap();
    fs::write(repo.join("cancelled"), "before").unwrap();
    fs::remove_file(repo.join("deleted")).unwrap();
    git(&repo, &["mv", "renamed", "newname"]);
    fs::write(repo.join("untracked"), "must not be included").unwrap();
    let network = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    network.set_nonblocking(true).unwrap();
    git(
        &repo,
        &[
            "config",
            "remote.origin.url",
            &format!("http://{}/objects", network.local_addr().unwrap()),
        ],
    );
    git(&repo, &["config", "remote.origin.promisor", "true"]);
    let marker = directory.0.join("script-ran");
    let script = directory.0.join("hostile");
    fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    for key in [
        "core.fsmonitor",
        "core.hooksPath",
        "diff.external",
        "diff.evil.textconv",
        "filter.evil.clean",
        "filter.evil.smudge",
    ] {
        git(&repo, &["config", key, script.to_str().unwrap()]);
    }
    fs::write(repo.join(".gitattributes"), "* filter=evil diff=evil\n").unwrap();
    let index = fs::read(repo.join(".git/index")).unwrap();
    let server = Server::start(&socket, Arc::new(Replay::default()), None).await;
    let result = output_json(
        &cli(&socket, &repo, "Review current changes")
            .args(["--workspace", ".", "--format", "json"])
            .output()
            .unwrap(),
        0,
    );
    let objects = result["candidate"]["binding_snapshot"]["objects"]
        .as_array()
        .unwrap();
    assert_eq!(objects.len(), 5);
    assert!(objects.iter().all(|object| {
        !["untracked", "cancelled", ".gitattributes"].contains(&object["path"].as_str().unwrap())
    }));
    assert!(
        objects
            .iter()
            .any(|object| object["path"] == "deleted" && object["version"] == "before")
    );
    assert!(
        objects
            .iter()
            .any(|object| object["path"] == "newname" && object["version"] == "current")
    );
    assert_eq!(index, fs::read(repo.join(".git/index")).unwrap());
    assert!(!marker.exists());
    assert!(
        matches!(network.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    server.stop().await;
}

#[test]
fn unsupported_git_layouts_and_incomplete_baselines_never_send_requests() {
    let directory = common::Directory::new();
    let socket = directory.0.join("absent.sock");
    for case in [
        "unborn", "clean", "conflict", "split", "sparse", "shallow", "promisor", "missing",
        "symlink", "corrupt",
    ] {
        let repo = directory.0.join(case);
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        fs::write(repo.join("file"), "before").unwrap();
        if case != "unborn" {
            git(&repo, &["add", "."]);
            git(&repo, &["commit", "-qm", "baseline"]);
            if case != "clean" {
                fs::write(repo.join("file"), "after").unwrap();
            }
        }
        match case {
            "conflict" => {
                git(&repo, &["checkout", "-qb", "other"]);
                git(&repo, &["commit", "-qam", "other"]);
                git(&repo, &["checkout", "-q", "-"]);
                fs::write(repo.join("file"), "conflict").unwrap();
                git(&repo, &["commit", "-qam", "current"]);
                let merge = git_output(&repo, &["merge", "other"]);
                assert!(!merge.status.success());
                assert!(String::from_utf8_lossy(&merge.stdout).contains("CONFLICT"));
                assert!(
                    !git_output(&repo, &["ls-files", "--unmerged"])
                        .stdout
                        .is_empty()
                );
            }
            "split" => git(&repo, &["update-index", "--split-index"]),
            "sparse" => fs::write(repo.join(".git/info/sparse-checkout"), "file").unwrap(),
            "shallow" => fs::write(repo.join(".git/shallow"), "untrusted").unwrap(),
            "promisor" => {
                fs::write(repo.join(".git/objects/pack/pack-missing.promisor"), "").unwrap();
            }
            "missing" => {
                fs::rename(repo.join(".git/objects"), repo.join("saved-objects")).unwrap();
                fs::create_dir(repo.join(".git/objects")).unwrap();
            }
            "symlink" => {
                fs::rename(repo.join("file"), repo.join("target")).unwrap();
                symlink("target", repo.join("file")).unwrap();
            }
            "corrupt" => fs::write(repo.join(".git/index"), "not an index").unwrap(),
            _ => {}
        }
        let index = fs::read(repo.join(".git/index")).ok();
        let output = cli(&socket, &repo, "Review current changes")
            .args(["--workspace", "."])
            .output()
            .unwrap();
        assert!(matches!(output.status.code(), Some(1 | 2)), "{case}");
        assert!(output.stdout.is_empty(), "{case}");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("cloud model"),
            "{case}"
        );
        assert_eq!(fs::read(repo.join(".git/index")).ok(), index, "{case}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn output_failure_never_claims_candidate_or_approval_delivery() {
    let directory = common::Directory::new();
    let socket = directory.0.join("daemon.sock");
    let attachment = directory.0.join("report.csv");
    fs::write(&attachment, "bytes").unwrap();
    let server = Server::start(&socket, Arc::new(Replay::default()), None).await;
    let output = cli(&socket, &directory.0, "Read report.csv")
        .arg("--attach")
        .arg(&attachment)
        .args(["--format", "json"])
        .stdout(
            fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Approval request generated"));
    server.stop().await;
}

#[test]
fn unsafe_and_oversized_inputs_fail_before_daemon_transport() {
    let directory = common::Directory::new();
    let socket = directory.0.join("absent.sock");
    let regular = directory.0.join("report.csv");
    fs::write(&regular, "bytes").unwrap();
    let link = directory.0.join("link");
    symlink(&regular, &link).unwrap();
    let fifo = directory.0.join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR,
        0,
    )
    .unwrap();
    let huge = directory.0.join("huge");
    fs::File::create(&huge)
        .unwrap()
        .set_len(1024 * 1024 + 1)
        .unwrap();
    for path in [link, fifo, huge, directory.0.join("../report.csv")] {
        let output = cli(&socket, &directory.0, "Read report.csv")
            .arg("--attach")
            .arg(path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("cloud model"));
    }
    let output = cli(&socket, &directory.0, "Review current changes")
        .args(["--workspace", "."])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a Git"));
}

#[test]
fn changes_during_combined_collection_are_rejected_by_the_real_process() {
    let directory = common::Directory::new();
    let repo = directory.0.join("repo");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    for index in 0..32 {
        fs::write(repo.join(index.to_string()), "before").unwrap();
    }
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "fixture"]);
    for index in 0..32 {
        fs::write(repo.join(index.to_string()), "after").unwrap();
    }
    let attachment = directory.0.join("report.csv");
    fs::write(&attachment, "before").unwrap();
    let output = Command::new("python3")
        .args(["-c", COLLECTION_CHANGE, env!("CARGO_BIN_EXE_agent-sec-cli")])
        .arg(&attachment)
        .arg(&repo)
        .arg(directory.0.join("missing.sock"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

const COLLECTION_CHANGE: &str = r"
import ctypes, os, select, subprocess, sys
binary, attachment, repo, socket = sys.argv[1:]
libc = ctypes.CDLL(None, use_errno=True)
fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
assert fd >= 0
assert libc.inotify_add_watch(fd, os.fsencode(attachment), 0x10) >= 0
child = subprocess.Popen([binary, '--socket', socket, 'intent', 'propose', '--task', 'Read report.csv', '--attach', attachment, '--workspace', repo], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
try:
    assert select.select([fd], [], [], 5)[0], 'attachment was never collected'
    os.read(fd, 4096)
    with open(attachment, 'w') as stream: stream.write('changed during collection')
    stdout, stderr = child.communicate(timeout=10)
    assert child.returncode == 1, (child.returncode, stdout, stderr)
    assert stdout == b''
    assert b'inaccessible, changed or unsupported' in stderr, stderr
    assert b'cloud model' not in stderr, stderr
finally:
    if child.poll() is None: child.kill(); child.wait()
    os.close(fd)
";

const PTY: &str = r#"
import os, pty, select, signal, subprocess, sys, termios, time, json
binary, socket, attachment, mode = sys.argv[1:]
master, slave = pty.openpty()
before = termios.tcgetattr(slave)
task = 'Read report.csv\x1b[2J\u202e' if mode=='controls' else 'Read report.csv'
if mode=='directory': task = '当前目录下有几个文件'
args = [binary, '--socket', socket, 'intent', 'propose', '--attach', attachment, '--task', task]
if mode=='expire': args += ['--ttl', '2']
child = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave)
data = b''
all_data = b''
def wait_for(needle):
    global data, all_data
    deadline = time.monotonic()+10
    while needle not in data:
        assert child.poll() is None, data
        assert time.monotonic()<deadline, data
        if select.select([master], [], [], .05)[0]:
            chunk=os.read(master,65536); data+=chunk; all_data+=chunk
def press(key, needle):
    global data
    data=b''; os.write(master,key); wait_for(needle)
try:
    wait_for(b'[a] Request approval')
    assert all_data.index(b'Candidate generated') < all_data.index(b'[a]')
    if mode=='approve':
        press(b'v\r', b'[a] Request approval')
        assert b'permit (' in data
        press(b's\r', b'[a] Request approval')
        assert b'content_sha256' in data
        os.write(master,b'a\r'); wait_for(b'Approval request generated')
        line=next(line for line in all_data.splitlines() if line.startswith(b'{') and b'request_approval' in line)
        request=json.loads(line)
        assert request['candidate']['status']=='CANDIDATE'
        for key in ['candidate_hash','binding_snapshot_digest','expires_at']: assert request[key]==request['candidate'][key]
        code=0
    elif mode=='modify':
        press(b'm\r', b'Complete revised task')
        press(b'Read revised report.csv\r', b'[a] Request approval')
        assert b'Original task\n  Read revised report.csv' in data.replace(b'\r', b'')
        os.write(master,b'q\r'); code=4
    elif mode=='directory':
        press(b's\r', b'[a] Request approval')
        assert b'Directory:' in data and os.getcwd().encode() in data
        assert b'List directory entries' in data and b'Inspect file types and metadata' in data
        assert b'no recursion, symlink traversal or file-content reads' in data
        os.write(master,b'q\r'); code=4
    elif mode=='change':
        with open(attachment,'w') as file: file.write('changed')
        os.write(master,b'a\r'); wait_for(b'Materials changed'); code=2
    elif mode=='expire':
        time.sleep(2.05)
        os.write(master,b'a\r'); wait_for(b'Candidate expired'); code=2
    elif mode=='controls':
        assert b'\\u{1b}' in all_data and b'\\u{202e}' in all_data
        os.write(master,b'a\r'); wait_for(b'Approval request generated'); code=0
        line=next(line for line in all_data.splitlines() if line.startswith(b'{') and b'request_approval' in line)
        assert '\u202e'.encode() not in line
        assert json.loads(line)['candidate']['draft']['intent']['goal']==task
    elif mode=='eof': os.write(master,b'\x04'); code=4
    elif mode=='interrupt': os.write(master,b'\x03'); code=130
    elif mode=='signal': os.kill(child.pid, signal.SIGINT); code=130
    else:
        press(b'\r', b'[a] Request approval')
        os.write(master,b'q\r'); code=4
    assert child.wait(timeout=5)==code, (child.returncode,all_data)
    while select.select([master],[],[],.05)[0]: all_data+=os.read(master,65536)
    if mode not in ['approve','controls']: assert b'"decision":"request_approval"' not in all_data
    assert termios.tcgetattr(slave)==before
finally:
    if child.poll() is None: child.kill(); child.wait()
    os.close(master); os.close(slave)
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_only_approves_exact_candidate_after_collection_recheck() {
    let directory = common::Directory::new();
    let socket = directory.0.join("daemon.sock");
    let attachment = directory.0.join("report.csv");
    fs::write(&attachment, "PRIVATE_FILE_BYTES").unwrap();
    let provider = Arc::new(Replay::default());
    let server = Server::start(&socket, provider.clone(), None).await;
    for mode in [
        "approve",
        "modify",
        "change",
        "eof",
        "interrupt",
        "signal",
        "empty",
        "expire",
        "controls",
        "directory",
    ] {
        let before = provider.calls.load(Ordering::Relaxed);
        let output = Command::new("python3")
            .args(["-c", PTY, env!("CARGO_BIN_EXE_agent-sec-cli")])
            .arg(&socket)
            .arg(&attachment)
            .arg(mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            provider.calls.load(Ordering::Relaxed) - before,
            if mode == "modify" { 2 } else { 1 }
        );
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_responses_never_render_a_candidate_or_leak_diagnostics() {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::net::UnixListener;
    let directory = common::Directory::new();
    let socket = directory.0.join("real.sock");
    let attachment = directory.0.join("report.csv");
    fs::write(&attachment, "PRIVATE_FILE_BYTES").unwrap();
    let server = Server::start(&socket, Arc::new(Replay::default()), None).await;
    let valid = output_json(
        &cli(&socket, &directory.0, "Read report.csv")
            .arg("--attach")
            .arg(&attachment)
            .args(["--format", "json"])
            .output()
            .unwrap(),
        0,
    );
    let directory_valid = output_json(
        &cli(&socket, &directory.0, "当前目录下有几个文件")
            .args(["--format", "json"])
            .output()
            .unwrap(),
        0,
    );
    server.stop().await;
    for case in [
        "empty_evidence",
        "forged_quote",
        "evidence_range",
        "directory_path",
        "directory_permissions",
        "status",
        "hash",
        "binding",
        "source",
        "objects",
        "reads",
        "digest",
        "truncated",
        "oversized",
        "error",
    ] {
        let directory_case = case.starts_with("directory_");
        let task = if directory_case {
            "当前目录下有几个文件"
        } else {
            "Read report.csv"
        };
        let mut result = if directory_case {
            directory_valid.clone()
        } else {
            valid.clone()
        };
        corrupt_candidate(&mut result["candidate"], case);
        let socket = directory.0.join(format!("{case}.sock"));
        let listener = UnixListener::bind(&socket).unwrap();
        let mut bytes =
            serde_json::to_vec(&json!({"requestId":"fixture", "result":result})).unwrap();
        if case == "error" {
            bytes = serde_json::to_vec(&json!({"requestId":"fixture", "error":{"code":"unavailable", "message":"PRIVATE_FILE_BYTES"}})).unwrap();
        }
        if case == "truncated" {
            bytes.truncate(bytes.len() / 2);
        }
        bytes.push(b'\n');
        let responder = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line).unwrap()["method"],
                "intent.propose"
            );
            stream.write_all(&bytes).unwrap();
        });
        let mut command = cli(&socket, &directory.0, task);
        if !directory_case {
            command.arg("--attach").arg(&attachment);
        }
        let output = command.args(["--format", "json"]).output().unwrap();
        responder.join().unwrap();
        assert_eq!(output.status.code(), Some(1), "{case}");
        assert!(output.stdout.is_empty(), "{case}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_FILE_BYTES"));
    }
}

fn corrupt_candidate(candidate: &mut Value, case: &str) {
    match case {
        "empty_evidence" => {
            let evidence = candidate["draft"]["field_evidence"]
                .as_object_mut()
                .unwrap();
            let goal = evidence.remove("/goal").unwrap();
            evidence.insert(String::new(), goal);
        }
        "forged_quote" => {
            candidate["draft"]["field_evidence"]["/goal"]["quote"] = json!("PRIVATE_FILE_BYTES");
        }
        "evidence_range" => candidate["draft"]["field_evidence"]["/goal"]["end_byte"] = json!(4096),
        "directory_path" => {
            use sha2::{Digest as _, Sha256};
            let id = format!(
                "directory-{:x}",
                Sha256::digest(
                    serde_json::to_vec(&json!([candidate["task_id"], "directory", "/daemon"]))
                        .unwrap()
                )
            );
            candidate["directories"][0]["path"] = json!("/daemon");
            candidate["directories"][0]["entity_id"] = json!(id);
        }
        "directory_permissions" => {
            candidate["directories"][0]["permissions"] = json!(["filesystem.list"]);
            candidate["required_permissions"] = json!(["filesystem.list"]);
        }
        "status" => candidate["status"] = json!("APPROVED"),
        "hash" => candidate["candidate_hash"] = json!("forged"),
        "binding" => candidate["binding_snapshot"]["source"] = json!("host_registry"),
        "source" => candidate["draft"]["source"]["sha256"] = json!("forged"),
        "objects" => {
            candidate["binding_snapshot"]["objects"][0]["content_sha256"] = json!("forged");
        }
        "reads" => candidate["reads"][0]["object"]["path"] = json!("uncollected.csv"),
        "digest" => candidate["binding_snapshot_digest"] = json!("forged"),
        "oversized" => candidate["policy_set"] = json!("x".repeat(512 * 1024)),
        _ => {}
    }
    if !matches!(case, "hash" | "truncated" | "oversized" | "error") {
        rehash(candidate);
    }
}

fn rehash(candidate: &mut Value) {
    use sha2::{Digest as _, Sha256};
    fn sort(value: &mut Value) {
        match value {
            Value::Object(map) => {
                map.sort_keys();
                map.values_mut().for_each(sort);
            }
            Value::Array(values) => values.iter_mut().for_each(sort),
            _ => {}
        }
    }
    candidate.as_object_mut().unwrap().remove("candidate_hash");
    sort(candidate);
    candidate["candidate_hash"] = json!(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(candidate).unwrap())
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupt_while_waiting_for_daemon_never_delivers_a_candidate() {
    let directory = common::Directory::new();
    let socket = directory.0.join("daemon.sock");
    let attachment = directory.0.join("report.csv");
    fs::write(&attachment, "bytes").unwrap();
    let (started, entered) = std::sync::mpsc::channel();
    let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let server = Server::start(
        &socket,
        Arc::new(Blocking {
            started,
            release: release.clone(),
        }),
        None,
    )
    .await;
    let child = cli(&socket, &directory.0, "Read report.csv")
        .arg("--attach")
        .arg(&attachment)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        Command::new("/bin/kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    *release.0.lock().unwrap() = true;
    release.1.notify_all();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(130));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Approval request generated"));
    server.stop().await;
}

struct Blocking {
    started: std::sync::mpsc::Sender<()>,
    release: Arc<(Mutex<bool>, std::sync::Condvar)>,
}
impl ModelProvider for Blocking {
    fn complete(&self, _: &str, _: &str, _: &str, _: Instant) -> Result<String, ProviderError> {
        self.started.send(()).unwrap();
        let (lock, wake) = &*self.release;
        let (release, _) = wake
            .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(10), |value| {
                !*value
            })
            .unwrap();
        assert!(*release);
        Err(ProviderError::Transport)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uds_timeout_does_not_release_actual_execution_capacity() {
    let directory = common::Directory::new();
    let socket = directory.0.join("daemon.sock");
    let attachment = directory.0.join("report.csv");
    fs::write(&attachment, "bytes").unwrap();
    let (started, entered) = std::sync::mpsc::channel();
    let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let server = Server::start(
        &socket,
        Arc::new(Blocking {
            started,
            release: Arc::clone(&release),
        }),
        Some(Duration::from_millis(200)),
    )
    .await;
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&attachment, fs::Permissions::from_mode(0o644)).unwrap();
    common::executable(&directory.0);
    let uid = rustix::process::geteuid().as_raw();
    let owners = if uid == 0 {
        vec![0, 65531, 65532, 65533]
    } else {
        vec![uid]
    };
    for owner in &owners {
        let first = cli(&socket, &directory.0, "Read report.csv")
            .uid(*owner)
            .gid(*owner)
            .arg("--attach")
            .arg(&attachment)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        let output = first.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("deadline_exceeded"));
    }
    let rejected = if uid == 0 { vec![0, 65534] } else { vec![uid] };
    for owner in rejected {
        let output = cli(&socket, &directory.0, "Read report.csv")
            .uid(owner)
            .gid(owner)
            .arg("--attach")
            .arg(&attachment)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("resource_exhausted"));
    }
    *release.0.lock().unwrap() = true;
    release.1.notify_all();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let output = cli(&socket, &directory.0, "Read report.csv")
            .arg("--attach")
            .arg(&attachment)
            .output()
            .unwrap();
        if String::from_utf8_lossy(&output.stderr).contains("unavailable") {
            break;
        }
        assert!(Instant::now() < deadline);
    }
    server.stop().await;
}
