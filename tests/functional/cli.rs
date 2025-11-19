use std::{
    fs,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use assert_cmd::assert::OutputAssertExt;
use predicates::prelude::*;
use tempfile::tempdir;

const VALID_CONFIG: &str = r#"
version: 1

server:
  bind_address: "127.0.0.1:18080"
  max_connections: 64
upstreams:
  request_timeout_ms: 1000
  default:
    target_url: "https://llm.example.com/v1"
    api_key: "secret"
    request_path: "/test"
"#;

fn spawn_proxy(temp_dir: &tempfile::TempDir, envs: &[(&str, &str)]) -> Child {
    let binary = assert_cmd::cargo::cargo_bin!("fluxgate");
    let mut cmd = Command::new(binary);
    cmd.current_dir(temp_dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("FLUXGATE_LOG")
        .env_remove("FLUXGATE_LOG_STYLE");

    for (key, value) in envs {
        cmd.env(key, value);
    }

    cmd.spawn().expect("spawn fluxgate proxy")
}

fn capture_proxy_output(mut child: Child) -> (String, String, bool, std::process::ExitStatus) {
    thread::sleep(Duration::from_millis(500));
    let mut was_running = false;

    let output = match child.try_wait().expect("check process status") {
        Some(_) => child.wait_with_output().expect("retrieve proxy output"),
        None => {
            was_running = true;
            child.kill().expect("terminate proxy process");
            child.wait_with_output().expect("retrieve proxy output")
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_status = output.status;

    (stdout, stderr, was_running, exit_status)
}

#[test]
fn run_without_arguments_uses_default_config() {
    // Preconditions: valid configuration file present at default path.
    // Action: execute the binary without arguments.
    // Expected behaviour: proxy loads the default configuration and runs until terminated.
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    fs::write(&config_path, VALID_CONFIG).expect("write config");

    let binary = assert_cmd::cargo::cargo_bin!("fluxgate");
    let child = Command::new(binary)
        .current_dir(temp_dir.path())
        .env("FLUXGATE_LOG", "info")
        .env("FLUXGATE_LOG_STYLE", "never")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fluxgate proxy");

    let (stdout, _stderr, _was_running, _exit_status) = capture_proxy_output(child);

    // Check that proxy started with correct configuration
    assert!(
        stdout.contains("Starting fluxgate proxy with configuration path"),
        "expected startup log with configuration path, got: {stdout}"
    );
    assert!(
        stdout.contains("path=fluxgate.yaml"),
        "expected default configuration path in logs, got: {stdout}"
    );
    assert!(
        stdout.contains("Fluxgate proxy initialized"),
        "expected initialization log, got: {stdout}"
    );
    assert!(
        stdout.contains("Starting proxy server on"),
        "expected server startup log, got: {stdout}"
    );
}

#[test]
fn run_with_explicit_config_path() {
    // Preconditions: custom configuration file exists outside the default name.
    // Action: execute the binary with the --config flag pointing at the custom file.
    // Expected behaviour: proxy loads the provided configuration path and reports it in logs.
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("custom-config.yaml");
    fs::write(&config_path, VALID_CONFIG).expect("write custom config");

    let binary = assert_cmd::cargo::cargo_bin!("fluxgate");
    let child = Command::new(binary)
        .current_dir(temp_dir.path())
        .arg("--config")
        .arg(&config_path)
        .env("FLUXGATE_LOG", "info")
        .env("FLUXGATE_LOG_STYLE", "never")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fluxgate proxy");

    let (stdout, _stderr, _was_running, _exit_status) = capture_proxy_output(child);
    let expected_path_fragment = format!("path={}", config_path.display());

    assert!(
        stdout.contains("Starting fluxgate proxy with configuration path"),
        "expected startup log with configuration path, got: {stdout}"
    );
    assert!(
        stdout.contains(&expected_path_fragment),
        "expected custom configuration path in logs, got: {stdout}"
    );
    assert!(
        stdout.contains("Fluxgate proxy initialized"),
        "expected initialization log, got: {stdout}"
    );
}

#[test]
fn ignores_environment_configuration_override() {
    // Preconditions: default configuration file is present; alternate configuration path is provided via environment.
    // Action: execute the binary without arguments while setting an environment variable hinting at an alternate config file.
    // Expected behaviour: proxy ignores the environment variable and uses the documented default path.
    let temp_dir = tempdir().expect("create temp dir");
    let default_config_path = temp_dir.path().join("fluxgate.yaml");
    fs::write(&default_config_path, VALID_CONFIG).expect("write default config");

    let env_config_path = temp_dir.path().join("env-controlled.yaml");
    fs::write(&env_config_path, "not: valid: yaml").expect("write env config");

    let binary = assert_cmd::cargo::cargo_bin!("fluxgate");
    let child = Command::new(binary)
        .current_dir(temp_dir.path())
        .env(
            "FLUXGATE_CONFIG",
            env_config_path.to_string_lossy().to_string(),
        )
        .env("FLUXGATE_LOG", "info")
        .env("FLUXGATE_LOG_STYLE", "never")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fluxgate proxy");

    let (stdout, _stderr, _was_running, _exit_status) = capture_proxy_output(child);
    assert!(
        stdout.contains("Starting fluxgate proxy with configuration path"),
        "expected startup log with configuration path, got: {stdout}"
    );
    assert!(
        stdout.contains("path=fluxgate.yaml"),
        "expected logged configuration path to remain the documented default, got: {stdout}"
    );
    assert!(
        !stdout.contains("env-controlled.yaml"),
        "environment-provided configuration path should be ignored, got: {stdout}"
    );
    assert!(
        stdout.contains("Fluxgate proxy initialized"),
        "expected initialization log, got: {stdout}"
    );
}

#[test]
fn help_output_lists_subcommands_and_flags() {
    // Preconditions: binary is available for execution.
    // Action: invoke the CLI with --help.
    // Expected behaviour: help text describes usage and available options.
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("fluxgate"));
    cmd.arg("--help")
        .env("NO_COLOR", "1") // More reliable way to disable colors
        .env("CLICOLOR_FORCE", "0")
        .env("CLICOLOR", "0");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Fluxgate proxy service"))
        .stdout(predicate::str::contains("Usage:"))
        .stdout(predicate::str::contains("fluxgate"))
        .stdout(predicate::str::contains("[OPTIONS]"))
        .stdout(predicate::str::contains("Options:"))
        .stdout(predicate::str::contains("--config"))
        .stdout(predicate::str::contains("fluxgate.yaml"))
        .stdout(predicate::str::contains("--help"))
        .stdout(predicate::str::contains("Print help"));
}

#[test]
fn help_flag_succeeds_without_configuration() {
    // Preconditions: binary is available for execution.
    // Action: invoke the CLI with --help from a temporary directory.
    // Expected behaviour: command exits successfully and prints usage information.
    let temp_dir = tempdir().expect("create temp dir");
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("fluxgate"));
    cmd.current_dir(temp_dir.path())
        .arg("--help")
        .env("NO_COLOR", "1")
        .env("CLICOLOR_FORCE", "0")
        .env("CLICOLOR", "0");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage:"))
        .stdout(predicate::str::contains("fluxgate"));
}

#[test]
fn unknown_option_is_rejected() {
    // Preconditions: binary is available for execution.
    // Action: invoke the CLI with an unknown option.
    // Expected behaviour: process exits with error and prints informative message.
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("fluxgate"));
    cmd.arg("--unknown")
        .env("NO_COLOR", "1") // More reliable way to disable colors
        .env("CLICOLOR_FORCE", "0")
        .env("CLICOLOR", "0");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument"))
        .stderr(predicate::str::contains("--unknown"))
        .stderr(predicate::str::contains("Usage:"))
        .stderr(predicate::str::contains("fluxgate"))
        .stderr(predicate::str::contains("[OPTIONS]"))
        .stderr(predicate::str::contains("--help"));
}

#[test]
fn logging_defaults_to_info_without_environment_overrides() {
    // Preconditions: no logging environment overrides are set; valid configuration file exists.
    // Action: start the proxy without `FLUXGATE_LOG` or `FLUXGATE_LOG_STYLE`.
    // Expected behaviour: proxy logs at the default info level and renders startup messages.
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    fs::write(&config_path, VALID_CONFIG).expect("write config");

    let child = spawn_proxy(&temp_dir, &[]);
    let (stdout, _stderr, _was_running, _exit_status) = capture_proxy_output(child);

    assert!(
        stdout.contains("Fluxgate proxy initialized"),
        "expected initialization log at default info level, got: {stdout}"
    );
    assert!(
        stdout.contains("path=fluxgate.yaml"),
        "expected default configuration path to be logged, got: {stdout}"
    );
}

#[test]
fn logging_respects_fluxgate_log_directive() {
    // Preconditions: valid configuration file exists.
    // Action: start the proxy with `FLUXGATE_LOG=warn`.
    // Expected behaviour: info-level startup messages are suppressed.
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    fs::write(&config_path, VALID_CONFIG).expect("write config");

    let child = spawn_proxy(&temp_dir, &[("FLUXGATE_LOG", "warn")]);
    let (stdout, stderr, _was_running, _exit_status) = capture_proxy_output(child);
    assert!(
        !stdout.contains("Fluxgate proxy initialized"),
        "info-level log should be suppressed when FLUXGATE_LOG=warn, got: {stdout}"
    );
    assert!(
        !stderr.contains("invalid filter"),
        "expected logging filter to be applied successfully, got stderr: {stderr}"
    );
}

#[test]
fn logging_respects_fluxgate_log_style_setting() {
    // Preconditions: valid configuration file exists.
    // Action: start the proxy with `FLUXGATE_LOG_STYLE=never`.
    // Expected behaviour: logs omit ANSI escape sequences.
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    fs::write(&config_path, VALID_CONFIG).expect("write config");

    let child = spawn_proxy(
        &temp_dir,
        &[("FLUXGATE_LOG", "info"), ("FLUXGATE_LOG_STYLE", "never")],
    );
    let (stdout, _stderr, _was_running, _exit_status) = capture_proxy_output(child);

    assert!(
        stdout.contains("Fluxgate proxy initialized"),
        "expected initialization log for validation, got: {stdout}"
    );
    assert!(
        !stdout.contains('\u{1b}'),
        "expected logs without ANSI escapes when FLUXGATE_LOG_STYLE=never, got: {stdout}"
    );
}

#[test]
fn run_with_invalid_config_path() {
    // Preconditions: Config file path points to a file with invalid content.
    // Action: Run proxy with --config pointing to invalid config file.
    // Expected behaviour: Falls back to default configuration and logs warning.

    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("invalid.yaml");
    fs::write(&config_path, "invalid: yaml: content: [unbalanced").expect("write invalid config");

    let binary = assert_cmd::cargo::cargo_bin!("fluxgate");
    let child = Command::new(binary)
        .current_dir(temp_dir.path())
        .arg("--config")
        .arg(&config_path)
        .env("FLUXGATE_LOG", "info")
        .env("FLUXGATE_LOG_STYLE", "never")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fluxgate proxy");

    let (stdout, _stderr, _was_running, _exit_status) = capture_proxy_output(child);

    assert!(
        stdout.contains("Using default configuration"),
        "expected fallback to default configuration, got: {stdout}"
    );
    // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded from file
    assert!(
        !stdout.contains("Fluxgate proxy initialized"),
        "expected proxy to NOT log initialization message when config was not loaded, got: {stdout}"
    );
}

#[test]
fn run_with_non_existent_config_path() {
    // Preconditions: Config file path does not exist.
    // Action: Run proxy with --config pointing to non-existent file.
    // Expected behaviour: Falls back to default configuration and logs warning.

    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("does-not-exist.yaml");

    let binary = assert_cmd::cargo::cargo_bin!("fluxgate");
    let child = Command::new(binary)
        .current_dir(temp_dir.path())
        .arg("--config")
        .arg(&config_path)
        .env("FLUXGATE_LOG", "info")
        .env("FLUXGATE_LOG_STYLE", "never")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fluxgate proxy");

    let (stdout, _stderr, _was_running, _exit_status) = capture_proxy_output(child);

    assert!(
        stdout.contains("Using default configuration"),
        "expected fallback to default configuration, got: {stdout}"
    );
    // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded from file
    assert!(
        !stdout.contains("Fluxgate proxy initialized"),
        "expected proxy to NOT log initialization message when config was not loaded, got: {stdout}"
    );
}

#[test]
fn run_with_directory_as_config_path() {
    // Preconditions: Config file path points to a directory.
    // Action: Run proxy with --config pointing to a directory.
    // Expected behaviour: Falls back to default configuration and logs warning.

    let temp_dir = tempdir().expect("create temp dir");

    let binary = assert_cmd::cargo::cargo_bin!("fluxgate");
    let child = Command::new(binary)
        .current_dir(temp_dir.path())
        .arg("--config")
        .arg(temp_dir.path())
        .env("FLUXGATE_LOG", "info")
        .env("FLUXGATE_LOG_STYLE", "never")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fluxgate proxy");

    let (stdout, _stderr, _was_running, _exit_status) = capture_proxy_output(child);

    assert!(
        stdout.contains("Using default configuration"),
        "expected fallback to default configuration, got: {stdout}"
    );
    // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded from file
    assert!(
        !stdout.contains("Fluxgate proxy initialized"),
        "expected proxy to NOT log initialization message when config was not loaded, got: {stdout}"
    );
}

#[test]
fn run_with_relative_config_path() {
    // Preconditions: Config file exists at relative path.
    // Action: Run proxy with --config pointing to relative path.
    // Expected behaviour: Resolves relative path correctly.

    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("relative-config.yaml");
    fs::write(&config_path, VALID_CONFIG).expect("write config");

    let binary = assert_cmd::cargo::cargo_bin!("fluxgate");
    let child = Command::new(binary)
        .current_dir(temp_dir.path())
        .arg("--config")
        .arg("relative-config.yaml")
        .env("FLUXGATE_LOG", "info")
        .env("FLUXGATE_LOG_STYLE", "never")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fluxgate proxy");

    let (stdout, _stderr, _was_running, _exit_status) = capture_proxy_output(child);

    assert!(
        stdout.contains("Fluxgate proxy initialized"),
        "expected proxy to start with relative config path, got: {stdout}"
    );
}

#[test]
fn run_with_config_flag_without_path() {
    // Preconditions: --config flag provided without path argument.
    // Action: Run proxy with --config flag but no path.
    // Expected behaviour: Displays usage error and exits.

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("fluxgate"));
    cmd.arg("--config")
        .env("NO_COLOR", "1")
        .env("CLICOLOR_FORCE", "0")
        .env("CLICOLOR", "0");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("a value is required for"))
        .stderr(predicate::str::contains("--config"));
}
