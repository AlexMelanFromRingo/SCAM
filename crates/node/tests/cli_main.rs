use std::process::{Command, Output};

fn run_scam_node(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_scam-node"))
        .args(args)
        .output()
        .expect("run scam-node")
}

#[test]
fn binary_main_returns_nonzero_for_invalid_flag() {
    let output = run_scam_node(&["--definitely-invalid-flag"]);
    assert_eq!(output.status.code(), Some(2), "usage errors exit with 2");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument"),
        "unexpected stderr: {stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn binary_main_prints_version() {
    for flag in ["--version", "-V"] {
        let output = run_scam_node(&[flag]);
        assert!(output.status.success(), "{flag} must exit 0");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("scam-node {}\n", env!("CARGO_PKG_VERSION"))
        );
        assert!(output.stderr.is_empty());
    }
}

/// Help is output, not an error: stdout, exit 0, no `error:` prefix — for
/// the binary, a subcommand and the options nested in `serve --rpc`.
#[test]
fn binary_main_prints_help_to_stdout() {
    for (args, usage) in [
        (&["--help"][..], "Usage: scam-node"),
        (&["help"][..], "Usage: scam-node"),
        (&["serve", "--help"][..], "Usage: scam-node serve"),
        (&["serve", "--rpc", "--help"][..], "Usage: serve --rpc"),
    ] {
        let output = run_scam_node(args);
        assert!(output.status.success(), "{args:?} must exit 0");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(usage), "{args:?}: {stdout}");
        assert!(!stdout.contains("error:"), "{args:?}: {stdout}");
        assert!(output.stderr.is_empty(), "{args:?}");
    }
}

#[test]
fn binary_main_reports_runtime_errors_with_status_1() {
    let missing = std::env::temp_dir()
        .join("scam-cli-main-missing")
        .join("missing.toml");
    let output = run_scam_node(&[
        "status",
        "--network",
        "devnet",
        "--config",
        missing.to_str().expect("utf-8 temp path"),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("error: cannot read config"),
        "unexpected stderr: {stderr}"
    );
}
