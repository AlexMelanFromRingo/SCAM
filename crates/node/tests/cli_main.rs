use std::process::Command;

#[test]
fn binary_main_returns_nonzero_for_invalid_flag() {
    let bin = env!("CARGO_BIN_EXE_scam-node");
    let output = Command::new(bin)
        .arg("--definitely-invalid-flag")
        .output()
        .expect("run scam-node");
    assert!(
        !output.status.success(),
        "invalid cli flag must produce non-zero exit"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("error:"),
        "unexpected stderr: {stderr}"
    );
}
