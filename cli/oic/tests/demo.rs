//! End-to-end test: run the real `oic` binary's `demo` subcommand and assert the
//! full custody flow ran — both chains settled, the theft was blocked, and a
//! non-empty signed audit journal was produced.

use std::process::Command;

#[test]
fn oic_demo_runs_full_flow_and_blocks_theft() {
    let output = Command::new(env!("CARGO_BIN_EXE_oic"))
        .arg("demo")
        .output()
        .expect("spawn oic demo");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "oic demo exited non-zero: {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );

    // Both chains settled.
    assert!(
        stdout.contains("[1/2] EVM transfer"),
        "missing EVM settlement section:\n{stdout}"
    );
    assert!(
        stdout.contains("EVM SETTLED"),
        "EVM did not settle:\n{stdout}"
    );
    assert!(
        stdout.contains("[2/2] Solana transfer"),
        "missing Solana settlement section:\n{stdout}"
    );
    assert!(
        stdout.contains("Solana SETTLED"),
        "Solana did not settle:\n{stdout}"
    );

    // The headline whoa.
    assert!(
        stdout.contains("THEFT BLOCKED"),
        "theft was not blocked:\n{stdout}"
    );

    // A non-empty signed audit journal line.
    let journal_line = stdout
        .lines()
        .find(|l| l.contains("journal entries:"))
        .expect("missing audit journal line");
    let count: u64 = journal_line
        .split("journal entries:")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert!(
        count >= 1,
        "audit journal is empty: {journal_line:?}\n{stdout}"
    );
}

/// `oic demo --check` is what the custody-check GitHub Action runs: one PASS
/// line per assertion, a final RESULT line, and exit code 0.
#[test]
fn oic_demo_check_reports_each_assertion_and_passes() {
    let output = Command::new(env!("CARGO_BIN_EXE_oic"))
        .args(["demo", "--check"])
        .output()
        .expect("spawn oic demo --check");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(0),
        "oic demo --check did not pass\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    for assertion in [
        "PASS  dev-only guard",
        "PASS  EVM transfer settled",
        "PASS  Solana transfer settled",
        "PASS  theft blocked",
        "PASS  audit export verified",
    ] {
        assert!(
            stdout.lines().any(|l| l.starts_with(assertion)),
            "missing {assertion:?}:\n{stdout}"
        );
    }
    assert_eq!(
        stdout.lines().last(),
        Some("RESULT: PASS"),
        "missing final RESULT line:\n{stdout}"
    );
}
