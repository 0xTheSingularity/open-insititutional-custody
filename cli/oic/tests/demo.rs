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
