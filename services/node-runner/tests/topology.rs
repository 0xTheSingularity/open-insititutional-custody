//! The provisioned reference topology runs as real OS processes: three
//! signer nodes (each with a separate share-holding core child), one
//! authority and one gateway, over the production transport profile, from
//! nothing but the files `provision` wrote.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn oic_node() -> Command {
    Command::new(env!("CARGO_BIN_EXE_oic-node"))
}

struct Node {
    child: Child,
    name: &'static str,
}

impl Drop for Node {
    fn drop(&mut self) {
        unsafe { libc_kill(self.child.id() as i32) };
        let _ = self.child.wait();
    }
}

/// `kill(pid, SIGTERM)` without a libc dependency in the test.
unsafe fn libc_kill(pid: i32) {
    let _ = Command::new("kill").args(["-TERM", &pid.to_string()]).status();
}

fn spawn(dir: &Path, name: &'static str) -> Node {
    let child = oic_node()
        .args(["run", "--dir"])
        .arg(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn oic-node");
    Node { child, name }
}

#[test]
fn provisioned_topology_converges_across_real_processes() {
    let out = tempfile::tempdir().unwrap();
    let base = out.path().join("topology");

    // Five distinct ports on 127.0.0.1: one host address, as provision and
    // the production profile's registered-address check both expect here.
    let listeners: Vec<_> = (0..5).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
    let addresses: Vec<String> = listeners.iter().map(|l| l.local_addr().unwrap().to_string()).collect();
    drop(listeners);
    let status = oic_node()
        .args(["provision", "--out"])
        .arg(&base)
        .arg("--address")
        .args(&addresses)
        .status()
        .expect("run provision");
    assert!(status.success(), "provision failed");
    for index in 0..5 {
        assert!(base.join(format!("node-{index}/node.json")).exists());
    }

    // Start everything except the gateway, then let the gateway's --check
    // prove convergence. The production profile shares one IP here, so the
    // per-IP handshake quota and cooldown dominate startup time.
    let started = Instant::now();
    let _signers: Vec<Node> = (0..3).map(|i| spawn(&base.join(format!("node-{i}")), "signer")).collect();
    let authority = spawn(&base.join("node-4"), "authority");
    let check = oic_node()
        .args(["run", "--check", "--check-budget", "600", "--dir"])
        .arg(base.join("node-3"))
        .status()
        .expect("run the gateway check");
    assert!(check.success(), "the topology did not converge");
    println!("topology converged across real processes in {}ms", started.elapsed().as_millis());

    // Clean shutdown: SIGTERM each long-running node; every exit is clean,
    // including the signer cores their parents stop on the way out.
    let mut nodes = _signers;
    nodes.push(authority);
    for node in &mut nodes {
        unsafe { libc_kill(node.child.id() as i32) };
    }
    for node in &mut nodes {
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = node.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "{} missed the shutdown deadline", node.name);
            std::thread::sleep(Duration::from_millis(100));
        };
        assert!(status.success(), "{} exited uncleanly: {status}", node.name);
    }
}
