//! Bounded real-authority and RFC003 composition checks. A violation or a
//! missed reachability target panics with an explanation/counterexample.
//! Stateright counts the initial state at depth 1 and does not evaluate the
//! cutoff frontier: cutoff N checks paths of at most N-2 actions.

use std::process::ExitCode;

fn parse_depths() -> Result<(usize, usize), String> {
    let mut depth = 10usize;
    let mut replication_depth = 11usize;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--depth" | "--replication-depth" => {
                let v = args.next().ok_or_else(|| format!("{a} requires a value"))?;
                let value = v.parse().map_err(|_| format!("invalid depth {v:?}"))?;
                if a == "--depth" {
                    depth = value;
                } else {
                    replication_depth = value;
                }
            }
            s if s.starts_with("--depth=") => {
                let v = &s["--depth=".len()..];
                depth = v.parse().map_err(|_| format!("invalid depth {v:?}"))?;
            }
            s if s.starts_with("--replication-depth=") => {
                let v = &s["--replication-depth=".len()..];
                replication_depth = v.parse().map_err(|_| format!("invalid depth {v:?}"))?;
            }
            "-h" | "--help" => return Err("usage: oic-model-authorization-state [--depth N] [--replication-depth N]".into()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok((depth, replication_depth))
}

fn main() -> ExitCode {
    let (depth, replication_depth) = match parse_depths() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let r = oic_model_authorization_state::check(depth);
    println!(
        "D1 P1-P5 bounded check passed: frontier_depth={} action_bound={} states={} unique_states={}",
        r.max_depth,
        depth.saturating_sub(2),
        r.state_count,
        r.unique_state_count
    );
    let r = oic_model_authorization_state::replication::check_replication(replication_depth);
    println!(
        "RFC003 composition bounded check passed: frontier_depth={} action_bound={} states={} unique_states={}",
        r.search.max_depth,
        replication_depth.saturating_sub(2),
        r.search.state_count,
        r.search.unique_state_count
    );
    for (name, actions) in r.witnesses {
        println!("{name}: {actions:?}");
    }
    println!("Assumes one authenticated finalized order, authenticated roster/operator inputs and atomic durable recovery; does not verify Simplex or a production D2 runtime.");
    ExitCode::SUCCESS
}
