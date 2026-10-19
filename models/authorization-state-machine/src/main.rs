//! `oic-model-authorization-state [--depth N]`: bounded breadth-first model
//! check of the real authorization-state authority. Exits non-zero (panics
//! with a counterexample path) if any property is violated.

use std::process::ExitCode;

fn parse_depth() -> Result<usize, String> {
    let mut depth = 10usize;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--depth" => {
                let v = args.next().ok_or("--depth requires a value")?;
                depth = v.parse().map_err(|_| format!("invalid depth {v:?}"))?;
            }
            s if s.starts_with("--depth=") => {
                let v = &s["--depth=".len()..];
                depth = v.parse().map_err(|_| format!("invalid depth {v:?}"))?;
            }
            "-h" | "--help" => return Err("usage: oic-model-authorization-state [--depth N]".into()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(depth)
}

fn main() -> ExitCode {
    let depth = match parse_depth() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let r = oic_model_authorization_state::check(depth);
    println!(
        "all properties hold: depth={} states={} unique_states={}",
        r.max_depth, r.state_count, r.unique_state_count
    );
    ExitCode::SUCCESS
}
