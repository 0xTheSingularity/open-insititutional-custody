//! Development fixture bridge, not a node API or production consensus service.
mod common;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::*;
use oic_replicated_authority::Command;
use std::{env, fs, path::Path};

fn write(path: impl AsRef<Path>, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}
fn main() {
    let args: Vec<_> = env::args().collect();
    let chain = if args.get(2).is_some_and(|s| s == "solana") {
        d2::Chain::Solana
    } else {
        d2::Chain::Evm
    };
    let mut scenario = Scenario::new(chain);
    match args.get(1).map(String::as_str) {
        Some("generate") => {
            let dir = Path::new(&args[3]);
            fs::create_dir_all(dir).unwrap();
            write(dir.join("provision.json"), &scenario.provision);
            write(dir.join("initial.json"), &scenario.initial);
            write(dir.join("package.json"), &scenario.fixture.built.package);
            let point = key().verifying_key().to_encoded_point(false);
            write(
                dir.join("virtual-credential.json"),
                &serde_json::json!({
                    "rawId":hex::encode(RAW_ID), "identity":credential_id(), "now":d2::NOW,
                    "jwk":{"kty":"EC","crv":"P-256","d":URL_SAFE_NO_PAD.encode([42;32]),"x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())}
                }),
            );
        }
        Some("order") => {
            let command: Command = serde_json::from_slice(&fs::read(&args[3]).unwrap()).unwrap();
            let Command::Authority(inner) = &command else {
                panic!("fixture only accepts Approve");
            };
            assert!(matches!(
                inner.as_ref(),
                oic_authorization_state::AuthorityCommand::Approve { .. }
            ));
            let approval = scenario.order(&[command]).unwrap();
            let middle = scenario.order(&[]).unwrap();
            let mut checkpoint = scenario.order(&[]).unwrap();
            // Match marshal: ancestor approvals need not have their own cert.
            checkpoint.ancestors = vec![approval.block, middle.block];
            write(&args[4], &checkpoint);
        }
        _ => panic!("generate|order evm|solana directory-or-command [output]"),
    }
}
