use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=OIC_APPROVER_PROVISION");
    println!("cargo:rerun-if-env-changed=OIC_APPROVER_PROVISION_SHA256");
    let provision = match env::var("OIC_APPROVER_PROVISION") {
        Ok(path) => {
            println!("cargo:rerun-if-changed={path}");
            let bytes = fs::read(path).expect("read independently provisioned trust bundle");
            let expected = env::var("OIC_APPROVER_PROVISION_SHA256")
                .expect("independent trust bundle digest required");
            assert_eq!(
                hex::encode(Sha256::digest(&bytes)),
                expected,
                "provisioned trust digest differs"
            );
            String::from_utf8(bytes).expect("trust bundle is UTF-8 JSON")
        }
        Err(_) => String::new(), // Unprovisioned builds compile but cannot open a browser client.
    };
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("provision.rs"),
        format!("const PROVISION: &str = {provision:?};\n"),
    )
    .unwrap();
}
