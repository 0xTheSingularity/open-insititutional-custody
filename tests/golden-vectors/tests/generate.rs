//! Vector generator. Writes `vectors/*.json` only when
//! `OIC_REGENERATE_VECTORS=1`; otherwise it does nothing (the conformance
//! tests compare the committed files against a fresh build instead).
//!
//! ```text
//! OIC_REGENERATE_VECTORS=1 cargo test -p oic-golden-vectors --test generate
//! ```

mod common;

use oic_golden_vectors::{to_file_json, vectors_dir};
use std::fs;

#[test]
fn regenerate_vectors() {
    if std::env::var("OIC_REGENERATE_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let dir = vectors_dir();
    fs::create_dir_all(&dir).unwrap();
    for (file, vectors) in common::build_domain_vectors() {
        fs::write(dir.join(&file), to_file_json(&vectors).unwrap()).unwrap();
    }
    for (file, vectors) in common::build_native_vectors() {
        fs::write(dir.join(&file), to_file_json(&vectors).unwrap()).unwrap();
    }
}
