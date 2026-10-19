//! The binary embeds `rulesets/` (including each `tests.toml`); rebuild when
//! any of it changes.
fn main() {
    println!("cargo:rerun-if-changed=../../rulesets");
}
