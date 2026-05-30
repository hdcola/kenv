use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn status_prints_script_friendly_vault_state() {
    let home = TempDir::new().unwrap();
    Command::cargo_bin("kenv")
        .unwrap()
        .env("HOME", home.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("vault_status=missing"));
}
