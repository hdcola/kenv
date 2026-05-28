use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn status_prints_script_friendly_vault_state() {
    let mut command = Command::cargo_bin("kenv").unwrap();

    command
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("vault_status=missing\n"));
}
