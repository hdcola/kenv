use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn status_prints_script_friendly_vault_state() {
    Command::cargo_bin("kenv")
        .unwrap()
        .arg("status")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("vault_status=missing")
                .or(predicate::str::contains("vault_status=locked")),
        );
}
