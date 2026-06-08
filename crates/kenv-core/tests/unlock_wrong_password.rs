use kenv_core::{create_vault_at, crypto::KdfParams, unlock, vault, KenvError};
use serial_test::serial;
use tempfile::TempDir;

fn setup(password: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");
    create_vault_at(&path, password, &KdfParams::for_tests()).expect("test vault setup failed");
    vault::set_test_vault_path(path);
    dir
}

fn teardown() {
    kenv_core::lock().ok();
    vault::clear_test_vault_path();
}

#[test]
#[serial]
fn unlock_with_wrong_password_fails() {
    let _dir = setup("correct-password");
    let err = unlock("wrong-password").unwrap_err();
    assert!(matches!(err, KenvError::UnlockFailed));
    teardown();
}

#[test]
#[serial]
fn unlock_with_empty_password_fails() {
    let _dir = setup("my-password");
    let err = unlock("").unwrap_err();
    assert!(matches!(err, KenvError::UnlockFailed));
    teardown();
}

#[test]
#[serial]
fn unlock_with_slightly_different_password_fails() {
    let _dir = setup("password123");
    let err = unlock("password124").unwrap_err();
    assert!(matches!(err, KenvError::UnlockFailed));
    teardown();
}
