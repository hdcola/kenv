use kenv_core::crypto::KdfParams;
use kenv_core::vault::{validate_vault_header, MIN_FILE_SIZE, V2_SLOTS_OFFSET};
use kenv_core::{create_vault_at, KenvError};
use tempfile::TempDir;

fn p() -> KdfParams {
    KdfParams::for_tests()
}

#[test]
fn creates_a_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");
    create_vault_at(&path, "password123", &p()).unwrap();
    assert!(path.exists());
}

#[test]
fn file_passes_header_validation() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");
    create_vault_at(&path, "my_password", &p()).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    validate_vault_header(&bytes).expect("header should be valid");
}

#[test]
fn file_is_at_least_minimum_size() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");
    create_vault_at(&path, "some_password", &p()).unwrap();
    assert!(std::fs::metadata(&path).unwrap().len() >= MIN_FILE_SIZE as u64);
}

#[test]
fn returns_error_if_vault_already_exists() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");
    create_vault_at(&path, "password", &p()).unwrap();
    let result = create_vault_at(&path, "password", &p());
    assert!(matches!(result, Err(KenvError::VaultAlreadyExists)));
}

#[test]
fn creates_parent_dirs_if_missing() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("nested").join("dirs").join("vault.kenv");
    create_vault_at(&path, "password", &p()).unwrap();
    assert!(path.exists());
}

#[test]
fn ciphertext_does_not_contain_plaintext_json_keys() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");
    create_vault_at(&path, "secret", &p()).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let ciphertext = &bytes[V2_SLOTS_OFFSET..];
    assert!(!ciphertext.windows(7).any(|w| w == b"version"));
}

#[test]
fn two_vaults_with_same_password_differ() {
    let dir1 = TempDir::new().unwrap();
    let dir2 = TempDir::new().unwrap();
    let p1 = dir1.path().join("vault.kenv");
    let p2 = dir2.path().join("vault.kenv");
    create_vault_at(&p1, "same_password", &p()).unwrap();
    create_vault_at(&p2, "same_password", &p()).unwrap();
    assert_ne!(std::fs::read(&p1).unwrap(), std::fs::read(&p2).unwrap());
}

#[test]
fn rejects_empty_password() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");
    let result = create_vault_at(&path, "", &p());
    assert!(matches!(result, Err(KenvError::WeakPassword)));
}

#[test]
fn rejects_whitespace_only_password() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");
    let result = create_vault_at(&path, "   ", &p());
    assert!(matches!(result, Err(KenvError::WeakPassword)));
}
