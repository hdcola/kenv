use kenv_core::{list_ssh_keys, sign_ssh_key, KenvError};
use serial_test::serial;

#[test]
fn list_ssh_keys_requires_unlocked_vault() {
    let error = list_ssh_keys().unwrap_err();
    assert_eq!(error.to_string(), "vault is locked");
}

#[test]
fn sign_ssh_key_requires_unlocked_vault() {
    let error = sign_ssh_key("key-id", b"data").unwrap_err();
    assert_eq!(error.to_string(), "vault is locked");
}

/// Verify that once the vault is unlocked and a key is present, sign() returns
/// SshSigningNotImplemented — not a fake success or a stale VaultLocked error.
/// This locks the "honest unimplemented" path that lib.rs::sign_ssh_key delegates to
/// ssh::sign_ssh_key, preventing silent regression to a fake-success mock.
#[test]
#[serial]
fn sign_ssh_key_not_implemented_when_unlocked() {
    use kenv_core::{
        crypto::KdfParams,
        lock,
        ssh::{SshKey, SshKeyType},
        vault,
    };
    use std::time::SystemTime;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("vault.kenv");
    let params = KdfParams::for_tests();

    kenv_core::create_vault_at(&path, "pw", &params).unwrap();
    vault::set_test_vault_path(path);
    kenv_core::unlock("pw").unwrap();

    kenv_core::test_insert_ssh_key(SshKey {
        key_id: "test-ed25519".to_string(),
        name: "test".to_string(),
        public_key: vec![0u8; 32],
        private_key: vec![0u8; 64],
        key_type: SshKeyType::Ed25519,
        created_at: SystemTime::now(),
        last_used: None,
        disabled: false,
        require_reauthentication: false,
    });

    let error = sign_ssh_key("test-ed25519", b"data").unwrap_err();
    assert!(matches!(error, KenvError::SshSigningNotImplemented));

    lock().ok();
    vault::clear_test_vault_path();
}
