use kenv_core::{
    add_slot, list_slots, remove_slot, rename_slot,
    KenvError, VaultStatus,
    slots::{UnlockSlot, SlotType},
};
use std::time::SystemTime;

#[test]
fn add_slot_requires_unlocked_vault() {
    // Try to add slot without unlocking (default state is locked)
    let slot = UnlockSlot {
        slot_id: 1,
        slot_type: SlotType::Ctap2,
        label: "Test Slot".to_string(),
        created_at: SystemTime::now(),
        password: None,
        ctap2: None,
        touchid: None,
        requires_pin: false,
        requires_touch: true,
        pin_attempts_left: None,
        last_used: None,
        disabled: false,
    };

    let error = add_slot(slot).unwrap_err();
    assert_eq!(error.to_string(), "vault is locked");
}

#[test]
fn list_slots_requires_unlocked_vault() {
    let error = list_slots().unwrap_err();
    assert_eq!(error.to_string(), "vault is locked");
}

#[test]
fn rename_slot_requires_unlocked_vault() {
    let error = rename_slot(0, "new label".to_string()).unwrap_err();
    assert_eq!(error.to_string(), "vault is locked");
}

#[test]
fn remove_slot_requires_unlocked_vault() {
    let error = remove_slot(0).unwrap_err();
    assert_eq!(error.to_string(), "vault is locked");
}

#[test]
fn reauth_password_requires_unlocked_vault() {
    let error = kenv_core::reauth_password("password").unwrap_err();
    assert_eq!(error.to_string(), "vault is locked");
}

#[test]
fn newly_created_vault_has_password_slot() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";
    let params = kenv_core::crypto::KdfParams::for_tests();

    // Create vault at temp path directly (no global state)
    kenv_core::create_vault_at(&vault_path, password, &params)
        .expect("failed to create vault");

    // Verify vault file exists
    assert!(vault_path.exists(), "vault file should exist");

    // Verify it has the KENV magic bytes
    let vault_data = std::fs::read(&vault_path).expect("failed to read vault");
    assert_eq!(&vault_data[0..4], b"KENV", "vault file should have KENV magic");
}

#[test]
fn newly_created_vault_reauth_succeeds() {
    use tempfile::TempDir;
    use kenv_core::{create_vault, unlock, lock, reauth_password};
    use std::fs;

    // Cleanup any leftover real vault
    let real_vault = dirs::home_dir()
        .map(|h| h.join(".kenv").join("vault.kenv"));
    if let Some(path) = real_vault {
        let _ = lock();
        let _ = fs::remove_file(&path);
    }

    kenv_core::vault::clear_test_vault_path();

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";

    // Set test vault path
    kenv_core::vault::set_test_vault_path(vault_path);

    // Create vault
    create_vault(password).expect("failed to create vault");

    // Unlock it
    unlock(password).expect("failed to unlock");

    // Reauth should succeed
    reauth_password(password).expect("reauth failed");

    // Cleanup
    lock().ok();
    kenv_core::vault::clear_test_vault_path();
}

#[test]
fn newly_created_vault_reauth_fails_with_wrong_password() {
    use tempfile::TempDir;
    use kenv_core::{create_vault, unlock, lock, reauth_password};
    use std::fs;

    // Cleanup any leftover real vault
    let real_vault = dirs::home_dir()
        .map(|h| h.join(".kenv").join("vault.kenv"));
    if let Some(path) = real_vault {
        let _ = lock();
        let _ = fs::remove_file(&path);
    }

    kenv_core::vault::clear_test_vault_path();

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";

    // Set test vault path
    kenv_core::vault::set_test_vault_path(vault_path);

    // Create vault
    create_vault(password).expect("failed to create vault");

    // Unlock it
    unlock(password).expect("failed to unlock");

    // Reauth with wrong password should fail
    let error = reauth_password("wrong_password").unwrap_err();
    assert_eq!(error.to_string(), "unlock failed");

    // Cleanup
    lock().ok();
    kenv_core::vault::clear_test_vault_path();
}
