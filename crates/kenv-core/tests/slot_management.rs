use kenv_core::{
    add_password_slot, add_slot, list_slots, remove_slot, rename_slot,
    slots::{UnlockSlot, SlotType},
};
use serial_test::serial;
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
#[serial]
fn newly_created_vault_has_password_slot() {
    use tempfile::TempDir;
    use kenv_core::{unlock, reauth_password, vault};

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";
    let params = kenv_core::crypto::KdfParams::for_tests();

    // Create vault at temp path
    kenv_core::create_vault_at(&vault_path, password, &params)
        .expect("failed to create vault");

    // Set test vault path so vault_path() uses temp location
    vault::set_test_vault_path(vault_path.clone());

    // Verify vault can be unlocked with correct password
    unlock(password).expect("failed to unlock with correct password");

    // Verify reauth_password works - this proves password slot wraps correct key
    reauth_password(password).expect("reauth should succeed with correct password");

    // Cleanup: clear state and vault path (in that order)
    kenv_core::lock().ok();
    vault::clear_test_vault_path();
}

#[test]
#[serial]
fn newly_created_vault_reauth_succeeds() {
    use tempfile::TempDir;
    use kenv_core::{create_vault, unlock, lock, reauth_password, vault};
    use std::fs;

    // Ensure clean state: clear test vault path and lock first
    vault::clear_test_vault_path();
    lock().ok();

    // Cleanup any leftover real vault
    let real_vault = dirs::home_dir()
        .map(|h| h.join(".kenv").join("vault.kenv"));
    if let Some(path) = &real_vault {
        let _ = fs::remove_file(path);
    }

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";

    // Set test vault path
    vault::set_test_vault_path(vault_path);

    // Create vault
    create_vault(password).expect("failed to create vault");

    // Unlock it
    unlock(password).expect("failed to unlock");

    // Reauth should succeed
    reauth_password(password).expect("reauth failed");

    // Cleanup
    lock().ok();
    vault::clear_test_vault_path();
}

#[test]
#[serial]
fn newly_created_vault_reauth_fails_with_wrong_password() {
    use tempfile::TempDir;
    use kenv_core::{create_vault, unlock, lock, reauth_password, vault};
    use std::fs;

    // Ensure clean state: clear test vault path and lock first
    vault::clear_test_vault_path();
    lock().ok();

    // Cleanup any leftover real vault
    let real_vault = dirs::home_dir()
        .map(|h| h.join(".kenv").join("vault.kenv"));
    if let Some(path) = &real_vault {
        let _ = fs::remove_file(path);
    }

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";

    // Set test vault path
    vault::set_test_vault_path(vault_path);

    // Create vault
    create_vault(password).expect("failed to create vault");

    // Unlock it
    unlock(password).expect("failed to unlock");

    // Reauth with wrong password should fail
    let error = reauth_password("wrong_password").unwrap_err();
    assert_eq!(error.to_string(), "unlock failed");

    // Cleanup
    lock().ok();
    vault::clear_test_vault_path();
}

/// Build a non-password unlock slot for tests that only need an extra slot to mutate.
fn ctap2_slot(slot_id: u8, label: &str) -> UnlockSlot {
    UnlockSlot {
        slot_id,
        slot_type: SlotType::Ctap2,
        label: label.to_string(),
        created_at: SystemTime::now(),
        password: None,
        ctap2: None,
        touchid: None,
        requires_pin: false,
        requires_touch: true,
        pin_attempts_left: None,
        last_used: None,
        disabled: false,
    }
}


/// Create a fast vault (cheap test KDF params) at `path` and route `vault_path()` to it on the
/// current thread. Using `for_tests` params keeps these serial tests off the slow Argon2 path.
fn create_test_vault(path: &std::path::Path, password: &str) {
    use kenv_core::{create_vault_at, crypto::KdfParams, vault};
    create_vault_at(path, password, &KdfParams::for_tests()).expect("failed to create vault");
    vault::set_test_vault_path(path.to_path_buf());
}

// --- Issue 1: success-path persistence survives a lock/unlock cycle ---

#[test]
#[serial]
fn add_slot_persists_across_lock_unlock() {
    use tempfile::TempDir;
    use kenv_core::{add_slot, lock, unlock, vault};

    vault::clear_test_vault_path();
    lock().ok();

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";

    create_test_vault(&vault_path, password);
    unlock(password).expect("failed to unlock");

    // Before the persistence fix this returned VaultAlreadyExists.
    add_slot(ctap2_slot(2, "yubikey")).expect("add_slot should persist");

    // Reload from disk and confirm the new slot survived.
    lock().ok();
    unlock(password).expect("failed to re-unlock");
    let slots = list_slots().expect("list_slots after reload");
    assert!(slots.iter().any(|s| s.slot_id == 2), "added slot must survive reload");

    lock().ok();
    vault::clear_test_vault_path();
}

#[test]
#[serial]
fn rename_slot_persists_across_lock_unlock() {
    use tempfile::TempDir;
    use kenv_core::{lock, unlock, vault};

    vault::clear_test_vault_path();
    lock().ok();

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";

    create_test_vault(&vault_path, password);
    unlock(password).expect("failed to unlock");

    rename_slot(1, "renamed".to_string()).expect("rename_slot should persist");

    lock().ok();
    unlock(password).expect("failed to re-unlock");
    let slots = list_slots().expect("list_slots after reload");
    let slot = slots.iter().find(|s| s.slot_id == 1).expect("slot 1 present");
    assert_eq!(slot.label, "renamed", "renamed label must survive reload");

    lock().ok();
    vault::clear_test_vault_path();
}

#[test]
#[serial]
fn remove_slot_persists_across_lock_unlock() {
    use tempfile::TempDir;
    use kenv_core::{add_slot, lock, unlock, vault};

    vault::clear_test_vault_path();
    lock().ok();

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";

    create_test_vault(&vault_path, password);
    unlock(password).expect("failed to unlock");

    // Add a non-password slot, then remove it (no reauth, no last-slot guard).
    add_slot(ctap2_slot(2, "yubikey")).expect("add_slot should persist");
    remove_slot(2).expect("remove_slot should persist");

    lock().ok();
    unlock(password).expect("failed to re-unlock");
    let slots = list_slots().expect("list_slots after reload");
    assert!(slots.iter().all(|s| s.slot_id != 2), "removed slot must stay gone after reload");
    assert!(slots.iter().any(|s| s.slot_id == 1), "password slot must remain");

    lock().ok();
    vault::clear_test_vault_path();
}

// --- Issue 4: the last enabled password slot cannot be removed ---

#[test]
#[serial]
fn cannot_remove_last_password_slot() {
    use tempfile::TempDir;
    use kenv_core::{lock, unlock, vault};

    vault::clear_test_vault_path();
    lock().ok();

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";

    create_test_vault(&vault_path, password);
    unlock(password).expect("failed to unlock");

    // Guard fires before the reauth check, so no reauth is needed to observe it.
    let error = remove_slot(1).unwrap_err();
    assert_eq!(error.to_string(), "cannot remove the last password slot");

    // Slot must still be there.
    let slots = list_slots().expect("list_slots");
    assert!(slots.iter().any(|s| s.slot_id == 1), "last password slot must survive");

    lock().ok();
    vault::clear_test_vault_path();
}

#[test]
#[serial]
fn can_remove_password_slot_when_another_remains() {
    use tempfile::TempDir;
    use kenv_core::{lock, reauth_password, unlock, vault, crypto::KdfParams};

    vault::clear_test_vault_path();
    lock().ok();

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";

    create_test_vault(&vault_path, password);
    unlock(password).expect("failed to unlock");

    // Add a REAL second password slot that wraps the vault DEK.
    // After slot 1 is deleted, this slot must be the only way to unlock the vault.
    add_password_slot(password, &KdfParams::for_tests()).expect("add second password slot");
    reauth_password(password).expect("reauth should succeed");
    remove_slot(1).expect("removing a non-last password slot should succeed");

    // Verify slot 2's cleartext key record allows the vault to be re-opened.
    lock().ok();
    unlock(password).expect("re-unlock via backup slot must succeed");
    let slots = list_slots().expect("list_slots after reload");
    assert!(slots.iter().all(|s| s.slot_id != 1), "removed slot stays gone");
    assert!(slots.iter().any(|s| s.slot_id == 2), "backup slot persists");

    lock().ok();
    vault::clear_test_vault_path();
}

// --- Issue 3: reauth works on a different thread than unlock ---

#[test]
#[serial]
fn reauth_succeeds_on_different_thread_than_unlock() {
    use tempfile::TempDir;
    use kenv_core::{lock, reauth_password, unlock, vault};

    vault::clear_test_vault_path();
    lock().ok();

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";

    create_test_vault(&vault_path, password);

    // Unlock on one spawned thread...
    {
        let path = vault_path.clone();
        std::thread::spawn(move || {
            // TEST_VAULT_PATH is thread-local, so re-inject it on this thread.
            vault::set_test_vault_path(path);
            unlock(password).expect("unlock on thread A");
        })
        .join()
        .unwrap();
    }

    // ...and reauth on a *different* thread. Before the fix this returned "vault is locked"
    // because of the thread-id binding.
    {
        let path = vault_path.clone();
        std::thread::spawn(move || {
            vault::set_test_vault_path(path);
            reauth_password(password).expect("reauth should succeed cross-thread");
        })
        .join()
        .unwrap();
    }

    lock().ok();
    vault::clear_test_vault_path();
}

// --- Bug P1: reauth must verify against the slot that actually unlocked the session ---

#[test]
#[serial]
fn reauth_uses_unlock_slot_not_first_slot() {
    use tempfile::TempDir;
    use kenv_core::{lock, reauth_password, unlock, vault, crypto::KdfParams};

    vault::clear_test_vault_path();
    lock().ok();

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password1 = "first_password";
    let password2 = "second_password";

    // Vault created with password1 (slot 1).
    create_test_vault(&vault_path, password1);
    unlock(password1).expect("unlock with password1");

    // Add slot 2 with a *different* password.
    add_password_slot(password2, &KdfParams::for_tests())
        .expect("add second password slot");

    lock().ok();

    // Unlock using slot 2's password; last_unlock_slot_id should be set to 2.
    unlock(password2).expect("unlock with password2");

    // reauth with password2 must succeed (it targets slot 2).
    reauth_password(password2)
        .expect("reauth with password2 must succeed after unlocking with it");

    // reauth with password1 must fail — slot 2 requires password2.
    let err = reauth_password(password1).unwrap_err();
    assert_eq!(
        err.to_string(),
        "unlock failed",
        "reauth with the wrong slot's password must fail"
    );

    lock().ok();
    vault::clear_test_vault_path();
}
