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
    use kenv_core::{create_vault, unlock, lock};

    let password = "test_password_123";
    let vault_path = dirs::home_dir()
        .unwrap()
        .join(".kenv")
        .join("vault.kenv");

    // Cleanup
    let _ = lock();
    for _ in 0..10 {
        if std::fs::remove_file(&vault_path).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Create vault
    create_vault(password).expect("failed to create vault");

    // Unlock it
    unlock(password).expect("failed to unlock");

    // List slots - should have at least one password slot
    let slots = list_slots().expect("failed to list slots");
    assert!(!slots.is_empty(), "new vault should have at least one slot");

    // Check that one slot is the password slot
    let password_slot = slots
        .iter()
        .find(|s| s.slot_type == SlotType::Password)
        .expect("password slot not found");
    assert_eq!(password_slot.slot_id, 1);
    assert_eq!(password_slot.label, "password");

    // Cleanup
    let _ = lock();
    for _ in 0..10 {
        if std::fs::remove_file(&vault_path).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn newly_created_vault_reauth_succeeds() {
    use kenv_core::{create_vault, unlock, lock, reauth_password};

    let password = "test_password_123";
    let vault_path = dirs::home_dir()
        .unwrap()
        .join(".kenv")
        .join("vault.kenv");

    // Cleanup
    let _ = lock();
    for _ in 0..10 {
        if std::fs::remove_file(&vault_path).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Create vault
    create_vault(password).expect("failed to create vault");

    // Unlock it
    unlock(password).expect("failed to unlock");

    // Reauth should succeed
    reauth_password(password).expect("reauth failed");

    // Cleanup
    let _ = lock();
    for _ in 0..10 {
        if std::fs::remove_file(&vault_path).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn newly_created_vault_reauth_fails_with_wrong_password() {
    use kenv_core::{create_vault, unlock, lock, reauth_password};

    let password = "test_password_123";
    let vault_path = dirs::home_dir()
        .unwrap()
        .join(".kenv")
        .join("vault.kenv");

    // Cleanup
    let _ = lock();
    for _ in 0..10 {
        if std::fs::remove_file(&vault_path).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Create vault
    create_vault(password).expect("failed to create vault");

    // Unlock it
    unlock(password).expect("failed to unlock");

    // Reauth with wrong password should fail
    let error = reauth_password("wrong_password").unwrap_err();
    assert_eq!(error.to_string(), "unlock failed");

    // Cleanup
    let _ = lock();
    for _ in 0..10 {
        if std::fs::remove_file(&vault_path).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
