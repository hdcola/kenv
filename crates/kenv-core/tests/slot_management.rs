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
