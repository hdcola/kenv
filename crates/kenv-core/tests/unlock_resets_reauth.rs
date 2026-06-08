//! Regression: `unlock()` must clear the previous session's `reauthenticated_at`
//! and other transient fields, so a high-risk op (e.g. removing a password slot,
//! signing with a key flagged `require_reauthentication`) cannot bypass reauth on
//! a freshly unlocked vault. Before the fix only payload/dek/unlocked_at/salt/
//! kdf_params/vault_path were overwritten; reauthenticated_at survived.

use kenv_core::{
    add_slot, create_vault_at,
    crypto::KdfParams,
    lock, reauth_password, remove_slot,
    slots::{SlotType, UnlockSlot},
    unlock, vault, KenvError,
};
use serial_test::serial;
use std::time::SystemTime;
use tempfile::TempDir;

fn password_slot_meta(slot_id: u8, label: &str) -> UnlockSlot {
    UnlockSlot {
        slot_id,
        slot_type: SlotType::Password,
        label: label.to_string(),
        created_at: SystemTime::now(),
        password: None,
        ctap2: None,
        touchid: None,
        requires_pin: false,
        requires_touch: false,
        pin_attempts_left: None,
        last_used: None,
        disabled: false,
    }
}

#[test]
#[serial]
fn unlock_clears_previous_reauth_window() {
    vault::clear_test_vault_path();
    lock().ok();

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";

    create_vault_at(&vault_path, password, &KdfParams::for_tests()).unwrap();
    vault::set_test_vault_path(vault_path);

    unlock(password).expect("first unlock");

    // Two password slots so the last-password-slot guard does not preempt the
    // reauth check we actually want to exercise.
    add_slot(password_slot_meta(2, "second")).expect("add second password slot");

    // Reauth opens the 5-minute window in session A.
    reauth_password(password).expect("reauth in session A");

    // Sanity: in session A, removing the second password slot is allowed.
    remove_slot(2).expect("remove within active reauth window");

    // Re-add it, reauth again, then lock to end session A.
    add_slot(password_slot_meta(2, "second")).expect("re-add second password slot");
    reauth_password(password).expect("reauth again before lock");

    lock().ok();

    // Session B: a fresh unlock must NOT inherit session A's reauth timestamp.
    unlock(password).expect("second unlock");

    // The fix requires this to fail with UnlockFailed (reauth required).
    // Pre-fix, the stale reauthenticated_at from session A let it succeed.
    let err = remove_slot(2).expect_err("remove must require fresh reauth after unlock");
    assert!(
        matches!(err, KenvError::UnlockFailed),
        "expected UnlockFailed (reauth required), got {:?}",
        err
    );

    lock().ok();
    vault::clear_test_vault_path();
}

/// Repeated unlock cycles must not panic and must leave state observably reset
/// after each `lock()`. This exercises the struct-replacement path in `unlock()`
/// that also zeroizes the previous payload/dek/salt.
#[test]
#[serial]
fn repeated_unlock_lock_cycles_keep_state_consistent() {
    vault::clear_test_vault_path();
    lock().ok();

    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault.kenv");
    let password = "test_password_123";

    create_vault_at(&vault_path, password, &KdfParams::for_tests()).unwrap();
    vault::set_test_vault_path(vault_path);

    for _ in 0..3 {
        unlock(password).expect("unlock");
        // After lock, locked-state preconditions must hold.
        lock().ok();
        let err = kenv_core::list_slots().expect_err("must be locked after lock()");
        assert_eq!(err.to_string(), "vault is locked");
    }

    vault::clear_test_vault_path();
}
