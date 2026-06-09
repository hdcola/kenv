//! Rollback correctness for vault slot mutations.
//!
//! Each mutation function (add_slot, remove_slot, rename_slot) rolls back its
//! in-memory change when persist_vault_state fails. These tests verify:
//!
//!   1. The rollback restores the exact pre-mutation state.
//!   2. A subsequent successful mutation is not affected by the prior rollback.
//!
//! NOTE on the concurrent clobber scenario (not tested deterministically here):
//! Without MUTATION_LOCK, if thread B completes Phase 1 (e.g. renames a slot)
//! after thread A's Phase 1 but before A's rollback, A's rollback will restore
//! the label it saved — before B's rename — clobbering B's change. MUTATION_LOCK
//! (added in the P1 fix) serialises the full modify→persist→rollback cycle,
//! preventing this race. The concurrent_persist tests exercise the happy path.

use kenv_core::{
    add_slot, arm_fail_next_persist_for_test, create_vault_at,
    crypto::KdfParams,
    list_slots, lock, remove_slot, rename_slot,
    slots::{Ctap2SlotData, SlotType, UnlockSlot},
    unlock, vault,
};
use serial_test::serial;
use std::time::SystemTime;
use tempfile::TempDir;

fn ctap2_slot(slot_id: u8) -> UnlockSlot {
    UnlockSlot {
        slot_id,
        slot_type: SlotType::Ctap2,
        label: format!("slot-{slot_id}"),
        created_at: SystemTime::now(),
        password: None,
        ctap2: Some(Ctap2SlotData {
            credential_id: vec![slot_id],
            public_key: vec![0u8; 65],
            challenge: vec![0u8; 32],
            counter: 0,
            algorithm: -7,
            device_serial: None,
            attestation_data: None,
            nonce: [0u8; 12],
            encrypted_dek: vec![0u8; 32],
            tag: [0u8; 16],
            requires_pin: false,
            requires_uv: false,
            requires_touch: false,
        }),
        touchid: None,
        requires_pin: false,
        requires_touch: false,
        pin_attempts_left: None,
        last_used: None,
        disabled: false,
    }
}

fn setup() -> (TempDir, std::path::PathBuf) {
    vault::clear_test_vault_path();
    lock().ok();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");
    create_vault_at(&path, "pass", &KdfParams::for_tests()).unwrap();
    vault::set_test_vault_path(path.clone());
    unlock("pass").unwrap();
    (dir, path)
}

fn teardown() {
    lock().ok();
    vault::clear_test_vault_path();
}

/// add_slot: a failed persist removes the slot from in-memory state.
#[test]
#[serial]
fn add_slot_rollback_on_persist_failure() {
    let (_dir, _path) = setup();

    arm_fail_next_persist_for_test();
    let result = add_slot(ctap2_slot(10));
    assert!(
        result.is_err(),
        "add_slot must return Err when persist fails"
    );

    let slots = list_slots().expect("list_slots");
    assert!(
        slots.iter().all(|s| s.slot_id != 10),
        "slot 10 must be absent after rollback; slots present: {:?}",
        slots.iter().map(|s| s.slot_id).collect::<Vec<_>>()
    );

    teardown();
}

/// rename_slot: a failed persist restores the original label.
#[test]
#[serial]
fn rename_slot_rollback_on_persist_failure() {
    let (_dir, _path) = setup();

    // The password slot (slot_id 1) is created by create_vault_at.
    let original_label = {
        let slots = list_slots().unwrap();
        slots.iter().find(|s| s.slot_id == 1).unwrap().label.clone()
    };

    arm_fail_next_persist_for_test();
    let result = rename_slot(1, "renamed".to_string());
    assert!(
        result.is_err(),
        "rename_slot must return Err when persist fails"
    );

    let slots = list_slots().expect("list_slots");
    let label = slots.iter().find(|s| s.slot_id == 1).unwrap().label.clone();
    assert_eq!(
        label, original_label,
        "slot 1 label must be restored to original after rollback"
    );

    teardown();
}

/// remove_slot: a failed persist re-inserts the slot.
#[test]
#[serial]
fn remove_slot_rollback_on_persist_failure() {
    let (_dir, _path) = setup();

    // Add a second slot so we can remove it without triggering reauthentication.
    add_slot(ctap2_slot(2)).expect("add second slot");

    arm_fail_next_persist_for_test();
    let result = remove_slot(2);
    assert!(
        result.is_err(),
        "remove_slot must return Err when persist fails"
    );

    let slots = list_slots().expect("list_slots");
    assert!(
        slots.iter().any(|s| s.slot_id == 2),
        "slot 2 must still be present after rollback"
    );

    teardown();
}

/// After a failed+rolled-back mutation, a subsequent successful mutation works.
#[test]
#[serial]
fn rollback_does_not_affect_subsequent_mutation() {
    let (_dir, _path) = setup();

    // Fail add_slot(10), then succeed add_slot(11).
    arm_fail_next_persist_for_test();
    add_slot(ctap2_slot(10)).unwrap_err();

    add_slot(ctap2_slot(11)).expect("second add_slot must succeed");

    let slots = list_slots().expect("list_slots");
    assert!(
        slots.iter().all(|s| s.slot_id != 10),
        "slot 10 must remain absent"
    );
    assert!(
        slots.iter().any(|s| s.slot_id == 11),
        "slot 11 must be present"
    );

    teardown();
}
