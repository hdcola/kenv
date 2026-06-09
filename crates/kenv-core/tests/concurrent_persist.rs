//! Regression: concurrent slot mutations from multiple IPC threads must not corrupt
//! the on-disk vault. `add_slot`/`remove_slot`/`rename_slot` release the VAULT_STATE
//! write lock before calling `persist_vault_state`, and the underlying
//! `overwrite_vault_file` previously used a fixed sibling tmp path
//! (`vault.kenv.tmp`), so two threads could collide on the tmp file and corrupt
//! the final rename. The fix is a dedicated `PERSIST_MUTEX` plus a randomized
//! tmp suffix.

use kenv_core::{
    add_slot, create_vault_at,
    crypto::KdfParams,
    list_slots, lock, rename_slot,
    slots::{Ctap2SlotData, SlotType, UnlockSlot},
    unlock, vault,
};
use serial_test::serial;
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;
use tempfile::TempDir;

fn ctap2_slot(slot_id: u8, label: &str) -> UnlockSlot {
    UnlockSlot {
        slot_id,
        slot_type: SlotType::Ctap2,
        label: label.to_string(),
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
        requires_touch: true,
        pin_attempts_left: None,
        last_used: None,
        disabled: false,
    }
}

#[test]
#[serial]
fn concurrent_add_slot_persists_all_changes() {
    vault::clear_test_vault_path();
    lock().ok();

    let temp_dir = TempDir::new().unwrap();
    let vault_path = Arc::new(temp_dir.path().join("vault.kenv"));
    let password = "test_password_123";

    create_vault_at(&*vault_path, password, &KdfParams::for_tests()).unwrap();
    vault::set_test_vault_path((*vault_path).clone());

    unlock(password).expect("unlock");

    // Spawn N threads each adding a distinct slot. Without the fix the fixed
    // tmp path causes two threads to collide and at least one persist to
    // corrupt the rename or produce an on-disk state that disagrees with
    // memory after a lock/unlock round-trip.
    const N: u8 = 8;
    let handles: Vec<_> = (2..2 + N)
        .map(|slot_id| {
            let path = Arc::clone(&vault_path);
            thread::spawn(move || {
                // set_test_vault_path is thread-local, so each worker must
                // route its own vault_path() lookup to the temp file.
                vault::set_test_vault_path((*path).clone());
                add_slot(ctap2_slot(slot_id, "concurrent")).expect("add_slot");
            })
        })
        .collect();
    for h in handles {
        h.join().expect("thread joined");
    }

    // In-memory state must contain all N + the original password slot.
    let in_mem = list_slots().expect("list_slots in memory");
    for expected in 2..2 + N {
        assert!(
            in_mem.iter().any(|s| s.slot_id == expected),
            "in-memory state missing slot {} after concurrent adds",
            expected
        );
    }

    // Reload from disk: every slot must survive. If the rename race lost an
    // update, the round-trip would drop slots.
    lock().ok();
    unlock(password).expect("re-unlock");
    let on_disk = list_slots().expect("list_slots after re-unlock");

    for expected in 2..2 + N {
        assert!(
            on_disk.iter().any(|s| s.slot_id == expected),
            "on-disk state lost slot {} after concurrent adds",
            expected
        );
    }
    assert!(
        on_disk.iter().any(|s| s.slot_id == 1),
        "original password slot must remain on disk"
    );

    // No orphaned tmp files should sit alongside the vault under normal
    // (non-crashing) operation; if any remain it indicates a persist failed
    // silently mid-rename.
    let parent = vault_path.parent().unwrap();
    let stray_tmp: Vec<_> = std::fs::read_dir(parent)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with("vault.kenv.tmp")
        })
        .collect();
    assert!(
        stray_tmp.is_empty(),
        "unexpected tmp files left after concurrent persists: {:?}",
        stray_tmp.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );

    lock().ok();
    vault::clear_test_vault_path();
}

#[test]
#[serial]
fn persist_uses_state_vault_path_not_global_vault_path() {
    vault::clear_test_vault_path();
    lock().ok();

    let dir_a = TempDir::new().unwrap();
    let path_a = dir_a.path().join("vault.kenv");
    create_vault_at(&path_a, "password", &KdfParams::for_tests()).unwrap();
    vault::set_test_vault_path(path_a.clone());
    unlock("password").expect("unlock at path_a");

    // Redirect the global vault path to a second directory.
    // With the bug, persist will write to path_b and leave path_a stale.
    // With the fix, persist uses state.vault_path = path_a regardless.
    let dir_b = TempDir::new().unwrap();
    let path_b = dir_b.path().join("vault.kenv");
    vault::set_test_vault_path(path_b.clone());

    rename_slot(1, "renamed".to_string()).expect("rename must succeed");

    // Reload from path_a to verify the rename was persisted there.
    vault::set_test_vault_path(path_a.clone());
    lock().ok();
    unlock("password").expect("re-unlock from path_a");
    let slots = kenv_core::list_slots().expect("list_slots");
    assert_eq!(
        slots
            .iter()
            .find(|s| s.slot_id == 1)
            .map(|s| s.label.as_str()),
        Some("renamed"),
        "rename must be persisted to state.vault_path (path_a), not the redirected global path"
    );

    lock().ok();
    vault::clear_test_vault_path();
}
