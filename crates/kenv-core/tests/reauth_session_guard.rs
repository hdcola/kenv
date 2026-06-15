use kenv_core::{
    advance_session_id_for_test, corrupt_dek_for_test, create_vault_at, crypto::KdfParams,
    get_session_id_for_test, reauth_password, reauth_stamp_for_test, unlock, vault, KenvError,
};
use serial_test::serial;
use tempfile::TempDir;

fn setup(password: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");
    create_vault_at(&path, password, &KdfParams::for_tests()).expect("setup failed");
    vault::set_test_vault_path(path);
    dir
}

fn teardown() {
    kenv_core::lock().ok();
    vault::clear_test_vault_path();
}

/// Happy path: reauth succeeds when the session hasn't changed.
#[test]
#[serial]
fn reauth_succeeds_when_session_is_unchanged() {
    let _dir = setup("password");
    unlock("password").unwrap();
    reauth_password("password").expect("reauth must succeed on an unchanged session");
    teardown();
}

/// Guard path: the write-lock stamp must reject a snapshot_session_id that is one
/// generation behind the current session_id.
///
/// This directly tests the TOCTOU guard without needing real concurrent threads.
/// `advance_session_id_for_test` mimics what a concurrent lock()+unlock() would do
/// between reauth's verify step (read lock) and its stamp step (write lock).
#[test]
#[serial]
fn stale_session_stamp_returns_vault_locked() {
    let _dir = setup("password");
    unlock("password").unwrap();

    // Capture the session_id that reauth would have snapshotted at verify time.
    let good_id = get_session_id_for_test();

    // A concurrent lock()+unlock() replaces the session.
    advance_session_id_for_test();

    // Stamping with the old (stale) session_id must fail.
    assert!(
        matches!(reauth_stamp_for_test(good_id), Err(KenvError::VaultLocked)),
        "stamping with a stale session_id must return VaultLocked"
    );

    teardown();
}

/// Counterpart to the guard test: stamping with the CURRENT session_id must succeed.
#[test]
#[serial]
fn fresh_session_stamp_succeeds() {
    let _dir = setup("password");
    unlock("password").unwrap();
    advance_session_id_for_test(); // simulate some prior lock/unlock cycle

    let current_id = get_session_id_for_test();
    reauth_stamp_for_test(current_id).expect("stamping with the current session_id must succeed");

    teardown();
}

/// Regression: reauth must fail when the password slot decrypts successfully but the
/// resulting bytes do not equal the current session DEK.
/// Simulated by corrupting state.dek after unlock without touching the slot material.
#[test]
#[serial]
fn reauth_fails_when_decrypted_dek_does_not_match_session_dek() {
    let _dir = setup("password");
    unlock("password").unwrap();

    // Overwrite state.dek with a different value. The password slot still encrypts
    // the original DEK, so crypto::decrypt succeeds — but the result must not match
    // the (now-different) session DEK.
    corrupt_dek_for_test([0xAB; 32]);

    let err = reauth_password("password").unwrap_err();
    assert!(
        matches!(err, KenvError::UnlockFailed),
        "reauth must return UnlockFailed when decrypted DEK != session DEK, got: {err:?}"
    );

    teardown();
}
