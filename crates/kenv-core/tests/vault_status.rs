use kenv_core::{get_vault_status, get_vault_status_with, KenvError, VaultStatus};

#[test]
fn returns_missing_or_locked_depending_on_real_filesystem() {
    let status = get_vault_status().unwrap();
    assert!(
        status == VaultStatus::Missing || status == VaultStatus::Locked,
        "unexpected status: {:?}",
        status
    );
}

#[test]
fn supports_injected_status_provider_for_tests() {
    let status = get_vault_status_with(|| Ok(VaultStatus::Locked)).unwrap();
    assert_eq!(status, VaultStatus::Locked);
}

#[test]
fn returns_injected_error_for_tests() {
    let error = get_vault_status_with(|| Err(KenvError::UnlockFailed)).unwrap_err();
    assert_eq!(error.to_string(), "unlock failed");
}
