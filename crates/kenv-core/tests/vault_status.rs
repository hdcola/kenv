use kenv_core::{get_vault_status, get_vault_status_with, KenvError, VaultStatus};

#[test]
fn reports_missing_vault_before_storage_is_implemented() {
    assert_eq!(get_vault_status().unwrap(), VaultStatus::Missing);
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
