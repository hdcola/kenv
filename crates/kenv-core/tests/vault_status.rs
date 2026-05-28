use kenv_core::{get_vault_status, VaultStatus};

#[test]
fn reports_missing_vault_before_storage_is_implemented() {
    assert_eq!(get_vault_status().unwrap(), VaultStatus::Missing);
}
