use kenv_core::{get_vault_status, get_vault_status_with, KenvError, VaultStatus};
use tempfile::TempDir;

#[test]
fn returns_missing_or_locked_depending_on_real_filesystem() {
    let status = get_vault_status().unwrap();
    assert!(
        status == VaultStatus::Missing || status == VaultStatus::Locked || status == VaultStatus::Corrupted,
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

#[test]
fn returns_corrupted_when_vault_file_has_invalid_content() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");
    std::fs::write(&path, b"garbage").unwrap();

    let status = get_vault_status_with(|| {
        let data = std::fs::read(&path).map_err(|_| KenvError::FileOperationFailed)?;
        match kenv_core::vault::validate_vault_header(&data) {
            Ok(()) => Ok(VaultStatus::Locked),
            Err(_) => Ok(VaultStatus::Corrupted),
        }
    }).unwrap();

    assert_eq!(status, VaultStatus::Corrupted);
}

#[test]
fn returns_corrupted_when_header_valid_but_kdf_params_zero() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");

    // Build a 91-byte file with valid header but zero KDF params
    let mut data = vec![0u8; 91];
    data[0..4].copy_from_slice(b"KENV");
    data[4] = 1; // version
    data[5] = 1; // kdf_id
    // m_cost, t_cost, p_cost remain 0 (bytes 6-17) — structurally invalid
    std::fs::write(&path, &data).unwrap();

    let status = get_vault_status_with(|| {
        let data = std::fs::read(&path).map_err(|_| KenvError::FileOperationFailed)?;
        match kenv_core::vault::validate_vault_header(&data) {
            Ok(()) => Ok(VaultStatus::Locked),
            Err(_) => Ok(VaultStatus::Corrupted),
        }
    }).unwrap();

    assert_eq!(status, VaultStatus::Corrupted);
}
