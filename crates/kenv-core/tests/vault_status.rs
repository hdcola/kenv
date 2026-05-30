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

#[test]
fn returns_corrupted_when_salt_is_all_zeros() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");

    let mut data = vec![0u8; 91];
    data[0..4].copy_from_slice(b"KENV");
    data[4] = 1; // version
    data[5] = 1; // kdf_id
    data[6..10].copy_from_slice(&1u32.to_be_bytes()); // m_cost = 1
    data[10..14].copy_from_slice(&1u32.to_be_bytes()); // t_cost = 1
    data[14..18].copy_from_slice(&1u32.to_be_bytes()); // p_cost = 1
    // salt at bytes 18..50 remains all zeros
    // nonce at bytes 50..62 remains all zeros
    // ciphertext at bytes 62..91 remains all zeros
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

#[test]
fn returns_corrupted_when_nonce_is_all_zeros() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");

    let mut data = vec![0u8; 91];
    data[0..4].copy_from_slice(b"KENV");
    data[4] = 1; // version
    data[5] = 1; // kdf_id
    data[6..10].copy_from_slice(&1u32.to_be_bytes()); // m_cost = 1
    data[10..14].copy_from_slice(&1u32.to_be_bytes()); // t_cost = 1
    data[14..18].copy_from_slice(&1u32.to_be_bytes()); // p_cost = 1
    // salt at bytes 18..50 has valid random-looking data
    for i in 18..50 {
        data[i] = ((i as u32).wrapping_mul(0x9e3779b9)) as u8;
    }
    // nonce at bytes 50..62 remains all zeros
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

#[test]
fn returns_locked_when_header_valid_and_ciphertext_is_garbage() {
    // This test documents the intentional limitation: AEAD tag verification
    // happens at unlock time, not at status check time. A file with valid
    // header and valid salt/nonce but bitflipped or garbage ciphertext will
    // still return Locked from get_vault_status(). Only unlock will catch it.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");

    let mut data = vec![0u8; 91];
    data[0..4].copy_from_slice(b"KENV");
    data[4] = 1; // version
    data[5] = 1; // kdf_id
    data[6..10].copy_from_slice(&1u32.to_be_bytes()); // m_cost = 1
    data[10..14].copy_from_slice(&1u32.to_be_bytes()); // t_cost = 1
    data[14..18].copy_from_slice(&1u32.to_be_bytes()); // p_cost = 1
    // salt at bytes 18..50 has valid data
    for i in 18..50 {
        data[i] = ((i as u32).wrapping_mul(0x9e3779b9)) as u8;
    }
    // nonce at bytes 50..62 has valid data
    for i in 50..62 {
        data[i] = ((i as u32).wrapping_mul(0x9e3779b9)) as u8;
    }
    // ciphertext at bytes 62..91 is garbage (all zeros or bitflipped)
    std::fs::write(&path, &data).unwrap();

    let status = get_vault_status_with(|| {
        let data = std::fs::read(&path).map_err(|_| KenvError::FileOperationFailed)?;
        match kenv_core::vault::validate_vault_header(&data) {
            Ok(()) => Ok(VaultStatus::Locked),
            Err(_) => Ok(VaultStatus::Corrupted),
        }
    }).unwrap();

    assert_eq!(status, VaultStatus::Locked);
}
