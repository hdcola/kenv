use kenv_core::{
    get_vault_status, get_vault_status_with,
    vault::FILE_VERSION_V2,
    KenvError, VaultStatus,
};
use tempfile::TempDir;

#[test]
fn returns_missing_or_locked_depending_on_real_filesystem() {
    let status = get_vault_status().unwrap();
    assert!(
        status == VaultStatus::Missing
            || status == VaultStatus::Locked
            || status == VaultStatus::Corrupted,
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
            Ok(_version) => Ok(VaultStatus::Locked),
            Err(_) => Ok(VaultStatus::Corrupted),
        }
    })
    .unwrap();

    assert_eq!(status, VaultStatus::Corrupted);
}

#[test]
fn returns_corrupted_when_v2_salt_is_all_zeros() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");

    // Build a 91-byte V2 file where salt bytes are all zero (invalid).
    // In V2, KDF params at bytes 6-17 are intentionally zero; the rejection
    // here comes from the zero salt at bytes 18-50.
    let mut data = vec![0u8; 91];
    data[0..4].copy_from_slice(b"KENV");
    data[4] = FILE_VERSION_V2;
    data[5] = 1; // kdf_id
                 // salt at bytes 18..50 remains all zeros — invalid
    std::fs::write(&path, &data).unwrap();

    let status = get_vault_status_with(|| {
        let data = std::fs::read(&path).map_err(|_| KenvError::FileOperationFailed)?;
        match kenv_core::vault::validate_vault_header(&data) {
            Ok(_version) => Ok(VaultStatus::Locked),
            Err(_) => Ok(VaultStatus::Corrupted),
        }
    })
    .unwrap();

    assert_eq!(status, VaultStatus::Corrupted);
}

#[test]
fn returns_corrupted_when_salt_is_all_zeros() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");

    let mut data = vec![0u8; 91];
    data[0..4].copy_from_slice(b"KENV");
    data[4] = FILE_VERSION_V2;
    data[5] = 1; // kdf_id
                 // salt at bytes 18..50 remains all zeros — invalid
    std::fs::write(&path, &data).unwrap();

    let status = get_vault_status_with(|| {
        let data = std::fs::read(&path).map_err(|_| KenvError::FileOperationFailed)?;
        match kenv_core::vault::validate_vault_header(&data) {
            Ok(_version) => Ok(VaultStatus::Locked),
            Err(_) => Ok(VaultStatus::Corrupted),
        }
    })
    .unwrap();

    assert_eq!(status, VaultStatus::Corrupted);
}

#[test]
fn returns_corrupted_when_nonce_is_all_zeros() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");

    let mut data = vec![0u8; 91];
    data[0..4].copy_from_slice(b"KENV");
    data[4] = FILE_VERSION_V2;
    data[5] = 1; // kdf_id
                 // salt at bytes 18..50 has valid random-looking data
    for i in 18..50 {
        data[i] = ((i as u32).wrapping_mul(0x9e3779b9)) as u8;
    }
    // nonce at bytes 50..62 remains all zeros — invalid
    std::fs::write(&path, &data).unwrap();

    let status = get_vault_status_with(|| {
        let data = std::fs::read(&path).map_err(|_| KenvError::FileOperationFailed)?;
        match kenv_core::vault::validate_vault_header(&data) {
            Ok(_version) => Ok(VaultStatus::Locked),
            Err(_) => Ok(VaultStatus::Corrupted),
        }
    })
    .unwrap();

    assert_eq!(status, VaultStatus::Corrupted);
}

#[test]
fn returns_locked_when_header_valid_and_ciphertext_is_garbage() {
    // Documents the intentional limitation: AEAD tag verification happens at
    // unlock time, not at status check time. When unlock() is implemented, it
    // must map aes_gcm::Error (authentication tag mismatch) to a distinct
    // error from "wrong password" so the frontend can surface it as Corrupted.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kenv");

    let mut data = vec![0u8; 91];
    data[0..4].copy_from_slice(b"KENV");
    data[4] = 2; // version = V2
    data[5] = 1; // kdf_id
                 // bytes 6..18: KDF params are zero in V2 (per-slot)
                 // salt at bytes 18..50 has valid data
    for i in 18..50 {
        data[i] = ((i as u32).wrapping_mul(0x9e3779b9)) as u8;
    }
    // nonce at bytes 50..62 has valid data
    for i in 50..62 {
        data[i] = ((i as u32).wrapping_mul(0x9e3779b9)) as u8;
    }
    // slot section + ciphertext at bytes 62..91 is garbage (all zeros)
    std::fs::write(&path, &data).unwrap();

    let status = get_vault_status_with(|| {
        let data = std::fs::read(&path).map_err(|_| KenvError::FileOperationFailed)?;
        match kenv_core::vault::validate_vault_header(&data) {
            Ok(_version) => Ok(VaultStatus::Locked),
            Err(_) => Ok(VaultStatus::Corrupted),
        }
    })
    .unwrap();

    assert_eq!(status, VaultStatus::Locked);
}
