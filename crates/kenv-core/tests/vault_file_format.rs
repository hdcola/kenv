use kenv_core::crypto::KdfParams;
use kenv_core::vault::{validate_vault_header, write_vault_file, FILE_VERSION_V1, FILE_VERSION_V2, MAGIC};
use kenv_core::KenvError;
use tempfile::NamedTempFile;

fn p() -> KdfParams {
    KdfParams::for_tests()
}

// Minimal V2 slot section: slot_count = 0, no records.
const EMPTY_SLOTS: &[u8] = &[0u8];

#[test]
fn write_produces_minimum_size_file() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    // V2 layout: 62-byte header + 1-byte slot_count(=0) + 16-byte ciphertext
    write_vault_file(
        &path,
        &[0u8; 32],
        &[0u8; 12],
        &[0u8; 16],
        &p(),
        EMPTY_SLOTS,
        FILE_VERSION_V2,
    )
    .unwrap();
    assert_eq!(std::fs::read(&path).unwrap().len(), 62 + 1 + 16);
}

#[test]
fn write_starts_with_magic() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    write_vault_file(
        &path,
        &[0u8; 32],
        &[0u8; 12],
        &[0u8; 16],
        &p(),
        EMPTY_SLOTS,
        FILE_VERSION_V2,
    )
    .unwrap();
    let b = std::fs::read(&path).unwrap();
    assert_eq!(&b[0..4], MAGIC);
}

#[test]
fn write_encodes_file_version_2_at_offset_4() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    write_vault_file(
        &path,
        &[0u8; 32],
        &[0u8; 12],
        &[0u8; 16],
        &p(),
        EMPTY_SLOTS,
        FILE_VERSION_V2,
    )
    .unwrap();
    assert_eq!(std::fs::read(&path).unwrap()[4], 2u8);
}

#[test]
fn write_encodes_kdf_id_1_at_offset_5() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    write_vault_file(
        &path,
        &[0u8; 32],
        &[0u8; 12],
        &[0u8; 16],
        &p(),
        EMPTY_SLOTS,
        FILE_VERSION_V2,
    )
    .unwrap();
    assert_eq!(std::fs::read(&path).unwrap()[5], 1u8);
}

/// For V2, KDF params live per-slot in the cleartext slot section, so the header
/// fields at bytes 6–17 are intentionally zero.
#[test]
fn v2_header_kdf_params_are_zero() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    write_vault_file(
        &path,
        &[0u8; 32],
        &[0u8; 12],
        &[0u8; 16],
        &p(),
        EMPTY_SLOTS,
        FILE_VERSION_V2,
    )
    .unwrap();
    let b = std::fs::read(&path).unwrap();
    assert_eq!(&b[6..18], &[0u8; 12]);
}

#[test]
fn write_embeds_salt_at_offset_18() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    write_vault_file(
        &path,
        &[42u8; 32],
        &[0u8; 12],
        &[0u8; 16],
        &p(),
        EMPTY_SLOTS,
        FILE_VERSION_V2,
    )
    .unwrap();
    let b = std::fs::read(&path).unwrap();
    assert_eq!(&b[18..50], &[42u8; 32]);
}

#[test]
fn write_embeds_nonce_at_offset_50() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    write_vault_file(
        &path,
        &[0u8; 32],
        &[99u8; 12],
        &[0u8; 16],
        &p(),
        EMPTY_SLOTS,
        FILE_VERSION_V2,
    )
    .unwrap();
    let b = std::fs::read(&path).unwrap();
    assert_eq!(&b[50..62], &[99u8; 12]);
}

#[test]
fn validate_accepts_valid_header() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    salt[0] = 1;
    nonce[0] = 1;
    write_vault_file(
        &path,
        &salt,
        &nonce,
        &[0u8; 29],
        &p(),
        EMPTY_SLOTS,
        FILE_VERSION_V2,
    )
    .unwrap();
    let b = std::fs::read(&path).unwrap();
    assert!(validate_vault_header(&b).is_ok());
}

#[test]
fn validate_rejects_wrong_magic() {
    let mut b = vec![0u8; 78];
    b[0..4].copy_from_slice(b"XXXX");
    assert!(validate_vault_header(&b).is_err());
}

#[test]
fn validate_rejects_too_short() {
    assert!(validate_vault_header(&[0u8; 10]).is_err());
}

#[test]
fn validate_rejects_v2_with_bad_kdf_id() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    salt[0] = 1;
    nonce[0] = 1;
    write_vault_file(
        &path,
        &salt,
        &nonce,
        &[0u8; 29],
        &p(),
        EMPTY_SLOTS,
        FILE_VERSION_V2,
    )
    .unwrap();
    let mut b = std::fs::read(&path).unwrap();
    b[5] = 0xFF;
    assert!(validate_vault_header(&b).is_err());
}

#[test]
fn validate_rejects_v1_with_version_unsupported_error() {
    // Minimal V1-shaped blob: MAGIC + version=1 + kdf_id + non-zero KDF params +
    // non-zero salt + non-zero nonce + placeholder ciphertext bytes.
    let mut data = vec![0u8; 91];
    data[0..4].copy_from_slice(b"KENV");
    data[4] = FILE_VERSION_V1;
    data[5] = 1; // KDF_ID_ARGON2ID
    data[6..10].copy_from_slice(&65536u32.to_be_bytes()); // m_cost
    data[10..14].copy_from_slice(&3u32.to_be_bytes()); // t_cost
    data[14..18].copy_from_slice(&1u32.to_be_bytes()); // p_cost
    data[18] = 1; // non-zero salt
    data[50] = 1; // non-zero nonce
    assert!(matches!(
        validate_vault_header(&data),
        Err(KenvError::VaultVersionUnsupported(1))
    ));
}

#[test]
fn v1_error_is_distinct_from_invalid_format() {
    let mut corrupt = vec![0u8; 91];
    corrupt[0..4].copy_from_slice(b"KENV");
    corrupt[4] = 0xFF; // unknown future version
    corrupt[18] = 1;
    corrupt[50] = 1;

    let mut v1 = vec![0u8; 91];
    v1[0..4].copy_from_slice(b"KENV");
    v1[4] = FILE_VERSION_V1;
    v1[18] = 1;
    v1[50] = 1;

    assert!(matches!(
        validate_vault_header(&corrupt),
        Err(KenvError::InvalidVaultFormat)
    ));
    assert!(matches!(
        validate_vault_header(&v1),
        Err(KenvError::VaultVersionUnsupported(1))
    ));
}

#[cfg(not(unix))]
#[test]
fn write_vault_file_returns_platform_error_on_non_unix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kenv");
    let result = write_vault_file(
        &path,
        &[0u8; 32],
        &[0u8; 12],
        &[],
        &p(),
        EMPTY_SLOTS,
        FILE_VERSION_V2,
    );
    assert!(matches!(
        result,
        Err(KenvError::PlatformCapabilityUnavailable)
    ));
}
