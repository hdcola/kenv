use kenv_core::crypto::KdfParams;
use kenv_core::vault::{validate_vault_header, write_vault_file, MAGIC, FILE_VERSION_V2};
#[cfg(not(unix))]
use kenv_core::KenvError;
use tempfile::NamedTempFile;

fn p() -> KdfParams {
    KdfParams::for_tests()
}

#[test]
fn write_produces_minimum_size_file() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    write_vault_file(&path, &[0u8; 32], &[0u8; 12], &[0u8; 16], &p(), FILE_VERSION_V2).unwrap();
    assert_eq!(std::fs::read(&path).unwrap().len(), 62 + 16);
}

#[test]
fn write_starts_with_magic() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    write_vault_file(&path, &[0u8; 32], &[0u8; 12], &[0u8; 16], &p(), FILE_VERSION_V2).unwrap();
    let b = std::fs::read(&path).unwrap();
    assert_eq!(&b[0..4], MAGIC);
}

#[test]
fn write_encodes_file_version_2_at_offset_4() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    write_vault_file(&path, &[0u8; 32], &[0u8; 12], &[0u8; 16], &p(), FILE_VERSION_V2).unwrap();
    assert_eq!(std::fs::read(&path).unwrap()[4], 2u8);
}

#[test]
fn write_encodes_kdf_id_1_at_offset_5() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    write_vault_file(&path, &[0u8; 32], &[0u8; 12], &[0u8; 16], &p(), FILE_VERSION_V2).unwrap();
    assert_eq!(std::fs::read(&path).unwrap()[5], 1u8);
}

#[test]
fn write_encodes_kdf_params_big_endian() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    let params = KdfParams {
        m_cost: 0x100,
        t_cost: 0x2,
        p_cost: 0x1,
    };
    write_vault_file(&path, &[0u8; 32], &[0u8; 12], &[0u8; 16], &params, FILE_VERSION_V2).unwrap();
    let b = std::fs::read(&path).unwrap();
    assert_eq!(&b[6..10], &0x100u32.to_be_bytes());
    assert_eq!(&b[10..14], &0x2u32.to_be_bytes());
    assert_eq!(&b[14..18], &0x1u32.to_be_bytes());
}

#[test]
fn write_embeds_salt_at_offset_18() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    write_vault_file(&path, &[42u8; 32], &[0u8; 12], &[0u8; 16], &p(), FILE_VERSION_V2).unwrap();
    let b = std::fs::read(&path).unwrap();
    assert_eq!(&b[18..50], &[42u8; 32]);
}

#[test]
fn write_embeds_nonce_at_offset_50() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    write_vault_file(&path, &[0u8; 32], &[99u8; 12], &[0u8; 16], &p(), FILE_VERSION_V2).unwrap();
    let b = std::fs::read(&path).unwrap();
    assert_eq!(&b[50..62], &[99u8; 12]);
}

#[test]
fn validate_accepts_valid_header() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_path_buf();
    drop(f);
    // Write a 29-byte ciphertext (minimum: 13-byte plaintext + 16-byte GCM tag)
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    salt[0] = 1;
    nonce[0] = 1;
    write_vault_file(&path, &salt, &nonce, &[0u8; 29], &p(), FILE_VERSION_V2).unwrap();
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

#[cfg(not(unix))]
#[test]
fn write_vault_file_returns_platform_error_on_non_unix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kenv");
    let result = write_vault_file(&path, &[0u8; 32], &[0u8; 12], &[], &p(), FILE_VERSION_V2);
    assert!(matches!(
        result,
        Err(KenvError::PlatformCapabilityUnavailable)
    ));
}
