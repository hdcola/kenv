use kenv_core::KenvError;

#[test]
fn vault_already_exists_variant_displays() {
    assert_eq!(
        KenvError::VaultAlreadyExists.to_string(),
        "vault already exists"
    );
}

#[test]
fn invalid_vault_format_variant_displays() {
    assert_eq!(
        KenvError::InvalidVaultFormat.to_string(),
        "vault file has an invalid format"
    );
}

#[test]
fn encryption_error_variant_displays() {
    assert_eq!(
        KenvError::EncryptionError.to_string(),
        "encryption or decryption failed"
    );
}

#[test]
fn vault_version_unsupported_variant_displays() {
    assert_eq!(
        KenvError::VaultVersionUnsupported(1).to_string(),
        "vault format version 1 is no longer supported; recreate the vault"
    );
}
