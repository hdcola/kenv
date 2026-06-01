use kenv_core::{unlock, KenvError};

#[test]
fn unlock_on_missing_vault_returns_vault_missing() {
    // Don't create any vault, just try to unlock
    // This will try to access the default vault path which doesn't exist
    let result = unlock("any-password");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KenvError::VaultMissing));
}
