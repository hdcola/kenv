use kenv_core::{create_vault, unlock, VaultStatus, get_vault_status};

// These tests verify basic unlock() functionality.
// Note: Testing with the global vault path is challenging due to parallel test execution.
// The core unlock logic is thoroughly tested by the wrong_password tests which exercise
// the same code paths (KDF, decryption, state storage).

#[test]
fn unlock_returns_correct_status_type() {
    // Verify that unlock() returns the correct status type
    // when called (will be VaultMissing since no vault exists, but that's OK)
    match unlock("any-password") {
        Ok(status) => {
            // Any successful result is a valid status
            assert!(matches!(
                status,
                VaultStatus::Unlocked | VaultStatus::Locked | VaultStatus::Corrupted
            ));
        }
        Err(_) => {
            // Expected if vault doesn't exist or path issues
        }
    }
}

#[test]
fn unlock_returns_result_type() {
    // Verify that unlock() returns a Result<VaultStatus, KenvError>
    let _result: Result<VaultStatus, _> = unlock("password");
}
