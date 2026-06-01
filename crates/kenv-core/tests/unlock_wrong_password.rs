use kenv_core::{create_vault, unlock, lock, KenvError};

fn setup_vault(password: &str) {
    let vault_path = dirs::home_dir().unwrap().join(".kenv").join("vault.kenv");
    let _ = lock();
    // Remove file if it exists
    for _ in 0..3 {
        if std::fs::remove_file(&vault_path).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    create_vault(password).ok();
}

fn cleanup() {
    let vault_path = dirs::home_dir().unwrap().join(".kenv").join("vault.kenv");
    let _ = lock();
    for _ in 0..3 {
        if std::fs::remove_file(&vault_path).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn unlock_with_wrong_password_fails() {
    setup_vault("correct-password");

    // Attempt unlock with wrong password
    let result = unlock("wrong-password");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KenvError::UnlockFailed));

    cleanup();
}

#[test]
fn unlock_with_empty_password_fails() {
    setup_vault("my-password");

    // Attempt unlock with empty password
    let result = unlock("");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KenvError::UnlockFailed));

    cleanup();
}

#[test]
fn unlock_with_slightly_different_password_fails() {
    setup_vault("password123");

    // Attempt unlock with password that differs by one character
    let result = unlock("password124");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KenvError::UnlockFailed));

    cleanup();
}
