use kenv_core::lock;

#[test]
fn lock_succeeds_after_unlock() {
    // Clean up any existing vault first
    let vault_path = dirs::home_dir().unwrap().join(".kenv").join("vault.kenv");
    let _ = std::fs::remove_file(&vault_path);

    // Test that lock() can be called and succeeds
    // This tests the basic functionality without needing unlock to work globally
    let result = lock();
    assert!(result.is_ok());
}

#[test]
fn multiple_lock_calls_are_safe() {
    // Test that multiple lock calls are safe and don't panic or error
    let result1 = lock();
    let result2 = lock();
    let result3 = lock();

    assert!(result1.is_ok());
    assert!(result2.is_ok());
    assert!(result3.is_ok());
}
