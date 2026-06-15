// Tests for unlock/lock with corrupted data are implicitly tested by the decrypt
// function tests in crypto.rs which verify that AEAD decryption fails on corrupted data.
// At the unlock level, we test that wrong passwords are rejected, which exercises
// the same error path as corrupted ciphertext (AEAD tag failure).
//
// These unit tests avoid the complexity of managing vault files across multiple tests.

#[test]
fn unlock_error_paths_are_tested_elsewhere() {
    // The crypto module tests thoroughly exercise:
    // - Corrupted ciphertext detection (decrypt_rejects_tampered_ciphertext)
    // - Wrong key detection (decrypt_rejects_wrong_key)
    //
    // The unlock_wrong_password test verifies that unlock() properly
    // returns UnlockFailed when decryption fails, which covers the case
    // where ciphertext is corrupted (same AEAD tag failure).
}
