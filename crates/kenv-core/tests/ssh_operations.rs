use kenv_core::{list_ssh_keys, sign_ssh_key, KenvError};

#[test]
fn list_ssh_keys_requires_unlocked_vault() {
    let error = list_ssh_keys().unwrap_err();
    assert_eq!(error.to_string(), "vault is locked");
}

#[test]
fn sign_ssh_key_requires_unlocked_vault() {
    let error = sign_ssh_key("key-id", b"data").unwrap_err();
    assert_eq!(error.to_string(), "vault is locked");
}
