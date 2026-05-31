use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};

#[derive(Clone, Debug)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub fn for_tests() -> Self {
        Self {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    pub fn recommended() -> Self {
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

pub fn derive_key(
    password: &str,
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<[u8; 32], argon2::Error> {
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| argon2::Error::MemoryTooLittle)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)?;
    Ok(key)
}

pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.encrypt(nonce, plaintext)
}

pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_returns_32_bytes() {
        let salt = [0u8; 32];
        let key = derive_key("hunter2", &salt, &KdfParams::for_tests()).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_key_is_deterministic() {
        let salt = [1u8; 32];
        let key1 = derive_key("password", &salt, &KdfParams::for_tests()).unwrap();
        let key2 = derive_key("password", &salt, &KdfParams::for_tests()).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_key_differs_for_different_passwords() {
        let salt = [2u8; 32];
        let key1 = derive_key("password1", &salt, &KdfParams::for_tests()).unwrap();
        let key2 = derive_key("password2", &salt, &KdfParams::for_tests()).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_differs_for_different_salts() {
        let salt1 = [3u8; 32];
        let salt2 = [4u8; 32];
        let key1 = derive_key("same_password", &salt1, &KdfParams::for_tests()).unwrap();
        let key2 = derive_key("same_password", &salt2, &KdfParams::for_tests()).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn encrypt_produces_ciphertext_longer_than_plaintext() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"hello vault";
        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn decrypt_reverses_encrypt() {
        let key = [5u8; 32];
        let nonce = [6u8; 12];
        let plaintext = b"round-trip test";
        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let recovered = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = [7u8; 32];
        let nonce = [8u8; 12];
        let plaintext = b"tamper test";
        let mut ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        ciphertext[0] ^= 0xFF;
        assert!(decrypt(&key, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let key1 = [9u8; 32];
        let key2 = [10u8; 32];
        let nonce = [11u8; 12];
        let ciphertext = encrypt(&key1, &nonce, b"secret").unwrap();
        assert!(decrypt(&key2, &nonce, &ciphertext).is_err());
    }
}
