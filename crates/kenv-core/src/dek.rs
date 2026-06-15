/// Data Encryption Key (DEK) management
///
/// The DEK is a random 256-bit key that encrypts the vault payload.
/// Each unlock slot wraps this DEK using a different method (password, Touch ID, CTAP2, etc.).
use crate::crypto;
use crate::KenvError;
use rand::RngCore;

/// Generate a random DEK
pub fn generate() -> [u8; 32] {
    let mut dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut dek);
    dek
}

/// Encrypt payload with DEK
pub fn encrypt_payload(dek: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedPayload, KenvError> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext =
        crypto::encrypt(dek, &nonce, plaintext, &[]).map_err(|_| KenvError::EncryptionError)?;

    // Extract GCM tag (last 16 bytes)
    if ciphertext.len() < 16 {
        return Err(KenvError::EncryptionError);
    }

    let encrypted_payload = ciphertext[..ciphertext.len() - 16].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext[ciphertext.len() - 16..]);

    Ok(EncryptedPayload {
        nonce,
        ciphertext: encrypted_payload,
        tag,
    })
}

/// Decrypt payload with DEK
pub fn decrypt_payload(dek: &[u8; 32], encrypted: &EncryptedPayload) -> Result<Vec<u8>, KenvError> {
    // Reconstruct ciphertext (encrypted_payload + tag)
    let mut ciphertext = Vec::with_capacity(encrypted.ciphertext.len() + 16);
    ciphertext.extend_from_slice(&encrypted.ciphertext);
    ciphertext.extend_from_slice(&encrypted.tag);

    crypto::decrypt(dek, &encrypted.nonce, &ciphertext, &[]).map_err(|_| KenvError::EncryptionError)
}

/// Encrypted vault payload
#[derive(Clone, Debug)]
pub struct EncryptedPayload {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_32_bytes() {
        let dek = generate();
        assert_eq!(dek.len(), 32);
    }

    #[test]
    fn encrypt_and_decrypt_payload() {
        let dek = generate();
        let plaintext = b"test payload";

        let encrypted = encrypt_payload(&dek, plaintext).expect("encrypt failed");
        assert_eq!(encrypted.nonce.len(), 12);
        assert_eq!(encrypted.tag.len(), 16);
        assert!(encrypted.ciphertext.len() > 0);

        let decrypted = decrypt_payload(&dek, &encrypted).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_dek_fails() {
        let dek1 = generate();
        let dek2 = generate();
        let plaintext = b"secret message";

        let encrypted = encrypt_payload(&dek1, plaintext).expect("encrypt failed");
        let result = decrypt_payload(&dek2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn different_encryptions_use_different_nonces() {
        let dek = generate();
        let plaintext = b"same plaintext";

        let enc1 = encrypt_payload(&dek, plaintext).expect("encrypt1 failed");
        let enc2 = encrypt_payload(&dek, plaintext).expect("encrypt2 failed");

        // Nonces should be different (with overwhelming probability)
        assert_ne!(enc1.nonce, enc2.nonce);
    }
}
