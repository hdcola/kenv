use super::PasswordSlotData;
use crate::crypto;
use crate::KenvError;
use rand::RngCore;
use zeroize::Zeroizing;

/// Wrap DEK using password-derived key
pub fn wrap_dek(
    password: &str,
    dek: &[u8; 32],
    params: &crypto::KdfParams,
) -> Result<PasswordSlotData, KenvError> {
    if password.trim().is_empty() {
        return Err(KenvError::WeakPassword);
    }

    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    // Derive wrapping key from password
    let wrapping_key = Zeroizing::new(
        crypto::derive_key(password, &salt, params)
            .map_err(|_| KenvError::EncryptionError)?,
    );

    // Encrypt DEK with wrapping key
    let ciphertext = crypto::encrypt(&*wrapping_key, &nonce, dek)
        .map_err(|_| KenvError::EncryptionError)?;

    // Extract GCM tag (last 16 bytes)
    if ciphertext.len() < 16 {
        return Err(KenvError::EncryptionError);
    }
    let encrypted_dek = ciphertext[..ciphertext.len() - 16].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext[ciphertext.len() - 16..]);

    Ok(PasswordSlotData {
        salt,
        kdf_m_cost: params.m_cost,
        kdf_t_cost: params.t_cost,
        kdf_p_cost: params.p_cost,
        nonce,
        encrypted_dek,
        tag,
    })
}

/// Unwrap DEK using password-derived key
pub fn unwrap_dek(
    password: &str,
    slot: &PasswordSlotData,
) -> Result<[u8; 32], KenvError> {
    if password.trim().is_empty() {
        return Err(KenvError::WeakPassword);
    }

    let params = crypto::KdfParams {
        m_cost: slot.kdf_m_cost,
        t_cost: slot.kdf_t_cost,
        p_cost: slot.kdf_p_cost,
    };

    // Derive wrapping key from password
    let wrapping_key = Zeroizing::new(
        crypto::derive_key(password, &slot.salt, &params)
            .map_err(|_| KenvError::EncryptionError)?,
    );

    // Reconstruct ciphertext (encrypted_dek + tag)
    let mut ciphertext = Vec::with_capacity(slot.encrypted_dek.len() + 16);
    ciphertext.extend_from_slice(&slot.encrypted_dek);
    ciphertext.extend_from_slice(&slot.tag);

    // Decrypt DEK
    let plaintext = crypto::decrypt(&*wrapping_key, &slot.nonce, &ciphertext)
        .map_err(|_| KenvError::UnlockFailed)?;

    if plaintext.len() != 32 {
        return Err(KenvError::EncryptionError);
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plaintext);
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_and_unwrap_dek() {
        let password = "test_password_123";
        let dek = [42u8; 32];
        let params = crypto::KdfParams::for_tests();

        let slot = wrap_dek(password, &dek, &params).expect("wrap failed");
        assert_eq!(slot.salt.len(), 32);
        assert_eq!(slot.nonce.len(), 12);
        assert!(slot.encrypted_dek.len() > 0);

        let recovered = unwrap_dek(password, &slot).expect("unwrap failed");
        assert_eq!(recovered, dek);
    }

    #[test]
    fn unwrap_with_wrong_password_fails() {
        let password = "correct_password";
        let dek = [99u8; 32];
        let params = crypto::KdfParams::for_tests();

        let slot = wrap_dek(password, &dek, &params).expect("wrap failed");
        let result = unwrap_dek("wrong_password", &slot);
        assert!(result.is_err());
    }

    #[test]
    fn wrap_empty_password_fails() {
        let dek = [7u8; 32];
        let params = crypto::KdfParams::for_tests();
        let result = wrap_dek("", &dek, &params);
        assert!(matches!(result, Err(KenvError::WeakPassword)));
    }
}
