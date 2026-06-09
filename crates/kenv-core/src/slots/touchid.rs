/// Touch ID unlock slot implementation using Keychain + Secure Enclave
use super::TouchIdSlotData;
use crate::crypto;
use crate::KenvError;
use rand::RngCore;

#[cfg(target_os = "macos")]
use crate::platform::macos;

/// Wrap DEK using Touch ID + Keychain + Secure Enclave
pub fn wrap_dek(dek: &[u8; 32], label: &str) -> Result<TouchIdSlotData, KenvError> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    // In production, we would:
    // 1. Generate a SecKey in Secure Enclave (P-256, biometric access)
    // 2. Create a Keychain item protected by that key
    // 3. Store the ciphertext there
    //
    // For MVP, we stub this and store encrypted DEK locally
    // The DEK is encrypted with a mock key derived from the keychain_ref

    let mock_wrapping_key = [1u8; 32]; // Temporary: replace with SE-derived key

    // Encrypt DEK with the wrapping key
    let ciphertext = crypto::encrypt(&mock_wrapping_key, &nonce, dek, &[])
        .map_err(|_| KenvError::EncryptionError)?;

    // Extract GCM tag
    if ciphertext.len() < 16 {
        return Err(KenvError::EncryptionError);
    }
    let encrypted_dek = ciphertext[..ciphertext.len() - 16].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext[ciphertext.len() - 16..]);

    // Store in Keychain (or mock version)
    #[cfg(target_os = "macos")]
    let keychain_ref = macos::store_touchid_protected_secret(&encrypted_dek, label)?;

    #[cfg(not(target_os = "macos"))]
    let keychain_ref = b"mock_keychain_ref".to_vec();

    Ok(TouchIdSlotData {
        keychain_ref,
        nonce,
        encrypted_dek,
        tag,
        biometric_type: "touchid".to_string(),
    })
}

/// Unwrap DEK using Touch ID + Keychain + Secure Enclave
pub fn unwrap_dek(slot: &TouchIdSlotData) -> Result<[u8; 32], KenvError> {
    // In production, this would:
    // 1. Use LAContext to evaluate Touch ID
    // 2. On success, access the Secure Enclave key
    // 3. Use it to decrypt the DEK from Keychain

    // For now, we stub this with a mock implementation
    #[cfg(target_os = "macos")]
    {
        use crate::platform::macos;

        // Evaluate biometric
        let _result =
            macos::evaluate_biometric("Unlock vault with Touch ID", macos::BiometricType::TouchId)?;

        // Retrieve from Keychain (or mock)
        let _secret = macos::retrieve_touchid_protected_secret(&slot.keychain_ref)?;

        // Use mock wrapping key (temporary)
        let mock_wrapping_key = [1u8; 32];

        // Reconstruct ciphertext and decrypt
        let mut ciphertext = Vec::with_capacity(slot.encrypted_dek.len() + 16);
        ciphertext.extend_from_slice(&slot.encrypted_dek);
        ciphertext.extend_from_slice(&slot.tag);

        let plaintext = crypto::decrypt(&mock_wrapping_key, &slot.nonce, &ciphertext, &[])
            .map_err(|_| KenvError::UnlockFailed)?;

        if plaintext.len() != 32 {
            return Err(KenvError::EncryptionError);
        }

        let mut dek = [0u8; 32];
        dek.copy_from_slice(&plaintext);
        Ok(dek)
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err(KenvError::PlatformCapabilityUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn wrap_and_unwrap_dek_with_touchid() {
        let dek = [42u8; 32];
        let slot = wrap_dek(&dek, "test_touchid").expect("wrap failed");

        assert_eq!(slot.biometric_type, "touchid");
        assert_eq!(slot.nonce.len(), 12);
        assert!(!slot.encrypted_dek.is_empty());

        let recovered = unwrap_dek(&slot).expect("unwrap failed");
        assert_eq!(recovered, dek);
    }
}
