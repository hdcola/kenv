/// CTAP2/YubiKey unlock slot implementation with hmac-secret extension
use super::Ctap2SlotData;
use crate::crypto;
use crate::platform::ctap2;
use crate::KenvError;
use rand::RngCore;

/// Register a CTAP2 credential on a device and wrap DEK
pub fn register_and_wrap_dek(
    device: &ctap2::Ctap2Device,
    dek: &[u8; 32],
    _label: &str,
) -> Result<Ctap2SlotData, KenvError> {
    // Generate challenge (vault-specific binding)
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);

    // Register credential on device
    let credential = ctap2::register_credential(device, &challenge)?;

    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Obtain hmac-secret from device via initial assertion
    let initial_assertion = ctap2::get_assertion_with_hmac_secret(
        device,
        &credential.credential_id,
        &challenge,
        0, // registration: expect counter >= 1 from hardware
    )?;
    let wrapping_key = derive_wrapping_key(&initial_assertion.hmac_secret, &challenge)?;

    // Encrypt DEK with wrapping key
    let ciphertext =
        crypto::encrypt(&wrapping_key, &nonce, dek, &[]).map_err(|_| KenvError::EncryptionError)?;

    // Extract GCM tag
    if ciphertext.len() < 16 {
        return Err(KenvError::EncryptionError);
    }
    let encrypted_dek = ciphertext[..ciphertext.len() - 16].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext[ciphertext.len() - 16..]);

    Ok(Ctap2SlotData {
        credential_id: credential.credential_id,
        public_key: credential.public_key,
        challenge: challenge.to_vec(),
        counter: initial_assertion.counter,
        algorithm: -7, // ES256
        device_serial: device.serial.clone(),
        attestation_data: Some(credential.attestation_data),
        nonce,
        encrypted_dek,
        tag,
        requires_pin: false,
        requires_uv: true,
        requires_touch: true,
    })
}

/// Unlock with CTAP2 credential and derive DEK via hmac-secret
pub fn assert_and_unwrap_dek(
    device: &ctap2::Ctap2Device,
    slot: &Ctap2SlotData,
) -> Result<[u8; 32], KenvError> {
    // Perform GetAssertion with hmac-secret
    let challenge_array: [u8; 32] = slot
        .challenge
        .iter()
        .copied()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| KenvError::EncryptionError)?;
    let assertion = ctap2::get_assertion_with_hmac_secret(
        device,
        &slot.credential_id,
        &challenge_array,
        slot.counter,
    )?;

    // Verify counter increment (prevent cloning)
    if assertion.counter <= slot.counter {
        return Err(KenvError::UnlockFailed); // Counter didn't increment
    }

    // Derive wrapping key from hmac-secret
    let wrapping_key = derive_wrapping_key(&assertion.hmac_secret, &*slot.challenge)?;

    // Reconstruct ciphertext and decrypt
    let mut ciphertext = Vec::with_capacity(slot.encrypted_dek.len() + 16);
    ciphertext.extend_from_slice(&slot.encrypted_dek);
    ciphertext.extend_from_slice(&slot.tag);

    let plaintext = crypto::decrypt(&wrapping_key, &slot.nonce, &ciphertext, &[])
        .map_err(|_| KenvError::UnlockFailed)?;

    if plaintext.len() != 32 {
        return Err(KenvError::EncryptionError);
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plaintext);
    Ok(dek)
}

/// Derive wrapping key from hmac-secret
///
/// Uses HMAC-SHA256(hmac_secret, challenge || additional_data)
/// to derive the wrapping key deterministically.
fn derive_wrapping_key(hmac_secret: &[u8; 32], challenge: &[u8]) -> Result<[u8; 32], KenvError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(hmac_secret).map_err(|_| KenvError::EncryptionError)?;

    mac.update(challenge);
    mac.update(b"vault_wrapping_key");

    let result = mac.finalize();
    let bytes = result.into_bytes();

    let mut wrapping_key = [0u8; 32];
    if bytes.len() != 32 {
        return Err(KenvError::EncryptionError);
    }
    wrapping_key.copy_from_slice(&bytes);
    Ok(wrapping_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_wrap_dek_succeeds() {
        let device = ctap2::Ctap2Device {
            device_id: "test".to_string(),
            serial: Some("YubiKey#123".to_string()),
        };
        let dek = [99u8; 32];

        let slot = register_and_wrap_dek(&device, &dek, "test_label").expect("register failed");
        assert!(slot.counter > 0, "counter must be set from initial assertion");
        assert_eq!(slot.algorithm, -7); // ES256
        assert!(!slot.encrypted_dek.is_empty());
    }

    #[test]
    fn derive_wrapping_key_deterministic() {
        let hmac_secret = [1u8; 32];
        let challenge = b"test_challenge";

        let key1 = derive_wrapping_key(&hmac_secret, challenge).expect("derive1 failed");
        let key2 = derive_wrapping_key(&hmac_secret, challenge).expect("derive2 failed");

        assert_eq!(key1, key2);
    }

    #[test]
    fn different_challenges_produce_different_keys() {
        let hmac_secret = [2u8; 32];
        let challenge1 = b"challenge1";
        let challenge2 = b"challenge2";

        let key1 = derive_wrapping_key(&hmac_secret, challenge1).expect("derive1 failed");
        let key2 = derive_wrapping_key(&hmac_secret, challenge2).expect("derive2 failed");

        assert_ne!(key1, key2);
    }

    #[test]
    fn round_trip_register_then_unwrap_recovers_dek() {
        let device = ctap2::Ctap2Device {
            device_id: "test".to_string(),
            serial: Some("YubiKey#456".to_string()),
        };
        let original_dek = [77u8; 32];

        let slot = register_and_wrap_dek(&device, &original_dek, "round_trip")
            .expect("registration failed");

        let recovered_dek = assert_and_unwrap_dek(&device, &slot).expect("unlock failed");

        assert_eq!(original_dek, recovered_dek);
    }
}
