/// CTAP2 (WebAuthn) device support for universal FIDO2 keys
///
/// Supports YubiKey 5.2+, Google Titan, Feitian, and other CTAP2 devices.
/// Uses hmac-secret extension for deterministic key derivation.
use crate::KenvError;

/// CTAP2 device information
#[derive(Clone, Debug)]
pub struct Ctap2Device {
    pub device_id: String,
    pub serial: Option<String>,
}

/// CTAP2 credential (result of MakeCredential)
#[derive(Clone, Debug)]
pub struct Ctap2Credential {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>, // CBOR-encoded COSE public key
    pub attestation_data: Vec<u8>,
}

/// CTAP2 assertion (result of GetAssertion with hmac-secret)
#[derive(Clone, Debug)]
pub struct Ctap2Assertion {
    pub signature: Vec<u8>,
    pub counter: u32,
    pub hmac_secret: [u8; 32],
}

/// Enumerate connected CTAP2 devices
pub fn enumerate_devices() -> Result<Vec<Ctap2Device>, KenvError> {
    // TODO: Implement with ctap2-rs or fido-device crate
    // For now, return empty list (stub)

    #[cfg(test)]
    {
        Ok(vec![Ctap2Device {
            device_id: "mock_device_1".to_string(),
            serial: Some("YubiKey 5Ci #AB1234".to_string()),
        }])
    }

    #[cfg(not(test))]
    {
        Err(KenvError::PlatformCapabilityUnavailable)
    }
}

/// Create a credential on a CTAP2 device (MakeCredential)
///
/// Returns credential_id, public_key, and attestation data.
pub fn register_credential(
    _device: &Ctap2Device,
    _challenge: &[u8; 32],
) -> Result<Ctap2Credential, KenvError> {
    // TODO: Implement with ctap2-rs
    // For now, return mock data

    #[cfg(test)]
    {
        Ok(Ctap2Credential {
            credential_id: b"mock_credential_id".to_vec(),
            public_key: b"mock_public_key".to_vec(),
            attestation_data: b"mock_attestation".to_vec(),
        })
    }

    #[cfg(not(test))]
    {
        Err(KenvError::PlatformCapabilityUnavailable)
    }
}

/// Assert with a credential and derive hmac-secret (GetAssertion)
///
/// The challenge should be the vault-specific binding challenge.
/// Returns signature, counter, and hmac-secret for key derivation.
pub fn get_assertion_with_hmac_secret(
    _device: &Ctap2Device,
    _credential_id: &[u8],
    _challenge: &[u8; 32],
    _expected_counter: u32,
) -> Result<Ctap2Assertion, KenvError> {
    // TODO: Implement with ctap2-rs
    // Must verify counter > expected_counter to prevent cloning
    // For now, return mock data

    #[cfg(test)]
    {
        let mut hmac_secret = [0u8; 32];
        hmac_secret[0] = 42; // Mock value
        Ok(Ctap2Assertion {
            signature: b"mock_signature".to_vec(),
            counter: _expected_counter + 1,
            hmac_secret,
        })
    }

    #[cfg(not(test))]
    {
        Err(KenvError::PlatformCapabilityUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_devices_returns_mocks() {
        let devices = enumerate_devices().expect("enumerate failed");
        assert!(!devices.is_empty());
        assert!(devices[0].serial.is_some());
    }

    #[test]
    fn register_credential_returns_valid_data() {
        let device = Ctap2Device {
            device_id: "test_device".to_string(),
            serial: Some("TEST#123".to_string()),
        };
        let challenge = [1u8; 32];

        let cred = register_credential(&device, &challenge).expect("register failed");
        assert!(!cred.credential_id.is_empty());
        assert!(!cred.public_key.is_empty());
    }

    #[test]
    fn get_assertion_returns_hmac_secret() {
        let device = Ctap2Device {
            device_id: "test_device".to_string(),
            serial: None,
        };
        let credential_id = b"test_cred_id".to_vec();
        let challenge = [2u8; 32];

        let assertion = get_assertion_with_hmac_secret(&device, &credential_id, &challenge, 1)
            .expect("assertion failed");
        assert_eq!(assertion.hmac_secret.len(), 32);
        assert!(assertion.counter > 1); // Counter incremented
    }

    #[test]
    fn assertion_counter_always_exceeds_expected() {
        let device = Ctap2Device {
            device_id: "test".to_string(),
            serial: None,
        };
        let cred = b"cred_id".to_vec();
        let challenge = [3u8; 32];

        // With expected_counter = 0 (registration time)
        let a0 = get_assertion_with_hmac_secret(&device, &cred, &challenge, 0).unwrap();
        assert!(a0.counter > 0, "counter must exceed expected=0");

        // With expected_counter = a0.counter (unlock time — simulates second call after
        // register)
        let a1 = get_assertion_with_hmac_secret(&device, &cred, &challenge, a0.counter).unwrap();
        assert!(
            a1.counter > a0.counter,
            "counter must exceed expected={}",
            a0.counter
        );
    }
}
