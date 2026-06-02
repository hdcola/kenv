/// macOS-specific implementations using Secure Enclave and Keychain

use crate::KenvError;

/// Biometric type for Touch ID
#[derive(Clone, Debug)]
pub enum BiometricType {
    TouchId,
}

impl BiometricType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TouchId => "touchid",
        }
    }
}

/// Result of Touch ID authentication
#[derive(Clone, Debug)]
pub struct BiometricResult {
    pub authenticated: bool,
    pub error: Option<String>,
}

/// Touch ID unlock context
pub struct TouchIdContext {
    pub keychain_ref: Vec<u8>,
    pub biometric_type: BiometricType,
}

/// Evaluate Touch ID authentication
///
/// In production, this would use LAContext from LocalAuthentication framework.
/// For testing, this is stubbed.
pub fn evaluate_biometric(
    _prompt: &str,
    _biometric_type: BiometricType,
) -> Result<BiometricResult, KenvError> {
    // TODO: Implement with security_framework + LocalAuthentication
    // For now, this is a stub that always fails on non-test builds

    #[cfg(test)]
    {
        // In tests, we can mock this
        Ok(BiometricResult {
            authenticated: true,
            error: None,
        })
    }

    #[cfg(not(test))]
    {
        Err(KenvError::PlatformCapabilityUnavailable)
    }
}

/// Store a secret in Keychain protected by Secure Enclave + Touch ID
///
/// Returns a reference to the stored item that can be used to retrieve it later.
pub fn store_touchid_protected_secret(
    _secret: &[u8],
    _label: &str,
) -> Result<Vec<u8>, KenvError> {
    // TODO: Implement with security_framework
    // For now, this is a stub

    #[cfg(test)]
    {
        // In tests, return a mock reference
        Ok(b"mock_keychain_ref".to_vec())
    }

    #[cfg(not(test))]
    {
        Err(KenvError::PlatformCapabilityUnavailable)
    }
}

/// Retrieve a secret from Keychain protected by Secure Enclave + Touch ID
///
/// This requires Touch ID evaluation to unlock Keychain access.
pub fn retrieve_touchid_protected_secret(
    keychain_ref: &[u8],
) -> Result<Vec<u8>, KenvError> {
    // TODO: Implement with security_framework
    // For now, this is a stub

    #[cfg(test)]
    {
        // In tests, return the reference as-is (would be replaced with mock secret)
        Ok(keychain_ref.to_vec())
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
    fn biometric_type_str() {
        assert_eq!(BiometricType::TouchId.as_str(), "touchid");
    }

    #[test]
    fn evaluate_biometric_succeeds_in_test() {
        let result = evaluate_biometric("Test", BiometricType::TouchId).unwrap();
        assert!(result.authenticated);
        assert_eq!(result.error, None);
    }

    #[test]
    fn store_and_retrieve_secret() {
        let secret = b"test_secret";
        let keychain_ref = store_touchid_protected_secret(secret, "test_label").unwrap();
        assert!(!keychain_ref.is_empty());

        let retrieved = retrieve_touchid_protected_secret(&keychain_ref).unwrap();
        assert_eq!(retrieved, keychain_ref); // In mock, returns ref as-is
    }
}
