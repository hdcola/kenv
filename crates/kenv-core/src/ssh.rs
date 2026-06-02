/// SSH key management and signing operations

use crate::KenvError;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use zeroize::Zeroizing;

/// SSH private key stored in vault
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SshKey {
    pub key_id: String,          // ed25519, rsa, ecdsa, etc.
    pub name: String,            // human-readable label
    pub public_key: Vec<u8>,     // OpenSSH format public key
    pub private_key: Vec<u8>,    // encrypted private key material
    pub key_type: SshKeyType,    // algorithm
    pub created_at: SystemTime,
    pub last_used: Option<SystemTime>,
    pub disabled: bool,
    pub require_reauthentication: bool, // Force reauthentication before signing
}

/// SSH key algorithm type
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SshKeyType {
    Ed25519,
    Rsa,
    EcdsaP256,
}

impl SshKeyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Rsa => "rsa",
            Self::EcdsaP256 => "ecdsa-p256",
        }
    }
}

/// SSH signature operation result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SshSignature {
    pub key_id: String,
    pub signature: Vec<u8>,
    pub signed_at: SystemTime,
}

/// Sign data with SSH key
///
/// If the key requires reauthentication (`require_reauthentication=true`),
/// returns KenvError::UnlockFailed to indicate reauthentication is needed.
/// Caller should invoke reauth_password() separately, then retry sign_ssh_key().
pub fn sign_ssh_key(
    _key_id: &str,
    _data_to_sign: &[u8],
) -> Result<SshSignature, KenvError> {
    // TODO: Implement actual SSH signing with libsodium or similar
    // For now, return stub implementation

    #[cfg(test)]
    {
        Ok(SshSignature {
            key_id: _key_id.to_string(),
            signature: vec![0u8; 64], // Mock Ed25519 signature length
            signed_at: SystemTime::now(),
        })
    }

    #[cfg(not(test))]
    {
        Err(KenvError::PlatformCapabilityUnavailable)
    }
}

/// Get SSH key metadata (non-secret information)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SshKeyInfo {
    pub key_id: String,
    pub name: String,
    pub key_type: SshKeyType,
    pub created_at: SystemTime,
    pub last_used: Option<SystemTime>,
    pub disabled: bool,
    pub require_reauthentication: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_key_type_to_string() {
        assert_eq!(SshKeyType::Ed25519.as_str(), "ed25519");
        assert_eq!(SshKeyType::Rsa.as_str(), "rsa");
        assert_eq!(SshKeyType::EcdsaP256.as_str(), "ecdsa-p256");
    }

    #[test]
    fn sign_ssh_key_returns_signature() {
        let signature = sign_ssh_key("test-key", b"test data").expect("signing failed");
        assert_eq!(signature.key_id, "test-key");
        assert_eq!(signature.signature.len(), 64); // Ed25519 signature
    }
}
