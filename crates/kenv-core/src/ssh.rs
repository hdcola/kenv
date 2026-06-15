/// SSH key management and signing operations
use crate::KenvError;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// SSH private key stored in vault
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SshKey {
    pub key_id: String,       // ed25519, rsa, ecdsa, etc.
    pub name: String,         // human-readable label
    pub public_key: Vec<u8>,  // OpenSSH format public key
    pub private_key: Vec<u8>, // encrypted private key material
    pub key_type: SshKeyType, // algorithm
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
/// **Not yet implemented**: This is a test-only stub.
/// Returns SshSigningNotImplemented in production.
///
/// To implement SSH signing, the following is required:
/// 1. OpenSSH private key parsing (RFC 4251 wire format or OpenSSH format)
/// 2. Per-key-type signing implementations:
///    - Ed25519: ed25519-dalek
///    - RSA: rsa crate
///    - ECDSA P-256: ecdsa crate
/// 3. Private key decryption after vault unlock (use stored DEK)
/// 4. Signature generation matching OpenSSH format
pub fn sign_ssh_key(_key_id: &str, _data_to_sign: &[u8]) -> Result<SshSignature, KenvError> {
    Err(KenvError::SshSigningNotImplemented)
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
    fn sign_ssh_key_not_implemented() {
        let error = sign_ssh_key("test-key", b"test data").unwrap_err();
        assert!(matches!(error, KenvError::SshSigningNotImplemented));
    }
}
