pub mod crypto;
pub mod vault;

use crate::crypto::KdfParams;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Missing,
    Locked,
    Unlocked,
}

impl VaultStatus {
    pub fn as_script_value(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Locked => "locked",
            Self::Unlocked => "unlocked",
        }
    }
}

#[derive(Debug, Error)]
pub enum KenvError {
    #[error("vault does not exist")]
    VaultMissing,
    #[error("vault is locked")]
    VaultLocked,
    #[error("unlock failed")]
    UnlockFailed,
    #[error("context does not exist")]
    ContextMissing,
    #[error("environment variable name is invalid")]
    InvalidEnvironmentVariableName,
    #[error("ssh key does not exist or is unsupported")]
    SshKeyUnavailable,
    #[error("platform capability is unavailable")]
    PlatformCapabilityUnavailable,
    #[error("file operation failed")]
    FileOperationFailed,
    #[error("vault already exists")]
    VaultAlreadyExists,
    #[error("vault file has an invalid format")]
    InvalidVaultFormat,
    #[error("encryption or decryption failed")]
    EncryptionError,
}

pub fn create_vault(password: &str) -> Result<(), KenvError> {
    let path = vault::vault_path()?;
    create_vault_at(&path, password, &KdfParams::recommended())
}

pub fn create_vault_at(path: &Path, password: &str, params: &KdfParams) -> Result<(), KenvError> {
    if path.exists() {
        return Err(KenvError::VaultAlreadyExists);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| KenvError::FileOperationFailed)?;
    }
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let key =
        crypto::derive_key(password, &salt, params).map_err(|_| KenvError::EncryptionError)?;
    let payload = vault::VaultPayload::new();
    let plaintext = serde_json::to_vec(&payload).map_err(|_| KenvError::FileOperationFailed)?;
    let ciphertext =
        crypto::encrypt(&key, &nonce, &plaintext).map_err(|_| KenvError::EncryptionError)?;
    vault::write_vault_file(path, &salt, &nonce, &ciphertext, params)
}

pub fn get_vault_status() -> Result<VaultStatus, KenvError> {
    let path = vault::vault_path()?;
    if path.exists() {
        Ok(VaultStatus::Locked)
    } else {
        Ok(VaultStatus::Missing)
    }
}

pub fn get_vault_status_with<F>(status_provider: F) -> Result<VaultStatus, KenvError>
where
    F: FnOnce() -> Result<VaultStatus, KenvError>,
{
    status_provider()
}
