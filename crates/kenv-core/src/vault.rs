use crate::{crypto::KdfParams, KenvError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const MAGIC: &[u8; 4] = b"KENV";
pub const FILE_VERSION: u8 = 1;
pub const KDF_ID_ARGON2ID: u8 = 1;
pub const CIPHERTEXT_OFFSET: usize = 62;
pub const MIN_FILE_SIZE: usize = 78;

#[derive(Debug, Deserialize, Serialize)]
pub struct VaultPayload {
    pub version: u32,
}

impl VaultPayload {
    pub fn new() -> Self {
        Self { version: 1 }
    }
}

pub fn vault_path() -> Result<std::path::PathBuf, KenvError> {
    let home = dirs::home_dir().ok_or(KenvError::FileOperationFailed)?;
    Ok(home.join(".kenv").join("vault.kenv"))
}

pub fn write_vault_file(
    path: &Path,
    salt: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    params: &KdfParams,
) -> Result<(), KenvError> {
    let mut buf = Vec::with_capacity(CIPHERTEXT_OFFSET + ciphertext.len());
    buf.extend_from_slice(MAGIC);
    buf.push(FILE_VERSION);
    buf.push(KDF_ID_ARGON2ID);
    buf.extend_from_slice(&params.m_cost.to_be_bytes());
    buf.extend_from_slice(&params.t_cost.to_be_bytes());
    buf.extend_from_slice(&params.p_cost.to_be_bytes());
    buf.extend_from_slice(salt);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(ciphertext);
    std::fs::write(path, &buf).map_err(|_| KenvError::FileOperationFailed)
}

pub fn validate_vault_header(data: &[u8]) -> Result<(), KenvError> {
    if data.len() < MIN_FILE_SIZE {
        return Err(KenvError::InvalidVaultFormat);
    }
    if &data[0..4] != MAGIC.as_slice() {
        return Err(KenvError::InvalidVaultFormat);
    }
    if data[4] != FILE_VERSION {
        return Err(KenvError::InvalidVaultFormat);
    }
    if data[5] != KDF_ID_ARGON2ID {
        return Err(KenvError::InvalidVaultFormat);
    }
    Ok(())
}
