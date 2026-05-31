use crate::{crypto::KdfParams, KenvError};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub const MAGIC: &[u8; 4] = b"KENV";
pub const FILE_VERSION: u8 = 1;
pub const KDF_ID_ARGON2ID: u8 = 1;
pub const SALT_OFFSET: usize = 18;
pub const SALT_SIZE: usize = 32;
pub const NONCE_OFFSET: usize = 50;
pub const NONCE_SIZE: usize = 12;
pub const CIPHERTEXT_OFFSET: usize = 62;
pub const MIN_FILE_SIZE: usize = 91;

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
    #[cfg(unix)]
    let open_result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path);
    #[cfg(not(unix))]
    compile_error!("vault file creation is currently supported only on macOS and Linux; Windows support will be added later");
    let mut file = open_result.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            KenvError::VaultAlreadyExists
        } else {
            KenvError::FileOperationFailed
        }
    })?;
    file.write_all(&buf).map_err(|_| {
        let _ = std::fs::remove_file(path);
        KenvError::FileOperationFailed
    })?;
    file.sync_all().map_err(|_| {
        let _ = std::fs::remove_file(path);
        KenvError::FileOperationFailed
    })
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

    let m_cost = u32::from_be_bytes(
        data[6..10]
            .try_into()
            .map_err(|_| KenvError::InvalidVaultFormat)?,
    );
    let t_cost = u32::from_be_bytes(
        data[10..14]
            .try_into()
            .map_err(|_| KenvError::InvalidVaultFormat)?,
    );
    let p_cost = u32::from_be_bytes(
        data[14..18]
            .try_into()
            .map_err(|_| KenvError::InvalidVaultFormat)?,
    );

    if m_cost == 0 || t_cost == 0 || p_cost == 0 {
        return Err(KenvError::InvalidVaultFormat);
    }

    let salt = &data[SALT_OFFSET..SALT_OFFSET + SALT_SIZE];
    if salt.iter().all(|&b| b == 0) {
        return Err(KenvError::InvalidVaultFormat);
    }

    let nonce = &data[NONCE_OFFSET..NONCE_OFFSET + NONCE_SIZE];
    if nonce.iter().all(|&b| b == 0) {
        return Err(KenvError::InvalidVaultFormat);
    }

    Ok(())
}
