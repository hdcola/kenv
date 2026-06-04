pub mod tlv;

use crate::{crypto::KdfParams, KenvError, slots, ssh};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub const MAGIC: &[u8; 4] = b"KENV";
pub const FILE_VERSION_V1: u8 = 1;
pub const FILE_VERSION_V2: u8 = 2;

// V1 format constants
pub const KDF_ID_ARGON2ID: u8 = 1;
pub const SALT_OFFSET: usize = 18;
pub const SALT_SIZE: usize = 32;
pub const NONCE_OFFSET: usize = 50;
pub const NONCE_SIZE: usize = 12;
pub const CIPHERTEXT_OFFSET: usize = 62;
pub const MIN_FILE_SIZE: usize = 91;

// V2 format header constants
pub const V2_HEADER_SIZE: usize = 62; // Same header as V1, followed by slots
pub const V2_SLOTS_OFFSET: usize = 62;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultPayload {
    pub version: u32,
    pub slots: Vec<slots::UnlockSlot>,
    pub ssh_keys: Vec<ssh::SshKey>,
}

impl VaultPayload {
    pub fn new() -> Self {
        Self {
            version: 1,
            slots: Vec::new(),
            ssh_keys: Vec::new(),
        }
    }
}

impl Zeroize for VaultPayload {
    fn zeroize(&mut self) {
        // Zeroize the slots
        for slot in &mut self.slots {
            // Zeroize sensitive data in each slot
            if let Some(ref mut pwd_data) = slot.password {
                pwd_data.salt.zeroize();
                pwd_data.nonce.zeroize();
                pwd_data.encrypted_dek.zeroize();
                pwd_data.tag.zeroize();
            }
            if let Some(ref mut ctap2_data) = slot.ctap2 {
                ctap2_data.challenge.zeroize();
                ctap2_data.nonce.zeroize();
                ctap2_data.encrypted_dek.zeroize();
                ctap2_data.tag.zeroize();
            }
            if let Some(ref mut touchid_data) = slot.touchid {
                touchid_data.keychain_ref.zeroize();
                touchid_data.nonce.zeroize();
                touchid_data.encrypted_dek.zeroize();
                touchid_data.tag.zeroize();
            }
        }
        self.slots.clear();
    }
}

// Thread-local storage for test vault path overrides
// Each test thread gets its own isolated path, preventing interference in concurrent test execution
thread_local! {
    static TEST_VAULT_PATH: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);
}

/// Set vault path for testing (truly isolated to calling thread)
pub fn set_test_vault_path(path: std::path::PathBuf) {
    TEST_VAULT_PATH.with(|p| {
        *p.lock().unwrap() = Some(path);
    });
}

/// Clear vault path for testing
pub fn clear_test_vault_path() {
    TEST_VAULT_PATH.with(|p| {
        *p.lock().unwrap() = None;
    });
}

pub fn vault_path() -> Result<std::path::PathBuf, KenvError> {
    // Check for test-injected path first (each thread has its own isolated thread-local value)
    if let Some(path) = TEST_VAULT_PATH.with(|p| p.lock().unwrap().clone()) {
        return Ok(path);
    }

    let home = dirs::home_dir().ok_or(KenvError::FileOperationFailed)?;
    Ok(home.join(".kenv").join("vault.kenv"))
}

pub fn write_vault_file(
    path: &Path,
    salt: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    params: &KdfParams,
    version: u8,
) -> Result<(), KenvError> {
    let mut buf = Vec::with_capacity(CIPHERTEXT_OFFSET + ciphertext.len());
    buf.extend_from_slice(MAGIC);
    buf.push(version);
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
    return Err(KenvError::PlatformCapabilityUnavailable);

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
    })?;

    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|_| {
                let _ = std::fs::remove_file(path);
                KenvError::FileOperationFailed
            })?;
    }

    Ok(())
}

pub fn validate_vault_header(data: &[u8]) -> Result<u8, KenvError> {
    if data.len() < MIN_FILE_SIZE {
        return Err(KenvError::InvalidVaultFormat);
    }
    if &data[0..4] != MAGIC.as_slice() {
        return Err(KenvError::InvalidVaultFormat);
    }

    let version = data[4];
    if version != FILE_VERSION_V1 && version != FILE_VERSION_V2 {
        return Err(KenvError::InvalidVaultFormat);
    }

    // V2 uses same header as V1, so check KDF ID only for V1
    if version == FILE_VERSION_V1 && data[5] != KDF_ID_ARGON2ID {
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

    Ok(version)
}
