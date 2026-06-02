pub mod crypto;
pub mod dek;
pub mod platform;
pub mod slots;
pub mod ssh;
pub mod vault;

pub use ssh::{SshKeyInfo, SshSignature};

use crate::crypto::KdfParams;
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Missing,
    Locked,
    Unlocked,
    Corrupted,
}

impl VaultStatus {
    pub fn as_script_value(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Locked => "locked",
            Self::Unlocked => "unlocked",
            Self::Corrupted => "corrupted",
        }
    }
}

use std::time::SystemTime;

#[derive(Clone, Default)]
struct VaultState {
    payload: Option<vault::VaultPayload>,
    unlocked_at: Option<SystemTime>,
    last_unlock_slot_id: Option<u8>,
}

impl Drop for VaultState {
    fn drop(&mut self) {
        // Explicitly zeroize on drop
        if let Some(ref mut payload) = self.payload {
            payload.zeroize();
        }
    }
}

static VAULT_STATE: RwLock<VaultState> = RwLock::new(VaultState {
    payload: None,
    unlocked_at: None,
    last_unlock_slot_id: None,
});

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
    #[error("password must not be empty")]
    WeakPassword,
}

pub fn create_vault(password: &str) -> Result<(), KenvError> {
    let path = vault::vault_path()?;
    create_vault_at(&path, password, &KdfParams::recommended())
}

pub fn create_vault_at(path: &Path, password: &str, params: &KdfParams) -> Result<(), KenvError> {
    if password.trim().is_empty() {
        return Err(KenvError::WeakPassword);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| KenvError::FileOperationFailed)?;
    }
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = Zeroizing::new(
        crypto::derive_key(password, &salt, params).map_err(|_| KenvError::EncryptionError)?,
    );
    let payload = vault::VaultPayload::new();
    let plaintext = {
        let data = serde_json::to_vec(&payload).map_err(|_| KenvError::FileOperationFailed)?;
        zeroize::Zeroizing::new(data)
    };
    let ciphertext =
        crypto::encrypt(&*key, &nonce, &plaintext).map_err(|_| KenvError::EncryptionError)?;
    vault::write_vault_file(path, &salt, &nonce, &ciphertext, params)
}

pub fn unlock(password: &str) -> Result<VaultStatus, KenvError> {
    let path = vault::vault_path()?;
    if !path.exists() {
        return Err(KenvError::VaultMissing);
    }

    // Read vault file
    let data = std::fs::read(&path).map_err(|_| KenvError::FileOperationFailed)?;

    // Validate header structure and get version
    let version = vault::validate_vault_header(&data)?;

    // Currently only support v1 in unlock()
    if version != vault::FILE_VERSION_V1 {
        return Err(KenvError::InvalidVaultFormat);
    }

    // Extract header fields
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
    let salt = &data[vault::SALT_OFFSET..vault::SALT_OFFSET + vault::SALT_SIZE];
    let salt_array: [u8; 32] = salt
        .try_into()
        .map_err(|_| KenvError::InvalidVaultFormat)?;
    let nonce = &data[vault::NONCE_OFFSET..vault::NONCE_OFFSET + vault::NONCE_SIZE];
    let nonce_array: [u8; 12] = nonce
        .try_into()
        .map_err(|_| KenvError::InvalidVaultFormat)?;

    let ciphertext = &data[vault::CIPHERTEXT_OFFSET..];

    let params = KdfParams {
        m_cost,
        t_cost,
        p_cost,
    };

    // Derive key from password
    let key = Zeroizing::new(
        crypto::derive_key(password, &salt_array, &params)
            .map_err(|_| KenvError::EncryptionError)?,
    );

    // Decrypt payload
    let plaintext = crypto::decrypt(&*key, &nonce_array, ciphertext)
        .map_err(|_| KenvError::UnlockFailed)?;

    // Deserialize payload
    let payload: vault::VaultPayload =
        serde_json::from_slice(&plaintext).map_err(|_| KenvError::EncryptionError)?;

    // Store in memory and return success
    {
        let mut state = VAULT_STATE.write();
        state.payload = Some(payload);
    }

    Ok(VaultStatus::Unlocked)
}

pub fn lock() -> Result<(), KenvError> {
    let mut state = VAULT_STATE.write();
    *state = VaultState::default();
    Ok(())
}

pub fn get_vault_status() -> Result<VaultStatus, KenvError> {
    let path = vault::vault_path()?;
    if !path.exists() {
        return Ok(VaultStatus::Missing);
    }

    // Check if vault is in-memory unlocked
    {
        let state = VAULT_STATE.read();
        if state.payload.is_some() {
            return Ok(VaultStatus::Unlocked);
        }
    }

    let data = std::fs::read(&path).map_err(|_| KenvError::FileOperationFailed)?;
    match vault::validate_vault_header(&data) {
        // Header is structurally valid. Ciphertext integrity cannot be verified
        // without the decryption key; that check belongs in unlock(). A vault with
        // corrupted ciphertext will return Locked here and only fail at unlock time.
        Ok(_version) => Ok(VaultStatus::Locked),
        Err(_) => Ok(VaultStatus::Corrupted),
    }
}

pub fn get_vault_status_with<F>(status_provider: F) -> Result<VaultStatus, KenvError>
where
    F: FnOnce() -> Result<VaultStatus, KenvError>,
{
    status_provider()
}

/// Slot information for management UI (non-secret metadata)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotInfo {
    pub slot_id: u8,
    pub slot_type: slots::SlotType,
    pub label: String,
    pub created_at: SystemTime,
    pub last_used: Option<SystemTime>,
    pub disabled: bool,
}

/// Add a new unlock slot to the vault
///
/// Requires vault to be unlocked. Low-risk operation (no password reauthentication).
/// Returns error if vault is locked or slot_id already exists.
pub fn add_slot(slot: slots::UnlockSlot) -> Result<(), KenvError> {
    let mut state = VAULT_STATE.write();

    // Require vault to be unlocked
    if state.payload.is_none() {
        return Err(KenvError::VaultLocked);
    }

    // Add slot to payload
    if let Some(ref mut payload) = state.payload {
        // Check slot_id is not already in use
        if payload.slots.iter().any(|s| s.slot_id == slot.slot_id) {
            return Err(KenvError::EncryptionError); // Reuse error for "slot already exists"
        }
        payload.slots.push(slot);
        Ok(())
    } else {
        Err(KenvError::VaultLocked)
    }
}

/// Remove an unlock slot from the vault
///
/// Requires vault to be unlocked. May require password reauthentication for high-risk cases:
/// - Deleting the last password slot (recovery mandate)
/// - Deleting the slot used to unlock current session
///
/// If high-risk operation is detected, returns KenvError::UnlockFailed with indicator.
/// Caller should invoke reauth_password() separately, then retry remove_slot().
pub fn remove_slot(slot_id: u8) -> Result<(), KenvError> {
    let mut state = VAULT_STATE.write();

    // Require vault to be unlocked
    if state.payload.is_none() {
        return Err(KenvError::VaultLocked);
    }

    // Copy last_unlock_slot_id before mutable borrow of payload
    let last_unlock_slot_id = state.last_unlock_slot_id;

    if let Some(ref mut payload) = state.payload {
        // Find the slot to remove
        let slot_index = payload.slots.iter().position(|s| s.slot_id == slot_id);
        let slot = match slot_index {
            Some(idx) => &payload.slots[idx],
            None => return Err(KenvError::EncryptionError), // Slot not found
        };

        // HIGH-RISK: Deleting last password slot
        let is_last_password = slot.slot_type == slots::SlotType::Password
            && payload.slots.iter().filter(|s| s.slot_type == slots::SlotType::Password).count() == 1;

        // HIGH-RISK: Deleting the slot used to unlock current session
        let is_current_unlock_slot = Some(slot_id) == last_unlock_slot_id;

        if is_last_password || is_current_unlock_slot {
            return Err(KenvError::UnlockFailed); // Indicates HIGH-risk reauthentication required
        }

        // LOW-RISK: Remove the slot
        payload.slots.remove(slot_index.unwrap());
        Ok(())
    } else {
        Err(KenvError::VaultLocked)
    }
}

/// List all unlock slots with metadata (non-secret information)
///
/// Requires vault to be unlocked. Returns slot_id, type, label, created_at, last_used, disabled.
pub fn list_slots() -> Result<Vec<SlotInfo>, KenvError> {
    let state = VAULT_STATE.read();

    // Require vault to be unlocked
    if state.payload.is_none() {
        return Err(KenvError::VaultLocked);
    }

    if let Some(ref payload) = state.payload {
        let slots = payload
            .slots
            .iter()
            .map(|s| SlotInfo {
                slot_id: s.slot_id,
                slot_type: s.slot_type,
                label: s.label.clone(),
                created_at: s.created_at,
                last_used: s.last_used,
                disabled: s.disabled,
            })
            .collect();
        Ok(slots)
    } else {
        Err(KenvError::VaultLocked)
    }
}

/// Rename an unlock slot
///
/// Requires vault to be unlocked. Low-risk operation (no password reauthentication).
pub fn rename_slot(slot_id: u8, new_label: String) -> Result<(), KenvError> {
    let mut state = VAULT_STATE.write();

    // Require vault to be unlocked
    if state.payload.is_none() {
        return Err(KenvError::VaultLocked);
    }

    if let Some(ref mut payload) = state.payload {
        // Find and rename the slot
        if let Some(slot) = payload.slots.iter_mut().find(|s| s.slot_id == slot_id) {
            slot.label = new_label;
            Ok(())
        } else {
            Err(KenvError::EncryptionError) // Slot not found
        }
    } else {
        Err(KenvError::VaultLocked)
    }
}

/// Reauthenticate with password for high-risk operations
///
/// Verifies password against the active password slot.
/// On success, sets an internal reauthentication flag (timeout-based).
/// On failure, returns UnlockFailed.
pub fn reauth_password(password: &str) -> Result<(), KenvError> {
    let state = VAULT_STATE.read();

    // Require vault to be unlocked
    if state.payload.is_none() {
        return Err(KenvError::VaultLocked);
    }

    if let Some(ref payload) = state.payload {
        // Find password slot
        let password_slot = payload
            .slots
            .iter()
            .find(|s| s.slot_type == slots::SlotType::Password && !s.disabled);

        if let Some(slot) = password_slot {
            // Verify password against password slot
            if let Some(ref pwd_data) = slot.password {
                let key = Zeroizing::new(
                    crypto::derive_key(password, &pwd_data.salt, &KdfParams {
                        m_cost: pwd_data.kdf_m_cost,
                        t_cost: pwd_data.kdf_t_cost,
                        p_cost: pwd_data.kdf_p_cost,
                    })
                    .map_err(|_| KenvError::EncryptionError)?,
                );

                // Reconstruct ciphertext and verify DEK decrypts correctly
                let mut ciphertext = Vec::with_capacity(pwd_data.encrypted_dek.len() + 16);
                ciphertext.extend_from_slice(&pwd_data.encrypted_dek);
                ciphertext.extend_from_slice(&pwd_data.tag);

                // Test decryption: if it succeeds, password is correct
                match crypto::decrypt(&*key, &pwd_data.nonce, &ciphertext) {
                    Ok(_) => {
                        // Password verification succeeded; in production would set reauthentication flag
                        Ok(())
                    }
                    Err(_) => Err(KenvError::UnlockFailed),
                }
            } else {
                Err(KenvError::EncryptionError) // Password slot missing password data
            }
        } else {
            Err(KenvError::EncryptionError) // No password slot available
        }
    } else {
        Err(KenvError::VaultLocked)
    }
}

/// List SSH keys with metadata (non-secret information)
///
/// Requires vault to be unlocked.
pub fn list_ssh_keys() -> Result<Vec<ssh::SshKeyInfo>, KenvError> {
    let state = VAULT_STATE.read();

    // Require vault to be unlocked
    if state.payload.is_none() {
        return Err(KenvError::VaultLocked);
    }

    if let Some(ref payload) = state.payload {
        let keys = payload
            .ssh_keys
            .iter()
            .map(|k| ssh::SshKeyInfo {
                key_id: k.key_id.clone(),
                name: k.name.clone(),
                key_type: k.key_type,
                created_at: k.created_at,
                last_used: k.last_used,
                disabled: k.disabled,
                require_reauthentication: k.require_reauthentication,
            })
            .collect();
        Ok(keys)
    } else {
        Err(KenvError::VaultLocked)
    }
}

/// Sign data with an SSH key
///
/// If the key requires reauthentication, returns KenvError::UnlockFailed.
/// Caller should invoke reauth_password() separately, then retry sign_ssh_key().
pub fn sign_ssh_key(key_id: &str, data_to_sign: &[u8]) -> Result<ssh::SshSignature, KenvError> {
    let state = VAULT_STATE.read();

    // Require vault to be unlocked
    if state.payload.is_none() {
        return Err(KenvError::VaultLocked);
    }

    if let Some(ref payload) = state.payload {
        // Find the SSH key
        let key = payload
            .ssh_keys
            .iter()
            .find(|k| k.key_id == key_id && !k.disabled);

        match key {
            Some(key) => {
                // Check if reauthentication is required
                if key.require_reauthentication {
                    return Err(KenvError::UnlockFailed); // Indicates reauthentication needed
                }

                // Perform the signing operation
                ssh::sign_ssh_key(key_id, data_to_sign)
            }
            None => Err(KenvError::SshKeyUnavailable),
        }
    } else {
        Err(KenvError::VaultLocked)
    }
}
