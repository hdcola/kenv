pub mod crypto;
pub mod dek;
pub mod platform;
pub mod slots;
pub mod ssh;
pub mod vault;

pub use ssh::{SshKeyInfo, SshSignature};

use crate::crypto::KdfParams;
use parking_lot::{Mutex, RwLock};
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

#[derive(Clone)]
struct VaultState {
    payload: Option<vault::VaultPayload>,
    unlocked_at: Option<SystemTime>,
    last_unlock_slot_id: Option<u8>,
    dek: Option<[u8; 32]>,
    reauthenticated_at: Option<SystemTime>,
    /// FILE_SALT for V2 (random at creation, constant); KDF salt for V1 (used to re-derive key).
    salt: Option<[u8; 32]>,
    /// Only populated for V1 vaults (KDF params live per-slot for V2).
    kdf_params: Option<KdfParams>,
    vault_path: Option<std::path::PathBuf>,
    file_version: Option<u8>,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            payload: None,
            unlocked_at: None,
            last_unlock_slot_id: None,
            dek: None,
            reauthenticated_at: None,
            salt: None,
            kdf_params: None,
            vault_path: None,
            file_version: None,
        }
    }
}

impl Drop for VaultState {
    fn drop(&mut self) {
        // Explicitly zeroize on drop
        if let Some(ref mut payload) = self.payload {
            payload.zeroize();
        }
        if let Some(ref mut dek) = self.dek {
            dek.zeroize();
        }
    }
}

static VAULT_STATE: RwLock<VaultState> = RwLock::new(VaultState {
    payload: None,
    unlocked_at: None,
    last_unlock_slot_id: None,
    dek: None,
    reauthenticated_at: None,
    salt: None,
    kdf_params: None,
    vault_path: None,
    file_version: None,
});

/// Serializes disk writes from `persist_vault_state`. Acquired BEFORE `VAULT_STATE` is read
/// for snapshotting, so concurrent slot operations cannot collide on the on-disk tmp file or
/// produce interleaved rename ordering. Never acquired while holding any `VAULT_STATE` lock.
static PERSIST_MUTEX: Mutex<()> = Mutex::new(());

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
    #[error("ssh key signing is not yet implemented")]
    SshSigningNotImplemented,
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
    #[error("cannot remove the last password slot")]
    LastPasswordSlot,
}

pub fn create_vault(password: &str) -> Result<(), KenvError> {
    let path = vault::vault_path()?;
    create_vault_at(&path, password, &KdfParams::recommended())
}

/// Create a password unlock slot wrapping the provided encryption key
/// The key parameter should be the same key used to encrypt the vault payload
fn create_password_slot(
    password: &str,
    key: &[u8; 32],
    slot_id: u8,
    label: String,
    params: &KdfParams,
) -> Result<slots::UnlockSlot, KenvError> {
    let password_data = slots::password::wrap_dek(password, key, params)?;

    Ok(slots::UnlockSlot {
        slot_id,
        slot_type: slots::SlotType::Password,
        label,
        created_at: std::time::SystemTime::now(),
        password: Some(password_data),
        ctap2: None,
        touchid: None,
        requires_pin: false,
        requires_touch: false,
        pin_attempts_left: None,
        last_used: None,
        disabled: false,
    })
}

pub fn create_vault_at(path: &Path, password: &str, params: &KdfParams) -> Result<(), KenvError> {
    if password.trim().is_empty() {
        return Err(KenvError::WeakPassword);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| KenvError::FileOperationFailed)?;
    }

    // Random file-identity salt (written to header bytes 18-49, never changes per vault).
    let mut file_salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut file_salt);

    // Random payload nonce (bytes 50-61, refreshed on every persist).
    let mut payload_nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut payload_nonce);

    // Random DEK — NOT derived from the password; each slot wraps a copy of this DEK.
    let dek = Zeroizing::new(dek::generate());
    let mut dek_array = [0u8; 32];
    dek_array.copy_from_slice(&*dek);

    // Wrap the DEK in an initial password slot.
    let password_slot = create_password_slot(password, &dek_array, 1, "password".to_string(), params)?;

    let mut payload = vault::VaultPayload::new();
    payload.slots.push(password_slot);

    // Build the cleartext slot key-material section for V2.
    let slot_records = vault::build_cleartext_slot_records(&payload.slots);

    let plaintext = {
        let data = serde_json::to_vec(&payload).map_err(|_| KenvError::FileOperationFailed)?;
        zeroize::Zeroizing::new(data)
    };
    let ciphertext = crypto::encrypt(&dek_array, &payload_nonce, &plaintext)
        .map_err(|_| KenvError::EncryptionError)?;

    // KDF params in V2 header are unused (zeros); params live per-slot in slot_records.
    let zero_params = KdfParams { m_cost: 0, t_cost: 0, p_cost: 0 };
    vault::write_vault_file(
        path,
        &file_salt,
        &payload_nonce,
        &ciphertext,
        &zero_params,
        &slot_records,
        vault::FILE_VERSION_V2,
    )
}

pub fn unlock(password: &str) -> Result<VaultStatus, KenvError> {
    let path = vault::vault_path()?;
    if !path.exists() {
        return Err(KenvError::VaultMissing);
    }

    let data = std::fs::read(&path).map_err(|_| KenvError::FileOperationFailed)?;
    let version = vault::validate_vault_header(&data)?;

    let salt_array: [u8; 32] = data[vault::SALT_OFFSET..vault::SALT_OFFSET + vault::SALT_SIZE]
        .try_into()
        .map_err(|_| KenvError::InvalidVaultFormat)?;
    let nonce_array: [u8; 12] =
        data[vault::NONCE_OFFSET..vault::NONCE_OFFSET + vault::NONCE_SIZE]
            .try_into()
            .map_err(|_| KenvError::InvalidVaultFormat)?;

    let (dek, unlock_slot_id, ciphertext, kdf_params_opt) = if version == vault::FILE_VERSION_V2 {
        // V2: iterate cleartext slot records to unwrap the DEK.
        let (records, ciphertext_start) = vault::parse_cleartext_slot_records(&data)?;

        let mut found: Option<([u8; 32], u8)> = None; // (dek, slot_id)
        for rec in &records {
            if let vault::ParsedSlotKeyData::Password(ref pwd_data) = rec.key_data {
                if let Ok(d) = slots::password::unwrap_dek(password, pwd_data) {
                    found = Some((d, rec.slot_id));
                    break;
                }
            }
        }
        let (dek, slot_id) = found.ok_or(KenvError::UnlockFailed)?;
        (dek, Some(slot_id), &data[ciphertext_start..], None)
    } else {
        // V1: re-derive the DEK from the header salt (single-password format).
        let m_cost = u32::from_be_bytes(
            data[6..10].try_into().map_err(|_| KenvError::InvalidVaultFormat)?,
        );
        let t_cost = u32::from_be_bytes(
            data[10..14].try_into().map_err(|_| KenvError::InvalidVaultFormat)?,
        );
        let p_cost = u32::from_be_bytes(
            data[14..18].try_into().map_err(|_| KenvError::InvalidVaultFormat)?,
        );
        let params = KdfParams { m_cost, t_cost, p_cost };
        let key_bytes = crypto::derive_key(password, &salt_array, &params)
            .map_err(|_| KenvError::EncryptionError)?;
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&key_bytes);
        // V1 is single-password; no slot_id tracking.
        (dek, None, &data[vault::CIPHERTEXT_OFFSET..], Some(params))
    };

    let plaintext =
        crypto::decrypt(&dek, &nonce_array, ciphertext).map_err(|_| KenvError::UnlockFailed)?;
    let payload: vault::VaultPayload =
        serde_json::from_slice(&plaintext).map_err(|_| KenvError::EncryptionError)?;

    // Replace VaultState wholesale to zeroize prior secrets and reset all session fields.
    // See the comment in the previous implementation for the full rationale.
    {
        let mut state = VAULT_STATE.write();
        if let Some(ref mut p) = state.payload {
            p.zeroize();
        }
        if let Some(ref mut d) = state.dek {
            d.zeroize();
        }
        if let Some(ref mut s) = state.salt {
            s.zeroize();
        }
        *state = VaultState {
            payload: Some(payload),
            unlocked_at: Some(SystemTime::now()),
            last_unlock_slot_id: unlock_slot_id,
            dek: Some(dek),
            reauthenticated_at: None,
            salt: Some(salt_array),
            kdf_params: kdf_params_opt,
            vault_path: Some(path.clone()),
            file_version: Some(version),
        };
    }

    Ok(VaultStatus::Unlocked)
}

/// Unlock the vault using Touch ID (macOS Secure Enclave / Keychain).
///
/// Iterates V2 cleartext TouchID slot records; for each one calls
/// `slots::touchid::unwrap_dek` which triggers a biometric prompt. Returns
/// `UnlockFailed` if no TouchID slot can be unwrapped, or
/// `PlatformCapabilityUnavailable` on non-macOS builds.
pub fn unlock_with_touchid() -> Result<VaultStatus, KenvError> {
    let path = vault::vault_path()?;
    if !path.exists() {
        return Err(KenvError::VaultMissing);
    }

    let data = std::fs::read(&path).map_err(|_| KenvError::FileOperationFailed)?;
    let version = vault::validate_vault_header(&data)?;

    if version != vault::FILE_VERSION_V2 {
        // V1 vaults have no slot section; TouchID unlock requires V2.
        return Err(KenvError::PlatformCapabilityUnavailable);
    }

    let salt_array: [u8; 32] = data[vault::SALT_OFFSET..vault::SALT_OFFSET + vault::SALT_SIZE]
        .try_into()
        .map_err(|_| KenvError::InvalidVaultFormat)?;
    let nonce_array: [u8; 12] =
        data[vault::NONCE_OFFSET..vault::NONCE_OFFSET + vault::NONCE_SIZE]
            .try_into()
            .map_err(|_| KenvError::InvalidVaultFormat)?;

    let (records, ciphertext_start) = vault::parse_cleartext_slot_records(&data)?;
    let ciphertext = &data[ciphertext_start..];

    let mut found: Option<([u8; 32], u8)> = None;
    for rec in &records {
        if let vault::ParsedSlotKeyData::TouchId {
            keychain_ref,
            nonce,
            encrypted_dek,
            tag,
        } = &rec.key_data
        {
            let stub = slots::TouchIdSlotData {
                keychain_ref: keychain_ref.clone(),
                nonce: *nonce,
                encrypted_dek: encrypted_dek.clone(),
                tag: *tag,
                biometric_type: "touchid".to_string(),
            };
            if let Ok(d) = slots::touchid::unwrap_dek(&stub) {
                found = Some((d, rec.slot_id));
                break;
            }
        }
    }
    let (dek, unlock_slot_id) = found.ok_or(KenvError::UnlockFailed)?;

    let plaintext =
        crypto::decrypt(&dek, &nonce_array, ciphertext).map_err(|_| KenvError::UnlockFailed)?;
    let payload: vault::VaultPayload =
        serde_json::from_slice(&plaintext).map_err(|_| KenvError::EncryptionError)?;

    {
        let mut state = VAULT_STATE.write();
        if let Some(ref mut p) = state.payload {
            p.zeroize();
        }
        if let Some(ref mut d) = state.dek {
            d.zeroize();
        }
        if let Some(ref mut s) = state.salt {
            s.zeroize();
        }
        *state = VaultState {
            payload: Some(payload),
            unlocked_at: Some(SystemTime::now()),
            last_unlock_slot_id: Some(unlock_slot_id),
            dek: Some(dek),
            reauthenticated_at: None,
            salt: Some(salt_array),
            kdf_params: None,
            vault_path: Some(path.clone()),
            file_version: Some(vault::FILE_VERSION_V2),
        };
    }

    Ok(VaultStatus::Unlocked)
}

pub fn lock() -> Result<(), KenvError> {
    let mut state = VAULT_STATE.write();
    *state = VaultState::default();
    Ok(())
}

fn persist_vault_state() -> Result<(), KenvError> {
    let _persist_guard = PERSIST_MUTEX.lock();
    let state = VAULT_STATE.read();
    let payload = state.payload.as_ref().ok_or(KenvError::VaultLocked)?;
    let dek = state.dek.ok_or(KenvError::VaultLocked)?;
    let salt = state.salt.ok_or(KenvError::VaultLocked)?;
    let file_version = state.file_version.unwrap_or(vault::FILE_VERSION_V2);

    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let plaintext = {
        let data = serde_json::to_vec(&payload).map_err(|_| KenvError::FileOperationFailed)?;
        zeroize::Zeroizing::new(data)
    };
    let ciphertext =
        crypto::encrypt(&dek, &nonce, &plaintext).map_err(|_| KenvError::EncryptionError)?;

    let vault_path = vault::vault_path()?;

    if file_version == vault::FILE_VERSION_V2 {
        // Rebuild cleartext slot records from current in-memory slot list.
        let slot_records = vault::build_cleartext_slot_records(&payload.slots);
        let zero_params = KdfParams { m_cost: 0, t_cost: 0, p_cost: 0 };
        vault::overwrite_vault_file(
            &vault_path, &salt, &nonce, &ciphertext, &zero_params, &slot_records,
            vault::FILE_VERSION_V2,
        )
    } else {
        let kdf_params = state.kdf_params.clone().ok_or(KenvError::VaultLocked)?;
        vault::overwrite_vault_file(
            &vault_path, &salt, &nonce, &ciphertext, &kdf_params, &[],
            vault::FILE_VERSION_V1,
        )
    }
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
    {
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
        } else {
            return Err(KenvError::VaultLocked);
        }
    }
    // Drop write lock before persisting
    persist_vault_state()
}

/// Whether a recorded reauthentication timestamp is still within the 5-minute window.
///
/// Takes the timestamp by value so callers can pass a field read from a `VAULT_STATE` guard
/// they already hold — acquiring a fresh lock here would deadlock a caller holding the write
/// lock, since `parking_lot::RwLock` is not reentrant.
fn reauth_window_valid(reauth_time: Option<SystemTime>) -> bool {
    if let Some(reauth_time) = reauth_time {
        if let Ok(elapsed) = SystemTime::now().duration_since(reauth_time) {
            elapsed < std::time::Duration::from_secs(300) // 5-minute window
        } else {
            false // Clock went backwards
        }
    } else {
        false
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
    {
        let mut state = VAULT_STATE.write();

        // Require vault to be unlocked
        if state.payload.is_none() {
            return Err(KenvError::VaultLocked);
        }

        // Read reauth status from the guard we already hold; calling a helper that re-locks
        // VAULT_STATE here would deadlock (the write lock is held below).
        let reauthenticated = reauth_window_valid(state.reauthenticated_at);

        if let Some(ref mut payload) = state.payload {
            // Find the slot to remove
            let slot_index = payload.slots.iter().position(|s| s.slot_id == slot_id);
            let slot = match slot_index {
                Some(idx) => &payload.slots[idx],
                None => return Err(KenvError::EncryptionError), // Slot not found
            };

            // Check if removing a password slot (requires reauthentication)
            let is_password_slot = slot.slot_type == slots::SlotType::Password;
            let is_enabled_password_slot = is_password_slot && !slot.disabled;

            // Recovery mandate: never let the vault lose its last usable password slot,
            // which would make it permanently unlockable. Checked before reauth so the
            // operation is rejected up front.
            if is_enabled_password_slot {
                let enabled_password_count = payload
                    .slots
                    .iter()
                    .filter(|s| s.slot_type == slots::SlotType::Password && !s.disabled)
                    .count();
                if enabled_password_count <= 1 {
                    return Err(KenvError::LastPasswordSlot);
                }
            }

            if is_password_slot && !reauthenticated {
                return Err(KenvError::UnlockFailed); // Requires password reauthentication
            }

            // Remove the slot
            payload.slots.remove(slot_index.unwrap());
        } else {
            return Err(KenvError::VaultLocked);
        }
    }
    // Drop write lock before persisting
    persist_vault_state()
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
    {
        let mut state = VAULT_STATE.write();

        // Require vault to be unlocked
        if state.payload.is_none() {
            return Err(KenvError::VaultLocked);
        }

        if let Some(ref mut payload) = state.payload {
            // Find and rename the slot
            if let Some(slot) = payload.slots.iter_mut().find(|s| s.slot_id == slot_id) {
                slot.label = new_label;
            } else {
                return Err(KenvError::EncryptionError); // Slot not found
            }
        } else {
            return Err(KenvError::VaultLocked);
        }
    }
    // Drop write lock before persisting
    persist_vault_state()
}

/// Reauthenticate with password for high-risk operations
///
/// Verifies password against the active password slot.
/// On success, sets an internal reauthentication flag (timeout-based).
/// On failure, returns UnlockFailed.
pub fn reauth_password(password: &str) -> Result<(), KenvError> {
    // Verify password (requires read lock)
    {
        let state = VAULT_STATE.read();

        // Require vault to be unlocked and for the same vault path. The unlocking thread is
        // intentionally NOT checked: VAULT_STATE is process-global, and the desktop socket
        // server handles each connection on a fresh thread, so unlock and reauth legitimately
        // run on different threads.
        let current_path = vault::vault_path()?;
        if state.payload.is_none() || state.vault_path.as_ref() != Some(&current_path) {
            return Err(KenvError::VaultLocked);
        }

        if let Some(ref payload) = state.payload {
            // Prefer the slot that was actually used to unlock this session. This ensures
            // multi-password vaults verify against the right password — otherwise a vault
            // with slot 1 (password A) and slot 2 (password B) would always verify against
            // slot 1, silently failing when the user unlocked with slot 2's password.
            // Fall back to any enabled password slot if last_unlock_slot_id is missing or
            // the specific slot was subsequently deleted.
            let target_id = state.last_unlock_slot_id;
            let password_slot = target_id
                .and_then(|id| {
                    payload.slots.iter().find(|s| {
                        s.slot_id == id
                            && s.slot_type == slots::SlotType::Password
                            && !s.disabled
                    })
                })
                .or_else(|| {
                    payload
                        .slots
                        .iter()
                        .find(|s| s.slot_type == slots::SlotType::Password && !s.disabled)
                });

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
                            // Password verification succeeded; will set reauthentication flag below
                        }
                        Err(_) => return Err(KenvError::UnlockFailed),
                    }
                } else {
                    return Err(KenvError::EncryptionError); // Password slot missing password data
                }
            } else {
                return Err(KenvError::EncryptionError); // No password slot available
            }
        } else {
            return Err(KenvError::VaultLocked);
        }
    }

    // Set reauthentication flag (requires write lock)
    {
        let mut state = VAULT_STATE.write();
        state.reauthenticated_at = Some(SystemTime::now());
    }

    Ok(())
}

/// Add a new password-based unlock slot, wrapping the vault DEK with the given password.
///
/// Requires the vault to be unlocked. The new slot gets a `slot_id` one above the current
/// maximum. On success, the updated slot list is persisted to disk.
pub fn add_password_slot(password: &str, params: &KdfParams) -> Result<(), KenvError> {
    if password.trim().is_empty() {
        return Err(KenvError::WeakPassword);
    }

    // Read DEK and compute next slot_id under a short-lived read guard.
    // [u8; 32] is Copy, so we can safely move a copy out before dropping the guard.
    let (dek_raw, next_slot_id) = {
        let state = VAULT_STATE.read();
        let dek = state.dek.ok_or(KenvError::VaultLocked)?;
        let next_id = state
            .payload
            .as_ref()
            .map(|p| {
                let max_id = p.slots.iter().map(|s| s.slot_id as u16).max().unwrap_or(0);
                (max_id + 1).min(255) as u8
            })
            .ok_or(KenvError::VaultLocked)?;
        (dek, next_id)
    };
    let dek = Zeroizing::new(dek_raw);

    let password_data = slots::password::wrap_dek(password, &*dek, params)?;

    let slot = slots::UnlockSlot {
        slot_id: next_slot_id,
        slot_type: slots::SlotType::Password,
        label: "password".to_string(),
        created_at: std::time::SystemTime::now(),
        password: Some(password_data),
        ctap2: None,
        touchid: None,
        requires_pin: false,
        requires_touch: false,
        pin_attempts_left: None,
        last_used: None,
        disabled: false,
    };

    add_slot(slot)
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
                // Check if key requires reauthentication. Read the timestamp from the guard we
                // already hold rather than re-locking VAULT_STATE.
                if key.require_reauthentication && !reauth_window_valid(state.reauthenticated_at) {
                    return Err(KenvError::UnlockFailed);
                }
                ssh::sign_ssh_key(key_id, data_to_sign)
            }
            None => Err(KenvError::SshKeyUnavailable),
        }
    } else {
        Err(KenvError::VaultLocked)
    }
}

/// Inject an SSH key into the unlocked vault payload. **Test-only helper.**
///
/// Requires the vault to already be unlocked (payload present). Used by integration tests
/// to exercise the sign path before a public add_ssh_key API exists. Mirrors the
/// `vault::set_test_vault_path` pattern: plain `pub` so integration test binaries can
/// reach it (integration tests link the lib in non-test mode, so `#[cfg(test)]` is not
/// compiled into the integration test binary).
#[doc(hidden)]
pub fn test_insert_ssh_key(key: ssh::SshKey) {
    VAULT_STATE.write().payload.as_mut().map(|p| p.ssh_keys.push(key));
}
