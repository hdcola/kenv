use kenv_core;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UnlockRequest {
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListSlotsResponse {
    pub slots: Vec<SlotInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlotInfo {
    pub slot_id: u8,
    pub slot_type: String,
    pub label: String,
    pub last_used: Option<i64>,
    pub disabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListKeysResponse {
    pub keys: Vec<SshKeyInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SshKeyInfo {
    pub key_id: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveSlotRequest {
    pub slot_id: u8,
}

pub fn handle_unlock(req: UnlockRequest) -> Result<String, String> {
    kenv_core::unlock(&req.password)
        .map_err(|e| e.to_string())
        .map(|_| "ok".to_string())
}

pub fn handle_list_slots() -> Result<ListSlotsResponse, String> {
    let slots = kenv_core::list_slots().map_err(|e| e.to_string())?;
    let slots_info = slots
        .into_iter()
        .map(|s| SlotInfo {
            slot_id: s.slot_id,
            slot_type: format!("{:?}", s.slot_type),
            label: s.label,
            last_used: s.last_used.and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs() as i64)
            }),
            disabled: s.disabled,
        })
        .collect();
    Ok(ListSlotsResponse { slots: slots_info })
}

pub fn handle_list_keys() -> Result<ListKeysResponse, String> {
    let keys = kenv_core::list_ssh_keys().map_err(|e| e.to_string())?;
    let keys_info = keys
        .into_iter()
        .map(|k| SshKeyInfo {
            key_id: k.key_id,
            name: k.name,
        })
        .collect();
    Ok(ListKeysResponse { keys: keys_info })
}

pub fn handle_remove_slot(req: RemoveSlotRequest) -> Result<String, String> {
    match kenv_core::remove_slot(req.slot_id) {
        Ok(()) => Ok("ok".to_string()),
        Err(kenv_core::KenvError::UnlockFailed) => Err("reauthentication_required".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn handle_reauth_password(password: String) -> Result<String, String> {
    kenv_core::reauth_password(&password)
        .map_err(|e| e.to_string())
        .map(|_| "ok".to_string())
}

pub fn handle_lock() -> Result<String, String> {
    kenv_core::lock()
        .map_err(|e| e.to_string())
        .map(|_| "ok".to_string())
}

pub fn handle_create(password: String) -> Result<String, String> {
    let password_zeroizing = zeroize::Zeroizing::new(password);
    kenv_core::create_vault(&password_zeroizing)
        .map_err(|e| e.to_string())
        .map(|_| "vault_status=locked".to_string())
}

pub fn handle_status() -> Result<String, String> {
    kenv_core::get_vault_status()
        .map(|s| s.as_script_value().to_string())
        .map_err(|e| e.to_string())
}

