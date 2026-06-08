use kenv_core::{self, KenvError};
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
pub struct SignRequest {
    pub key_id: String,
    #[serde(with = "base64_format")]
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub key_id: String,
    #[serde(with = "base64_format")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveSlotRequest {
    pub slot_id: u8,
}

pub mod base64_format {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64_encode(data))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64_decode(&s).map_err(serde::de::Error::custom)
    }

    fn base64_encode(data: &[u8]) -> String {
        use std::fmt::Write;
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        for chunk in data.chunks(3) {
            let b1 = chunk[0];
            let b2 = chunk.get(1).copied().unwrap_or(0);
            let b3 = chunk.get(2).copied().unwrap_or(0);

            let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);

            result.push(CHARS[(((n >> 18) & 0x3F) as usize)] as char);
            result.push(CHARS[(((n >> 12) & 0x3F) as usize)] as char);
            if chunk.len() > 1 {
                result.push(CHARS[(((n >> 6) & 0x3F) as usize)] as char);
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(CHARS[((n & 0x3F) as usize)] as char);
            } else {
                result.push('=');
            }
        }
        result
    }

    fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
        let mut result = Vec::new();
        let chars: Vec<_> = s.chars().collect();
        for chunk in chars.chunks(4) {
            if chunk.len() < 4 {
                return Err("invalid base64".to_string());
            }
            let c0 = decode_char(chunk[0])?;
            let c1 = decode_char(chunk[1])?;
            let c2 = if chunk[2] == '=' { 0 } else { decode_char(chunk[2])? };
            let c3 = if chunk[3] == '=' { 0 } else { decode_char(chunk[3])? };

            let n = ((c0 as u32) << 18) | ((c1 as u32) << 12) | ((c2 as u32) << 6) | (c3 as u32);

            result.push(((n >> 16) & 0xFF) as u8);
            if chunk[2] != '=' {
                result.push(((n >> 8) & 0xFF) as u8);
            }
            if chunk[3] != '=' {
                result.push((n & 0xFF) as u8);
            }
        }
        Ok(result)
    }

    fn decode_char(c: char) -> Result<u8, String> {
        match c {
            'A'..='Z' => Ok((c as u8) - b'A'),
            'a'..='z' => Ok((c as u8) - b'a' + 26),
            '0'..='9' => Ok((c as u8) - b'0' + 52),
            '+' => Ok(62),
            '/' => Ok(63),
            _ => Err(format!("invalid base64 char: {}", c)),
        }
    }
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

pub fn handle_sign(req: SignRequest) -> Result<SignResponse, String> {
    match kenv_core::sign_ssh_key(&req.key_id, &req.data) {
        Ok(sig) => Ok(SignResponse {
            key_id: sig.key_id,
            signature: sig.signature,
        }),
        Err(KenvError::UnlockFailed) => Err("reauthentication_required".to_string()),
        Err(e) => Err(e.to_string()),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_response_encodes_signature_as_base64() {
        // Cross-boundary wire contract: verify the desktop serializes the signature field
        // as the canonical base64 string the CLI's deserializer expects. The companion
        // test in kenv-cli/src/ipc.rs decodes this exact string back to the original bytes.
        //
        // [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02] must serialize to "3q2+7wABAg==".
        let response = SignResponse {
            key_id: "k".to_string(),
            signature: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02],
        };
        let wire = serde_json::to_string(&response).expect("serialize failed");
        let parsed: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed["signature"], "3q2+7wABAg==");
    }
}
